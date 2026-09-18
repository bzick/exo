use std::{
    collections::HashSet,
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use bytemuck::{Pod, Zeroable};
use log::{debug, trace, warn};
use netwatcher::WatchHandle;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket,
    time::{Interval, interval},
};
use zenoh::config::ZenohId;

const GROUP: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0xe0a1, 0xde89);
const MAGIC: [u8; 3] = *b"EXO";
/// bounds an individual `send_to`; without it, a single stalled call parks the
/// whole announce loop forever with no error and no log line.
const SEND_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Discovery {
    sock: Arc<UdpSocket>,
    ifaces: Arc<Mutex<Vec<SocketAddrV6>>>,
    /// every interface index netwatcher currently reports as present, kept in
    /// sync independently of whatever `announce` has pruned from `ifaces` for
    /// send failures -- the source of truth `resync_ifaces` rebuilds against.
    known_ifaces: Arc<Mutex<HashSet<u32>>>,
    discovery_port: u16,
    namespace: [u8; 8],
    last_nonce: Mutex<[u8; 8]>,
    /// the port of the service we are doing discovery for - transmitted to peers
    listen_port: u16,
    zid: ZenohId,
    tick: Interval,
    /// periodically re-adds any interface still in `known_ifaces` but missing
    /// from `ifaces`, so a send-side prune heals even when no netwatcher
    /// interface event ever fires again to trigger the AddrInUse path below.
    resync: Interval,
    _sync: Mutex<WatchHandle>,
}

#[derive(Debug, Clone, Copy)]
pub struct Discovered {
    pub zid: ZenohId,
    pub addr: SocketAddrV6,
}

impl Discovery {
    pub async fn new(
        zid: ZenohId,
        namespace: [u8; 8],
        listen_port: u16,
        discovery_port: u16,
    ) -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, discovery_port, 0, 0).into())?;
        sock.set_nonblocking(true)?;
        // Loopback delivery of our own multicast sends is never used for
        // anything -- `respond`'s Hello branch already drops a message whose
        // nonce matches our own last-sent one, precisely because it expected
        // to see its own packet looped back. On Darwin's IPv6 stack a looped
        // multicast send can trigger a bogus ICMP6 "unreachable" for the
        // multicast destination (RFC1122/1812 both say this must never
        // happen, but old BSD-derived stacks are known to do it anyway), and
        // that error latches onto the socket and is returned on every
        // subsequent send from then on -- explaining a HostUnreachable prune
        // that starts after the very first tick and never once recovers on
        // its own, on every interface including lo0, while a brand new
        // socket sends fine at the same instant. Not needed, and the
        // simplest way to remove the trigger entirely.
        sock.set_multicast_loop_v6(false)?;
        let sock = Arc::new(UdpSocket::from_std(sock.into())?);
        let ifaces: Arc<Mutex<Vec<SocketAddrV6>>> = Default::default();
        let known_ifaces: Arc<Mutex<HashSet<u32>>> = Default::default();
        let _sync = Mutex::new(
            netwatcher::watch_interfaces_with_callback({
                let sock = sock.clone();
                let ifaces = ifaces.clone();
                let known_ifaces = known_ifaces.clone();
                move |update| {
                    for (iface_idx, iface) in update.interfaces.iter() {
                        if iface
                            .ipv6_ips()
                            .all(|addr| addr.is_loopback() || addr.is_unspecified())
                        {
                            continue;
                        }

                        // AddrInUse means this interface's membership is already held,
                        // from an earlier join on the same iface_idx -- most often
                        // because `announce`'s HostUnreachable prune removed the
                        // address from `ifaces` without ever leaving the multicast
                        // group. Restoring it here, instead of only on a first-ever
                        // Ok(()) join, is what makes that prune self-healing instead
                        // of permanent.
                        let can_send = match sock.join_multicast_v6(&GROUP, *iface_idx) {
                            Ok(()) => true,
                            Err(e) if e.kind() == io::ErrorKind::AddrInUse => true,
                            Err(e) => {
                                if let Some(iface) = update.interfaces.get(&iface_idx) {
                                    warn!(
                                        "failed to join multicast v6 for interface {}: {e}",
                                        iface.name
                                    )
                                }
                                false
                            }
                        };
                        if can_send {
                            known_ifaces.lock().insert(*iface_idx);
                            let candidate =
                                SocketAddrV6::new(GROUP, discovery_port, 0, *iface_idx);
                            let mut ifaces = ifaces.lock();
                            if !ifaces.contains(&candidate) {
                                ifaces.push(candidate);
                            }
                        }
                    }
                    for iface_idx in update.diff.removed {
                        ifaces.lock().retain(|addr| addr.scope_id() != iface_idx);
                        known_ifaces.lock().remove(&iface_idx);

                        if let Err(e) = sock.leave_multicast_v6(&GROUP, iface_idx) {
                            if let Some(iface) = update.interfaces.get(&iface_idx) {
                                warn!(
                                    "failed to leave multicast v6 for interface {}: {e}",
                                    iface.name
                                )
                            }
                        }
                    }
                }
            })
            // todo: better error handling here
            .expect("failed to bind discovery watcher"),
        );

        // Diagnostic only, for the Mode B investigation: an independent task,
        // polled by the runtime regardless of whatever `next()`'s own future
        // is doing. If this stops logging during a stall, the whole runtime
        // is starved; if it keeps logging while `next()` goes silent, the
        // `next()` future itself stopped being polled (most likely a lost
        // wakeup somewhere between tokio and the pyo3 async bridge, not a
        // blocked call inside this file).
        tokio::spawn(async {
            let mut n: u64 = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                n += 1;
                debug!("discovery heartbeat #{n}: runtime is still polling tasks");
            }
        });

        Ok(Self {
            sock,
            namespace,
            ifaces,
            known_ifaces,
            discovery_port,
            last_nonce: Mutex::new(rand::random()),
            listen_port,
            zid,
            tick: interval(Duration::from_secs(1)),
            resync: interval(Duration::from_secs(10)),
            _sync,
        })
    }

    /// Rebuilds `ifaces` to include every interface `known_ifaces` still
    /// considers present, regardless of any earlier HostUnreachable prune.
    /// Membership (`join_multicast_v6`) is a receive-side concern and is left
    /// alone here; this only concerns the send-side address list.
    fn resync_ifaces(&self) {
        let known = self.known_ifaces.lock();
        let mut ifaces = self.ifaces.lock();
        let mut restored = 0;
        for &iface_idx in known.iter() {
            let candidate = SocketAddrV6::new(GROUP, self.discovery_port, 0, iface_idx);
            if !ifaces.contains(&candidate) {
                ifaces.push(candidate);
                restored += 1;
            }
        }
        if restored > 0 {
            debug!("resync: restored {restored} discovery address(es) from known_ifaces");
        }
    }

    pub async fn next(&mut self) -> io::Result<Discovered> {
        let mut buf = [0u8; Hello::buf_size() + WhatsUp::buf_size() + 1];
        loop {
            tokio::select! {
                _ = self.tick.tick() => {
                    debug!("next(): tick fired, entering announce()");
                    self.announce().await?;
                    debug!("next(): announce() returned");
                }
                _ = self.resync.tick() => {
                    debug!("next(): resync tick fired, entering resync_ifaces()");
                    self.resync_ifaces();
                    debug!("next(): resync_ifaces() returned");
                }
                res = self.sock.recv_from(&mut buf) => {
                    debug!("next(): recv_from resolved: {res:?}");
                    let Ok((bytes_read, addr)) = res else { continue; };
                    if let Some(discovered) = self.respond(bytes_read, addr, &buf).await? {
                        debug!("next(): respond() returned Discovered, exiting loop");
                        return Ok(discovered)
                    }
                    debug!("next(): respond() returned None");
                }
            }
        }
    }

    async fn respond(
        &self,
        bytes_read: usize,
        addr: SocketAddr,
        buf: &[u8],
    ) -> io::Result<Option<Discovered>> {
        trace!(
            "raw recv: {bytes_read} bytes from {addr}: {:02x?}",
            &buf[..bytes_read]
        );
        if bytes_read < size_of::<Header>() {
            trace!("dropped: early EOF");
            return Ok(None);
        }
        let header: &Header = bytemuck::from_bytes(&buf[0..size_of::<Header>()]);
        if header.magic != MAGIC {
            trace!("dropped: wrong magic");
            return Ok(None);
        }
        let Ok(kind) = header.kind.try_into() else {
            trace!("dropped: unknown message kind {}", header.kind);
            return Ok(None);
        };
        match kind {
            Kind::Hello => {
                let total = Hello::buf_size();
                if bytes_read != total {
                    trace!("dropped: hello wrong size");
                    return Ok(None);
                }
                let hello: &Hello = bytemuck::from_bytes(&buf[size_of::<Header>()..total]);
                if hello.nonce == *self.last_nonce.lock() {
                    trace!("dropped: local hello nonce");
                    return Ok(None);
                }
                if hello.namespace != self.namespace {
                    trace!("dropped: different namespace");
                    return Ok(None);
                }

                // reply
                trace!("replying to Hello({:?})", hello.nonce);
                let reply = WhatsUp {
                    nonce: hello.nonce,
                    zid: self.zid.to_le_bytes(),
                    port_le: self.listen_port.to_le_bytes(),
                }
                .alloc();

                for i in 1..6 {
                    match tokio::time::timeout(SEND_TIMEOUT, self.sock.send_to(&reply, addr)).await
                    {
                        Ok(Ok(sent)) if sent == WhatsUp::buf_size() => {
                            trace!(
                                "sent {} bytes to {addr} after {} attempt(s)",
                                WhatsUp::buf_size(),
                                i
                            );
                            break;
                        }
                        Ok(Ok(sent)) => debug!("short send to {addr}: {sent} bytes"),
                        Ok(Err(e)) => debug!("send to {addr} failed: {e}"),
                        Err(_) => debug!("send to {addr} timed out after {SEND_TIMEOUT:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Ok(None)
            }
            Kind::WhatsUp => {
                let total = WhatsUp::buf_size();
                if bytes_read != total {
                    trace!("dropped: whatsup wrong size");
                    return Ok(None);
                }
                let whats_up: &WhatsUp = bytemuck::from_bytes(&buf[size_of::<Header>()..total]);
                if whats_up.nonce != *self.last_nonce.lock() {
                    trace!("dropped: stale nonce");
                    return Ok(None);
                }
                let SocketAddr::V6(v6) = addr else {
                    trace!("dropped: v4 addr used");
                    return Ok(None);
                };
                let Ok(zid) = ZenohId::try_from(&whats_up.zid[..]) else {
                    trace!("dropped: zenoh conversion failed");
                    return Ok(None);
                };
                if zid == self.zid {
                    trace!("dropped: self zenoh id");
                    return Ok(None);
                }
                // discovery success!
                // the incoming port is our listen port;
                // overwrite it with the whats_up port corresponding to the remote zenoh service
                let addr = {
                    let mut x = v6;
                    x.set_port(u16::from_le_bytes(whats_up.port_le));
                    x
                };
                Ok(Some(Discovered { addr, zid }))
            }
        }
    }

    async fn announce(&self) -> io::Result<()> {
        let nonce = rand::random();
        *self.last_nonce.lock() = nonce;
        let buf = Hello {
            nonce,
            namespace: self.namespace,
        }
        .alloc();

        let addrs = self.ifaces.lock().clone();
        debug!("announcing Hello({nonce:?}) to {addrs:?}");
        // rev so .remove() doesn't break things
        for (i, addr) in addrs.into_iter().enumerate().rev() {
            match tokio::time::timeout(SEND_TIMEOUT, self.sock.send_to(&buf, addr)).await {
                Ok(Ok(bytes)) => trace!("sent {bytes} to {addr}"),
                Ok(Err(e)) if e.kind() == io::ErrorKind::HostUnreachable => {
                    debug!("disabling discovery address {addr}: {e}");
                    _ = self.ifaces.lock().swap_remove(i);
                }
                Ok(Err(e)) => debug!("failed to reach {addr}: {e}"),
                Err(_) => debug!("send to {addr} timed out after {SEND_TIMEOUT:?}, skipping"),
            }
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
// packet & version
pub enum Kind {
    Hello = 0,
    WhatsUp = 1,
}

pub struct UnknownKind;
impl TryFrom<u8> for Kind {
    type Error = UnknownKind;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Hello),
            1 => Ok(Self::WhatsUp),
            _ => Err(UnknownKind),
        }
    }
}

pub trait Message: Pod {
    const KIND: Kind;
}
// should be part of the Message trait, but const in traits isnt stabilized. this lets alloc :: Self -> [u8; Self::buf_size()]
macro_rules! impl_alloc {
    ($a:ident) => {
        impl $a {
            const fn buf_size() -> usize {
                size_of::<Header>() + size_of::<Self>()
            }
            pub fn alloc(self) -> [u8; Self::buf_size()] {
                let mut buf = [0u8; Self::buf_size()];
                buf[0..size_of::<Header>()].copy_from_slice(bytemuck::bytes_of(&Header {
                    magic: MAGIC,
                    kind: Self::KIND as u8,
                }));
                buf[size_of::<Header>()..Self::buf_size()]
                    .copy_from_slice(bytemuck::bytes_of(&self));
                buf
            }
        }
    };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Header {
    magic: [u8; 3],
    kind: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Hello {
    pub nonce: [u8; 8],
    pub namespace: [u8; 8],
}
impl Message for Hello {
    const KIND: Kind = Kind::Hello;
}
impl_alloc!(Hello);

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct WhatsUp {
    pub nonce: [u8; 8],
    pub zid: [u8; 16],
    pub port_le: [u8; 2],
}
impl Message for WhatsUp {
    const KIND: Kind = Kind::WhatsUp;
}
impl_alloc!(WhatsUp);

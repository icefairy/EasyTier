//! smoltcp stack generation and its peer-packet bridge.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
};

use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};

use crate::{
    foundation::task::reap_joinset_background,
    gateway::smoltcp::{BufferSize, Net, NetConfig, channel_device},
    packet::{PacketType, ZCPacket},
    peers::peer_manager::PeerManagerCore,
};

use super::{
    DataPlaneErrorKind, DataPlaneIoGuard,
    via::{ViaKey, ViaRoutes},
};

pub(super) struct SmoltcpPlane {
    pub(super) ipv4_addr: cidr::Ipv4Inet,
    pub(super) net: Arc<Net>,
    generation: DataPlaneIoGuard,
    _forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl SmoltcpPlane {
    pub(super) fn new(
        ipv4_addr: cidr::Ipv4Inet,
        peer_manager: Weak<PeerManagerCore>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
        via_routes: Arc<ViaRoutes>,
    ) -> Self {
        let mut forward_tasks = JoinSet::new();
        let mut capabilities = smoltcp::phy::DeviceCapabilities::default();
        // Fragment offsets are expressed in eight-byte units.
        capabilities.max_transmission_unit = 1284;
        capabilities.medium = smoltcp::phy::Medium::Ip;
        let (device, stack_sink, mut stack_stream) =
            channel_device::ChannelDevice::new(capabilities);

        forward_tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Some(packet) = packet_recv.recv().await {
                tracing::trace!(?packet, "deliver peer packet to smoltcp");
                if let Err(error) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                    tracing::error!(?error, "deliver peer packet to smoltcp failed");
                }
            }
            tracing::debug!("peer-to-smoltcp bridge stopped");
        });

        forward_tasks.spawn(async move {
            while let Some(data) = stack_stream.recv().await {
                let Ok(ipv4) = Ipv4Packet::new_checked(&data) else {
                    tracing::error!(?data, "smoltcp emitted a non-IPv4 packet");
                    continue;
                };
                let destination = ipv4.dst_addr();
                let Some(peer_manager) = peer_manager.upgrade() else {
                    tracing::debug!("smoltcp-to-peer bridge lost PeerManager");
                    return;
                };
                let mut packet = ZCPacket::new_with_payload(&data);
                // A port-forward rule may pin its flows to a specific relay
                // peer that forwards them into its own network.
                let via = via_key(&data).and_then(|key| via_routes.lookup(&key));
                if let Some(via) = via {
                    if let Some(peer_id) = peer_manager
                        .get_peer_map()
                        .get_peer_id_by_ipv4(&match via {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => {
                                tracing::error!(%via, "port-forward relay must be IPv4");
                                continue;
                            }
                        })
                        .await
                    {
                        packet.fill_peer_manager_hdr(
                            peer_manager.my_peer_id(),
                            peer_id,
                            PacketType::Data as u8,
                        );
                        // Ask the relay to act as an exit node for this packet
                        // only: it forwards to the real destination instead of
                        // requiring an overlay route for it.
                        packet
                            .mut_peer_manager_header()
                            .expect("peer manager header")
                            .set_exit_node(true);
                        if let Err(error) = peer_manager.send_msg_for_proxy(packet, peer_id).await {
                            tracing::error!(?error, %via, "deliver relayed packet to peer failed");
                        }
                        continue;
                    }
                    tracing::warn!(
                        %via,
                        %destination,
                        "port-forward relay peer is missing, falling back to the overlay route"
                    );
                }
                if let Err(error) = peer_manager
                    .send_msg_by_ip(packet, IpAddr::V4(destination), false)
                    .await
                {
                    tracing::error!(?error, "deliver smoltcp packet to peer failed");
                }
            }
            tracing::debug!("smoltcp-to-peer bridge stopped");
        });

        // A fixed seed replays IP IDs after the last consumer closes and the
        // stack is recreated, potentially reusing a remote shallow-cache route.
        let interface_config = Self::interface_config(rand::random());
        let net = Net::new(
            device,
            NetConfig::new(
                interface_config,
                format!("{}/{}", ipv4_addr.address(), ipv4_addr.network_length())
                    .parse()
                    .expect("validated IPv4 prefix"),
                vec![
                    ipv4_addr
                        .address()
                        .to_string()
                        .parse()
                        .expect("validated IPv4 address"),
                ],
                Some(BufferSize {
                    tcp_rx_size: 1024 * 128,
                    tcp_tx_size: 1024 * 128,
                    udp_rx_size: 1024 * 128,
                    udp_tx_size: 1024 * 128,
                    udp_rx_meta_size: 128,
                    udp_tx_meta_size: 128,
                }),
            ),
        );

        let forward_tasks = Arc::new(std::sync::Mutex::new(forward_tasks));
        forward_tasks.lock().unwrap().spawn(reap_joinset_background(
            Arc::downgrade(&forward_tasks),
            "SmoltcpPlane",
        ));

        Self {
            ipv4_addr,
            net: Arc::new(net),
            generation: DataPlaneIoGuard::new(),
            _forward_tasks: forward_tasks,
        }
    }

    pub(super) fn interface_config(random_seed: u64) -> smoltcp::iface::Config {
        let mut config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = random_seed;
        config
    }

    pub(super) fn lease(&self) -> DataPlaneIoGuard {
        self.generation.clone()
    }

    pub(super) fn close(&self, kind: DataPlaneErrorKind) {
        self.generation.close(kind);
    }
}

/// Extracts the flow destination of a packet emitted by the smoltcp stack.
fn via_key(buf: &[u8]) -> Option<ViaKey> {
    let ipv4 = Ipv4Packet::new_checked(buf).ok()?;
    let dst_ip = SocketAddr::new(IpAddr::V4(ipv4.dst_addr()), 0);
    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
            Some(ViaKey {
                dst: SocketAddr::new(dst_ip.ip(), tcp.dst_port()),
                udp: false,
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ipv4.payload()).ok()?;
            Some(ViaKey {
                dst: SocketAddr::new(dst_ip.ip(), udp.dst_port()),
                udp: true,
            })
        }
        _ => None,
    }
}

impl Drop for SmoltcpPlane {
    fn drop(&mut self) {
        self.close(DataPlaneErrorKind::HandleClosed);
    }
}

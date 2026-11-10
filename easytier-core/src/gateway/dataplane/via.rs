//! Per-destination relay ("via") routing for port-forward flows.
//!
//! A port-forward rule may pin its flows to a specific overlay peer that acts
//! as an exit node for those flows only. The smoltcp stack still emits plain
//! IPv4 packets towards the real destination, so the peer bridge needs a
//! destination -> relay-peer mapping to know where to send them.

use std::net::{IpAddr, SocketAddr};

use dashmap::DashMap;

/// Identifies the destination of a flow emitted by the smoltcp stack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ViaKey {
    pub dst: SocketAddr,
    /// `true` for UDP, `false` for TCP. Kept separate so a TCP and a UDP rule
    /// with the same destination address can use different relays.
    pub udp: bool,
}

#[derive(Default)]
pub(crate) struct ViaRoutes {
    inner: DashMap<ViaKey, IpAddr>,
}

impl ViaRoutes {
    pub(crate) fn lookup(&self, key: &ViaKey) -> Option<IpAddr> {
        self.inner.get(key).map(|entry| *entry.value())
    }

    /// Replaces the whole table; called whenever the port-forward rules are
    /// reconciled so removed rules drop their relay mapping.
    pub(crate) fn replace(&self, routes: impl IntoIterator<Item = (ViaKey, IpAddr)>) {
        self.inner.clear();
        for (key, via) in routes {
            self.inner.insert(key, via);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(dst: &str, udp: bool) -> ViaKey {
        ViaKey {
            dst: dst.parse().unwrap(),
            udp,
        }
    }

    #[test]
    fn replace_swaps_the_whole_table() {
        let routes = ViaRoutes::default();
        routes.replace([(
            key("192.168.1.50:80", false),
            "10.144.0.20".parse().unwrap(),
        )]);
        assert_eq!(
            routes.lookup(&key("192.168.1.50:80", false)),
            Some("10.144.0.20".parse().unwrap())
        );

        routes.replace([]);
        assert!(routes.is_empty());
        assert_eq!(routes.lookup(&key("192.168.1.50:80", false)), None);
    }

    #[test]
    fn tcp_and_udp_entries_are_independent() {
        let routes = ViaRoutes::default();
        routes.replace([
            (key("192.168.1.50:53", true), "10.144.0.20".parse().unwrap()),
            (
                key("192.168.1.50:53", false),
                "10.144.0.21".parse().unwrap(),
            ),
        ]);
        assert_eq!(
            routes.lookup(&key("192.168.1.50:53", true)),
            Some("10.144.0.20".parse().unwrap())
        );
        assert_eq!(
            routes.lookup(&key("192.168.1.50:53", false)),
            Some("10.144.0.21".parse().unwrap())
        );
    }
}

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use easytier_proto::common::{PortForwardConfigPb, SocketType};

/// Runtime configuration for the core-owned SOCKS and port-forward gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRuntimeConfig {
    pub socks5_bind: Option<SocketAddr>,
    pub port_forwards: Vec<PortForwardConfig>,
}

/// One TCP or UDP port-forward rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortForwardConfig {
    pub bind_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub proto: String,
    /// Optional overlay address of the peer that must relay this rule's flows
    /// to its own network. Only these flows use that peer as an exit node, so
    /// `dst_addr` does not need an overlay route and other traffic is
    /// unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<IpAddr>,
}

impl From<PortForwardConfigPb> for PortForwardConfig {
    fn from(config: PortForwardConfigPb) -> Self {
        Self {
            bind_addr: config.bind_addr.unwrap_or_default().into(),
            dst_addr: config.dst_addr.unwrap_or_default().into(),
            proto: match SocketType::try_from(config.socket_type) {
                Ok(SocketType::Tcp) => "tcp".to_string(),
                Ok(SocketType::Udp) => "udp".to_string(),
                _ => "tcp".to_string(),
            },
            via: config
                .via
                .filter(|via| via.ip.is_some())
                .map(std::net::IpAddr::from)
                .filter(|ip| !ip.is_unspecified()),
        }
    }
}

impl From<PortForwardConfig> for PortForwardConfigPb {
    fn from(config: PortForwardConfig) -> Self {
        Self {
            bind_addr: Some(config.bind_addr.into()),
            dst_addr: Some(config.dst_addr.into()),
            socket_type: match config.proto.to_lowercase().as_str() {
                "tcp" => SocketType::Tcp as i32,
                "udp" => SocketType::Udp as i32,
                _ => SocketType::Tcp as i32,
            },
            via: config.via.map(Into::into),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRuntimeConfig {
    pub enable_exit_node: bool,
    pub no_tun: bool,
    pub forward_by_system: bool,
    pub force_smoltcp: bool,
    pub icmp_failure_is_fatal: bool,
    pub udp_response_ipv4_mtu: usize,
}

impl ProxyRuntimeConfig {
    pub fn should_start(self, has_proxy_networks: bool) -> bool {
        if !has_proxy_networks && !self.enable_exit_node && !self.no_tun {
            return false;
        }

        !self.forward_by_system || self.no_tun
    }
}

impl Default for ProxyRuntimeConfig {
    fn default() -> Self {
        Self {
            enable_exit_node: false,
            no_tun: false,
            forward_by_system: false,
            force_smoltcp: false,
            icmp_failure_is_fatal: false,
            udp_response_ipv4_mtu: 1280,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyRuntimeConfig;

    #[test]
    fn proxy_startup_policy_preserves_runtime_modes() {
        assert!(!ProxyRuntimeConfig::default().should_start(false));
        assert!(ProxyRuntimeConfig::default().should_start(true));
        assert!(
            ProxyRuntimeConfig {
                enable_exit_node: true,
                ..Default::default()
            }
            .should_start(false)
        );
        assert!(
            ProxyRuntimeConfig {
                no_tun: true,
                ..Default::default()
            }
            .should_start(false)
        );
    }

    #[test]
    fn proxy_startup_policy_preserves_system_forwarding_rules() {
        assert!(
            !ProxyRuntimeConfig {
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(true)
        );
        assert!(
            !ProxyRuntimeConfig {
                enable_exit_node: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(false)
        );
        assert!(
            ProxyRuntimeConfig {
                no_tun: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(false)
        );
    }

    #[test]
    fn proxy_runtime_defaults_preserve_udp_mtu() {
        assert_eq!(ProxyRuntimeConfig::default().udp_response_ipv4_mtu, 1280);
    }
}

#[cfg(test)]
mod port_forward_via_tests {
    use super::*;

    #[test]
    fn port_forward_via_roundtrips_through_proto() {
        let config = PortForwardConfig {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            dst_addr: "192.168.1.50:80".parse().unwrap(),
            proto: "tcp".to_string(),
            via: Some("10.144.0.20".parse().unwrap()),
        };

        let pb = PortForwardConfigPb::from(config.clone());
        assert!(pb.via.is_some());
        assert_eq!(PortForwardConfig::from(pb), config);
    }

    #[test]
    fn port_forward_without_via_stays_none() {
        let config = PortForwardConfig {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            dst_addr: "10.144.0.2:80".parse().unwrap(),
            proto: "udp".to_string(),
            via: None,
        };

        let pb = PortForwardConfigPb::from(config.clone());
        assert!(pb.via.is_none());
        assert_eq!(PortForwardConfig::from(pb), config);
    }

    #[test]
    fn unspecified_via_is_dropped() {
        let pb = PortForwardConfigPb {
            bind_addr: Some("0.0.0.0:8080".parse::<SocketAddr>().unwrap().into()),
            dst_addr: Some("10.144.0.2:80".parse::<SocketAddr>().unwrap().into()),
            socket_type: SocketType::Tcp as i32,
            via: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED).into()),
        };
        assert_eq!(PortForwardConfig::from(pb).via, None);
    }
}

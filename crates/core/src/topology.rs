use crate::model::{Channel, Node, Snapshot, parse_ip};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;

/// A cascade longer than this is a configuration mistake, not a topology.
pub const MAX_HOPS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("no node runs inbound '{inbound_tag}' of profile {profile_uuid}")]
    NoEntryNode {
        inbound_tag: String,
        profile_uuid: String,
    },
    #[error("inbound '{inbound_tag}' runs on several nodes ({}) and none has address {address}", candidates.join(", "))]
    AmbiguousEntryNode {
        inbound_tag: String,
        address: String,
        candidates: Vec<String>,
    },
    #[error("node '{node}' has no active config profile")]
    NodeWithoutProfile { node: String },
    #[error(
        "channel '{remark}' is not attached to any config profile, so its route cannot be resolved"
    )]
    ChannelWithoutProfile { remark: String },
    #[error("profile {uuid} is not known to the panel")]
    ProfileMissing { uuid: String },
    #[error("profile {profile} declares no outbounds")]
    NoOutbounds { profile: String },
    #[error("profile {profile} has no outbound tagged '{tag}'")]
    UnknownOutbound { profile: String, tag: String },
    #[error(
        "inbound '{inbound_tag}' is routed into blackhole outbound '{tag}'"
    )]
    Blackhole { inbound_tag: String, tag: String },
    #[error(
        "the rule for inbound '{inbound_tag}' selects its outbound in a way this tool cannot follow ({how})"
    )]
    UnsupportedRule {
        inbound_tag: String,
        how: UnsupportedSelector,
    },
    #[error(
        "outbound '{tag}' ({protocol}) ends the chain outside the node's own egress, so the expected exit address cannot be derived from the topology"
    )]
    OpaqueTerminal { tag: String, protocol: String },
    #[error("outbound '{tag}' carries no destination address")]
    NoDestination { tag: String },
    #[error("outbound '{tag}' points at {address}, which is not a known node")]
    UnknownNextHop { tag: String, address: String },
    #[error("node '{node}' has no inbound listening on port {port}")]
    NoInboundOnPort { node: String, port: u16 },
    #[error("routing loops back to node '{node}' inbound '{inbound_tag}'")]
    Cycle { node: String, inbound_tag: String },
    #[error("routing chain exceeded {max} hops")]
    TooDeep { max: usize },
}

/// The ways a matched rule can pick an outbound this tool cannot follow. Both
/// spellings are part of `UnsupportedRule`'s message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedSelector {
    /// The rule routes through a balancer, so the outbound depends on runtime
    /// state.
    BalancerTag,
    /// The rule names no outbound at all.
    NoOutboundTag,
}

impl std::fmt::Display for UnsupportedSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BalancerTag => "balancerTag",
            Self::NoOutboundTag => "no outboundTag",
        })
    }
}

/// What an outbound does with the traffic that reaches it. The one place
/// protocol strings turn into a decision, so a new protocol is classified once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundKind {
    /// Leaves through the node's own address: the chain ends at this node.
    NodeEgress,
    /// Traffic is dropped.
    Blackhole,
    /// Ends the chain elsewhere than the node's own address (wireguard such as
    /// WARP, dns, loopback): the exit IP is not derivable from the topology.
    OpaqueTerminal,
    /// Forwards to another hop, whose address the outbound carries.
    Proxy,
}

impl OutboundKind {
    fn from_protocol(protocol: &str) -> Self {
        match protocol {
            "freedom" => Self::NodeEgress,
            "blackhole" => Self::Blackhole,
            "wireguard" | "dns" | "loopback" => Self::OpaqueTerminal,
            _ => Self::Proxy,
        }
    }
}

/// Where a proxying outbound sends the traffic on to.
struct Destination {
    address: String,
    port: u16,
}

/// How an outbound with no `tag` appears in an error message. The resolver
/// itself keeps the absence as an `Option`.
const UNTAGGED: &str = "<untagged>";

/// One profile's Xray config, read as raw JSON: a profile is an arbitrary Xray configuration and a schema would break on everything else it legitimately contains.
#[derive(Clone, Copy)]
struct Config<'a>(&'a Value);

impl<'a> Config<'a> {
    /// Outbounds in declaration order, or `None` when the profile declares none
    /// at all.
    fn outbounds(self) -> Option<&'a [Value]> {
        self.0
            .get("outbounds")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .filter(|outbounds| !outbounds.is_empty())
    }

    /// Where this config sends the traffic of one inbound.
    fn route_for(self, inbound_tag: &str) -> Routed<'a> {
        let matched = self
            .0
            .get("routing")
            .and_then(|routing| routing.get("rules"))
            .and_then(Value::as_array)
            .and_then(|rules| {
                rules.iter().find(|rule| rule_matches(rule, inbound_tag))
            });

        let Some(rule) = matched else {
            return Routed::FirstOutbound;
        };
        match rule.get("outboundTag").and_then(Value::as_str) {
            Some(tag) => Routed::Tag(tag),
            None if rule.get("balancerTag").is_some() => {
                Routed::Unsupported(UnsupportedSelector::BalancerTag)
            }
            None => Routed::Unsupported(UnsupportedSelector::NoOutboundTag),
        }
    }

    fn outbound_tagged(self, tag: &str) -> Option<Outbound<'a>> {
        self.outbounds()?
            .iter()
            .find(|outbound| {
                outbound.get("tag").and_then(Value::as_str) == Some(tag)
            })
            .map(Outbound)
    }

    fn inbound_tag_on_port(self, port: u16) -> Option<String> {
        self.0
            .get("inbounds")?
            .as_array()?
            .iter()
            .find(|inbound| {
                inbound.get("port").and_then(Value::as_u64)
                    == Some(u64::from(port))
            })
            .and_then(|inbound| inbound.get("tag"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// Where a config routes an inbound's traffic — three cases that must not be
/// conflated.
enum Routed<'a> {
    /// A rule matched and named this outbound.
    Tag(&'a str),
    /// No rule matched. Xray sends such traffic into the first outbound, and
    /// mirroring that keeps rule-less exit profiles working.
    FirstOutbound,
    /// A rule matched but picks its outbound in a way this tool cannot follow.
    Unsupported(UnsupportedSelector),
}

/// Every host named in the panel's data that is not already an address: the
/// nodes' own addresses and the destinations of every profile's outbounds.
///
/// The caller resolves these and hands the answers back in `Snapshot.resolved`
/// before the graph is walked, because a cascade may point at a front domain
/// for a node the panel records by address — and this crate opens no sockets.
pub fn hosts_to_resolve(snapshot: &Snapshot) -> BTreeSet<String> {
    let nodes = snapshot.nodes.iter().map(|n| n.address.clone());
    let destinations = snapshot
        .profiles
        .values()
        .filter_map(|p| p.config.get("outbounds")?.as_array())
        .flatten()
        .filter_map(|o| Outbound(o).destination())
        .map(|d| d.address);
    nodes
        .chain(destinations)
        .filter(|host| !host.is_empty() && parse_ip(host).is_none())
        .collect()
}

/// One outbound of a config.
#[derive(Clone, Copy)]
struct Outbound<'a>(&'a Value);

impl<'a> Outbound<'a> {
    /// The tag, or `<untagged>` in messages.
    fn name(self) -> String {
        self.0
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or(UNTAGGED)
            .to_string()
    }

    fn protocol(self) -> &'a str {
        self.0
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    fn kind(self) -> OutboundKind {
        OutboundKind::from_protocol(self.protocol())
    }

    /// Destination of a proxying outbound: vless uses `vnext`, trojan and
    /// shadowsocks use `servers`.
    fn destination(self) -> Option<Destination> {
        let settings = self.0.get("settings")?;
        let first = settings
            .get("vnext")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .or_else(|| {
                settings
                    .get("servers")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
            })?;
        let address = first.get("address")?.as_str()?.to_string();
        let port = u16::try_from(first.get("port")?.as_u64()?).ok()?;
        Some(Destination { address, port })
    }
}

fn rule_matches(rule: &Value, inbound_tag: &str) -> bool {
    rule.get("inboundTag")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|t| t.as_str() == Some(inbound_tag))
        })
}

/// Follows one snapshot's routing to the node a channel leaves through.
#[derive(Debug, Clone, Copy)]
pub struct Resolver<'a> {
    snapshot: &'a Snapshot,
}

impl<'a> Resolver<'a> {
    pub const fn new(snapshot: &'a Snapshot) -> Self {
        Self { snapshot }
    }

    /// The node this channel is declared to exit through.
    pub fn exit_of(self, channel: &Channel) -> Result<&'a Node, ResolveError> {
        let nodes = &self.snapshot.nodes;
        let mut node = self.entry_node(channel)?;
        let mut inbound_tag = channel.inbound_tag.clone();
        // Borrowed from the snapshot the resolver holds: a hop need not be
        // copied to be remembered.
        let mut visited: HashSet<(&'a str, String)> = HashSet::new();

        for _ in 0..MAX_HOPS {
            if !visited.insert((node.name.as_str(), inbound_tag.clone())) {
                return Err(ResolveError::Cycle {
                    node: node.name.clone(),
                    inbound_tag,
                });
            }
            let outbound =
                outbound_for(self.config_of(node)?, &inbound_tag, node)?;

            match outbound.kind() {
                OutboundKind::NodeEgress => return Ok(node),
                OutboundKind::Blackhole => {
                    return Err(ResolveError::Blackhole {
                        inbound_tag,
                        tag: outbound.name(),
                    });
                }
                OutboundKind::OpaqueTerminal => {
                    return Err(ResolveError::OpaqueTerminal {
                        tag: outbound.name(),
                        protocol: outbound.protocol().to_string(),
                    });
                }
                OutboundKind::Proxy => {}
            }

            let Destination { address, port } = outbound
                .destination()
                .ok_or_else(|| ResolveError::NoDestination {
                    tag: outbound.name(),
                })?;
            let next = nodes
                .iter()
                .find(|n| self.same_host(&n.address, &address))
                .ok_or_else(|| ResolveError::UnknownNextHop {
                    tag: outbound.name(),
                    address,
                })?;
            inbound_tag = self
                .config_of(next)?
                .inbound_tag_on_port(port)
                .ok_or_else(|| ResolveError::NoInboundOnPort {
                    node: next.name.clone(),
                    port,
                })?;
            node = next;
        }
        Err(ResolveError::TooDeep { max: MAX_HOPS })
    }

    /// Whether two spellings name one machine. The panel records a node by its
    /// address while a cascade may point at a front domain for the same host,
    /// so equal text is sufficient but not necessary — equal addresses settle
    /// the rest. Names are resolved by `io` before the walk; this crate opens
    /// no sockets.
    fn same_host(self, a: &str, b: &str) -> bool {
        a == b
            || matches!(
                (self.address_of(a), self.address_of(b)),
                (Some(x), Some(y)) if x == y
            )
    }

    fn address_of(self, host: &str) -> Option<IpAddr> {
        parse_ip(host).or_else(|| self.snapshot.resolved.get(host).copied())
    }

    fn entry_node(self, channel: &Channel) -> Result<&'a Node, ResolveError> {
        let profile_uuid =
            channel.profile_uuid.as_deref().ok_or_else(|| {
                ResolveError::ChannelWithoutProfile {
                    remark: channel.remark.clone(),
                }
            })?;

        let candidates: Vec<&'a Node> = self
            .snapshot
            .nodes
            .iter()
            .filter(|n| {
                n.profile_uuid.as_deref() == Some(profile_uuid)
                    && n.inbound_tags.iter().any(|t| t == &channel.inbound_tag)
            })
            .collect();

        match candidates.as_slice() {
            [] => Err(ResolveError::NoEntryNode {
                inbound_tag: channel.inbound_tag.clone(),
                profile_uuid: profile_uuid.to_string(),
            }),
            [only] => Ok(only),
            // Several nodes share the profile and the inbound; the channel
            // address decides.
            several => several
                .iter()
                .copied()
                .find(|n| n.address == channel.address)
                .ok_or_else(|| ResolveError::AmbiguousEntryNode {
                    inbound_tag: channel.inbound_tag.clone(),
                    address: channel.address.clone(),
                    candidates: several
                        .iter()
                        .map(|n| n.name.clone())
                        .collect(),
                }),
        }
    }

    fn config_of(self, node: &Node) -> Result<Config<'a>, ResolveError> {
        let uuid = node.profile_uuid.as_deref().ok_or_else(|| {
            ResolveError::NodeWithoutProfile {
                node: node.name.clone(),
            }
        })?;
        self.snapshot
            .profiles
            .get(uuid)
            .map(|p| Config(&p.config))
            .ok_or_else(|| ResolveError::ProfileMissing {
                uuid: uuid.to_string(),
            })
    }
}

/// The outbound the traffic of `inbound_tag` ends up in.
fn outbound_for<'a>(
    config: Config<'a>,
    inbound_tag: &str,
    node: &Node,
) -> Result<Outbound<'a>, ResolveError> {
    let profile_label = node.profile_uuid.clone().unwrap_or_else(|| {
        format!("<node '{}' has no profile uuid>", node.name)
    });
    let outbounds =
        config
            .outbounds()
            .ok_or_else(|| ResolveError::NoOutbounds {
                profile: profile_label.clone(),
            })?;

    match config.route_for(inbound_tag) {
        Routed::Unsupported(how) => Err(ResolveError::UnsupportedRule {
            inbound_tag: inbound_tag.to_string(),
            how,
        }),
        Routed::FirstOutbound => Ok(Outbound(&outbounds[0])),
        Routed::Tag(tag) => config.outbound_tagged(tag).ok_or_else(|| {
            ResolveError::UnknownOutbound {
                profile: profile_label,
                tag: tag.to_string(),
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Channel, Node, Profile, Snapshot};
    use serde_json::json;
    use std::collections::HashMap;

    fn node(name: &str, address: &str, profile: &str, tags: &[&str]) -> Node {
        Node {
            name: name.into(),
            address: address.into(),
            profile_uuid: Some(profile.into()),
            inbound_tags: tags.iter().map(ToString::to_string).collect(),
            is_connected: true,
            xray_version: Some("26.6.27".into()),
            ..Default::default()
        }
    }

    /// Profile whose only outbound is freedom and which declares no routing
    /// rules — the shape of a plain exit node.
    fn exit_profile(uuid: &str, inbound_tag: &str, port: u16) -> Profile {
        Profile {
            uuid: uuid.into(),
            name: format!("profile-{uuid}"),
            config: json!({
                "inbounds": [{ "tag": inbound_tag, "port": port }],
                "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
            }),
        }
    }

    /// Profile that routes its inbound into a vless outbound aimed at another
    /// node.
    fn bridge_profile(
        uuid: &str,
        inbound_tag: &str,
        port: u16,
        out_tag: &str,
        next_addr: &str,
        next_port: u16,
    ) -> Profile {
        Profile {
            uuid: uuid.into(),
            name: format!("profile-{uuid}"),
            config: json!({
                "inbounds": [{ "tag": inbound_tag, "port": port }],
                "outbounds": [
                    { "tag": "direct", "protocol": "freedom" },
                    { "tag": out_tag, "protocol": "vless",
                      "settings": { "vnext": [{ "address": next_addr, "port": next_port,
                                                 "users": [{ "id": "00000000-0000-0000-0000-000000000000" }] }] } }
                ],
                "routing": { "rules": [{ "inboundTag": [inbound_tag], "outboundTag": out_tag }] }
            }),
        }
    }

    fn snapshot(nodes: Vec<Node>, profiles: Vec<Profile>) -> Snapshot {
        Snapshot {
            nodes,
            profiles: profiles
                .into_iter()
                .map(|p| (p.uuid.clone(), p))
                .collect(),
            ..Default::default()
        }
    }

    fn channel(
        remark: &str,
        inbound_tag: &str,
        profile: &str,
        address: &str,
    ) -> Channel {
        Channel {
            remark: remark.into(),
            inbound_tag: inbound_tag.into(),
            profile_uuid: Some(profile.into()),
            address: address.into(),
            port: 443,
            ..Default::default()
        }
    }

    #[test]
    fn direct_exit_resolves_to_the_entry_node() {
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p-exit", &["in-exit"])],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch =
            channel("beta direct", "in-exit", "p-exit", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch).unwrap();

        assert_eq!(exit.name, "beta");
    }

    #[test]
    fn channel_without_a_profile_fails_loudly_instead_of_resolving() {
        // A host unattached to any config profile is a legitimate panel state,
        // and such a channel cannot be resolved, not silently OK'd.
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p-exit", &["in-exit"])],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch = Channel {
            remark: "orphaned host".into(),
            inbound_tag: "in-exit".into(),
            profile_uuid: None,
            address: "beta.example.com".into(),
            port: 443,
            ..Default::default()
        };

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(
            exit,
            Err(ResolveError::ChannelWithoutProfile { remark }) if remark == "orphaned host"
        ));
    }

    #[test]
    fn cascade_resolves_through_the_bridge_to_the_far_node() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile(
                    "p-bridge",
                    "in-bridge",
                    443,
                    "to-gamma",
                    "192.0.2.30",
                    2087,
                ),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        let ch =
            channel("cdn front", "in-bridge", "p-bridge", "cdn.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch).unwrap();

        assert_eq!(exit.name, "gamma");
    }

    #[test]
    fn no_node_runs_the_inbound() {
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p-exit", &["other"])],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch = channel("orphan", "in-exit", "p-exit", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::NoEntryNode { .. })));
    }

    #[test]
    fn blackhole_is_an_explicit_failure() {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [{ "tag": "in", "port": 443 }],
                "outbounds": [{ "tag": "block", "protocol": "blackhole" }],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "block" }] }
            }),
        };
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p", &["in"])],
            vec![profile],
        );
        let ch = channel("blocked", "in", "p", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::Blackhole { .. })));
    }

    #[test]
    fn rule_pointing_at_a_missing_outbound_fails_loudly() {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [{ "tag": "in", "port": 443 }],
                "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "typo" }] }
            }),
        };
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p", &["in"])],
            vec![profile],
        );
        let ch = channel("typo", "in", "p", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::UnknownOutbound { .. })));
    }

    /// What `io` must resolve before the walk: the front domain, and not the
    /// addresses that are already addresses.
    #[test]
    fn hosts_to_resolve_lists_names_and_skips_literal_addresses() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile(
                    "p-bridge",
                    "in-bridge",
                    443,
                    "to-gamma",
                    "gamma.front.example",
                    2087,
                ),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );

        let hosts = hosts_to_resolve(&snap);

        assert_eq!(
            hosts.into_iter().collect::<Vec<_>>(),
            vec!["gamma.front.example".to_string()]
        );
    }

    /// The panel records a node by address while a cascade points at a front
    /// domain for the same machine. Both name one node, and only the resolved
    /// address says so.
    #[test]
    fn a_next_hop_named_by_a_domain_reaches_the_node_at_that_address() {
        let mut snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile(
                    "p-bridge",
                    "in-bridge",
                    443,
                    "to-gamma",
                    "gamma.front.example",
                    2087,
                ),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        snap.resolved = HashMap::from([(
            "gamma.front.example".to_string(),
            "192.0.2.30".parse().unwrap(),
        )]);
        let ch =
            channel("cdn front", "in-bridge", "p-bridge", "cdn.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch).unwrap();

        assert_eq!(exit.name, "gamma");
    }

    /// A domain that resolves somewhere else is still not that node.
    #[test]
    fn a_next_hop_resolving_elsewhere_is_not_a_match() {
        let mut snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile(
                    "p-bridge",
                    "in-bridge",
                    443,
                    "to-nowhere",
                    "elsewhere.example",
                    2087,
                ),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        snap.resolved = HashMap::from([(
            "elsewhere.example".to_string(),
            "203.0.113.9".parse().unwrap(),
        )]);
        let ch =
            channel("dangling", "in-bridge", "p-bridge", "cdn.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::UnknownNextHop { .. })));
    }

    #[test]
    fn next_hop_that_is_not_a_known_node_fails_loudly() {
        let snap = snapshot(
            vec![node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"])],
            vec![bridge_profile(
                "p-bridge",
                "in-bridge",
                443,
                "to-nowhere",
                "203.0.113.99",
                2087,
            )],
        );
        let ch =
            channel("dangling", "in-bridge", "p-bridge", "cdn.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::UnknownNextHop { .. })));
    }

    #[test]
    fn next_hop_without_a_matching_inbound_port_fails_loudly() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile(
                    "p-bridge",
                    "in-bridge",
                    443,
                    "to-gamma",
                    "192.0.2.30",
                    9999,
                ),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        let ch =
            channel("wrong port", "in-bridge", "p-bridge", "cdn.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::NoInboundOnPort { .. })));
    }

    #[test]
    fn rule_selecting_via_balancer_tag_is_unsupported() {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [{ "tag": "in", "port": 443 }],
                "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
                "routing": { "rules": [{ "inboundTag": ["in"], "balancerTag": "lb" }] }
            }),
        };
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p", &["in"])],
            vec![profile],
        );
        let ch = channel("balancer", "in", "p", "beta.example.com");

        let sut = Resolver::new(&snap);

        let err = sut.exit_of(&ch).unwrap_err();

        assert!(matches!(err, ResolveError::UnsupportedRule { .. }));
        assert_eq!(
            err.to_string(),
            "the rule for inbound 'in' selects its outbound in a way this tool cannot follow (balancerTag)"
        );
    }

    #[test]
    fn wireguard_outbound_is_an_opaque_terminal() {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [{ "tag": "in", "port": 443 }],
                "outbounds": [{ "tag": "warp", "protocol": "wireguard" }],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "warp" }] }
            }),
        };
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p", &["in"])],
            vec![profile],
        );
        let ch = channel("warp", "in", "p", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::OpaqueTerminal { .. })));
    }

    #[test]
    fn vless_outbound_without_settings_has_no_destination() {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [{ "tag": "in", "port": 443 }],
                "outbounds": [{ "tag": "broken", "protocol": "vless" }],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "broken" }] }
            }),
        };
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p", &["in"])],
            vec![profile],
        );
        let ch = channel("broken", "in", "p", "beta.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::NoDestination { .. })));
    }

    #[test]
    fn two_candidate_nodes_neither_matching_channel_address_is_ambiguous() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-exit", &["in-exit"]),
                node("beta", "192.0.2.20", "p-exit", &["in-exit"]),
            ],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch = channel("neither", "in-exit", "p-exit", "gamma.example.com");

        let sut = Resolver::new(&snap);

        let err = sut.exit_of(&ch).unwrap_err();

        // The candidates are kept as a list and named in the message, in order.
        assert!(matches!(
            &err,
            ResolveError::AmbiguousEntryNode { candidates, .. }
                if candidates == &["alpha".to_string(), "beta".to_string()]
        ));
        assert_eq!(
            err.to_string(),
            "inbound 'in-exit' runs on several nodes (alpha, beta) and none has address gamma.example.com"
        );
    }

    #[test]
    fn a_routing_loop_is_detected_instead_of_hanging() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-a", &["in-a"]),
                node("beta", "192.0.2.20", "p-b", &["in-b"]),
            ],
            vec![
                bridge_profile("p-a", "in-a", 443, "to-b", "192.0.2.20", 443),
                bridge_profile("p-b", "in-b", 443, "to-a", "192.0.2.10", 443),
            ],
        );
        let ch = channel("loop", "in-a", "p-a", "alpha.example.com");

        let sut = Resolver::new(&snap);

        let exit = sut.exit_of(&ch);

        assert!(matches!(exit, Err(ResolveError::Cycle { .. })));
    }
}

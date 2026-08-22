use crate::model::{Channel, Node, Snapshot};
use serde_json::Value;
use std::collections::HashSet;

/// A cascade longer than this is a configuration mistake, not a topology.
pub const MAX_HOPS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("no node runs inbound '{inbound_tag}' of profile {profile_uuid}")]
    NoEntryNode {
        inbound_tag: String,
        profile_uuid: String,
    },
    #[error("inbound '{inbound_tag}' runs on several nodes ({candidates}) and none has address {address}")]
    AmbiguousEntryNode {
        inbound_tag: String,
        address: String,
        candidates: String,
    },
    #[error("node '{node}' has no active config profile")]
    NodeWithoutProfile { node: String },
    #[error("profile {uuid} is not known to the panel")]
    ProfileMissing { uuid: String },
    #[error("profile {profile} declares no outbounds")]
    NoOutbounds { profile: String },
    #[error("profile {profile} has no outbound tagged '{tag}'")]
    UnknownOutbound { profile: String, tag: String },
    #[error("inbound '{inbound_tag}' is routed into blackhole outbound '{tag}'")]
    Blackhole { inbound_tag: String, tag: String },
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

/// Name of the node this channel is declared to exit through.
pub fn resolve_exit(channel: &Channel, snapshot: &Snapshot) -> Result<String, ResolveError> {
    let mut node = entry_node(channel, &snapshot.nodes)?;
    let mut inbound_tag = channel.inbound_tag.clone();
    let mut visited: HashSet<(String, String)> = HashSet::new();

    for _ in 0..MAX_HOPS {
        if !visited.insert((node.name.clone(), inbound_tag.clone())) {
            return Err(ResolveError::Cycle {
                node: node.name.clone(),
                inbound_tag,
            });
        }
        let config = profile_config(node, snapshot)?;
        let outbound = outbound_for(config, &inbound_tag, node)?;
        let tag = outbound
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("<untagged>")
            .to_string();

        match outbound
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "freedom" => return Ok(node.name.clone()),
            "blackhole" => return Err(ResolveError::Blackhole { inbound_tag, tag }),
            _ => {}
        }

        let (address, port) =
            destination(outbound).ok_or(ResolveError::NoDestination { tag: tag.clone() })?;
        let next = snapshot
            .nodes
            .iter()
            .find(|n| n.address == address)
            .ok_or(ResolveError::UnknownNextHop { tag, address })?;
        let next_config = profile_config(next, snapshot)?;
        inbound_tag = inbound_tag_on_port(next_config, port).ok_or_else(|| {
            ResolveError::NoInboundOnPort {
                node: next.name.clone(),
                port,
            }
        })?;
        node = next;
    }
    Err(ResolveError::TooDeep { max: MAX_HOPS })
}

fn entry_node<'a>(channel: &Channel, nodes: &'a [Node]) -> Result<&'a Node, ResolveError> {
    let candidates: Vec<&Node> = nodes
        .iter()
        .filter(|n| {
            n.profile_uuid.as_deref() == Some(channel.profile_uuid.as_str())
                && n.inbound_tags.iter().any(|t| t == &channel.inbound_tag)
        })
        .collect();

    match candidates.len() {
        0 => Err(ResolveError::NoEntryNode {
            inbound_tag: channel.inbound_tag.clone(),
            profile_uuid: channel.profile_uuid.clone(),
        }),
        1 => Ok(candidates[0]),
        // Several nodes share the profile and the inbound; the channel address decides.
        _ => candidates
            .iter()
            .copied()
            .find(|n| n.address == channel.address)
            .ok_or_else(|| ResolveError::AmbiguousEntryNode {
                inbound_tag: channel.inbound_tag.clone(),
                address: channel.address.clone(),
                candidates: candidates
                    .iter()
                    .map(|n| n.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            }),
    }
}

fn profile_config<'a>(node: &Node, snapshot: &'a Snapshot) -> Result<&'a Value, ResolveError> {
    let uuid = node
        .profile_uuid
        .as_deref()
        .ok_or_else(|| ResolveError::NodeWithoutProfile {
            node: node.name.clone(),
        })?;
    snapshot
        .profiles
        .get(uuid)
        .map(|p| &p.config)
        .ok_or_else(|| ResolveError::ProfileMissing {
            uuid: uuid.to_string(),
        })
}

/// Outbound the traffic of `inbound_tag` ends up in. Xray sends traffic that matches no rule
/// into the first outbound of the list — mirroring that here keeps rule-less exit profiles working.
fn outbound_for<'a>(
    config: &'a Value,
    inbound_tag: &str,
    node: &Node,
) -> Result<&'a Value, ResolveError> {
    let profile_label = node
        .profile_uuid
        .clone()
        .unwrap_or_else(|| node.name.clone());
    let outbounds = config
        .get("outbounds")
        .and_then(Value::as_array)
        .filter(|o| !o.is_empty())
        .ok_or_else(|| ResolveError::NoOutbounds {
            profile: profile_label.clone(),
        })?;

    let routed_tag = config
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array)
        .and_then(|rules| rules.iter().find(|rule| rule_matches(rule, inbound_tag)))
        .and_then(|rule| rule.get("outboundTag"))
        .and_then(Value::as_str);

    match routed_tag {
        Some(tag) => outbounds
            .iter()
            .find(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
            .ok_or_else(|| ResolveError::UnknownOutbound {
                profile: profile_label,
                tag: tag.to_string(),
            }),
        None => Ok(&outbounds[0]),
    }
}

fn rule_matches(rule: &Value, inbound_tag: &str) -> bool {
    rule.get("inboundTag")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(inbound_tag)))
}

/// Destination of a proxying outbound: vless uses `vnext`, trojan and shadowsocks use `servers`.
fn destination(outbound: &Value) -> Option<(String, u16)> {
    let settings = outbound.get("settings")?;
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
    Some((address, port))
}

fn inbound_tag_on_port(config: &Value, port: u16) -> Option<String> {
    config
        .get("inbounds")?
        .as_array()?
        .iter()
        .find(|i| i.get("port").and_then(Value::as_u64) == Some(u64::from(port)))
        .and_then(|i| i.get("tag"))
        .and_then(Value::as_str)
        .map(str::to_string)
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
            inbound_tags: tags.iter().map(|s| s.to_string()).collect(),
            inbound_ports: vec![],
            is_disabled: false,
            is_connected: true,
            last_status_message: None,
            xray_version: Some("26.6.27".into()),
        }
    }

    /// Profile whose only outbound is freedom and which declares no routing rules —
    /// the shape of a plain exit node.
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

    /// Profile that routes its inbound into a vless outbound aimed at another node.
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
                .collect::<HashMap<_, _>>(),
            channels: vec![],
            served_channel_count: 0,
        }
    }

    fn channel(remark: &str, inbound_tag: &str, profile: &str, address: &str) -> Channel {
        Channel {
            remark: remark.into(),
            inbound_tag: inbound_tag.into(),
            profile_uuid: profile.into(),
            address: address.into(),
            port: 443,
            outbound: json!({}),
        }
    }

    #[test]
    fn direct_exit_resolves_to_the_entry_node() {
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p-exit", &["in-exit"])],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch = channel("beta direct", "in-exit", "p-exit", "beta.example.com");
        assert_eq!(resolve_exit(&ch, &snap).unwrap(), "beta");
    }

    #[test]
    fn cascade_resolves_through_the_bridge_to_the_far_node() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile("p-bridge", "in-bridge", 443, "to-gamma", "192.0.2.30", 2087),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        let ch = channel("cdn front", "in-bridge", "p-bridge", "cdn.example.com");
        assert_eq!(resolve_exit(&ch, &snap).unwrap(), "gamma");
    }

    #[test]
    fn no_node_runs_the_inbound() {
        let snap = snapshot(
            vec![node("beta", "192.0.2.20", "p-exit", &["other"])],
            vec![exit_profile("p-exit", "in-exit", 443)],
        );
        let ch = channel("orphan", "in-exit", "p-exit", "beta.example.com");
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::NoEntryNode { .. })
        ));
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
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::Blackhole { .. })
        ));
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
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::UnknownOutbound { .. })
        ));
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
        let ch = channel("dangling", "in-bridge", "p-bridge", "cdn.example.com");
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::UnknownNextHop { .. })
        ));
    }

    #[test]
    fn next_hop_without_a_matching_inbound_port_fails_loudly() {
        let snap = snapshot(
            vec![
                node("alpha", "192.0.2.10", "p-bridge", &["in-bridge"]),
                node("gamma", "192.0.2.30", "p-exit", &["in-exit"]),
            ],
            vec![
                bridge_profile("p-bridge", "in-bridge", 443, "to-gamma", "192.0.2.30", 9999),
                exit_profile("p-exit", "in-exit", 2087),
            ],
        );
        let ch = channel("wrong port", "in-bridge", "p-bridge", "cdn.example.com");
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::NoInboundOnPort { .. })
        ));
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
        assert!(matches!(
            resolve_exit(&ch, &snap),
            Err(ResolveError::Cycle { .. })
        ));
    }
}

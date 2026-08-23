use crate::dto::{NodeDto, ProfileDto, ResolvedDto};
use crate::subscription::RenderedConfig;
use remnawave_healthcheck_core::model::{Channel, Node, Profile, Snapshot};
use serde_json::Value;
use std::collections::HashMap;

/// Joins the three panel views into one snapshot.
///
/// Channels keep every config the panel resolved, even when the rendered subscription did not
/// serve it — `served_remarks` carries what the subscription did serve, duplicates included, so
/// `subscription:coverage` can compare the two sets instead of the gap disappearing.
pub fn build_snapshot(
    nodes: &[NodeDto],
    profiles: Vec<ProfileDto>,
    resolved: Vec<ResolvedDto>,
    rendered: Vec<RenderedConfig>,
) -> Snapshot {
    // Recorded before the map collapses duplicates: a remark served twice is exactly what the
    // coverage check needs to see, and the map would hide it.
    let served_remarks: Vec<String> =
        rendered.iter().map(|c| c.remark.clone()).collect();
    let served: HashMap<String, Value> = rendered
        .into_iter()
        .map(|c| (c.remark, c.outbound))
        .collect();

    let channels: Vec<Channel> = resolved
        .into_iter()
        .map(|r| Channel {
            outbound: served
                .get(&r.final_remark)
                .cloned()
                .unwrap_or(Value::Null),
            remark: r.final_remark,
            inbound_tag: r.metadata.inbound_tag,
            profile_uuid: r.metadata.config_profile_uuid,
            address: r.address,
            port: r.port,
        })
        .collect();

    Snapshot {
        nodes: nodes.iter().map(Node::from).collect::<Vec<Node>>(),
        profiles: profiles
            .into_iter()
            .map(Profile::from)
            .map(|p| (p.uuid.clone(), p))
            .collect(),
        channels,
        served_remarks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_fields_do_not_break_node_parsing() {
        // A future panel release adds fields; the tool must not care.
        let raw = json!({"response": [{
            "name": "alpha",
            "address": "192.0.2.10",
            "isDisabled": false,
            "isConnected": true,
            "lastStatusMessage": null,
            "versions": {"xray": "26.6.27", "node": "2.8.1"},
            "configProfile": {
                "activeConfigProfileUuid": "p-1",
                "activeInbounds": [{"tag": "in-a", "port": 443, "type": "vless"}]
            },
            "somethingInventedNextYear": {"deeply": ["nested", 1, true]}
        }]})
        .to_string();

        let nodes = crate::dto::parse_nodes(&raw).unwrap();
        assert_eq!(nodes.len(), 1);
        let n = Node::from(&nodes[0]);
        assert_eq!(n.name, "alpha");
        assert_eq!(n.address, "192.0.2.10");
        assert_eq!(n.profile_uuid.as_deref(), Some("p-1"));
        assert_eq!(n.inbound_tags, vec!["in-a".to_string()]);
        assert_eq!(n.inbound_ports, vec![443]);
        assert_eq!(n.xray_version.as_deref(), Some("26.6.27"));
    }

    #[test]
    fn node_without_a_profile_still_parses() {
        let raw = json!({"response": [{
            "name": "beta", "address": "192.0.2.20",
            "isDisabled": true, "isConnected": false
        }]})
        .to_string();
        let nodes = crate::dto::parse_nodes(&raw).unwrap();
        let n = Node::from(&nodes[0]);
        assert!(n.profile_uuid.is_none());
        assert!(n.inbound_tags.is_empty());
        assert!(n.is_disabled && !n.is_connected && !n.is_connecting);
    }

    #[test]
    fn snapshot_joins_resolved_configs_with_subscription_outbounds() {
        let nodes = vec![];
        let profiles = vec![crate::dto::ProfileDto {
            uuid: "p-1".into(),
            name: "main".into(),
            config: json!({"outbounds": [{"tag": "direct", "protocol": "freedom"}]}),
        }];
        let resolved = vec![crate::dto::ResolvedDto {
            final_remark: "alpha direct".into(),
            address: "alpha.example.com".into(),
            port: 443,
            metadata: crate::dto::MetadataDto {
                inbound_tag: "in-a".into(),
                config_profile_uuid: Some("p-1".into()),
            },
        }];
        let rendered = vec![RenderedConfig {
            remark: "alpha direct".to_string(),
            outbound: json!({"protocol": "vless"}),
        }];

        let snap = build_snapshot(&nodes, profiles, resolved, rendered);
        assert_eq!(snap.channels.len(), 1);
        assert_eq!(snap.channels[0].inbound_tag, "in-a");
        assert_eq!(snap.channels[0].profile_uuid.as_deref(), Some("p-1"));
        assert_eq!(snap.channels[0].outbound["protocol"], "vless");
        assert_eq!(snap.served_remarks, vec!["alpha direct".to_string()]);
        assert!(snap.profiles.contains_key("p-1"));
    }

    #[test]
    fn unmatched_resolved_config_keeps_the_channel_but_drops_its_outbound() {
        // The subscription served fewer channels than the panel resolved — subscription:coverage
        // is what reports this, so the counts must stay honest here.
        let resolved = vec![crate::dto::ResolvedDto {
            final_remark: "alpha direct".into(),
            address: "alpha.example.com".into(),
            port: 443,
            metadata: crate::dto::MetadataDto {
                inbound_tag: "in-a".into(),
                config_profile_uuid: Some("p-1".into()),
            },
        }];
        let snap = build_snapshot(&[], vec![], resolved, vec![]);
        assert_eq!(
            snap.channels.len(),
            1,
            "resolved channels are kept for the coverage check"
        );
        assert!(snap.served_remarks.is_empty());
    }
}

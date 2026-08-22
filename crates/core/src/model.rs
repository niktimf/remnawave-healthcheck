use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity of a single check. Ordering matters: the run's overall severity is the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Ok,
    Warn,
    Fail,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }

    pub fn is_ok(self) -> bool {
        self == Severity::Ok
    }
}

/// One check outcome. `key` is stable across runs and is what the diff compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub detail: String,
}

impl CheckResult {
    pub fn new(
        key: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            severity,
            detail: detail.into(),
        }
    }
}

/// A node as the panel describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub name: String,
    /// Address the panel uses to reach the node; also the SSH target.
    pub address: String,
    pub profile_uuid: Option<String>,
    /// Tags of the inbounds currently active on this node.
    pub inbound_tags: Vec<String>,
    /// Ports of those inbounds; drives the "is it listening" check.
    pub inbound_ports: Vec<u16>,
    pub is_disabled: bool,
    pub is_connected: bool,
    pub last_status_message: Option<String>,
    pub xray_version: Option<String>,
}

/// A client-facing channel, exactly as the monitoring user receives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    /// Host remark; used as the human-facing channel name and as part of the check key.
    pub remark: String,
    pub inbound_tag: String,
    /// Config profile the panel attached this host to. `None` is a legitimate panel state — a
    /// legacy host, or one whose config profile was deleted — not corrupted data; such a channel
    /// has no entry node to resolve and must fail loudly rather than being treated as healthy.
    pub profile_uuid: Option<String>,
    pub address: String,
    pub port: u16,
    /// Ready-made Xray outbound taken from the subscription. Never assembled by us.
    /// `Value::Null` means the subscription served no config for this channel.
    pub outbound: serde_json::Value,
}

impl Channel {
    /// Stable key of this channel's check, unique by construction.
    ///
    /// The remark alone is not: it is rendered from a template configured in the panel and
    /// nothing there enforces uniqueness. Two channels sharing a remark would share a key, and
    /// since the problem set is a map, one of them would silently vanish from the alert while the
    /// report on stdout still showed both. The client-facing endpoint is what tells two hosts of
    /// the same inbound apart, so it goes into the key; the human-facing title stays the plain
    /// remark.
    pub fn check_key(&self) -> String {
        format!("channel:{}@{}:{}", self.remark, self.address, self.port)
    }
}

/// An Xray config profile: the full JSON, as stored in the panel.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub uuid: String,
    pub name: String,
    pub config: serde_json::Value,
}

/// Everything one run needs from the panel.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub nodes: Vec<Node>,
    pub profiles: HashMap<String, Profile>,
    pub channels: Vec<Channel>,
    /// Remarks the rendered subscription actually served, duplicates included. Kept as a list
    /// rather than a count so `subscription:coverage` can compare sets and name what is missing:
    /// one channel dropped and another one duplicated leaves the counts equal.
    pub served_remarks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_ok_below_warn_below_fail() {
        assert!(Severity::Ok < Severity::Warn);
        assert!(Severity::Warn < Severity::Fail);
    }

    #[test]
    fn channels_sharing_a_remark_still_get_different_keys() {
        let channel = |address: &str, port: u16| Channel {
            remark: "the same remark".into(),
            inbound_tag: "in-a".into(),
            profile_uuid: Some("p".into()),
            address: address.into(),
            port,
            outbound: serde_json::Value::Null,
        };
        let a = channel("alpha.example.com", 443);
        let b = channel("beta.example.com", 443);
        let c = channel("alpha.example.com", 8443);
        assert_ne!(a.check_key(), b.check_key());
        assert_ne!(a.check_key(), c.check_key());
        assert!(a.check_key().starts_with("channel:"));
        // Stable across calls: the diff between two runs depends on it.
        assert_eq!(a.check_key(), channel("alpha.example.com", 443).check_key());
    }

    #[test]
    fn check_result_carries_key_title_and_detail() {
        let r = CheckResult::new("channel:alpha", "alpha", Severity::Fail, "no exit");
        assert_eq!(r.key, "channel:alpha");
        assert_eq!(r.title, "alpha");
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.detail, "no exit");
    }
}

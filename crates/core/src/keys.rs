//! Every check key this tool can produce, in one place.
//!
//! A key is the tool's memory across runs: the problem set is a map keyed by it, and the diff
//! decides what is new, worse or recovered by comparing those keys between runs. Two facts follow,
//! and both are why the keys live here rather than at the places that build them.
//!
//! A key must be unique. Two results sharing one collapse into a single entry in the problem set,
//! and the loser disappears from the alert without a trace. The keys used to be assembled in four
//! files across three crates, where nothing showed the namespaces side by side and nothing stopped
//! a new check from picking one that was already taken.
//!
//! A key must be stable. Renaming one makes the old key look recovered and the new one look new,
//! once, for anything that was failing under it.

/// A node-side check. Every one there is: the node checks are a closed set, and seeing them all
/// at once is the point of naming them here rather than spelling their suffixes at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeAspect {
    /// What the panel itself says about the node. The only one of these that costs no SSH.
    Panel,
    Containers,
    Ports,
    Users,
    ConfigAge,
    /// How long the certificate has left.
    CertExpiry,
    /// Whether the machinery that renews the certificate still works — a different question from
    /// `CertExpiry`, and one that is answerable about two months earlier.
    CertRenewal,
    EgressIp,
}

impl NodeAspect {
    /// Every aspect, so that a test can walk them and no list of checks has to be maintained
    /// twice.
    pub const ALL: [NodeAspect; 8] = [
        NodeAspect::Panel,
        NodeAspect::Containers,
        NodeAspect::Ports,
        NodeAspect::Users,
        NodeAspect::ConfigAge,
        NodeAspect::CertExpiry,
        NodeAspect::CertRenewal,
        NodeAspect::EgressIp,
    ];

    /// The part of the key that names this aspect. Part of the contract: changing one costs a
    /// single run in which the old key reads as recovered and the new one as new.
    pub fn slug(self) -> &'static str {
        match self {
            NodeAspect::Panel => "panel",
            NodeAspect::Containers => "containers",
            NodeAspect::Ports => "ports",
            NodeAspect::Users => "users",
            NodeAspect::ConfigAge => "config-age",
            NodeAspect::CertExpiry => "cert-expiry",
            NodeAspect::CertRenewal => "cert-renewal",
            NodeAspect::EgressIp => "egress-ip",
        }
    }

    /// How the check is labelled in the report, next to the node's name. Free to reword: no
    /// history depends on a title.
    pub fn title(self) -> &'static str {
        match self {
            NodeAspect::Panel => "panel status",
            NodeAspect::Containers => "containers",
            NodeAspect::Ports => "inbound ports",
            NodeAspect::Users => "provisioned users",
            NodeAspect::ConfigAge => "config age",
            NodeAspect::CertExpiry => "certificate expiry",
            NodeAspect::CertRenewal => "certificate renewal",
            NodeAspect::EgressIp => "egress address",
        }
    }
}

/// The identity of one check result.
///
/// Every key the tool produces comes from here, so the namespaces are visible together and a new
/// check cannot quietly reuse one. What it cannot do by itself is stop two variants from spelling
/// the same string — that is what `keys_are_unique_across_every_kind_of_check` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKey<'a> {
    Node {
        node: &'a str,
        aspect: NodeAspect,
    },
    /// One client-facing channel. The endpoint is part of the key because a remark is not unique:
    /// it is rendered from a panel template and nothing there enforces uniqueness, so two hosts of
    /// the same inbound can share one — and sharing a key means one of them vanishing from the
    /// alert while the report still shows both.
    Channel {
        remark: &'a str,
        address: &'a str,
        port: u16,
    },
    /// Stands in for every channel when probing could not be set up at all.
    ChannelSetup,
    SubscriptionCoverage,
    MonitoringCoverage {
        inbound: &'a str,
    },
    XrayVersionDrift,
}

impl CheckKey<'_> {
    pub fn key(&self) -> String {
        match self {
            CheckKey::Node { node, aspect } => format!("node:{node}:{}", aspect.slug()),
            CheckKey::Channel {
                remark,
                address,
                port,
            } => format!("channel:{remark}@{address}:{port}"),
            CheckKey::ChannelSetup => "channels:setup".to_string(),
            CheckKey::SubscriptionCoverage => "subscription:coverage".to_string(),
            CheckKey::MonitoringCoverage { inbound } => format!("monitoring:coverage:{inbound}"),
            CheckKey::XrayVersionDrift => "xray:version-drift".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// One of every kind of check, with the same node and the same names throughout: if two kinds
    /// can collide, this is the shape in which they do.
    fn one_of_each() -> Vec<CheckKey<'static>> {
        let mut keys: Vec<CheckKey<'static>> = NodeAspect::ALL
            .iter()
            .map(|aspect| CheckKey::Node {
                node: "beta",
                aspect: *aspect,
            })
            .collect();
        keys.extend([
            CheckKey::Channel {
                remark: "beta",
                address: "beta.example.com",
                port: 443,
            },
            CheckKey::ChannelSetup,
            CheckKey::SubscriptionCoverage,
            CheckKey::MonitoringCoverage { inbound: "beta" },
            CheckKey::XrayVersionDrift,
        ]);
        keys
    }

    #[test]
    fn keys_are_unique_across_every_kind_of_check() {
        // The compiler keeps the variants apart; nothing but this keeps two of them from
        // rendering the same string. A collision would not fail a run — it would silently drop
        // one of the two problems out of the alert.
        let keys = one_of_each();
        let distinct: BTreeSet<String> = keys.iter().map(CheckKey::key).collect();
        assert_eq!(
            distinct.len(),
            keys.len(),
            "two checks share a key: {:?}",
            keys.iter().map(CheckKey::key).collect::<Vec<String>>()
        );
    }

    #[test]
    fn a_node_aspect_is_named_the_same_way_everywhere() {
        let slugs: BTreeSet<&str> = NodeAspect::ALL.iter().map(|a| a.slug()).collect();
        assert_eq!(
            slugs.len(),
            NodeAspect::ALL.len(),
            "two aspects share a slug"
        );
        let titles: BTreeSet<&str> = NodeAspect::ALL.iter().map(|a| a.title()).collect();
        assert_eq!(
            titles.len(),
            NodeAspect::ALL.len(),
            "two aspects share a title"
        );
        // Slugs go into keys, which are read in alerts and compared between runs: no spaces, and
        // no colon, which is what separates the parts of a key.
        for aspect in NodeAspect::ALL {
            let slug = aspect.slug();
            assert!(!slug.is_empty(), "{aspect:?}");
            assert!(
                !slug.contains(' ') && !slug.contains(':'),
                "{aspect:?}: {slug}"
            );
        }
    }

    #[test]
    fn the_two_certificate_checks_are_told_apart_by_name() {
        // They answer different questions — days left, and whether renewal still works — about
        // two months apart. An operator reads these keys in an alert, so the pair reads as a pair.
        assert_eq!(NodeAspect::CertExpiry.slug(), "cert-expiry");
        assert_eq!(NodeAspect::CertRenewal.slug(), "cert-renewal");
        assert_ne!(
            NodeAspect::CertExpiry.title(),
            NodeAspect::CertRenewal.title()
        );
    }

    #[test]
    fn a_key_names_its_namespace_and_then_its_subject() {
        let key = |k: CheckKey<'_>| k.key();
        assert_eq!(
            key(CheckKey::Node {
                node: "beta",
                aspect: NodeAspect::Panel
            }),
            "node:beta:panel"
        );
        assert_eq!(
            key(CheckKey::Channel {
                remark: "beta direct",
                address: "beta.example.com",
                port: 8443
            }),
            "channel:beta direct@beta.example.com:8443"
        );
        assert_eq!(
            key(CheckKey::MonitoringCoverage { inbound: "in-a" }),
            "monitoring:coverage:in-a"
        );
        assert_eq!(key(CheckKey::ChannelSetup), "channels:setup");
        assert_eq!(key(CheckKey::SubscriptionCoverage), "subscription:coverage");
        assert_eq!(key(CheckKey::XrayVersionDrift), "xray:version-drift");
    }
}

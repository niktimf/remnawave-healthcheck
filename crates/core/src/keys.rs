//! Every check key this tool can produce, in one place.
//!
//! A key is the tool's memory across runs, and two things follow from that.
//!
//! It must be unique: two results sharing a key collapse into one entry in the
//! problem set, and the loser disappears from the alert without a trace.
//!
//! It must be stable: renaming one makes the old key look recovered and the new
//! one look new, once, for anything that was failing under it.

/// A node-side check, and every one there is: seeing the closed set at once is
/// the point of naming them here instead of at each call site.
///
/// `EnumIter` but no `Display`: the two strings below answer to different
/// masters — a key part and a report label — so `{aspect}` would be ambiguous,
/// and the direction that goes wrong quietly is a title reaching a key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, strum::EnumIter,
)]
pub enum NodeAspect {
    /// What the panel says about the node — the only one costing no SSH.
    Panel,
    Containers,
    Ports,
    Users,
    ConfigAge,
    /// How long the certificate has left.
    CertExpiry,
    /// Whether renewal still works — a different question from `CertExpiry`,
    /// answerable about two months earlier.
    CertRenewal,
    EgressIp,
}

impl NodeAspect {
    /// The part of the key that names this aspect, and part of the contract.
    ///
    /// Written out rather than derived, though `kebab-case` of the variant
    /// names would spell exactly these strings: deriving would make the key a
    /// function of a Rust identifier, so renaming `CertExpiry` for clarity
    /// would reset the certificate history of every node.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Panel => "panel",
            Self::Containers => "containers",
            Self::Ports => "ports",
            Self::Users => "users",
            Self::ConfigAge => "config-age",
            Self::CertExpiry => "cert-expiry",
            Self::CertRenewal => "cert-renewal",
            Self::EgressIp => "egress-ip",
        }
    }

    /// How the check is labelled in the report, next to the node's name. Free
    /// to reword: no history depends on a title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Panel => "panel status",
            Self::Containers => "containers",
            Self::Ports => "inbound ports",
            Self::Users => "provisioned users",
            Self::ConfigAge => "config age",
            Self::CertExpiry => "certificate expiry",
            Self::CertRenewal => "certificate renewal",
            Self::EgressIp => "egress address",
        }
    }
}

/// The identity of one check result.
///
/// Every key comes from here, so the namespaces are visible together and a new
/// check cannot quietly reuse one. What this cannot do by itself is stop two
/// variants from spelling the same string — that is what
/// `keys_are_unique_across_every_kind_of_check` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKey<'a> {
    Node {
        node: &'a str,
        aspect: NodeAspect,
    },
    /// The endpoint is part of the key because a remark is not unique: it is
    /// rendered from a panel template, so two hosts of the same inbound can
    /// share one — and a shared key means one of them vanishes from the alert.
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

impl std::fmt::Display for CheckKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckKey::Node { node, aspect } => {
                write!(f, "node:{node}:{}", aspect.slug())
            }
            CheckKey::Channel {
                remark,
                address,
                port,
            } => write!(f, "channel:{remark}@{address}:{port}"),
            CheckKey::ChannelSetup => f.write_str("channels:setup"),
            CheckKey::SubscriptionCoverage => {
                f.write_str("subscription:coverage")
            }
            CheckKey::MonitoringCoverage { inbound } => {
                write!(f, "monitoring:coverage:{inbound}")
            }
            CheckKey::XrayVersionDrift => f.write_str("xray:version-drift"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use strum::IntoEnumIterator;

    /// One of every kind, same name in every position: if two kinds can
    /// collide, this is the shape in which they do.
    fn one_of_each() -> Vec<CheckKey<'static>> {
        let mut keys: Vec<CheckKey<'static>> = NodeAspect::iter()
            .map(|aspect| CheckKey::Node {
                node: "beta",
                aspect,
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
        // The compiler keeps the variants apart; only this keeps two of them
        // from rendering the same string. A collision does not fail a run — it
        // drops one of the two problems out of the alert.
        let keys = one_of_each();
        let rendered = || keys.iter().map(ToString::to_string);
        let distinct: BTreeSet<String> = rendered().collect();
        assert_eq!(
            distinct.len(),
            keys.len(),
            "two checks share a key: {:?}",
            rendered().collect::<Vec<String>>()
        );
    }

    #[test]
    fn a_node_aspect_is_named_the_same_way_everywhere() {
        let aspects = NodeAspect::iter().count();
        let slugs: BTreeSet<&str> =
            NodeAspect::iter().map(super::NodeAspect::slug).collect();
        assert_eq!(slugs.len(), aspects, "two aspects share a slug");
        let titles: BTreeSet<&str> =
            NodeAspect::iter().map(super::NodeAspect::title).collect();
        assert_eq!(titles.len(), aspects, "two aspects share a title");
        // Slugs are read in alerts and compared between runs: no spaces, and no
        // colon, which is what separates the parts of a key.
        for aspect in NodeAspect::iter() {
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
        // Different questions — days left, and whether renewal still works —
        // about two months apart, read as a pair in an alert.
        assert_eq!(NodeAspect::CertExpiry.slug(), "cert-expiry");
        assert_eq!(NodeAspect::CertRenewal.slug(), "cert-renewal");
        assert_ne!(
            NodeAspect::CertExpiry.title(),
            NodeAspect::CertRenewal.title()
        );
    }

    #[test]
    fn a_key_names_its_namespace_and_then_its_subject() {
        let key = |k: CheckKey<'_>| k.to_string();
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
        assert_eq!(
            key(CheckKey::SubscriptionCoverage),
            "subscription:coverage"
        );
        assert_eq!(key(CheckKey::XrayVersionDrift), "xray:version-drift");
    }
}

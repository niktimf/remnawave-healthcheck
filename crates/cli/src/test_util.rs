//! Helpers shared by this crate's unit tests.

use crate::config::{Args, Config};
use crate::judge::Judge;
use clap::Parser;
use remnawave_healthcheck_core::model::{
    Channel, CheckResult, Endpoint, Node, Profile, Served, Snapshot,
};
use serde_json::json;
use std::collections::HashMap;

/// The three required settings plus whatever a test wants to vary.
pub(crate) fn args(extra: &[&str]) -> Args {
    let mut argv = vec![
        "remnawave-healthcheck",
        "--panel-url",
        "https://panel.example.com",
        "--api-token",
        "t",
        "--user-id",
        "42",
    ];
    argv.extend_from_slice(extra);
    Args::parse_from(argv)
}

/// A configuration with nothing but the defaults.
pub(crate) fn config() -> Config {
    Config::from_args(args(&[])).unwrap()
}

/// The result named `name`.
///
/// # Panics
/// When there is none, listing every name that was produced.
pub(crate) fn by_name<'a>(
    results: &'a [CheckResult],
    name: &str,
) -> &'a CheckResult {
    results.iter().find(|r| r.name == name).unwrap_or_else(|| {
        panic!(
            "no {name}: {:?}",
            results.iter().map(|r| &r.name).collect::<Vec<_>>()
        )
    })
}

/// A judge built from the defaults.
pub(crate) fn judge() -> Judge {
    config().judge
}

/// One connected node serving one xhttp channel that the subscription did
/// serve — the smallest snapshot every family has something to say about.
pub(crate) fn snapshot() -> Snapshot {
    let node = Node {
        uuid: "u-beta".into(),
        name: "beta".into(),
        address: "beta.example.com".into(),
        country_code: "DE".into(),
        is_connected: true,
        users_online: 3,
        xray_uptime_secs: 3600,
        xray_version: Some("26.6.27".into()),
        node_version: Some("3.3.2".into()),
        profile_uuid: Some("p".into()),
        inbound_tags: vec!["in".into()],
        inbound_ports: vec![443],
        ..Default::default()
    };
    let profile = Profile {
        uuid: "p".into(),
        name: "p".into(),
        config: json!({"inbounds": [{"tag": "in", "port": 443}], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}),
    };
    Snapshot {
        nodes: vec![node],
        profiles: HashMap::from([("p".to_string(), profile)]),
        channels: vec![Channel {
            remark: "beta direct".into(),
            inbound_tag: "in".into(),
            profile_uuid: Some("p".into()),
            address: "beta.example.com".into(),
            port: 443,
            transport: Some("xhttp".into()),
            path: Some("/p".into()),
            served: Served::Direct(json!({"protocol": "vless"})),
            ..Default::default()
        }],
        served_remarks: vec!["beta direct".into()],
        panel: Endpoint {
            host: "panel.example.com".into(),
            port: 443,
        },
        sub: Some(Endpoint {
            host: "sub.example.com".into(),
            port: 443,
        }),
        ..Default::default()
    }
}

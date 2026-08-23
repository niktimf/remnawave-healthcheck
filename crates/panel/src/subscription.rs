use serde_json::Value;

fn is_proxy(outbound: &Value) -> bool {
    !matches!(
        outbound
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "freedom" | "blackhole" | "dns" | ""
    )
}

/// One config the subscription rendered: its remark and the first proxy outbound in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedConfig {
    /// The only thing that joins a served config to the channel the panel resolved
    /// (see `map::build_snapshot`).
    pub remark: String,
    /// Handed to the probe verbatim.
    pub outbound: Value,
}

/// The remark is mandatory, because the remark is the only thing that joins a served config to
/// the channel the panel resolved. A config without one cannot be attributed to a channel, and
/// guessing — keying by an outbound's `tag`, say — would attach some other channel's outbound to
/// it and probe a channel with evidence that is not its own.
fn config_entry(config: &Value) -> Option<RenderedConfig> {
    let remark = config.get("remarks").and_then(Value::as_str)?.to_string();
    let outbound = config
        .get("outbounds")?
        .as_array()?
        .iter()
        .find(|o| is_proxy(o))?;
    Some(RenderedConfig {
        remark,
        outbound: outbound.clone(),
    })
}

/// Ready-made client outbounds keyed by their remark, taken from the panel's JSON subscription.
///
/// The panel serves an array of per-host configs, each with `remarks` and its own `outbounds`; a
/// subscription rendering a single host may come as that one config on its own rather than
/// wrapped in an array, so both shapes are accepted.
///
/// Anything else yields nothing rather than a guess: `subscription:coverage` then reports every
/// resolved channel as not served, which is loud and points straight at the subscription — far
/// better than silently pairing channels with the wrong outbounds.
pub fn parse(raw: &str) -> anyhow::Result<Vec<RenderedConfig>> {
    let value: Value = serde_json::from_str(raw)?;

    if let Some(configs) = value.as_array() {
        return Ok(configs.iter().filter_map(config_entry).collect());
    }
    Ok(config_entry(&value).into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_an_array_of_per_host_configs() {
        let raw = json!([
            {"remarks": "alpha direct",
             "outbounds": [{"protocol": "vless", "tag": "proxy"},
                           {"protocol": "freedom", "tag": "direct"}]},
            {"remarks": "beta cdn",
             "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
        ])
        .to_string();
        let got = parse(&raw).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].remark, "alpha direct");
        assert_eq!(got[0].outbound["protocol"], "vless");
        assert_eq!(got[1].remark, "beta cdn");
    }

    #[test]
    fn parses_a_lone_config_that_is_not_wrapped_in_an_array() {
        let raw = json!({
            "remarks": "alpha direct",
            "outbounds": [{"protocol": "vless", "tag": "proxy"},
                          {"protocol": "freedom", "tag": "direct"}]
        })
        .to_string();
        let got = parse(&raw).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].remark, "alpha direct",
            "keyed by remark, as the join needs"
        );
        assert_eq!(got[0].outbound["protocol"], "vless");
    }

    #[test]
    fn a_config_without_a_remark_yields_nothing_instead_of_a_guess() {
        // Outbound tags are not remarks: keying by them could only produce channels paired with
        // some other channel's outbound. Yielding nothing makes subscription:coverage report it.
        let raw = json!({
            "outbounds": [
                {"protocol": "vless", "tag": "alpha direct"},
                {"protocol": "freedom", "tag": "direct"}
            ]
        })
        .to_string();
        assert!(parse(&raw).unwrap().is_empty());
    }

    #[test]
    fn rejects_something_that_is_not_a_subscription() {
        assert!(parse("nonsense").is_err());
        assert!(parse("{}").unwrap().is_empty());
    }
}

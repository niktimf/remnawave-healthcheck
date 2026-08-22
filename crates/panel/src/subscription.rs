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

/// Ready-made client outbounds keyed by their remark, taken from the panel's JSON subscription.
///
/// The panel serves either an array of per-host configs (each with `remarks` and its own
/// `outbounds`) or one config whose outbounds are tagged per host. Both shapes are accepted so a
/// template change cannot silently blind the checker.
pub fn parse(raw: &str) -> anyhow::Result<Vec<(String, Value)>> {
    let value: Value = serde_json::from_str(raw)?;

    if let Some(configs) = value.as_array() {
        return Ok(configs
            .iter()
            .filter_map(|cfg| {
                let remark = cfg.get("remarks").and_then(Value::as_str)?.to_string();
                let outbound = cfg
                    .get("outbounds")?
                    .as_array()?
                    .iter()
                    .find(|o| is_proxy(o))?;
                Some((remark, outbound.clone()))
            })
            .collect());
    }

    let outbounds = match value.get("outbounds").and_then(Value::as_array) {
        Some(list) => list,
        None => return Ok(Vec::new()),
    };
    Ok(outbounds
        .iter()
        .filter(|o| is_proxy(o))
        .filter_map(|o| {
            let tag = o.get("tag").and_then(Value::as_str)?.to_string();
            Some((tag, o.clone()))
        })
        .collect())
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
        assert_eq!(got[0].0, "alpha direct");
        assert_eq!(got[0].1["protocol"], "vless");
        assert_eq!(got[1].0, "beta cdn");
    }

    #[test]
    fn parses_a_single_config_carrying_tagged_outbounds() {
        let raw = json!({
            "outbounds": [
                {"protocol": "vless", "tag": "alpha direct"},
                {"protocol": "freedom", "tag": "direct"}
            ]
        })
        .to_string();
        let got = parse(&raw).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "alpha direct");
    }

    #[test]
    fn rejects_something_that_is_not_a_subscription() {
        assert!(parse("nonsense").is_err());
        assert!(parse("{}").unwrap().is_empty());
    }
}

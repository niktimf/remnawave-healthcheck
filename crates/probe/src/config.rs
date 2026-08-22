use serde_json::{json, Value};

/// Wrap a ready-made subscription outbound into a runnable Xray config.
///
/// The outbound is copied verbatim: this tool checks what the panel handed the client, so
/// re-deriving transport settings here would defeat the whole point.
pub fn build(outbound: &Value, socks_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {"udp": true, "auth": "noauth"}
        }],
        "outbounds": [outbound]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_subscription_outbound_is_used_verbatim() {
        let outbound = json!({
            "protocol": "vless",
            "settings": {"vnext": [{"address": "edge.example.com", "port": 443,
                                     "users": [{"id": "u", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": "edge.example.com", "fingerprint": "firefox"}}
        });
        let cfg = build(&outbound, 10800);
        assert_eq!(
            cfg["outbounds"][0], outbound,
            "outbound must not be rewritten"
        );
    }

    #[test]
    fn a_local_socks_inbound_is_added_on_the_given_port() {
        let cfg = build(&json!({"protocol": "vless"}), 10842);
        assert_eq!(cfg["inbounds"][0]["protocol"], "socks");
        assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(cfg["inbounds"][0]["port"], 10842);
    }
}

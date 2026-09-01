//! The panel API: five requests, one `Snapshot`. Only the fields this tool
//! uses are described; everything else in a response is ignored, which is what
//! keeps the client alive across panel upgrades.

use anyhow::{Context, Result, anyhow};
use backon::{ExponentialBuilder, Retryable};
use remnawave_healthcheck_core::model::{
    Channel, HostStats, Node, Profile, Snapshot,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

pub const USER_AGENT: &str =
    concat!("remnawave-healthcheck/", env!("CARGO_PKG_VERSION"));

/// Headers of a device registered for the monitoring user. Without them a
/// panel with a device limit answers the subscription with a placeholder.
#[derive(Debug, Clone)]
pub struct Hwid {
    pub hwid: String,
    pub os: String,
    pub os_version: String,
    pub model: String,
}

impl Hwid {
    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-hwid", &self.hwid),
            ("x-device-os", &self.os),
            ("x-ver-os", &self.os_version),
            ("x-device-model", &self.model),
        ] {
            if let Ok(value) = HeaderValue::from_str(v) {
                h.insert(k, value);
            }
        }
        h
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Auth {
    Token,
    /// The rendered subscription: the point is to see what a client gets.
    Anonymous,
}

pub struct PanelClient {
    http: Client,
    base: Url,
    token: String,
    hwid: Option<Hwid>,
}

/// A request that may be worth repeating (transport error, 5xx) or not (4xx).
#[derive(Debug)]
enum RequestError {
    Transient(String),
    Final(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(s) | Self::Final(s) => f.write_str(s),
        }
    }
}

fn backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(4))
        .with_max_times(2)
}

fn head(body: &str) -> String {
    body.chars().take(300).collect()
}

/// The whole reason chain of a reqwest error, without the URL: the top-level
/// Display is a generic "error sending request", while the DNS/TLS/socket
/// cause an operator can act on sits in the sources.
pub fn error_chain(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut parts = vec![e.to_string()];
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        let text = s.to_string();
        if parts.last() != Some(&text) {
            parts.push(text);
        }
        source = s.source();
    }
    parts.join(": ")
}

#[derive(Deserialize)]
struct Envelope<T> {
    response: T,
}

impl PanelClient {
    pub fn new(
        base_url: &str,
        token: &str,
        timeout: Duration,
        hwid: Option<Hwid>,
    ) -> Result<Self> {
        let base = Url::parse(base_url).with_context(|| {
            format!("REMNAWAVE_PANEL_URL is not a URL: {base_url}")
        })?;
        anyhow::ensure!(
            base.host_str().is_some(),
            "REMNAWAVE_PANEL_URL has no host: {base_url}"
        );
        let http = Client::builder()
            .timeout(timeout)
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self {
            http,
            base,
            token: token.to_string(),
            hwid,
        })
    }

    pub fn host(&self) -> &str {
        self.base.host_str().unwrap_or_default()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base.as_str().trim_end_matches('/'))
    }

    fn apply(
        &self,
        mut req: reqwest::RequestBuilder,
        auth: Auth,
    ) -> reqwest::RequestBuilder {
        if auth == Auth::Token {
            req = req.bearer_auth(&self.token);
        }
        if let Some(h) = &self.hwid {
            req = req.headers(h.headers());
        }
        req
    }

    async fn finish(
        url: &str,
        resp: reqwest::Result<reqwest::Response>,
    ) -> Result<String, RequestError> {
        let resp = resp.map_err(|e| {
            RequestError::Transient(format!("{url}: {}", error_chain(e)))
        })?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| {
            RequestError::Transient(format!(
                "{url}: reading body: {}",
                error_chain(e)
            ))
        })?;
        if status.is_server_error() {
            return Err(RequestError::Transient(format!(
                "{url} returned {status}"
            )));
        }
        if !status.is_success() {
            return Err(RequestError::Final(format!(
                "{url} returned {status}: {}",
                head(&body)
            )));
        }
        Ok(body)
    }

    async fn with_retries<F, Fut>(what: &str, send: F) -> Result<String>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<String, RequestError>>,
    {
        send.retry(backoff())
            .when(|e| matches!(e, RequestError::Transient(_)))
            .notify(|e, delay| {
                tracing::warn!("panel: {e}; retrying in {delay:?}");
            })
            .await
            .map_err(|e| anyhow!("{what} {e}"))
    }

    pub(crate) async fn get_text(
        &self,
        path: &str,
        auth: Auth,
    ) -> Result<String> {
        let url = self.url(path);
        Self::with_retries("GET", || async {
            let resp = self.apply(self.http.get(&url), auth).send().await;
            Self::finish(&url, resp).await
        })
        .await
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        auth: Auth,
    ) -> Result<T> {
        let body = self.get_text(path, auth).await?;
        tracing::debug!(path, bytes = body.len(), "panel response");
        Ok(serde_json::from_str::<Envelope<T>>(&body)
            .with_context(|| format!("parsing the response of {path}"))?
            .response)
    }

    /// POST with retries on transport errors only: a 5xx from a job start is
    /// not retried, so a job is never queued twice.
    pub(crate) async fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T> {
        let url = self.url(path);
        let text = Self::with_retries("POST", || async {
            let resp = self
                .apply(self.http.post(&url).json(body), Auth::Token)
                .send()
                .await;
            match Self::finish(&url, resp).await {
                Err(RequestError::Transient(e)) if e.contains("returned 5") => {
                    Err(RequestError::Final(e))
                }
                other => other,
            }
        })
        .await?;
        Ok(serde_json::from_str::<Envelope<T>>(&text)
            .with_context(|| format!("parsing the response of {path}"))?
            .response)
    }

    /// Everything one run needs, in five requests.
    pub async fn snapshot(&self, user_id: u64) -> Result<Snapshot> {
        let user: UserDto = self
            .get_json(&format!("/api/users/{user_id}"), Auth::Token)
            .await?;
        let nodes: Vec<NodeDto> =
            self.get_json("/api/nodes", Auth::Token).await?;
        let profiles: ProfilesDto =
            self.get_json("/api/config-profiles", Auth::Token).await?;
        let raw: RawDto = self
            .get_json(
                &format!(
                    "/api/subscriptions/by-short-uuid/{}/raw?withDisabledHosts=false",
                    user.short_uuid
                ),
                Auth::Token,
            )
            .await?;
        let rendered = self
            .get_text(
                &format!("/api/sub/{}/json", user.short_uuid),
                Auth::Anonymous,
            )
            .await?;
        let rendered = parse_rendered(&rendered)
            .context("parsing the JSON subscription")?;
        Ok(build_snapshot(
            self.host(),
            &user,
            nodes,
            profiles.config_profiles,
            raw,
            rendered,
        ))
    }
}

// --- DTOs --------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserDto {
    short_uuid: String,
    #[serde(default)]
    subscription_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeDto {
    uuid: String,
    name: String,
    address: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    is_disabled: bool,
    #[serde(default)]
    is_connected: bool,
    #[serde(default)]
    is_connecting: bool,
    #[serde(default)]
    last_status_message: Option<String>,
    #[serde(default)]
    users_online: f64,
    #[serde(default)]
    xray_uptime: f64,
    #[serde(default)]
    versions: Option<VersionsDto>,
    #[serde(default)]
    system: Option<SystemDto>,
    #[serde(default)]
    config_profile: Option<NodeProfileDto>,
}

#[derive(Debug, Deserialize)]
struct VersionsDto {
    #[serde(default)]
    xray: Option<String>,
    #[serde(default)]
    node: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SystemDto {
    info: SystemInfoDto,
    stats: SystemStatsDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoDto {
    #[serde(default)]
    cpus: u32,
    #[serde(default)]
    memory_total: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SystemStatsDto {
    #[serde(default)]
    memory_free: f64,
    #[serde(default)]
    uptime: f64,
    #[serde(default)]
    load_avg: Vec<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeProfileDto {
    #[serde(default)]
    active_config_profile_uuid: Option<String>,
    #[serde(default)]
    active_inbounds: Vec<InboundDto>,
}

#[derive(Debug, Deserialize)]
struct InboundDto {
    tag: String,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfilesDto {
    #[serde(default)]
    config_profiles: Vec<ProfileDto>,
}

#[derive(Debug, Deserialize)]
struct ProfileDto {
    uuid: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    config: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDto {
    #[serde(default)]
    resolved_proxy_configs: Vec<ResolvedDto>,
    #[serde(default)]
    converted_user_info: Option<ConvertedUserInfoDto>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConvertedUserInfoDto {
    #[serde(default)]
    hwid_checkup: Option<HwidCheckupDto>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HwidCheckupDto {
    #[serde(default = "yes")]
    subscription_allowed: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedDto {
    final_remark: String,
    address: String,
    port: u16,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    metadata: MetadataDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataDto {
    inbound_tag: String,
    /// `null` for a host without a profile — a real panel state.
    #[serde(default)]
    config_profile_uuid: Option<String>,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn to_u64(n: f64) -> u64 {
    if n.is_finite() && n > 0.0 {
        n as u64
    } else {
        0
    }
}

impl From<NodeDto> for Node {
    fn from(d: NodeDto) -> Self {
        let profile = d.config_profile;
        let inbounds = profile
            .as_ref()
            .map_or(&[][..], |p| p.active_inbounds.as_slice());
        Self {
            uuid: d.uuid,
            name: d.name,
            address: d.address,
            country_code: d.country_code,
            is_disabled: d.is_disabled,
            is_connected: d.is_connected,
            is_connecting: d.is_connecting,
            last_status_message: d.last_status_message,
            users_online: to_u64(d.users_online),
            xray_uptime_secs: to_u64(d.xray_uptime),
            xray_version: d.versions.as_ref().and_then(|v| v.xray.clone()),
            node_version: d.versions.as_ref().and_then(|v| v.node.clone()),
            system: d.system.map(|s| HostStats {
                cpus: s.info.cpus,
                memory_total: to_u64(s.info.memory_total),
                memory_free: to_u64(s.stats.memory_free),
                load_avg: s.stats.load_avg,
                uptime_secs: to_u64(s.stats.uptime),
            }),
            inbound_tags: inbounds.iter().map(|i| i.tag.clone()).collect(),
            inbound_ports: inbounds.iter().filter_map(|i| i.port).collect(),
            profile_uuid: profile.and_then(|p| p.active_config_profile_uuid),
        }
    }
}

// --- rendered subscription -----------------------------------------------

/// One config the subscription rendered: its remark and the first proxy outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedConfig {
    remark: String,
    outbound: Value,
}

fn is_proxy(outbound: &Value) -> bool {
    !matches!(
        outbound
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "freedom" | "blackhole" | "dns" | ""
    )
}

/// The remark is mandatory: it is the only join to the resolved channel.
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

/// The panel serves an array of per-host configs, or one config for a
/// single-host subscription. Anything else yields nothing rather than a guess.
fn parse_rendered(raw: &str) -> Result<Vec<RenderedConfig>> {
    let value: Value = serde_json::from_str(raw)?;
    if let Some(configs) = value.as_array() {
        return Ok(configs.iter().filter_map(config_entry).collect());
    }
    Ok(config_entry(&value).into_iter().collect())
}

/// The HWID placeholder: outbounds aimed at `0.0.0.0:1`.
fn is_hwid_stub(rendered: &[RenderedConfig]) -> bool {
    let target = |o: &Value| {
        let first = o
            .pointer("/settings/vnext/0")
            .or_else(|| o.pointer("/settings/servers/0"))?;
        Some((
            first.get("address")?.as_str()?.to_string(),
            first.get("port")?.as_u64()?,
        ))
    };
    !rendered.is_empty()
        && rendered.iter().all(|c| {
            target(&c.outbound).is_some_and(|(a, p)| a == "0.0.0.0" && p == 1)
        })
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(str::to_string)
}

fn build_snapshot(
    panel_host: &str,
    user: &UserDto,
    nodes: Vec<NodeDto>,
    profiles: Vec<ProfileDto>,
    raw: RawDto,
    rendered: Vec<RenderedConfig>,
) -> Snapshot {
    let hwid_stub = is_hwid_stub(&rendered)
        || raw
            .converted_user_info
            .as_ref()
            .and_then(|c| c.hwid_checkup.as_ref())
            .is_some_and(|h| !h.subscription_allowed);
    let served_remarks: Vec<String> =
        rendered.iter().map(|c| c.remark.clone()).collect();
    let served: HashMap<String, Value> = if hwid_stub {
        HashMap::new()
    } else {
        rendered
            .into_iter()
            .map(|c| (c.remark, c.outbound))
            .collect()
    };
    let channels = raw
        .resolved_proxy_configs
        .into_iter()
        .map(|r| Channel {
            outbound: served
                .get(&r.final_remark)
                .cloned()
                .unwrap_or(Value::Null),
            sni: r
                .server_name
                .filter(|s| !s.is_empty())
                .or(r.host.filter(|s| !s.is_empty())),
            remark: r.final_remark,
            inbound_tag: r.metadata.inbound_tag,
            profile_uuid: r.metadata.config_profile_uuid,
            address: r.address,
            port: r.port,
            transport: r.transport,
            path: r.path,
        })
        .collect();
    let sub_host = host_of(&user.subscription_url).filter(|h| h != panel_host);
    Snapshot {
        nodes: nodes.into_iter().map(Node::from).collect(),
        profiles: profiles
            .into_iter()
            .map(|p| {
                (
                    p.uuid.clone(),
                    Profile {
                        uuid: p.uuid,
                        name: p.name,
                        config: p.config,
                    },
                )
            })
            .collect(),
        channels,
        served_remarks,
        hwid_stub,
        panel_host: panel_host.to_string(),
        sub_host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{client, client_with, envelope, hwid};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// wiremock 0.6 has no built-in "header absent" matcher.
    struct NoHeader(&'static str);
    impl wiremock::Match for NoHeader {
        fn matches(&self, request: &wiremock::Request) -> bool {
            !request.headers.contains_key(self.0)
        }
    }

    fn node_fixture() -> Value {
        json!({
            "uuid": "11111111-1111-4111-8111-111111111111", "id": 1, "name": "alpha", "address": "192.0.2.10",
            "port": 2222, "isConnected": true, "isDisabled": false, "isConnecting": false,
            "lastStatusMessage": null, "countryCode": "DE", "ips": [],
            "configProfile": {"activeConfigProfileUuid": "p-1",
                "activeInbounds": [{"uuid": "i-1", "profileUuid": "p-1", "tag": "in-a", "type": "vless", "network": "xhttp", "security": "reality", "port": 443, "rawInbound": null}]},
            "system": {"info": {"arch": "x64", "cpus": 2, "cpuModel": "x", "memoryTotal": 4000, "hostname": "alpha", "platform": "linux", "release": "6", "type": "Linux", "version": "1", "networkInterfaces": ["eth0"]},
                       "stats": {"memoryFree": 1000, "memoryUsed": 3000, "uptime": 864_000, "loadAvg": [0.5, 0.4, 0.3], "interface": null}},
            "versions": {"xray": "26.6.27", "node": "3.3.2"},
            "xrayUptime": 172_800, "usersOnline": 12,
            "somethingInventedNextYear": {"deeply": ["nested", 1, true]}
        })
    }

    fn rendered_fixture() -> Value {
        json!([{"remarks": "alpha direct", "outbounds": [
            {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "alpha.example.com", "port": 443, "users": [{"id": "u"}]}]}},
            {"protocol": "freedom", "tag": "direct"}]}])
    }

    async fn mount_all(server: &MockServer, rendered: Value) {
        Mock::given(method("GET")).and(path("/api/users/42")).and(header("authorization", "Bearer tok"))
            .respond_with(envelope(&json!({"id": 42, "shortUuid": "abc123", "subscriptionUrl": "https://sub.example.com/abc123"})))
            .mount(server).await;
        Mock::given(method("GET"))
            .and(path("/api/nodes"))
            .respond_with(envelope(&json!([node_fixture()])))
            .mount(server)
            .await;
        Mock::given(method("GET")).and(path("/api/config-profiles"))
            .respond_with(envelope(&json!({"configProfiles": [{"uuid": "p-1", "name": "main", "config": {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}}]})))
            .mount(server).await;
        Mock::given(method("GET")).and(path("/api/subscriptions/by-short-uuid/abc123/raw")).and(query_param("withDisabledHosts", "false")).and(header("x-hwid", "dev-1"))
            .respond_with(envelope(&json!({"resolvedProxyConfigs": [{"finalRemark": "alpha direct", "address": "alpha.example.com", "port": 443,
                "transport": "xhttp", "path": "/p", "host": "cdn.example.com", "serverName": "",
                "metadata": {"inboundTag": "in-a", "configProfileUuid": "p-1"}}],
                "convertedUserInfo": {"hwidCheckup": {"subscriptionAllowed": true}}})))
            .mount(server).await;
        Mock::given(method("GET"))
            .and(path("/api/sub/abc123/json"))
            .and(header("x-hwid", "dev-1"))
            .and(NoHeader("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rendered))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_snapshot_is_built_from_five_requests() {
        let server = MockServer::start().await;
        mount_all(&server, rendered_fixture()).await;
        let sut = client_with(&server, Some(hwid()));

        let snapshot = sut.snapshot(42).await.unwrap();

        let node = &snapshot.nodes[0];
        assert_eq!(
            (
                node.name.as_str(),
                node.country_code.as_str(),
                node.users_online,
                node.xray_uptime_secs
            ),
            ("alpha", "DE", 12, 172_800)
        );
        assert_eq!(node.node_version.as_deref(), Some("3.3.2"));
        assert_eq!(
            node.system.as_ref().map(|s| (
                s.cpus,
                s.memory_free,
                s.uptime_secs
            )),
            Some((2, 1000, 864_000))
        );
        assert_eq!(node.inbound_ports, vec![443]);
        let channel = &snapshot.channels[0];
        assert_eq!(
            (
                channel.transport.as_deref(),
                channel.path.as_deref(),
                channel.sni.as_deref()
            ),
            (Some("xhttp"), Some("/p"), Some("cdn.example.com"))
        );
        assert_eq!(channel.outbound["protocol"], "vless");
        assert_eq!(snapshot.served_remarks, vec!["alpha direct".to_string()]);
        assert!(snapshot.profiles.contains_key("p-1"));
        assert!(!snapshot.hwid_stub);
        assert_eq!(snapshot.sub_host.as_deref(), Some("sub.example.com"));
        assert_eq!(snapshot.panel_host, "127.0.0.1");
    }

    #[tokio::test]
    async fn the_hwid_placeholder_is_recognised_and_serves_nothing() {
        let server = MockServer::start().await;
        let stub = json!([{"remarks": "📱 unsupported", "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "0.0.0.0", "port": 1}]}}]}]);
        mount_all(&server, stub).await;
        let sut = client_with(&server, Some(hwid()));

        let snapshot = sut.snapshot(42).await.unwrap();

        assert!(snapshot.hwid_stub);
        assert!(snapshot.channels[0].outbound.is_null());
    }

    #[tokio::test]
    async fn a_5xx_is_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes"))
            .respond_with(ResponseTemplate::new(502))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes"))
            .respond_with(envelope(&json!([])))
            .mount(&server)
            .await;
        let sut = client(&server);

        let nodes: Vec<NodeDto> =
            sut.get_json("/api/nodes", Auth::Token).await.unwrap();

        assert!(nodes.is_empty());
    }

    #[tokio::test]
    async fn a_4xx_is_final_and_tried_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/config-profiles"))
            .respond_with(
                ResponseTemplate::new(401).set_body_string("Unauthorized"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let sut = client(&server);

        let err = sut
            .get_json::<Vec<ProfileDto>>("/api/config-profiles", Auth::Token)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("401"), "{err:#}");
    }

    #[test]
    fn a_list_of_configs_yields_one_channel_each() {
        let body = json!([{"remarks": "a", "outbounds": [{"protocol": "vless"}]},
                          {"remarks": "b", "outbounds": [{"protocol": "trojan"}]}])
        .to_string();

        let channels = parse_rendered(&body).unwrap();

        assert_eq!(channels.len(), 2);
    }

    #[test]
    fn a_lone_config_is_read_as_one_channel_with_its_proxy_outbound() {
        let body = json!({"remarks": "a", "outbounds": [{"protocol": "freedom"}, {"protocol": "vless"}]})
            .to_string();

        let channels = parse_rendered(&body).unwrap();

        assert_eq!(channels[0].outbound["protocol"], "vless");
    }

    #[test]
    fn a_config_without_a_remark_is_dropped() {
        let body = json!({"outbounds": [{"protocol": "vless"}]}).to_string();

        let channels = parse_rendered(&body).unwrap();

        assert!(channels.is_empty());
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error() {
        let result = parse_rendered("nonsense");

        assert!(result.is_err());
    }

    #[test]
    fn a_panel_url_without_a_host_is_refused() {
        let result =
            PanelClient::new("not a url", "t", Duration::from_secs(1), None);

        assert!(result.is_err());
    }

    #[test]
    fn the_host_comes_from_the_panel_url() {
        let sut = PanelClient::new(
            "https://panel.example.com/",
            "t",
            Duration::from_secs(1),
            None,
        )
        .unwrap();

        let host = sut.host();

        assert_eq!(host, "panel.example.com");
    }
}

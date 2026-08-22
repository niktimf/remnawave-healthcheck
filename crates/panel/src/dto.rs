use remnawave_healthcheck_core::model::Node;
use serde::Deserialize;

/// Every panel response is wrapped in `{"response": ...}`.
#[derive(Deserialize)]
struct Envelope<T> {
    response: T,
}

/// Only the fields this tool actually uses. Everything else in the payload is ignored on purpose:
/// mirroring the full schema is what makes clients break on panel upgrades.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDto {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub is_disabled: bool,
    #[serde(default)]
    pub is_connected: bool,
    #[serde(default)]
    pub last_status_message: Option<String>,
    #[serde(default)]
    pub versions: Option<VersionsDto>,
    #[serde(default)]
    pub config_profile: Option<NodeProfileDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionsDto {
    #[serde(default)]
    pub xray: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeProfileDto {
    #[serde(default)]
    pub active_config_profile_uuid: Option<String>,
    #[serde(default)]
    pub active_inbounds: Vec<InboundDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundDto {
    pub tag: String,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileDto {
    pub uuid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfilesData {
    #[serde(default)]
    config_profiles: Vec<ProfileDto>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedDto {
    pub final_remark: String,
    pub address: String,
    pub port: u16,
    pub metadata: MetadataDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataDto {
    pub inbound_tag: String,
    pub config_profile_uuid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSubscriptionData {
    #[serde(default)]
    resolved_proxy_configs: Vec<ResolvedDto>,
}

pub fn parse_nodes(body: &str) -> anyhow::Result<Vec<NodeDto>> {
    Ok(serde_json::from_str::<Envelope<Vec<NodeDto>>>(body)?.response)
}

pub fn parse_profiles(body: &str) -> anyhow::Result<Vec<ProfileDto>> {
    Ok(serde_json::from_str::<Envelope<ProfilesData>>(body)?
        .response
        .config_profiles)
}

pub fn parse_resolved(body: &str) -> anyhow::Result<Vec<ResolvedDto>> {
    Ok(serde_json::from_str::<Envelope<RawSubscriptionData>>(body)?
        .response
        .resolved_proxy_configs)
}

pub fn to_domain_node(dto: &NodeDto) -> Node {
    let profile = dto.config_profile.as_ref();
    Node {
        name: dto.name.clone(),
        address: dto.address.clone(),
        profile_uuid: profile.and_then(|p| p.active_config_profile_uuid.clone()),
        inbound_tags: profile
            .map(|p| p.active_inbounds.iter().map(|i| i.tag.clone()).collect())
            .unwrap_or_default(),
        inbound_ports: profile
            .map(|p| p.active_inbounds.iter().filter_map(|i| i.port).collect())
            .unwrap_or_default(),
        is_disabled: dto.is_disabled,
        is_connected: dto.is_connected,
        last_status_message: dto.last_status_message.clone(),
        xray_version: dto.versions.as_ref().and_then(|v| v.xray.clone()),
    }
}

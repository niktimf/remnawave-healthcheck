use remnawave_healthcheck_core::model::{Node, Profile};
use serde::{de::DeserializeOwned, Deserialize};

/// Every panel response is wrapped in `{"response": ...}`.
#[derive(Deserialize)]
struct Envelope<T> {
    response: T,
}

/// Only the fields this tool actually uses. Everything else in the payload is
/// ignored on purpose: mirroring the full schema is what makes clients break on
/// panel upgrades.
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
    pub is_connecting: bool,
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
    /// `null` when the host has no config profile attached (legacy host, or a
    /// profile that was since deleted) — a real panel state per
    /// `resolved-proxy-config.schema.ts`, not drift.
    #[serde(default)]
    pub config_profile_uuid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSubscriptionData {
    #[serde(default)]
    resolved_proxy_configs: Vec<ResolvedDto>,
}

/// Unwrap one panel response. The envelope is the same for every endpoint; only
/// what sits inside it differs.
fn parse_response<T: DeserializeOwned>(body: &str) -> anyhow::Result<T> {
    Ok(serde_json::from_str::<Envelope<T>>(body)?.response)
}

pub fn parse_nodes(body: &str) -> anyhow::Result<Vec<NodeDto>> {
    parse_response(body)
}

pub fn parse_profiles(body: &str) -> anyhow::Result<Vec<ProfileDto>> {
    Ok(parse_response::<ProfilesData>(body)?.config_profiles)
}

pub fn parse_resolved(body: &str) -> anyhow::Result<Vec<ResolvedDto>> {
    Ok(parse_response::<RawSubscriptionData>(body)?.resolved_proxy_configs)
}

impl From<&NodeDto> for Node {
    fn from(dto: &NodeDto) -> Self {
        let profile = dto.config_profile.as_ref();
        // Taken once: a node with no profile simply has no active inbounds, and
        // both lists below are then empty for the same reason.
        let inbounds: &[InboundDto] =
            profile.map_or(&[], |p| p.active_inbounds.as_slice());
        Self {
            name: dto.name.clone(),
            address: dto.address.clone(),
            profile_uuid: profile
                .and_then(|p| p.active_config_profile_uuid.clone()),
            inbound_tags: inbounds.iter().map(|i| i.tag.clone()).collect(),
            inbound_ports: inbounds.iter().filter_map(|i| i.port).collect(),
            is_disabled: dto.is_disabled,
            is_connected: dto.is_connected,
            is_connecting: dto.is_connecting,
            last_status_message: dto.last_status_message.clone(),
            xray_version: dto.versions.as_ref().and_then(|v| v.xray.clone()),
        }
    }
}

impl From<ProfileDto> for Profile {
    fn from(dto: ProfileDto) -> Self {
        Self {
            uuid: dto.uuid,
            name: dto.name,
            config: dto.config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolved_config_with_a_null_profile_uuid_still_parses() {
        // hosts.schema.ts and resolved-proxy-config.schema.ts both declare
        // configProfileUuid nullable: a host can be unattached to any config
        // profile (legacy host, or one whose profile was deleted). This must
        // not fail parsing the whole response over one such host.
        let raw = json!({"response": {"resolvedProxyConfigs": [{
            "finalRemark": "orphaned host",
            "address": "orphan.example.com",
            "port": 443,
            "metadata": {
                "inboundTag": "in-a",
                "configProfileUuid": null
            }
        }]}})
        .to_string();

        let resolved = parse_resolved(&raw).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].metadata.config_profile_uuid, None);
    }
}

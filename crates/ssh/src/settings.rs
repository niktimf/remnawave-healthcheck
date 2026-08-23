use remnawave_healthcheck_core::model::{EchoUrl, ShellWord};

/// How one installation is laid out, and what this run calls stale.
///
/// Everything here has a default that fits Remnawave's own deployment, and
/// every one of them can be set from the environment: a container renamed in
/// `docker-compose.yml` or an acme.sh living outside `/root` are ordinary, and
/// used to mean this tool simply reported the node as broken.
///
/// Gathered into one value rather than passed a piece at a time, because both
/// halves of this crate need it: the collector builds its commands from these,
/// and the checks read the same names back out of what those commands printed.
#[derive(Debug, Clone)]
pub struct NodeSettings {
    /// Container the node's Xray runs in.
    pub container: ShellWord,
    /// Directory acme.sh keeps its per-domain configuration in, without a
    /// trailing slash.
    pub acme_dir: ShellWord,
    /// How many lines of the container log to read — and therefore how far back
    /// the last config push can be found.
    pub log_lines: usize,
    /// The endpoint asked for this node's own egress address.
    pub echo_url: EchoUrl,
    /// Warn this many days before a certificate expires.
    pub cert_warn_days: u32,
    /// Warn when the node last took a config this many days ago.
    pub config_warn_days: u32,
}

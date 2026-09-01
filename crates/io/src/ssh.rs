//! One multiplexed SSH session per node, four commands, raw output back.
//! Nothing is parsed here; `core::checks::ssh` judges the text.

use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use remnawave_healthcheck_core::checks::ssh::{PORT80_CLOSED, PORT80_OPEN};
use remnawave_healthcheck_core::model::{HostFacts, SshOutcome};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::NamedTempFile;

#[derive(Debug, Clone)]
pub struct SshConfig {
    /// `None`: no `-o User` is passed and ssh's own config decides.
    pub user: Option<String>,
    pub port: u16,
    /// Private key text; `None` leaves key selection to ssh-agent / `~/.ssh`.
    pub private_key: Option<String>,
    /// `known_hosts` text; `None` means `StrictHostKeyChecking=accept-new`.
    pub known_hosts: Option<String>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    /// Directory acme.sh keeps its per-domain configuration in.
    pub acme_dir: String,
}

/// Holds the key and `known_hosts` files for the length of a run; both are
/// removed when it is dropped.
pub struct SshRunner {
    config: SshConfig,
    key_file: Option<NamedTempFile>,
    known_hosts_file: Option<NamedTempFile>,
}

impl SshRunner {
    pub fn new(config: SshConfig) -> anyhow::Result<Self> {
        let key_file =
            config.private_key.as_deref().map(secret_file).transpose()?;
        let known_hosts_file =
            config.known_hosts.as_deref().map(secret_file).transpose()?;
        Ok(Self {
            config,
            key_file,
            known_hosts_file,
        })
    }

    pub async fn gather(
        &self,
        address: &str,
        domain: Option<&str>,
    ) -> SshOutcome {
        let session = match self.connect(address).await {
            Ok(s) => s,
            Err(e) => return SshOutcome::Unreachable(error_detail(&e)),
        };
        let cmds = Commands::new(&self.config.acme_dir, domain);
        let t = self.config.command_timeout;
        let (docker_ps, unhealthy, listening, renewal) = tokio::join!(
            run(&session, address, &cmds.docker_ps, t),
            run(&session, address, &cmds.unhealthy, t),
            run(&session, address, &cmds.listening, t),
            run(&session, address, &cmds.renewal, t),
        );
        let cert = match &cmds.cert {
            Some(c) => Some(run(&session, address, c, t).await),
            None => None,
        };
        SshOutcome::Reached(HostFacts {
            docker_ps,
            unhealthy,
            listening,
            cert,
            renewal,
        })
    }

    async fn connect(&self, address: &str) -> Result<Session, openssh::Error> {
        let mut b = SessionBuilder::default();
        if let Some(user) = &self.config.user {
            b.user(user.clone());
        }
        b.port(self.config.port)
            .connect_timeout(self.config.connect_timeout);
        match &self.known_hosts_file {
            Some(f) => {
                b.known_hosts_check(KnownHosts::Strict)
                    .user_known_hosts_file(f.path());
            }
            None => {
                b.known_hosts_check(KnownHosts::Add);
            }
        }
        if let Some(k) = &self.key_file {
            b.keyfile(k.path());
        }
        b.connect(address).await
    }
}

/// A `0600` temp file holding a secret, with the trailing newline OpenSSH
/// requires of a private key.
fn secret_file(content: &str) -> anyhow::Result<NamedTempFile> {
    let mut f = tempfile::Builder::new()
        .prefix("rwhc-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile()?;
    f.write_all(content.as_bytes())?;
    if !content.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    f.flush()?;
    Ok(f)
}

/// The same command through `sudo` and without, for a login that may already
/// talk to the docker socket.
fn sudo_or_not(command: &str) -> String {
    format!("sudo {command} 2>/dev/null || {command}")
}

fn quote(value: &str) -> String {
    shlex::try_quote(value)
        .map_or_else(|_| "''".to_string(), std::borrow::Cow::into_owned)
}

/// The remote commands, every configured value quoted at its insertion point.
/// No nested `sh -c`: one shell level, one quoting level.
pub(crate) struct Commands {
    pub docker_ps: String,
    pub unhealthy: String,
    pub listening: String,
    pub renewal: String,
    pub cert: Option<String>,
}

impl Commands {
    pub(crate) fn new(acme_dir: &str, domain: Option<&str>) -> Self {
        let acme = quote(acme_dir);
        let find_cmd = format!(
            "find {acme} -mindepth 2 -maxdepth 2 -name '*.conf' \
             -exec grep -HE 'Le_NextRenewTimeStr|Le_Webroot' {{}} +"
        );
        Self {
            docker_ps: sudo_or_not(
                "docker ps --format '{{.Names}}\\t{{.State}}'",
            ),
            unhealthy: sudo_or_not(
                "docker ps --filter health=unhealthy --format '{{.Names}}'",
            ),
            listening: sudo_or_not("ss -ltn"),
            renewal: format!(
                "{}; (sudo ufw status 2>/dev/null || ufw status 2>/dev/null) \
                 | grep -qE '^80/tcp' && echo {PORT80_OPEN} || echo {PORT80_CLOSED}",
                sudo_or_not(&find_cmd)
            ),
            cert: domain.map(|d| {
                let d = quote(d);
                format!(
                    "echo | openssl s_client -connect {d}:443 -servername {d} 2>/dev/null | openssl x509 -noout -enddate"
                )
            }),
        }
    }
}

/// Run one command as a channel of the session; the output, or the reason
/// there is none, as text for the checks.
async fn run(
    session: &Session,
    address: &str,
    command: &str,
    timeout: Duration,
) -> String {
    let mut cmd = session.raw_command(command);
    cmd.stdin(Stdio::null());
    let text = match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => "ssh timeout".to_string(),
        Ok(Err(e)) => format!("ssh error: {}", error_detail(&e)),
        Ok(Ok(out)) => {
            let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&out.stderr));
            t
        }
    };
    tracing::debug!(address, command, output = %text, "ssh");
    text
}

/// What went wrong in ssh's own words: the deepest source's last non-empty
/// line, capped so it fits an alert.
fn error_detail(err: &openssh::Error) -> String {
    let mut deepest: &dyn std::error::Error = err;
    while let Some(source) = deepest.source() {
        deepest = source;
    }
    let text = deepest.to_string();
    let reason = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let reason = if reason.is_empty() {
        err.to_string()
    } else {
        reason.to_string()
    };
    reason.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACME_WITH_SPACE: &str = "/home/deploy/my acme";

    #[test]
    fn a_configured_path_is_quoted_wherever_it_appears() {
        let sut = Commands::new(ACME_WITH_SPACE, None);

        assert!(
            sut.renewal
                .starts_with("sudo find '/home/deploy/my acme' -mindepth 2"),
            "{}",
            sut.renewal
        );
        assert!(
            sut.renewal.contains("|| find '/home/deploy/my acme'"),
            "{}",
            sut.renewal
        );
    }

    #[test]
    fn the_renewal_command_reports_whether_port_80_is_reachable() {
        let sut = Commands::new(ACME_WITH_SPACE, None);

        assert!(sut.renewal.contains("|| ufw status"), "{}", sut.renewal);
        assert!(
            sut.renewal.contains(PORT80_OPEN)
                && sut.renewal.contains(PORT80_CLOSED)
        );
    }

    /// A nested shell would undo the quoting above, so no command may spawn one.
    #[test]
    fn no_command_nests_a_shell() {
        let sut = Commands::new(ACME_WITH_SPACE, Some("beta.example.com"));

        for cmd in [
            &sut.docker_ps,
            &sut.unhealthy,
            &sut.listening,
            &sut.renewal,
            sut.cert.as_ref().unwrap(),
        ] {
            assert!(!cmd.contains("sh -c"), "{cmd}");
        }
    }

    #[test]
    fn a_node_with_a_domain_is_asked_for_its_certificate() {
        let sut = Commands::new("/root/.acme.sh", Some("beta.example.com"));

        assert!(
            sut.cert
                .as_deref()
                .unwrap()
                .contains("-servername beta.example.com")
        );
    }

    #[test]
    fn a_node_without_a_domain_has_no_certificate_command() {
        let sut = Commands::new("/root/.acme.sh", None);

        assert!(sut.cert.is_none());
    }

    #[test]
    fn a_hostile_domain_cannot_break_out_of_the_command() {
        let sut = Commands::new("/root/.acme.sh", Some("x; id #"));

        assert!(
            sut.cert
                .as_deref()
                .unwrap()
                .contains("-connect 'x; id #':443"),
            "{:?}",
            sut.cert
        );
    }

    #[test]
    fn a_secret_file_is_readable_only_by_its_owner() {
        let sut =
            secret_file("-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();

        let mode =
            std::fs::metadata(sut.path()).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);
    }

    /// ssh rejects a key whose last line is not terminated.
    #[test]
    fn a_secret_file_ends_with_a_newline() {
        let sut =
            secret_file("-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();

        let text = std::fs::read_to_string(sut.path()).unwrap();

        assert!(text.ends_with("-----END KEY-----\n"));
    }

    #[test]
    fn a_secret_file_vanishes_with_the_runner() {
        let sut =
            secret_file("-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();
        let path = sut.path().to_path_buf();

        drop(sut);

        assert!(!path.exists(), "the key file must vanish with the runner");
    }

    #[test]
    fn a_failed_connection_is_reported_in_sshs_own_words() {
        let sut = openssh::Error::Connect(std::io::Error::other(
            "warming up\nPermission denied (publickey).\n",
        ));

        let detail = error_detail(&sut);

        assert_eq!(detail, "Permission denied (publickey).");
    }

    #[test]
    fn a_long_connection_error_is_cut_to_a_readable_length() {
        let sut =
            openssh::Error::Connect(std::io::Error::other("x".repeat(500)));

        let detail = error_detail(&sut);

        assert_eq!(detail.chars().count(), 120);
    }

    #[tokio::test]
    #[ignore = "needs the ssh binary and a host that refuses port 22"]
    async fn an_unreachable_host_yields_a_reason_from_the_real_transport() {
        let sut = SshRunner::new(SshConfig {
            user: Some("root".into()),
            port: 22,
            private_key: None,
            known_hosts: None,
            connect_timeout: Duration::from_secs(3),
            command_timeout: Duration::from_secs(3),
            acme_dir: "/root/.acme.sh".into(),
        })
        .unwrap();

        let outcome = sut.gather("127.0.0.1", None).await;

        match outcome {
            SshOutcome::Unreachable(reason) => assert!(!reason.is_empty()),
            SshOutcome::Reached(_) => {
                panic!("a host with no sshd is unreachable")
            }
        }
    }
}

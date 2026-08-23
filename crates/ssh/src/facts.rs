use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use remnawave_healthcheck_core::model::EchoUrl;
use std::time::Duration;

/// How long the initial connection may take (`ssh -o ConnectTimeout`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one remote command may take before it is abandoned.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw command output from one host. Parsing happens elsewhere so it can be
/// tested against recorded samples without touching the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// Why SSH failed, or `None` when the host answered. One field, so the
    /// reason and the verdict cannot drift apart.
    pub unreachable_reason: Option<String>,
    /// `name<TAB>state`, where the state is the daemon's machine value
    /// (`running`, `restarting`, `paused`), not the human "Up 5 days" line.
    pub docker_ps: String,
    /// Containers the daemon itself calls unhealthy, one per line. Asked for
    /// separately because health is not a field `docker ps` can format on any
    /// version this tool can expect to meet — only its own filter knows.
    pub unhealthy: String,
    pub listening: String,
    pub node_logs: String,
    /// Output of the TLS probe, or `None` when the node has no name to probe.
    /// Empty output is a different thing — the endpoint was asked and said
    /// nothing — and the cert check must tell the two apart.
    pub cert: Option<String>,
    pub renewal: String,
    pub egress_ip: String,
}

impl HostFacts {
    /// The node's own view of its egress address, which is what channel exits
    /// are measured against. Shares `core::model::parse_ip` with the probe side
    /// so neither end can start accepting an error page as an address.
    pub fn egress_address(&self) -> Option<std::net::IpAddr> {
        remnawave_healthcheck_core::model::parse_ip(&self.egress_ip)
    }
}

/// Renewal state of acme.sh plus whether port 80 is open for http-01.
///
/// The glob is expanded inside `sudo sh -c`; a non-root shell cannot look into
/// /root. `-H` forces the `filename:` prefix even when the glob expands to one
/// file, which is the common case — without it `parse_renewal` cannot recover
/// the domain.
const RENEWAL_CMD: &str = "sudo sh -c 'grep -HE \"Le_NextRenewTimeStr|Le_Webroot\" /root/.acme.sh/*/*.conf \
2>/dev/null || echo NO_ACME_CONF; ufw status 2>/dev/null | grep -qE \"^80/tcp\" && echo PORT80=open || echo PORT80=closed'";

/// What became of one remote command.
///
/// The text is always there — either the output or the reason there is none —
/// while an exit status exists only for a command that ran, which is why it
/// sits inside one variant instead of being faked with a sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandOutcome {
    /// Ran on the host, with this status and output. `status` is `None` when
    /// the remote process was killed by a signal and reported no code.
    Ran { status: Option<i32>, text: String },
    /// The command did not finish within the timeout.
    TimedOut,
    /// The command never ran: the session could not carry it.
    Failed(String),
}

impl CommandOutcome {
    /// The output to parse, or the reason there is none. Consuming: the largest
    /// of these texts is a 200-line container log.
    fn text(self) -> String {
        match self {
            Self::Ran { text, .. } => text,
            Self::TimedOut => "ssh timeout".to_string(),
            Self::Failed(e) => format!("ssh error: {e}"),
        }
    }
}

/// Open the one session every command on this host will share.
///
/// Each command used to be its own `ssh` invocation — seven handshakes per node
/// per run. They are channels of one multiplexed session now.
///
/// `KnownHosts::Add` is `StrictHostKeyChecking=accept-new`, the policy this
/// tool has always had. `BatchMode=yes` the builder sets itself, which keeps a
/// host that wants a password from hanging on a prompt.
async fn connect(target: &str) -> Result<Session, openssh::Error> {
    let mut builder = SessionBuilder::default();
    builder
        .known_hosts_check(KnownHosts::Add)
        .connect_timeout(CONNECT_TIMEOUT);
    builder.connect(target).await
}

/// What actually went wrong, in ssh's own words.
///
/// The crate's messages are generic — "failed to connect to the remote host" —
/// while the line an operator needs sits in the error's source, so the chain is
/// walked to the end. Capped, so a wall of text cannot push the reason out of
/// an alert.
fn error_detail(err: &openssh::Error) -> String {
    let mut deepest: &dyn std::error::Error = err;
    while let Some(source) = deepest.source() {
        deepest = source;
    }
    let text = deepest.to_string();
    let reason = last_non_empty_line(&text);
    let reason = if reason.is_empty() {
        err.to_string()
    } else {
        reason.to_string()
    };
    reason.chars().take(120).collect()
}

/// Run one command as a channel of an open session. The remote end runs it
/// through a shell, which the pipes and `||` fallbacks below rely on.
async fn run(session: &Session, command: &str) -> CommandOutcome {
    let mut cmd = session.raw_command(command);
    cmd.stdin(Stdio::null());

    // If this fires, the future holding the channel is dropped and the channel
    // closes: nothing is left running locally.
    match tokio::time::timeout(COMMAND_TIMEOUT, cmd.output()).await {
        Err(_) => CommandOutcome::TimedOut,
        Ok(Err(e)) => CommandOutcome::Failed(error_detail(&e)),
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            CommandOutcome::Ran {
                status: out.status.code(),
                text,
            }
        }
    }
}

/// Collect everything the node-side checks need, in one pass.
///
/// `echo_url` is the endpoint the channel probes use, passed in rather than
/// fixed here so both sides of the exit comparison ask the same service: two of
/// them could disagree about a multi-homed host and turn a healthy channel red.
pub async fn gather(
    target: &str,
    domain: Option<&str>,
    echo_url: &EchoUrl,
) -> HostFacts {
    // Opening the session is the reachability check, and why it failed is the
    // reason to report.
    let session = match connect(target).await {
        Ok(session) => session,
        Err(e) => {
            return HostFacts {
                unreachable_reason: Some(format!(
                    "ssh unreachable: {}",
                    error_detail(&e)
                )),
                ..HostFacts::default()
            }
        }
    };

    // Single-quoted for the remote shell, which `EchoUrl` is what makes safe.
    let egress_cmd = format!("curl -fsS --max-time 8 '{echo_url}'");
    let cert_cmd = domain.map(|d| {
        format!("echo | openssl s_client -connect {d}:443 -servername {d} 2>/dev/null | openssl x509 -noout -enddate")
    });

    let (docker_ps, unhealthy, listening, node_logs, renewal, egress_ip) = tokio::join!(
        run(&session, "sudo docker ps --format '{{.Names}}\\t{{.State}}' 2>/dev/null || docker ps --format '{{.Names}}\\t{{.State}}'"),
        run(&session, "sudo docker ps --filter health=unhealthy --format '{{.Names}}' 2>/dev/null || docker ps --filter health=unhealthy --format '{{.Names}}'"),
        run(&session, "sudo ss -ltn 2>/dev/null || ss -ltn"),
        run(&session, "sudo docker logs --tail 200 remnanode 2>&1 || docker logs --tail 200 remnanode"),
        run(&session, RENEWAL_CMD),
        run(&session, &egress_cmd),
    );
    let cert = match cert_cmd {
        Some(cmd) => Some(run(&session, &cmd).await.text()),
        None => None,
    };

    HostFacts {
        unreachable_reason: None,
        docker_ps: docker_ps.text(),
        unhealthy: unhealthy.text(),
        listening: listening.text(),
        node_logs: node_logs.text(),
        cert,
        renewal: renewal.text(),
        egress_ip: egress_ip.text(),
    }
}

fn last_non_empty_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_egress_address_is_trimmed_and_validated() {
        let facts = |egress: &str| HostFacts {
            egress_ip: egress.into(),
            ..HostFacts::default()
        };
        assert_eq!(
            facts("192.0.2.20\n").egress_address(),
            Some("192.0.2.20".parse().unwrap())
        );
        // Not an address: a curl error line must never be reported as one.
        assert_eq!(
            facts("curl: (7) Failed to connect\n").egress_address(),
            None
        );
    }

    fn ran(status: Option<i32>, text: &str) -> CommandOutcome {
        CommandOutcome::Ran {
            status,
            text: text.to_string(),
        }
    }

    /// A connection failure as the crate reports one: a generic message, with
    /// ssh's actual line kept as the source.
    fn connect_error(ssh_said: &str) -> openssh::Error {
        openssh::Error::Connect(std::io::Error::other(ssh_said.to_string()))
    }

    #[test]
    fn a_failed_connection_is_reported_in_sshs_own_words() {
        // Not the crate's "failed to connect to the remote host", which says
        // nothing an operator can act on.
        assert_eq!(
            error_detail(&connect_error(
                "connect to host beta.example.com port 22: Connection refused"
            )),
            "connect to host beta.example.com port 22: Connection refused"
        );
    }

    #[test]
    fn a_multi_line_reason_keeps_the_line_that_says_why() {
        assert_eq!(
            error_detail(&connect_error(
                "warming up\nPermission denied (publickey).\n"
            )),
            "Permission denied (publickey)."
        );
    }

    #[test]
    fn an_error_with_nothing_underneath_it_still_explains_itself() {
        // No source to walk to: the crate's own message is all there is, and it
        // is still a reason rather than an empty line.
        assert_eq!(
            error_detail(&openssh::Error::Disconnected),
            "the connection was terminated"
        );
    }

    #[test]
    fn an_overlong_reason_is_capped() {
        let detail = error_detail(&connect_error(&"x".repeat(500)));
        assert_eq!(detail.chars().count(), 120);
    }

    /// Exercises the real transport: the session builder, the `ssh` binary and
    /// the reason a failure carries. Run it with `cargo test -- --ignored` when
    /// the transport changes.
    #[tokio::test]
    #[ignore = "needs the ssh binary and a host that refuses port 22"]
    async fn an_unreachable_host_yields_a_reason_from_the_real_transport() {
        let echo_url: EchoUrl = "https://example.invalid".parse().unwrap();
        let facts = gather("127.0.0.1", None, &echo_url).await;
        let reason = facts
            .unreachable_reason
            .expect("a host with no sshd is unreachable");
        assert!(reason.starts_with("ssh unreachable: "), "{reason}");
        assert!(reason.len() > "ssh unreachable: ".len(), "{reason}");
        // Nothing was asked of the host, so nothing was collected.
        assert_eq!(facts.docker_ps, "");
    }

    #[test]
    fn every_outcome_yields_text_for_the_parsers() {
        assert_eq!(ran(Some(0), "listening\n").text(), "listening\n");
        assert_eq!(CommandOutcome::TimedOut.text(), "ssh timeout");
        assert_eq!(
            CommandOutcome::Failed("boom".into()).text(),
            "ssh error: boom"
        );
    }
}

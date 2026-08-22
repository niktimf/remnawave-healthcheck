use std::process::Stdio;
use std::time::Duration;

/// Raw command output collected from one host. Parsing happens elsewhere so it can be tested
/// against recorded samples without touching the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    pub reachable: bool,
    /// Why SSH failed; empty when the host answered.
    pub unreachable_reason: String,
    pub docker_ps: String,
    pub listening: String,
    pub node_logs: String,
    pub cert: String,
    pub renewal: String,
    pub egress_ip: String,
}

/// Renewal state of acme.sh plus whether port 80 is open for http-01.
/// The glob is expanded inside `sudo sh -c`; a non-root shell cannot look into /root.
/// `-H` forces the `filename:` prefix even when the glob expands to exactly one file (the common
/// case for a single acme.sh `--ecc` cert) — without it `parse_renewal` can't recover the domain.
const RENEWAL_CMD: &str = "sudo sh -c 'grep -HE \"Le_NextRenewTimeStr|Le_Webroot\" /root/.acme.sh/*/*.conf \
2>/dev/null || echo NO_ACME_CONF; ufw status 2>/dev/null | grep -qE \"^80/tcp\" && echo PORT80=open || echo PORT80=closed'";

/// What became of one remote command. The text is always there — it is either the command's
/// combined output or the reason there is none — while the exit status only exists for a command
/// that actually ran, which is why it lives inside a single variant instead of being faked with a
/// sentinel number.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandOutcome {
    /// The command ran on the host and returned this status and combined output. `status` is
    /// `None` when the remote `ssh` process was killed by a signal and reported no code.
    Ran { status: Option<i32>, text: String },
    /// The command did not finish within the timeout.
    TimedOut,
    /// `ssh` itself could not be started.
    Failed(String),
    /// We refused to build this command line at all.
    Refused(String),
}

impl CommandOutcome {
    /// The output to parse, or the reason there is none. Every check but the reachability ping
    /// only wants this.
    fn text(&self) -> String {
        match self {
            CommandOutcome::Ran { text, .. } => text.clone(),
            CommandOutcome::TimedOut => "ssh timeout".to_string(),
            CommandOutcome::Failed(e) => format!("ssh error: {e}"),
            CommandOutcome::Refused(reason) => reason.clone(),
        }
    }
}

async fn run(target: &str, command: &str) -> CommandOutcome {
    let child = tokio::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            target,
            command,
        ])
        .stdin(Stdio::null())
        // If the timeout below fires, the future carrying this child is dropped; without
        // kill_on_drop the `ssh` process would be orphaned instead of reaped, and on a run
        // scheduled every few hours against a hung node those orphans accumulate.
        .kill_on_drop(true)
        .output();

    match tokio::time::timeout(Duration::from_secs(30), child).await {
        Err(_) => CommandOutcome::TimedOut,
        Ok(Err(e)) => CommandOutcome::Failed(e.to_string()),
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
/// An unreachable host short-circuits: no point issuing five more commands that will all fail.
///
/// `echo_url` is the same endpoint the channel probes use (`--echo-url`), passed in rather than
/// fixed here so that both sides of the exit comparison always ask the same service: two
/// different endpoints could disagree about the address of a multi-homed host and turn a healthy
/// channel red.
pub async fn gather(target: &str, domain: Option<&str>, echo_url: &str) -> HostFacts {
    let ping = run(target, "true").await;
    if let Some(detail) = unreachable_detail(&ping) {
        return HostFacts {
            reachable: false,
            unreachable_reason: format!("ssh unreachable: {detail}"),
            ..HostFacts::default()
        };
    }

    // Single-quoted for the remote shell; a URL carrying a quote of its own is refused rather
    // than pasted into a command line.
    let egress_cmd =
        (!echo_url.contains('\'')).then(|| format!("curl -fsS --max-time 8 '{echo_url}'"));
    let cert_cmd = domain.map(|d| {
        format!("echo | openssl s_client -connect {d}:443 -servername {d} 2>/dev/null | openssl x509 -noout -enddate")
    });

    let (docker_ps, listening, node_logs, renewal, egress_ip) = tokio::join!(
        run(target, "sudo docker ps --format '{{.Names}}\\t{{.Status}}' 2>/dev/null || docker ps --format '{{.Names}}\\t{{.Status}}'"),
        run(target, "sudo ss -ltn 2>/dev/null || ss -ltn"),
        run(target, "sudo docker logs --tail 200 remnanode 2>&1 || docker logs --tail 200 remnanode"),
        run(target, RENEWAL_CMD),
        async {
            match &egress_cmd {
                Some(cmd) => run(target, cmd).await,
                None => CommandOutcome::Refused(format!(
                    "refusing to run an echo URL containing a quote: {echo_url}"
                )),
            }
        },
    );
    let cert = match cert_cmd {
        Some(cmd) => run(target, &cmd).await.text(),
        None => String::new(),
    };

    HostFacts {
        reachable: true,
        unreachable_reason: String::new(),
        docker_ps: docker_ps.text(),
        listening: listening.text(),
        node_logs: node_logs.text(),
        cert,
        renewal: renewal.text(),
        egress_ip: egress_ip.text(),
    }
}

/// Why the reachability ping says the host is not reachable, or `None` when it is.
///
/// This is the one place in the tool that looks at an exit status: `true` returning anything but
/// 0 means the remote end never ran it. The detail is capped so a host that answers with a wall
/// of text cannot push the real reason out of the alert.
fn unreachable_detail(ping: &CommandOutcome) -> Option<String> {
    match ping {
        CommandOutcome::Ran {
            status: Some(0), ..
        } => None,
        CommandOutcome::Ran { status, text } => Some(match last_non_empty_line(text) {
            // Nothing was said about why, so the status is all there is to report. `-1` stands
            // for "killed by a signal, no code" and is what this line has always printed.
            "" => format!("rc={}", status.unwrap_or(-1)),
            reason => reason.chars().take(120).collect(),
        }),
        // Nothing ran, so there is no status: the outcome's own text is the whole reason.
        other => {
            let text = other.text();
            Some(last_non_empty_line(&text).chars().take(120).collect())
        }
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

    fn ran(status: Option<i32>, text: &str) -> CommandOutcome {
        CommandOutcome::Ran {
            status,
            text: text.to_string(),
        }
    }

    #[test]
    fn a_ping_that_returned_zero_means_the_host_is_reachable() {
        assert_eq!(unreachable_detail(&ran(Some(0), "")), None);
        assert_eq!(unreachable_detail(&ran(Some(0), "some banner\n")), None);
    }

    #[test]
    fn a_failing_ping_reports_the_last_line_ssh_printed() {
        let detail = unreachable_detail(&ran(
            Some(255),
            "warming up\nssh: connect to host beta.example.com port 22: Connection refused\n",
        ))
        .expect("a non-zero ping is unreachable");
        assert_eq!(
            detail,
            "ssh: connect to host beta.example.com port 22: Connection refused"
        );
    }

    #[test]
    fn a_silent_failure_falls_back_to_the_status() {
        assert_eq!(
            unreachable_detail(&ran(Some(255), "")).as_deref(),
            Some("rc=255")
        );
        // Killed by a signal: no exit code at all.
        assert_eq!(unreachable_detail(&ran(None, "")).as_deref(), Some("rc=-1"));
    }

    #[test]
    fn a_timeout_and_a_spawn_failure_explain_themselves() {
        assert_eq!(
            unreachable_detail(&CommandOutcome::TimedOut).as_deref(),
            Some("ssh timeout")
        );
        assert_eq!(
            unreachable_detail(&CommandOutcome::Failed("No such file or directory".into()))
                .as_deref(),
            Some("ssh error: No such file or directory")
        );
    }

    #[test]
    fn an_overlong_reason_is_capped() {
        let detail = unreachable_detail(&ran(Some(255), &"x".repeat(500))).unwrap();
        assert_eq!(detail.chars().count(), 120);
    }

    #[test]
    fn every_outcome_yields_text_for_the_parsers() {
        assert_eq!(ran(Some(0), "listening\n").text(), "listening\n");
        assert_eq!(CommandOutcome::TimedOut.text(), "ssh timeout");
        assert_eq!(
            CommandOutcome::Failed("boom".into()).text(),
            "ssh error: boom"
        );
        assert_eq!(
            CommandOutcome::Refused("refusing to run an echo URL containing a quote: x".into())
                .text(),
            "refusing to run an echo URL containing a quote: x"
        );
    }
}

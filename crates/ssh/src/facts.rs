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

async fn run(target: &str, command: &str) -> (i32, String) {
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
        Err(_) => (124, "ssh timeout".to_string()),
        Ok(Err(e)) => (125, format!("ssh error: {e}")),
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.code().unwrap_or(-1), text)
        }
    }
}

/// Collect everything the node-side checks need, in one pass.
/// An unreachable host short-circuits: no point issuing five more commands that will all fail.
pub async fn gather(target: &str, domain: Option<&str>) -> HostFacts {
    let (rc, ping) = run(target, "true").await;
    if rc != 0 {
        let reason = ping
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim();
        let detail = if reason.is_empty() {
            format!("rc={rc}")
        } else {
            reason.chars().take(120).collect()
        };
        return HostFacts {
            reachable: false,
            unreachable_reason: format!("ssh unreachable: {detail}"),
            ..HostFacts::default()
        };
    }

    let cert_cmd = domain.map(|d| {
        format!("echo | openssl s_client -connect {d}:443 -servername {d} 2>/dev/null | openssl x509 -noout -enddate")
    });

    let (docker_ps, listening, node_logs, renewal, egress_ip) = tokio::join!(
        run(target, "sudo docker ps --format '{{.Names}}\\t{{.Status}}' 2>/dev/null || docker ps --format '{{.Names}}\\t{{.Status}}'"),
        run(target, "sudo ss -ltn 2>/dev/null || ss -ltn"),
        run(target, "sudo docker logs --tail 200 remnanode 2>&1 || docker logs --tail 200 remnanode"),
        run(target, RENEWAL_CMD),
        run(target, "curl -fsS --max-time 8 https://api.ipify.org"),
    );
    let cert = match cert_cmd {
        Some(cmd) => run(target, &cmd).await.1,
        None => String::new(),
    };

    HostFacts {
        reachable: true,
        unreachable_reason: String::new(),
        docker_ps: docker_ps.1,
        listening: listening.1,
        node_logs: node_logs.1,
        cert,
        renewal: renewal.1,
        egress_ip: egress_ip.1,
    }
}

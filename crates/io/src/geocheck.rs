//! Geocheck: `POST /api/connections/geocheck/{nodeUuid}` queues a job on the
//! node; `GET /api/connections/geocheck/{jobId}` is polled until it completes.
//! The node may take up to a minute to answer.

use crate::panel::{Auth, PanelClient};
use remnawave_healthcheck_core::model::{GeoFacts, GeoOutcome, parse_ip};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub const POLL_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartDto {
    job_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobDto {
    #[serde(default)]
    is_completed: bool,
    #[serde(default)]
    is_failed: bool,
    #[serde(default)]
    result: Option<ResultDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResultDto {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    raw_report: Option<Value>,
}

impl PanelClient {
    pub async fn geocheck(
        &self,
        node_uuid: &str,
        timeout: Duration,
    ) -> GeoOutcome {
        self.geocheck_with(node_uuid, timeout, POLL_INTERVAL).await
    }

    pub(crate) async fn geocheck_with(
        &self,
        node_uuid: &str,
        timeout: Duration,
        poll: Duration,
    ) -> GeoOutcome {
        let start: StartDto = match self
            .post_json(
                &format!("/api/connections/geocheck/{node_uuid}"),
                &json!({}),
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                return GeoOutcome::Failed(format!("could not start: {e:#}"));
            }
        };
        let deadline = Instant::now() + timeout;
        loop {
            let job: JobDto = match self
                .get_json(
                    &format!("/api/connections/geocheck/{}", start.job_id),
                    Auth::Token,
                )
                .await
            {
                Ok(j) => j,
                Err(e) => return GeoOutcome::Failed(format!("polling: {e:#}")),
            };
            if job.is_failed {
                return GeoOutcome::Failed(
                    job.result
                        .and_then(|r| r.message)
                        .unwrap_or_else(|| "job failed".to_string()),
                );
            }
            if job.is_completed {
                let Some(result) = job.result else {
                    return GeoOutcome::Failed(
                        "completed without a result".to_string(),
                    );
                };
                if !result.success {
                    return GeoOutcome::Failed(result.message.unwrap_or_else(
                        || "node reported failure".to_string(),
                    ));
                }
                let report = result.raw_report.unwrap_or(Value::Null);
                tracing::debug!(node_uuid, report = %report, "geocheck report");
                let egress = report
                    .pointer("/identity/ipv4")
                    .and_then(Value::as_str)
                    .and_then(parse_ip);
                return GeoOutcome::Done(GeoFacts { egress, report });
            }
            if Instant::now() >= deadline {
                return GeoOutcome::Failed(format!(
                    "timeout after {}s",
                    timeout.as_secs()
                ));
            }
            tokio::time::sleep(poll).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NODE: &str = "11111111-1111-4111-8111-111111111111";

    fn envelope(v: &Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "response": v }))
    }

    fn client(server: &MockServer) -> PanelClient {
        PanelClient::new(&server.uri(), "tok", Duration::from_secs(5), None)
            .unwrap()
    }

    async fn mount_start(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!("/api/connections/geocheck/{NODE}")))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({"response": {"jobId": "job-1"}})),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_job_is_polled_until_it_completes() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/connections/geocheck/job-1"))
            .respond_with(envelope(
                &json!({"isCompleted": false, "isFailed": false, "result": null}),
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/connections/geocheck/job-1"))
            .respond_with(envelope(&json!({"isCompleted": true, "isFailed": false,
                "result": {"success": true, "nodeUuid": NODE, "image": null, "message": null,
                           "rawReport": {"identity": {"ipv4": "192.0.2.20", "asn": 64500}}}})))
            .mount(&server)
            .await;
        let out = client(&server)
            .geocheck_with(
                NODE,
                Duration::from_secs(5),
                Duration::from_millis(10),
            )
            .await;
        match out {
            GeoOutcome::Done(f) => {
                assert_eq!(f.egress, parse_ip("192.0.2.20"));
                assert_eq!(f.report["identity"]["asn"], 64500);
            }
            GeoOutcome::Failed(e) => panic!("{e}"),
        }
    }

    #[tokio::test]
    async fn a_failed_job_carries_the_nodes_message() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/connections/geocheck/job-1"))
            .respond_with(envelope(&json!({"isCompleted": true, "isFailed": true,
                "result": {"success": false, "message": "node too old", "rawReport": null}})))
            .mount(&server)
            .await;
        let out = client(&server)
            .geocheck_with(
                NODE,
                Duration::from_secs(5),
                Duration::from_millis(10),
            )
            .await;
        assert_eq!(out, GeoOutcome::Failed("node too old".into()));
    }

    #[tokio::test]
    async fn a_job_that_never_completes_times_out() {
        let server = MockServer::start().await;
        mount_start(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/connections/geocheck/job-1"))
            .respond_with(envelope(
                &json!({"isCompleted": false, "isFailed": false, "result": null}),
            ))
            .mount(&server)
            .await;
        let out = client(&server)
            .geocheck_with(
                NODE,
                Duration::from_millis(50),
                Duration::from_millis(10),
            )
            .await;
        assert!(
            matches!(out, GeoOutcome::Failed(ref e) if e.starts_with("timeout")),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_start_is_a_failure_not_a_panic() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/api/connections/geocheck/{NODE}")))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("scope missing"),
            )
            .mount(&server)
            .await;
        let out = client(&server)
            .geocheck_with(
                NODE,
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await;
        assert!(
            matches!(out, GeoOutcome::Failed(ref e) if e.contains("403")),
            "{out:?}"
        );
    }
}

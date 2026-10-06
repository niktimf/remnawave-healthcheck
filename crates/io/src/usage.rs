//! The panel's per-day history: traffic by node from
//! `GET /api/bandwidth-stats/nodes`, users by node from
//! `POST /api/bandwidth-stats/nodes/usage`, one request per day. The panel
//! buckets both by UTC day.

use crate::panel::{Auth, PanelClient, to_u64};
use anyhow::{Context, Result};
use chrono::{Days, NaiveDate};
use remnawave_healthcheck_core::checks::usage::{Day, UsageHistory};
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::task::JoinSet;

/// Days asked for: yesterday, the seven before it, and today, which the
/// panel is still counting.
const WINDOW_DAYS: u64 = 9;

#[derive(Deserialize)]
struct TrafficDto {
    categories: Vec<String>,
    /// Every node with traffic in the window. `topNodes` is cut to
    /// `topNodesLimit`; this is not.
    #[serde(default)]
    series: Vec<SeriesDto>,
}

#[derive(Deserialize)]
struct SeriesDto {
    uuid: String,
    /// Bytes per date of `categories`, in the same order.
    #[serde(default)]
    data: Vec<f64>,
}

#[derive(Deserialize)]
struct UsersDto {
    #[serde(default)]
    nodes: Vec<NodeUsersDto>,
}

#[derive(Deserialize)]
struct NodeUsersDto {
    uuid: String,
    /// Only how many there are is read.
    #[serde(default)]
    users: Vec<IgnoredAny>,
}

/// Users over the threshold per node, for one day.
type UsersOnDay = (NaiveDate, Vec<(String, u64)>);

impl PanelClient {
    /// Traffic and users of `nodes` (by uuid) per day, over the nine days
    /// ending `today`. A user counts on a day once they used `user_min_bytes`
    /// on that node. Any request that fails fails the whole history: a
    /// partial one would read as a drop.
    pub async fn usage_history(
        self: &Arc<Self>,
        nodes: &[String],
        today: NaiveDate,
        user_min_bytes: u64,
    ) -> Result<UsageHistory> {
        if nodes.is_empty() {
            return Ok(UsageHistory::default());
        }
        let start = today
            .checked_sub_days(Days::new(WINDOW_DAYS - 1))
            .context("the window starts before the calendar does")?;
        let traffic: TrafficDto = self
            .get_json(
                &format!(
                    "/api/bandwidth-stats/nodes?start={start}&end={today}&topNodesLimit={}",
                    nodes.len()
                ),
                Auth::Token,
            )
            .await?;
        let dates = traffic
            .categories
            .iter()
            .map(|date| {
                date.parse::<NaiveDate>()
                    .with_context(|| format!("the panel's date '{date}'"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut days: HashMap<String, BTreeMap<NaiveDate, Day>> =
            HashMap::new();
        for series in traffic.series {
            let node = days.entry(series.uuid).or_default();
            for (date, bytes) in dates.iter().zip(series.data) {
                node.entry(*date).or_default().bytes = to_u64(bytes);
            }
        }
        for (date, users) in
            self.users_by_day(nodes, &dates, user_min_bytes).await?
        {
            for (uuid, count) in users {
                days.entry(uuid).or_default().entry(date).or_default().users =
                    count;
            }
        }
        Ok(UsageHistory { dates, days })
    }

    /// One request per day, all at once.
    async fn users_by_day(
        self: &Arc<Self>,
        nodes: &[String],
        dates: &[NaiveDate],
        min_bytes: u64,
    ) -> Result<Vec<UsersOnDay>> {
        let body = json!({ "nodesUuids": nodes });
        let mut set = JoinSet::new();
        for date in dates.iter().copied() {
            let (panel, body) = (Arc::clone(self), body.clone());
            set.spawn(async move {
                let path = format!(
                    "/api/bandwidth-stats/nodes/usage?start={date}&end={date}&minTotalBytes={min_bytes}"
                );
                let users: UsersDto = panel.post_read(&path, &body).await?;
                let counts = users
                    .nodes
                    .into_iter()
                    .map(|n| (n.uuid, n.users.len() as u64))
                    .collect();
                Ok::<_, anyhow::Error>((date, counts))
            });
        }
        let mut out = Vec::with_capacity(dates.len());
        while let Some(joined) = set.join_next().await {
            // Nothing here aborts a task, so a join error is a panic, and a
            // panic must not turn into a quiet "not read".
            let day = joined
                .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()));
            out.push(day?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{client, envelope};
    use pretty_assertions::assert_eq;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NODE_A: &str = "11111111-1111-4111-8111-111111111111";
    const NODE_B: &str = "22222222-2222-4222-8222-222222222222";

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 6).unwrap()
    }

    fn date(text: &str) -> NaiveDate {
        text.parse().unwrap()
    }

    fn nodes() -> Vec<String> {
        vec![NODE_A.to_string(), NODE_B.to_string()]
    }

    const CATEGORIES: [&str; 9] = [
        "2026-09-28",
        "2026-09-29",
        "2026-09-30",
        "2026-10-01",
        "2026-10-02",
        "2026-10-03",
        "2026-10-04",
        "2026-10-05",
        "2026-10-06",
    ];

    /// `topNodes` names only node A, as with `topNodesLimit` below the
    /// node count; `series` carries both.
    async fn mount_traffic(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/bandwidth-stats/nodes"))
            .and(query_param("start", "2026-09-28"))
            .and(query_param("end", "2026-10-06"))
            .and(query_param("topNodesLimit", "2"))
            .respond_with(envelope(&json!({
                "categories": CATEGORIES,
                "sparklineData": [0, 0, 0, 0, 0, 0, 0, 0, 0],
                "topNodes": [{"uuid": NODE_A, "color": "#000", "name": "node-a",
                              "countryCode": "XX", "total": 9000}],
                "series": [
                    {"uuid": NODE_A, "name": "node-a", "color": "#000", "countryCode": "XX",
                     "total": 9000, "data": [1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000]},
                    {"uuid": NODE_B, "name": "exit-a", "color": "#000", "countryCode": "XX",
                     "total": 90, "data": [10, 10, 10, 10, 10, 10, 10, 10, 10]}
                ]
            })))
            .mount(server)
            .await;
    }

    async fn mount_users(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/api/bandwidth-stats/nodes/usage"))
            .and(query_param("minTotalBytes", "10485760"))
            .and(body_json(json!({"nodesUuids": [NODE_A, NODE_B]})))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn two_users_on_a() -> ResponseTemplate {
        envelope(&json!({"nodes": [
            {"uuid": NODE_A, "users": [{"id": 1, "totalBytes": 20_000_000},
                                       {"id": 2, "totalBytes": 30_000_000}]}
        ]}))
    }

    #[tokio::test]
    async fn traffic_and_users_are_joined_by_node_and_day() {
        let server = MockServer::start().await;
        mount_traffic(&server).await;
        mount_users(&server, two_users_on_a()).await;
        let sut = Arc::new(client(&server));

        let history = sut
            .usage_history(&nodes(), today(), 10_485_760)
            .await
            .unwrap();

        assert_eq!(history.dates.len(), 9);
        assert_eq!(
            history.days[NODE_A][&date("2026-10-05")],
            Day {
                bytes: 1000,
                users: 2
            }
        );
        assert_eq!(
            history.days[NODE_B][&date("2026-10-05")],
            Day {
                bytes: 10,
                users: 0
            }
        );
    }

    /// A token without the `nodes-usage` scope: the panel refuses, and that
    /// is final.
    #[tokio::test]
    async fn a_refused_scope_is_an_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/bandwidth-stats/nodes"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("Forbidden"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let sut = Arc::new(client(&server));

        let err = sut
            .usage_history(&nodes(), today(), 10_485_760)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("403"), "{err:#}");
    }

    /// The users query is a POST that only reads, so a 5xx is asked again
    /// like any read of the panel.
    #[tokio::test]
    async fn a_5xx_from_the_users_query_is_retried() {
        let server = MockServer::start().await;
        mount_traffic(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/bandwidth-stats/nodes/usage"))
            .respond_with(ResponseTemplate::new(502))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        mount_users(&server, two_users_on_a()).await;
        let sut = Arc::new(client(&server));

        let history = sut
            .usage_history(&nodes(), today(), 10_485_760)
            .await
            .unwrap();

        assert_eq!(
            history.days[NODE_A][&date("2026-10-05")],
            Day {
                bytes: 1000,
                users: 2
            }
        );
    }

    #[tokio::test]
    async fn a_date_that_is_not_a_date_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/bandwidth-stats/nodes"))
            .respond_with(envelope(
                &json!({"categories": ["yesterday"], "series": []}),
            ))
            .mount(&server)
            .await;
        let sut = Arc::new(client(&server));

        let err = sut
            .usage_history(&nodes(), today(), 10_485_760)
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("'yesterday'"), "{err:#}");
    }

    /// `topNodes` is cut below the node count; `series` still holds every
    /// node, so traffic is read from it.
    #[tokio::test]
    async fn traffic_is_read_from_series_when_top_nodes_is_shorter() {
        let server = MockServer::start().await;
        mount_traffic(&server).await;
        mount_users(&server, two_users_on_a()).await;
        let sut = Arc::new(client(&server));

        let history = sut
            .usage_history(&nodes(), today(), 10_485_760)
            .await
            .unwrap();

        assert_eq!(history.days.len(), 2);
        assert_eq!(history.days[NODE_B].len(), 9);
        assert_eq!(history.days[NODE_B][&date("2026-09-28")].bytes, 10);
    }
}

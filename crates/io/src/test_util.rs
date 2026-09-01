//! Helpers shared by this crate's unit tests.
//!
//! Everything here exists because more than one test module needs it: the
//! response envelope the panel wraps every payload in, and the client pointed
//! at a mock server.

use crate::panel::{Hwid, PanelClient};
use serde_json::{Value, json};
use std::time::Duration;
use wiremock::{MockServer, ResponseTemplate};

/// The panel answers `{ "response": … }` and never a bare payload.
pub(crate) fn envelope(v: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({ "response": v }))
}

/// A client pointed at the mock server, with a timeout short enough that a
/// test which stops being answered fails instead of hanging.
pub(crate) fn client(server: &MockServer) -> PanelClient {
    client_with(server, None)
}

pub(crate) fn client_with(
    server: &MockServer,
    hwid: Option<Hwid>,
) -> PanelClient {
    PanelClient::new(&server.uri(), "tok", Duration::from_secs(5), hwid)
        .unwrap()
}

/// A device registered for the monitoring user, so the subscription answers
/// with configs rather than the placeholder.
pub(crate) fn hwid() -> Hwid {
    Hwid {
        hwid: "dev-1".into(),
        os: "linux".into(),
        os_version: "1".into(),
        model: "hc".into(),
    }
}

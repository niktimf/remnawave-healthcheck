//! Whether the AI services and YouTube Premium answer through an exit, asked
//! the way a client's traffic reaches them: through a tunnel of the
//! subscription, so the exit profile's routing rules (direct, WARP, a cascade
//! to another exit) apply exactly as they do for users.
//!
//! The requests are described here as data and judged here from what came
//! back; `io` only carries them through the tunnel.
//!
//! A service counts as blocked only on a positive refusal marker. A page this
//! module does not recognise is "unrecognized", so a service changing its
//! markup raises a warning rather than a failure.

use super::channel::{Precheck, precheck};
use super::commas;
use super::youtube::{Country, CountryCode};
use crate::model::{Channel, CheckResult, Node, Snapshot, node_check};
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;

/// One service, probed with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Gemini,
    NotebookLm,
    YoutubePremium,
    ChatGpt,
    OpenAiApi,
    Claude,
    AnthropicApi,
    Copilot,
    Grok,
    XaiApi,
}

/// What one request looks like: where it goes and what it identifies as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub url: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
}

/// What a service answered. Redirects are not followed: Claude and
/// NotebookLM put their verdict in `Location`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
}

/// How a service treats the address the tunnel came out at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Available,
    /// A refusal marker was found. `region` is the region the service said it
    /// served, when it says one (Gemini does).
    Blocked {
        region: Option<String>,
    },
    /// An answer that carries neither marker.
    Unrecognized(Unread),
    /// No answer at all.
    NoAnswer(Silence),
}

/// Why an answer could not be read as available or blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// A Cloudflare challenge page: it says nothing about the region, and
    /// whether it is shown depends on the client's TLS fingerprint.
    Challenge,
    /// A status that is neither the refusal nor the pass this service gives.
    Status(u16),
    /// A page without the wording looked for.
    NoMarker,
    /// A page without the region the service embeds in it (Gemini, the
    /// YouTube home page).
    NoRegion,
    /// A service that answers with a redirect did not.
    NoRedirect,
    /// A redirect to neither the refusal nor the sign-in.
    UnexpectedRedirect,
}

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Challenge => f.write_str("challenge"),
            Self::Status(code) => write!(f, "HTTP {code}"),
            Self::NoMarker => f.write_str("no marker"),
            Self::NoRegion => f.write_str("no region in the page"),
            Self::NoRedirect => f.write_str("no redirect"),
            Self::UnexpectedRedirect => f.write_str("unexpected redirect"),
        }
    }
}

/// How a request got no answer. `io` tells these apart from the transport
/// error; the full error goes to its debug log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    Timeout,
    /// The connection through the tunnel could not be made.
    Connection,
    /// The answer broke off before its body was read.
    CutShort,
    /// Any other transport failure.
    Failed,
}

impl std::fmt::Display for Silence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Timeout => "timeout",
            Self::Connection => "connection failed",
            Self::CutShort => "answer cut short",
            Self::Failed => "request failed",
        })
    }
}

pub(super) const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
pub(super) const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const CURL_UA: &str = "curl/8.5.0";

pub(super) const BROWSER: &[(&str, &str)] = &[
    ("user-agent", CHROME_UA),
    ("accept-language", ACCEPT_LANGUAGE),
];
const BROWSER_HTML: &[(&str, &str)] = &[
    ("user-agent", CHROME_UA),
    ("accept-language", ACCEPT_LANGUAGE),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
];
const API: &[(&str, &str)] = &[("user-agent", CURL_UA)];
const ANTHROPIC_API: &[(&str, &str)] =
    &[("user-agent", CURL_UA), ("anthropic-version", "2023-06-01")];

/// Regions Google does not offer Gemini in, as geocheck v0.3.0 lists them
/// (`geminiUnsupported` in `internal/access/checks.go`).
const GEMINI_UNSUPPORTED: [&str; 7] =
    ["RUS", "BLR", "CHN", "PRK", "IRN", "CUB", "SYR"];

// Refusals as each service words them in a 403, lower case. The bodies were
// read by hand from a Russian address on 2026-10-02.
const OPENAI_REFUSAL: &str = "unsupported_country_region_territory";
const ANTHROPIC_REFUSAL: &str = "request not allowed";
/// Cloudflare's own "country blocked by the site owner" page.
const COPILOT_REFUSAL: &str = "error code: 1009";
/// grok.com and api.x.ai word it the same way.
const XAI_REFUSAL: &str = "this service is not available in your region";
const YOUTUBE_REFUSAL: &str =
    "youtube premium is not available in your country";
const YOUTUBE_OFFER: &str = "ad-free";
const CHATGPT_REFUSAL: &str = "unsupported_country";
const CLAUDE_REFUSAL: &str = "app-unavailable-in-region";

impl Service {
    /// Every service, in the order they are asked and reported.
    pub const ALL: [Self; 10] = [
        Self::Gemini,
        Self::NotebookLm,
        Self::YoutubePremium,
        Self::ChatGpt,
        Self::OpenAiApi,
        Self::Claude,
        Self::AnthropicApi,
        Self::Copilot,
        Self::Grok,
        Self::XaiApi,
    ];

    /// The name the report uses.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Gemini => "gemini",
            Self::NotebookLm => "notebooklm",
            Self::YoutubePremium => "youtube premium",
            Self::ChatGpt => "chatgpt",
            Self::OpenAiApi => "openai api",
            Self::Claude => "claude",
            Self::AnthropicApi => "anthropic api",
            Self::Copilot => "copilot",
            Self::Grok => "grok",
            Self::XaiApi => "xai api",
        }
    }

    pub const fn request(self) -> Request {
        let (url, headers) = match self {
            Self::Gemini => ("https://gemini.google.com/app", BROWSER_HTML),
            // notebooklm.google.com answered with a 301 to this host on
            // 2026-10-02; the verdict is in the redirect that follows.
            Self::NotebookLm => ("https://notebook.google.com/", BROWSER),
            Self::YoutubePremium => {
                ("https://www.youtube.com/premium", BROWSER)
            }
            Self::ChatGpt => (
                "https://api.openai.com/compliance/cookie_requirements",
                BROWSER,
            ),
            Self::OpenAiApi => ("https://api.openai.com/v1/models", API),
            Self::Claude => ("https://claude.ai/", BROWSER),
            Self::AnthropicApi => {
                ("https://api.anthropic.com/v1/models", ANTHROPIC_API)
            }
            Self::Copilot => ("https://copilot.microsoft.com/", BROWSER),
            Self::Grok => ("https://grok.com/", BROWSER),
            Self::XaiApi => ("https://api.x.ai/v1/models", API),
        };
        Request { url, headers }
    }

    /// What the answer says about access. The markers and statuses are the
    /// ones checked by hand from a Russian and a Finnish address on
    /// 2026-10-02; anything else is `Unrecognized`.
    pub fn classify(self, response: &Response) -> Access {
        let body = response.body.to_lowercase();
        let answer = Answer {
            status: response.status,
            location: response.location.as_deref().unwrap_or_default(),
            body: &body,
        };
        match self {
            Self::Gemini => gemini(&response.body, answer),
            Self::NotebookLm => notebooklm(answer, self.request().url),
            Self::YoutubePremium => youtube_premium(answer),
            Self::ChatGpt => chatgpt(answer),
            Self::OpenAiApi => api(answer, OPENAI_REFUSAL),
            Self::Claude => claude(answer, self.request().url),
            Self::AnthropicApi => api(answer, ANTHROPIC_REFUSAL),
            Self::Copilot => web(answer, COPILOT_REFUSAL),
            Self::Grok => web(answer, XAI_REFUSAL),
            Self::XaiApi => api(answer, XAI_REFUSAL),
        }
    }
}

/// A response with the body lowercased once, for the case-insensitive marker
/// searches every classifier does.
#[derive(Clone, Copy)]
struct Answer<'a> {
    status: u16,
    location: &'a str,
    body: &'a str,
}

impl Answer<'_> {
    /// A 403 carrying the service's own refusal wording.
    fn refuses(self, refusal: &str) -> bool {
        self.status == 403 && self.body.contains(refusal)
    }

    /// The page itself, served: 200 and no challenge in place of it.
    fn serves_page(self) -> bool {
        self.status == 200 && !self.challenged()
    }

    fn challenged(self) -> bool {
        is_challenge(self.body)
    }

    /// Why the answer could not be read: a challenge first, then a status
    /// that is not a success, then `fallback`, which names what the page
    /// lacked.
    fn unrecognized(self, fallback: Unread) -> Access {
        let why = if self.challenged() {
            Unread::Challenge
        } else if !(200..300).contains(&self.status) {
            Unread::Status(self.status)
        } else {
            fallback
        };
        Access::Unrecognized(why)
    }
}

/// Whether a lowercased body is a Cloudflare challenge rather than the page
/// asked for.
pub(super) fn is_challenge(body: &str) -> bool {
    ["just a moment", "cf_chl", "cf-browser-verification"]
        .iter()
        .any(|marker| body.contains(marker))
}

/// A browser-facing page that refuses with a 403 carrying `refusal` and
/// serves the page to a region it covers.
fn web(answer: Answer<'_>, refusal: &str) -> Access {
    if answer.refuses(refusal) {
        Access::Blocked { region: None }
    } else if answer.serves_page() {
        Access::Available
    } else {
        answer.unrecognized(Unread::NoMarker)
    }
}

/// An API that refuses with a 403 carrying `refusal` and answers an
/// anonymous caller from a region it covers with 401.
fn api(answer: Answer<'_>, refusal: &str) -> Access {
    if answer.refuses(refusal) {
        Access::Blocked { region: None }
    } else if answer.status == 401 {
        Access::Available
    } else {
        answer.unrecognized(Unread::NoMarker)
    }
}

/// The region Google embeds in the page, read against the regions it does
/// not serve Gemini in. `raw` is the body as served: the region code is
/// upper case.
fn gemini(raw: &str, answer: Answer<'_>) -> Access {
    match gemini_region(raw) {
        Some(region) if GEMINI_UNSUPPORTED.contains(&region) => {
            Access::Blocked {
                region: Some(region.to_string()),
            }
        }
        Some(_) => Access::Available,
        None => answer.unrecognized(Unread::NoRegion),
    }
}

/// The first `,<digits>,<digits>,200,"<AAA>"` in the body, which is
/// geocheck's `,\d+,\d+,200,"([A-Z]{3})"`: the region Google's account bar
/// says it served.
fn gemini_region(body: &str) -> Option<&str> {
    const MARK: &str = ",200,\"";
    body.match_indices(MARK).find_map(|(at, _)| {
        let after = at + MARK.len();
        let region = body.get(after..after + 3)?;
        let closed = body[after + 3..].starts_with('"');
        let upper = region.bytes().all(|b| b.is_ascii_uppercase());
        (closed && upper && two_numbers_before(&body[..at])).then_some(region)
    })
}

/// Whether `text` ends in `,<digits>,<digits>`.
fn two_numbers_before(text: &str) -> bool {
    strip_number(text).and_then(strip_number).is_some()
}

/// `text` without a trailing `,<digits>`, when it ends in one.
fn strip_number(text: &str) -> Option<&str> {
    let rest = text.trim_end_matches(|c: char| c.is_ascii_digit());
    if rest.len() == text.len() {
        return None;
    }
    rest.strip_suffix(',')
}

/// NotebookLM answers with a redirect either way: to itself with
/// `location=unsupported`, or to Google's sign-in.
fn notebooklm(answer: Answer<'_>, asked: &str) -> Access {
    let Some(target) = redirect(answer, asked) else {
        return answer.unrecognized(Unread::NoRedirect);
    };
    if target
        .query_pairs()
        .any(|(key, value)| key == "location" && value == "unsupported")
    {
        return Access::Blocked { region: None };
    }
    let host = target.host_str().unwrap_or_default();
    let sign_in = host == "accounts.google.com"
        || (host.ends_with(".google.com") && target.path().contains("/login"));
    if sign_in {
        Access::Available
    } else {
        Access::Unrecognized(Unread::UnexpectedRedirect)
    }
}

/// The refusal is looked for first: on a refused address the page carries
/// the offer's "ad-free" wording as well.
fn youtube_premium(answer: Answer<'_>) -> Access {
    if answer.body.contains(YOUTUBE_REFUSAL) {
        Access::Blocked { region: None }
    } else if answer.body.contains(YOUTUBE_OFFER) {
        Access::Available
    } else {
        answer.unrecognized(Unread::NoMarker)
    }
}

/// The cookie-requirements endpoint names the refusal in its body whatever
/// the status; a covered region gets 200 and the consent settings.
fn chatgpt(answer: Answer<'_>) -> Access {
    if answer.body.contains(CHATGPT_REFUSAL) {
        Access::Blocked { region: None }
    } else if answer.serves_page() {
        Access::Available
    } else {
        answer.unrecognized(Unread::NoMarker)
    }
}

/// claude.ai sends a closed region to `/app-unavailable-in-region`, by
/// redirect or, rendered, in the page. An open region gets the app (200) or
/// a redirect to its sign-in; reqwest got the latter from a Finnish address
/// on 2026-10-02.
fn claude(answer: Answer<'_>, asked: &str) -> Access {
    if answer.location.contains(CLAUDE_REFUSAL)
        || answer.body.contains(CLAUDE_REFUSAL)
    {
        return Access::Blocked { region: None };
    }
    let sign_in = redirect(answer, asked).is_some_and(|target| {
        let host = target.host_str().unwrap_or_default();
        ["claude.ai", "claude.com"].contains(&host)
            && target.path().starts_with("/login")
    });
    if sign_in || answer.serves_page() {
        Access::Available
    } else {
        answer.unrecognized(Unread::NoMarker)
    }
}

/// Where a redirect points, resolved against the URL that was asked.
fn redirect(answer: Answer<'_>, asked: &str) -> Option<Url> {
    if answer.location.is_empty() {
        return None;
    }
    Url::parse(asked).ok()?.join(answer.location).ok()
}

// ---------------------------------------------------------------------------
// Which tunnel each exit is asked through.
// ---------------------------------------------------------------------------

/// Why an exit is not asked through a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// The exit leaves in Russia, where these services are closed anyway.
    InRussia,
    /// The exit's egress address is unknown, so no tunnel can be shown to
    /// leave through it.
    EgressUnknown,
    /// No tunnel to this exit came out at its egress address.
    NoTunnel,
}

/// What the services stage does about one exit.
#[derive(Debug, Clone, Copy)]
pub enum ExitPlan<'a> {
    /// Ask through this channel's outbound.
    Probe {
        exit: &'a Node,
        channel: &'a Channel,
    },
    Skip {
        exit: &'a Node,
        why: Skip,
    },
}

impl<'a> ExitPlan<'a> {
    pub const fn exit(&self) -> &'a Node {
        match self {
            Self::Probe { exit, .. } | Self::Skip { exit, .. } => exit,
        }
    }
}

/// One plan per exit, in the order the subscription first leads to each.
///
/// The exit is asked through the first channel, in subscription order, whose
/// tunnel came out at the exit's egress address. One channel is enough: a
/// client's traffic to these services is routed by the exit's profile, and
/// the bridges in front of it send onward everything but Russian
/// destinations. `tunnels` maps a channel's index to the address its tunnel
/// came out at; `egress` maps a node name to the address geocheck saw it
/// leave from.
// Both maps are built by the caller with the default hasher; a generic one
// would add two type parameters and buy nothing.
#[allow(clippy::implicit_hasher)]
pub fn plan<'a>(
    snapshot: &'a Snapshot,
    tunnels: &HashMap<usize, IpAddr>,
    egress: &HashMap<&str, IpAddr>,
) -> Vec<ExitPlan<'a>> {
    let mut exits: Vec<&Node> = Vec::new();
    let mut through: HashMap<&str, &Channel> = HashMap::new();
    for (idx, channel) in snapshot.channels.iter().enumerate() {
        let Precheck::Probe(exit) = precheck(channel, snapshot) else {
            continue;
        };
        if !exits.iter().any(|e| e.name == exit.name) {
            exits.push(exit);
        }
        let came_out = tunnels.get(&idx);
        if came_out.is_some() && came_out == egress.get(exit.name.as_str()) {
            through.entry(exit.name.as_str()).or_insert(channel);
        }
    }
    exits
        .into_iter()
        .map(|exit| {
            let skip = |why| ExitPlan::Skip { exit, why };
            if exit.country_code.eq_ignore_ascii_case("RU") {
                skip(Skip::InRussia)
            } else if let Some(channel) = through.get(exit.name.as_str()) {
                ExitPlan::Probe { exit, channel }
            } else if egress.contains_key(exit.name.as_str()) {
                skip(Skip::NoTunnel)
            } else {
                skip(Skip::EgressUnknown)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The verdict.
// ---------------------------------------------------------------------------

/// Everything one tunnel was asked: each service, then the country the
/// YouTube home page placed the exit in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub services: Vec<(Service, Access)>,
    pub youtube: Country,
}

/// What the services stage ended with for one exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitServices {
    /// Every service was asked through the tunnel of channel `via`.
    Checked {
        via: String,
        answers: Answers,
    },
    /// The tunnel through `via` could not be brought up for the stage.
    TunnelFailed {
        via: String,
        reason: String,
    },
    Skipped(Skip),
    /// Switched off with `--no-services`.
    Disabled,
}

/// The row of one exit: FAIL when any service refused, WARN when any could
/// not be read or did not answer, OK otherwise. `expected` is the country
/// the operator configured for the exit's YouTube, if any.
pub fn verdict(
    exit: &str,
    expected: Option<CountryCode>,
    outcome: &ExitServices,
) -> CheckResult {
    let name = node_check(exit, "services");
    match outcome {
        ExitServices::Checked { via, answers } => {
            let excuse_premium = expected == Some(CountryCode::RU);
            checked(name, via, &answers.services, excuse_premium)
        }
        ExitServices::TunnelFailed { via, reason } => CheckResult::warn(
            name,
            format!(
                "not checked: the tunnel through {via} did not start: {reason}"
            ),
        ),
        ExitServices::Skipped(Skip::InRussia) => CheckResult::ok(
            name,
            "skipped: the exit is in RU, where these services are closed",
        ),
        ExitServices::Skipped(Skip::NoTunnel) => CheckResult::warn(
            name,
            format!("not checked: no channel came out through {exit}"),
        ),
        ExitServices::Skipped(Skip::EgressUnknown) => CheckResult::warn(
            name,
            format!(
                "not checked: the egress address of {exit} is unknown, so no channel is known to come out through it"
            ),
        ),
        ExitServices::Disabled => {
            CheckResult::ok(name, "disabled by --no-services")
        }
    }
}

/// The answers of one exit sorted by how they deviate.
#[derive(Default)]
struct Tally {
    blocked: Vec<String>,
    unrecognized: Vec<String>,
    silent: Vec<String>,
    /// Refusals the operator asked for: YouTube refuses Premium in RU, and
    /// an exit configured to stay in RU for YouTube is meant to be refused.
    not_counted: Vec<String>,
}

impl Tally {
    fn of(answers: &[(Service, Access)], excuse_premium: bool) -> Self {
        let mut tally = Self::default();
        for (service, access) in answers {
            let label = service.label();
            match access {
                Access::Available => {}
                Access::Blocked { .. }
                    if excuse_premium
                        && *service == Service::YoutubePremium =>
                {
                    tally.not_counted.push(format!("{label} (RU expected)"));
                }
                Access::Blocked { region: None } => {
                    tally.blocked.push(label.to_string());
                }
                Access::Blocked {
                    region: Some(region),
                } => tally.blocked.push(format!("{label} ({region})")),
                Access::Unrecognized(why) => {
                    tally.unrecognized.push(format!("{label} ({why})"));
                }
                Access::NoAnswer(why) => {
                    tally.silent.push(format!("{label} ({why})"));
                }
            }
        }
        tally
    }

    /// One `title: items` part per non-empty group; the refusals not
    /// counted come last, as a note.
    fn parts(&self) -> Vec<String> {
        [
            ("blocked", &self.blocked),
            ("unknown", &self.unrecognized),
            ("no answer", &self.silent),
            ("not counted", &self.not_counted),
        ]
        .iter()
        .filter(|(_, items)| !items.is_empty())
        .map(|(title, items)| format!("{title}: {}", commas(items.iter())))
        .collect()
    }

    fn deviates(&self) -> bool {
        !(self.blocked.is_empty()
            && self.unrecognized.is_empty()
            && self.silent.is_empty())
    }
}

/// The detail names only the services that deviate, and a refusal that is
/// not counted.
fn checked(
    name: String,
    via: &str,
    answers: &[(Service, Access)],
    excuse_premium: bool,
) -> CheckResult {
    let tally = Tally::of(answers, excuse_premium);
    let parts = tally.parts();
    if !tally.blocked.is_empty() {
        CheckResult::fail(name, parts.join("; "))
    } else if tally.deviates() {
        CheckResult::warn(name, parts.join("; "))
    } else {
        let total = answers.len();
        let counted = total - tally.not_counted.len();
        let summary = format!("{counted}/{total} available via {via}");
        CheckResult::ok(
            name,
            std::iter::once(summary)
                .chain(parts)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Profile, Served, Severity, parse_ip};
    use rstest::rstest;
    use serde_json::json;

    fn response(status: u16, location: Option<&str>, body: &str) -> Response {
        Response {
            status,
            location: location.map(str::to_string),
            body: body.to_string(),
        }
    }

    fn blocked() -> Access {
        Access::Blocked { region: None }
    }

    const CHALLENGE: &str =
        "<html><head><title>Just a moment...</title></head></html>";

    /// Bodies and statuses as the services answered a Russian (RU) and a
    /// Finnish (FI) address on 2026-10-02, plus a challenge and an empty
    /// answer for each.
    #[rstest]
    #[case::chatgpt_ru(
        Service::ChatGpt,
        response(
            403,
            None,
            r#"{"error":{"code":"unsupported_country_region_territory"}}"#
        ),
        blocked()
    )]
    #[case::chatgpt_fi(
        Service::ChatGpt,
        response(200, None, r#"{"cookie_consent_required": true}"#),
        Access::Available
    )]
    #[case::openai_api_ru(
        Service::OpenAiApi,
        response(
            403,
            None,
            r#"{"error":{"code":"unsupported_country_region_territory"}}"#
        ),
        blocked()
    )]
    #[case::openai_api_fi(
        Service::OpenAiApi,
        response(
            401,
            None,
            r#"{"error":{"message":"You didn't provide an API key."}}"#
        ),
        Access::Available
    )]
    #[case::claude_ru(
        Service::Claude,
        response(
            302,
            Some("https://claude.com/app-unavailable-in-region"),
            ""
        ),
        blocked()
    )]
    #[case::claude_app(
        Service::Claude,
        response(200, None, "<html>Claude</html>"),
        Access::Available
    )]
    #[case::claude_fi(
        Service::Claude,
        response(302, Some("https://claude.ai/login"), ""),
        Access::Available
    )]
    #[case::anthropic_api_ru(
        Service::AnthropicApi,
        response(
            403,
            None,
            r#"{"error":{"type":"forbidden","message":"Request not allowed"}}"#
        ),
        blocked()
    )]
    #[case::anthropic_api_fi(
        Service::AnthropicApi,
        response(401, None, r#"{"error":{"type":"authentication_error"}}"#),
        Access::Available
    )]
    #[case::copilot_ru(
        Service::Copilot,
        response(403, None, "error code: 1009"),
        blocked()
    )]
    #[case::copilot_fi(
        Service::Copilot,
        response(200, None, "<html>Copilot</html>"),
        Access::Available
    )]
    #[case::grok_ru(
        Service::Grok,
        response(403, None, "This service is not available in your region"),
        blocked()
    )]
    #[case::grok_fi(
        Service::Grok,
        response(200, None, "<html>Grok</html>"),
        Access::Available
    )]
    #[case::xai_api_ru(
        Service::XaiApi,
        response(403, None, "This service is not available in your region"),
        blocked()
    )]
    #[case::xai_api_fi(
        Service::XaiApi,
        response(401, None, "unauthenticated:no-credentials"),
        Access::Available
    )]
    #[case::youtube_premium_fi(
        Service::YoutubePremium,
        response(200, None, "Watch ad-free with YouTube Premium"),
        Access::Available
    )]
    #[case::notebooklm_refused(
        Service::NotebookLm,
        response(
            302,
            Some("https://notebooklm.google.com/?location=unsupported"),
            ""
        ),
        blocked()
    )]
    #[case::notebooklm_sign_in(
        Service::NotebookLm,
        response(
            302,
            Some("https://accounts.google.com/v3/signin/identifier"),
            ""
        ),
        Access::Available
    )]
    fn each_service_reads_its_own_answer(
        #[case] sut: Service,
        #[case] answer: Response,
        #[case] expected: Access,
    ) {
        let access = sut.classify(&answer);

        assert_eq!(access, expected);
    }

    /// A Cloudflare challenge says nothing about the region: it is neither
    /// a refusal nor a pass, whichever service answered with it.
    #[rstest]
    fn a_challenge_is_unrecognized_for_every_service(
        #[values(
            Service::Gemini,
            Service::NotebookLm,
            Service::YoutubePremium,
            Service::ChatGpt,
            Service::OpenAiApi,
            Service::Claude,
            Service::AnthropicApi,
            Service::Copilot,
            Service::Grok,
            Service::XaiApi
        )]
        sut: Service,
    ) {
        let answer = response(403, None, CHALLENGE);

        let access = sut.classify(&answer);

        assert_eq!(access, Access::Unrecognized(Unread::Challenge));
    }

    #[rstest]
    fn an_empty_answer_is_never_a_verdict(
        #[values(
            Service::Gemini,
            Service::NotebookLm,
            Service::YoutubePremium,
            Service::ChatGpt,
            Service::OpenAiApi,
            Service::Claude,
            Service::AnthropicApi,
            Service::Copilot,
            Service::Grok,
            Service::XaiApi
        )]
        sut: Service,
    ) {
        let answer = response(500, None, "");

        let access = sut.classify(&answer);

        assert_eq!(access, Access::Unrecognized(Unread::Status(500)));
    }

    /// From a Finnish address Google places in Russia, the refusal page also
    /// carries the offer's wording, so the refusal has to be looked for
    /// first.
    #[test]
    fn a_youtube_page_with_both_wordings_is_a_refusal() {
        let answer = response(
            200,
            None,
            "YouTube Premium is not available in your country. Enjoy ad-free videos",
        );

        let access = Service::YoutubePremium.classify(&answer);

        assert_eq!(access, blocked());
    }

    /// Only claude.ai's own sign-in counts: a redirect elsewhere says
    /// nothing about the region.
    #[test]
    fn a_claude_redirect_off_its_sign_in_is_unrecognized() {
        let answer = response(302, Some("https://example.com/login"), "");

        let access = Service::Claude.classify(&answer);

        assert_eq!(access, Access::Unrecognized(Unread::Status(302)));
    }

    #[rstest]
    #[case::russia(r#"...,7,42,200,"RUS",..."#, "RUS")]
    #[case::iran_from_warp(r#"...,1,3,200,"IRN"]..."#, "IRN")]
    fn gemini_refuses_the_regions_google_does_not_serve(
        #[case] body: &str,
        #[case] region: &str,
    ) {
        let answer = response(200, None, body);

        let access = Service::Gemini.classify(&answer);

        assert_eq!(
            access,
            Access::Blocked {
                region: Some(region.to_string())
            }
        );
    }

    #[test]
    fn gemini_serves_a_region_off_the_list() {
        let answer = response(200, None, r#"...,7,42,200,"NLD",..."#);

        let access = Service::Gemini.classify(&answer);

        assert_eq!(access, Access::Available);
    }

    /// `,200,"ABC"` lacks the two numbers geocheck's pattern starts with, so
    /// the real entry after it is the one read.
    #[test]
    fn a_decoy_without_the_numeric_prefix_is_not_read_as_the_region() {
        let answer = response(200, None, r#",200,"ABC" junk ,7,42,200,"RUS""#);

        let access = Service::Gemini.classify(&answer);

        assert_eq!(
            access,
            Access::Blocked {
                region: Some("RUS".into())
            }
        );
    }

    #[test]
    fn a_gemini_page_with_only_a_decoy_has_no_region() {
        let answer = response(200, None, r#"preamble ,200,"ABC" trailer"#);

        let access = Service::Gemini.classify(&answer);

        assert_eq!(access, Access::Unrecognized(Unread::NoRegion));
    }

    #[rstest]
    #[case::lookalike_host(
        "https://accounts.google.com.attacker.example/signin"
    )]
    #[case::reason_in_the_path("https://attacker.example/location=unsupported")]
    #[case::elsewhere_on_google("https://notebook.google.com/weird")]
    fn notebooklm_trusts_only_the_structured_redirect(#[case] location: &str) {
        let answer = response(302, Some(location), "");

        let access = Service::NotebookLm.classify(&answer);

        assert_eq!(access, Access::Unrecognized(Unread::UnexpectedRedirect));
    }

    // -- plan --------------------------------------------------------------

    fn exit_node(name: &str, country: &str, tag: &str) -> Node {
        Node {
            name: name.into(),
            address: format!("{name}.example.com"),
            country_code: country.into(),
            is_connected: true,
            profile_uuid: Some("p".into()),
            inbound_tags: vec![tag.into()],
            ..Default::default()
        }
    }

    fn channel(remark: &str, tag: &str, address: &str) -> Channel {
        Channel {
            remark: remark.into(),
            inbound_tag: tag.into(),
            profile_uuid: Some("p".into()),
            address: address.into(),
            port: 443,
            served: Served::Direct(json!({"protocol": "vless", "tag": remark})),
            ..Default::default()
        }
    }

    /// Two exits, `de` and `ru`; `de` is reached by two channels.
    fn snapshot() -> Snapshot {
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({
                "inbounds": [
                    {"tag": "in-de", "port": 443},
                    {"tag": "in-ru", "port": 443}
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}]
            }),
        };
        Snapshot {
            nodes: vec![
                exit_node("de", "DE", "in-de"),
                exit_node("ru", "RU", "in-ru"),
            ],
            profiles: HashMap::from([("p".to_string(), profile)]),
            channels: vec![
                channel("de first", "in-de", "de.example.com"),
                channel("de second", "in-de", "de.example.com"),
                channel("ru only", "in-ru", "ru.example.com"),
            ],
            ..Default::default()
        }
    }

    fn ip(text: &str) -> IpAddr {
        parse_ip(text).unwrap()
    }

    fn egress() -> HashMap<&'static str, IpAddr> {
        HashMap::from([("de", ip("192.0.2.1")), ("ru", ip("192.0.2.9"))])
    }

    /// The remark of the channel the exit is asked through, or the skip.
    fn summary(plans: &[ExitPlan<'_>]) -> Vec<(String, Result<String, Skip>)> {
        plans
            .iter()
            .map(|p| match p {
                ExitPlan::Probe { exit, channel } => {
                    (exit.name.clone(), Ok(channel.remark.clone()))
                }
                ExitPlan::Skip { exit, why } => (exit.name.clone(), Err(*why)),
            })
            .collect()
    }

    #[test]
    fn the_first_channel_out_at_the_right_egress_is_the_one_asked_through() {
        let s = snapshot();
        let tunnels = HashMap::from([
            (0, ip("192.0.2.1")),
            (1, ip("192.0.2.1")),
            (2, ip("192.0.2.9")),
        ]);

        let plans = plan(&s, &tunnels, &egress());

        assert_eq!(
            summary(&plans),
            [
                ("de".to_string(), Ok("de first".to_string())),
                ("ru".to_string(), Err(Skip::InRussia)),
            ]
        );
    }

    #[test]
    fn a_dead_channel_and_one_out_elsewhere_are_passed_over() {
        let mut s = snapshot();
        s.channels
            .insert(2, channel("de third", "in-de", "de.example.com"));
        // Channel 0 is dead, so absent; channel 1 came out elsewhere.
        let tunnels =
            HashMap::from([(1, ip("198.51.100.7")), (2, ip("192.0.2.1"))]);

        let plans = plan(&s, &tunnels, &egress());

        assert_eq!(summary(&plans)[0], ("de".into(), Ok("de third".into())));
    }

    #[test]
    fn an_exit_no_tunnel_came_out_of_is_not_checked() {
        let s = snapshot();
        let tunnels = HashMap::from([(0, ip("198.51.100.7"))]);

        let plans = plan(&s, &tunnels, &egress());

        assert_eq!(summary(&plans)[0], ("de".into(), Err(Skip::NoTunnel)));
    }

    #[test]
    fn an_exit_with_no_known_egress_is_named_as_such() {
        let s = snapshot();
        let tunnels = HashMap::from([(0, ip("192.0.2.1"))]);

        let plans = plan(&s, &tunnels, &HashMap::new());

        assert_eq!(summary(&plans)[0], ("de".into(), Err(Skip::EgressUnknown)));
    }

    // -- verdict -----------------------------------------------------------

    fn checked(services: Vec<(Service, Access)>) -> ExitServices {
        ExitServices::Checked {
            via: "de first".into(),
            answers: Answers {
                services,
                youtube: Country::Seen("DE".parse().unwrap()),
            },
        }
    }

    fn all_available() -> Vec<(Service, Access)> {
        Service::ALL.map(|s| (s, Access::Available)).to_vec()
    }

    #[test]
    fn every_service_available_names_the_tunnel_it_was_asked_through() {
        let outcome = checked(all_available());

        let result = verdict("de", None, &outcome);

        assert_eq!(result.name, "node de / services");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "10/10 available via de first");
    }

    #[test]
    fn one_refusal_fails_the_row_and_only_deviations_are_named() {
        let mut answers = all_available();
        answers[0].1 = Access::Blocked {
            region: Some("IRN".into()),
        };
        answers[2].1 = blocked();
        answers[5].1 = Access::Unrecognized(Unread::Challenge);

        let result = verdict("de", None, &checked(answers));

        assert_eq!(result.severity, Severity::Fail);
        assert_eq!(
            result.detail,
            "blocked: gemini (IRN), youtube premium; unknown: claude (challenge)"
        );
    }

    #[test]
    fn a_silent_service_without_a_refusal_only_warns() {
        let mut answers = all_available();
        answers[8].1 = Access::NoAnswer(Silence::Timeout);

        let result = verdict("de", None, &checked(answers));

        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(result.detail, "no answer: grok (timeout)");
    }

    /// YouTube refuses Premium in the country an exit is kept in for no
    /// ads, so with RU expected that refusal is a note, not a failure.
    #[test]
    fn a_premium_refusal_is_not_counted_when_ru_is_expected() {
        let mut answers = all_available();
        answers[2].1 = blocked();

        let result =
            verdict("exit-a", Some(CountryCode::RU), &checked(answers));

        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(
            result.detail,
            "9/10 available via de first; not counted: youtube premium (RU expected)"
        );
    }

    #[test]
    fn a_premium_refusal_still_fails_when_another_country_is_expected() {
        let mut answers = all_available();
        answers[2].1 = blocked();

        let result =
            verdict("exit-a", Some("DE".parse().unwrap()), &checked(answers));

        assert_eq!(result.severity, Severity::Fail);
        assert_eq!(result.detail, "blocked: youtube premium");
    }

    /// Only Premium is excused: NotebookLM refusing an exit kept in RU is
    /// still a failure.
    #[test]
    fn with_ru_expected_another_refusal_still_fails_the_row() {
        let mut answers = all_available();
        answers[1].1 = blocked();
        answers[2].1 = blocked();

        let result =
            verdict("exit-a", Some(CountryCode::RU), &checked(answers));

        assert_eq!(result.severity, Severity::Fail);
        assert_eq!(
            result.detail,
            "blocked: notebooklm; not counted: youtube premium (RU expected)"
        );
    }

    #[rstest]
    #[case::in_russia(ExitServices::Skipped(Skip::InRussia), Severity::Ok)]
    #[case::no_tunnel(ExitServices::Skipped(Skip::NoTunnel), Severity::Warn)]
    #[case::no_egress(
        ExitServices::Skipped(Skip::EgressUnknown),
        Severity::Warn
    )]
    #[case::disabled(ExitServices::Disabled, Severity::Ok)]
    #[case::tunnel_failed(
        ExitServices::TunnelFailed { via: "de first".into(), reason: "spawning xray: boom".into() },
        Severity::Warn
    )]
    fn an_exit_not_asked_says_why_at_its_own_severity(
        #[case] outcome: ExitServices,
        #[case] expected: Severity,
    ) {
        let result = verdict("de", None, &outcome);

        assert_eq!(result.severity, expected, "{}", result.detail);
    }
}

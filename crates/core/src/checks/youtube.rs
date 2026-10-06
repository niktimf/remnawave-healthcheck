//! Which country YouTube places an exit in, read from its home page as a
//! client gets it through the tunnel. YouTube shows no ads to an address it
//! places in RU, so the country is a fact the operator may want to keep, and
//! a change of it is worth a warning.

use super::services::{
    ACCEPT_LANGUAGE, CHROME_UA, Request, Response, Silence, Unread,
    is_challenge,
};

/// A browser's headers plus `SOCS=CAI`, which declines the cookie-consent
/// interstitial YouTube puts in front of the page for addresses it places in
/// the EU. Without it such an exit answers with a 302 to the consent page,
/// which carries no country.
const HEADERS: &[(&str, &str)] = &[
    ("user-agent", CHROME_UA),
    ("accept-language", ACCEPT_LANGUAGE),
    ("cookie", "SOCS=CAI"),
];

/// The home page: the country YouTube serves the content of is in its
/// bootstrap data.
pub const REQUEST: Request = Request {
    url: "https://www.youtube.com/",
    headers: HEADERS,
};

/// An ISO 3166 alpha-2 code, upper case. Parsed once where it enters, so a
/// configured `ru` and a page's `RU` compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// The country YouTube serves without ads and refuses Premium in.
    pub const RU: Self = Self(*b"RU");

    pub fn as_str(&self) -> &str {
        // Two ASCII letters by construction.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

/// Text that is not two Latin letters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a two-letter country code")]
pub struct NotACountry(pub String);

impl std::str::FromStr for CountryCode {
    type Err = NotACountry;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Ok(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => Err(NotACountry(text.to_string())),
        }
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What the home page said about the exit's country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Country {
    Seen(CountryCode),
    /// An answer that carries no country, with the same reasons a service
    /// page goes unread for.
    Unrecognized(Unread),
    NoAnswer(Silence),
}

/// The country in a home page that YouTube served. `countryCode` is the
/// content country shown by the logo; through WARP the page lacks it and
/// `INNERTUBE_CONTEXT_GL` carries the country instead.
pub fn read(response: &Response) -> Country {
    if is_challenge(&response.body.to_lowercase()) {
        return Country::Unrecognized(Unread::Challenge);
    }
    if response.status != 200 {
        return Country::Unrecognized(Unread::Status(response.status));
    }
    ["\"countryCode\":\"", "\"INNERTUBE_CONTEXT_GL\":\""]
        .iter()
        .find_map(|key| quoted_after(&response.body, key))
        .map_or(Country::Unrecognized(Unread::NoRegion), Country::Seen)
}

/// The code in the first `<key>XX"` of the body that holds one.
fn quoted_after(body: &str, key: &str) -> Option<CountryCode> {
    body.match_indices(key).find_map(|(at, _)| {
        let value = body.get(at + key.len()..)?;
        value
            .get(..2)?
            .parse()
            .ok()
            .filter(|_| value[2..].starts_with('"'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn page(status: u16, body: &str) -> Response {
        Response {
            status,
            location: None,
            body: body.to_string(),
        }
    }

    fn code(text: &str) -> CountryCode {
        text.parse().unwrap()
    }

    #[rstest]
    #[case::direct_address(
        r#"{"countryCode":"RU","INNERTUBE_CONTEXT_GL":"RU"}"#,
        "RU"
    )]
    #[case::through_warp(
        r#"ytcfg.set({"INNERTUBE_CONTEXT_GL":"US","GL":"US"})"#,
        "US"
    )]
    #[case::fields_disagree(
        r#"{"INNERTUBE_CONTEXT_GL":"US"} {"countryCode":"NL"}"#,
        "NL"
    )]
    fn the_country_is_read_from_the_page(
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        let response = page(200, body);

        let country = read(&response);

        assert_eq!(country, Country::Seen(code(expected)));
    }

    #[rstest]
    #[case::no_field(page(200, "<html>YouTube</html>"), Unread::NoRegion)]
    #[case::not_a_code(page(200, r#"{"countryCode":"ZZZ"}"#), Unread::NoRegion)]
    #[case::challenge(
        page(403, "<title>Just a moment...</title>"),
        Unread::Challenge
    )]
    #[case::consent_redirect(page(302, ""), Unread::Status(302))]
    fn a_page_without_a_country_is_unrecognized(
        #[case] response: Response,
        #[case] why: Unread,
    ) {
        let country = read(&response);

        assert_eq!(country, Country::Unrecognized(why));
    }

    #[test]
    fn the_home_page_is_asked_with_the_consent_declined() {
        let headers = REQUEST.headers;

        assert!(headers.contains(&("cookie", "SOCS=CAI")));
    }

    #[rstest]
    #[case::upper("RU", Ok("RU"))]
    #[case::lower("nl", Ok("NL"))]
    #[case::three_letters("RUS", Err(()))]
    #[case::digits("R1", Err(()))]
    #[case::empty("", Err(()))]
    fn a_country_code_is_two_latin_letters(
        #[case] text: &str,
        #[case] expected: Result<&str, ()>,
    ) {
        let parsed = text.parse::<CountryCode>();

        let got = parsed.as_ref().map(CountryCode::as_str).map_err(|_| ());
        assert_eq!(got, expected);
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

/// Parse `raw` as an `https` URL with a host, for the setting named `field`.
///
/// Plain HTTP would hand whatever travels on the connection to anything on the
/// path. An `https` URI with an empty host is invalid per
/// [RFC 9110 Section 4.2.2]. The parsed URL is returned for the caller's own
/// rules.
///
/// # Errors
///
/// A URL that does not parse, a scheme other than `https`, or no host.
///
/// [RFC 9110 Section 4.2.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.2.2
pub(crate) fn require_https_url(field: &str, raw: &str) -> Result<url::Url, String> {
    let url =
        url::Url::parse(raw).map_err(|e| format!("`{field}` is not a valid URL ('{raw}'): {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("`{field}` must be an https URL, got '{raw}'"));
    }
    // Checked on the raw text as well: the WHATWG parser reads `https:///x` as
    // host `x`, which would send the credential somewhere nobody configured.
    let authority_missing = raw
        .get("https://".len()..)
        .is_none_or(|rest| rest.is_empty() || rest.starts_with(['/', ':']));
    if authority_missing || url.host_str().is_none_or(str::is_empty) {
        return Err(format!("`{field}` has no host: '{raw}'"));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::require_https_url;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn an_https_url_with_a_host_is_accepted() {
        for raw in [
            "https://kubernetes.default.svc",
            "https://localhost:6443",
            "https://proxy.example/k8s/?x=1",
        ] {
            assert!(
                require_https_url("endpoint", raw).is_ok(),
                "{raw} should be accepted"
            );
        }
    }

    #[test]
    fn plain_http_or_an_unparseable_url_is_rejected() {
        for raw in ["http://kubernetes.default.svc", "not a url"] {
            let error = require_https_url("endpoint", raw).err();

            assert!(
                error.as_deref().is_some_and(|e| e.contains("`endpoint`")),
                "{raw} must be rejected naming the setting, got {error:?}"
            );
        }
    }

    // -----------------------------------------------------------------------------
    // RFC 9110 Section 4.2.2: an https URI with an empty host is invalid
    // -----------------------------------------------------------------------------

    /// [RFC 9110 Section 4.2.2] makes an `https` URI with an empty host
    /// invalid.
    ///
    /// [RFC 9110 Section 4.2.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.2.2
    #[test]
    fn rfc9110_4_2_2_an_https_url_with_an_empty_host_is_rejected() {
        for raw in ["https://", "https:///apis", "https://:6443"] {
            assert!(
                require_https_url("endpoint", raw).is_err(),
                "{raw} has no host and must be rejected"
            );
        }
    }
}

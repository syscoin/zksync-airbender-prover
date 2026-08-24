use anyhow::{anyhow, Context};
use secrecy::SecretString;
use url::Url;

/// SYSCOIN: Clap must accept endpoint environment values without validation so its error renderer
/// can never echo credentials. Debug is redacted too; callers explicitly parse only after Clap has
/// finished and attach value-free index/context errors.
#[derive(Clone)]
pub struct OpaqueSequencerEndpoint(String);

impl OpaqueSequencerEndpoint {
    pub fn into_endpoint(self) -> anyhow::Result<SequencerEndpoint> {
        SequencerEndpoint::parse(&self.0)
    }
}

impl std::str::FromStr for OpaqueSequencerEndpoint {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_owned()))
    }
}

impl std::fmt::Debug for OpaqueSequencerEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueSequencerEndpoint([REDACTED])")
    }
}

/// SYSCOIN: Convert opaque CLI/env values only after argument parsing. Errors identify the list
/// position but never interpolate the possibly credential-bearing source value.
pub fn parse_configured_sequencer_endpoints(
    endpoints: Vec<OpaqueSequencerEndpoint>,
) -> anyhow::Result<Vec<SequencerEndpoint>> {
    endpoints
        .into_iter()
        .enumerate()
        .map(|(index, endpoint)| {
            endpoint
                .into_endpoint()
                .with_context(|| format!("invalid configured sequencer endpoint at index {index}"))
        })
        .collect()
}

/// Internal: Credentials for authenticating with a sequencer.
#[derive(Clone)]
pub(crate) struct SequencerCredentials {
    pub(crate) username: String,
    pub(crate) password: SecretString,
}

/// A sequencer endpoint with optional credentials.
///
/// The URL is always stored without embedded credentials (user/pass stripped).
/// Any credentials found in the URL are extracted and stored separately.
#[derive(Clone)]
pub struct SequencerEndpoint {
    /// Clean URL without embedded credentials
    pub url: Url,
    /// Optional credentials for Basic Auth (internal use only)
    pub(crate) credentials: Option<SequencerCredentials>,
}

impl SequencerEndpoint {
    /// Parse a URL string into a sequencer endpoint.
    ///
    /// If the URL contains embedded credentials (e.g., `http://user:pass@host:port`),
    /// they are extracted and stored in the `credentials` field, and the URL is
    /// cleaned to remove them.
    ///
    /// # Examples
    /// ```
    /// use zksync_sequencer_proof_client::SequencerEndpoint;
    ///
    /// // Parse URL without credentials
    /// let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
    /// assert_eq!(endpoint.url.as_str(), "http://localhost:3124/");
    ///
    /// // Parse URL with embedded credentials (they are extracted and URL is cleaned)
    /// let endpoint = SequencerEndpoint::parse("http://user:pass@localhost:3124").unwrap();
    /// assert_eq!(endpoint.url.as_str(), "http://localhost:3124/");
    /// ```
    pub fn parse(url_str: &str) -> anyhow::Result<Self> {
        let mut url = Url::parse(url_str).context("Invalid URL")?;

        // SYSCOIN: Query and fragment data are neither part of the prover API base identity nor
        // an approved credential channel. Reject them before Debug/startup logs can expose a
        // token that would otherwise be silently stripped by durable endpoint canonicalization.
        anyhow::ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "sequencer endpoint must not contain a query or fragment"
        );

        // SYSCOIN: Userinfo is security-sensitive configuration. Reject every malformed shape
        // without interpolating the original URL, which may contain a password or control data.
        anyhow::ensure!(
            !(url.username().is_empty() && url.password().is_some()),
            "sequencer endpoint password requires a non-empty username"
        );

        // Extract credentials if present.
        let credentials = if !url.username().is_empty() {
            let username = url.username().to_string();

            let password = url
                .password()
                .ok_or_else(|| anyhow!("sequencer endpoint username requires a password"))?
                .to_string();

            if password.is_empty() {
                return Err(anyhow!("sequencer endpoint password cannot be empty"));
            }

            Some(SequencerCredentials {
                username,
                password: SecretString::new(password.into()),
            })
        } else {
            None
        };

        // Strip credentials from URL
        url.set_username("").map_err(|_| {
            anyhow!("Failed to strip username from URL (URL scheme may not support credentials)")
        })?;
        url.set_password(None).map_err(|_| {
            anyhow!("Failed to strip password from URL (URL scheme may not support credentials)")
        })?;

        // Warn if using credentials over HTTP
        if credentials.is_some() && url.scheme() == "http" {
            tracing::warn!(
                "Sending credentials over unencrypted HTTP to {}. \
                 Consider using HTTPS to protect credentials in transit.",
                url.host_str().unwrap_or("unknown")
            );
        }

        Ok(Self { url, credentials })
    }
}

impl std::fmt::Debug for SequencerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SequencerEndpoint");
        debug.field("url", &self.url.as_str());

        // SYSCOIN: Treat the username as credential metadata too. Routine startup logs need only
        // the sanitized routing identity and whether authentication is configured.
        if self.credentials.is_some() {
            debug.field("credentials", &Some("[REDACTED]"));
        } else {
            debug.field("credentials", &None::<()>);
        }

        debug.finish()
    }
}

impl std::str::FromStr for SequencerEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_without_credentials() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();

        assert_eq!(
            endpoint.url.as_str(),
            "http://localhost:3124/",
            "URL should remain unchanged when no credentials are present"
        );
        assert!(
            endpoint.credentials.is_none(),
            "Credentials should be None when URL has no credentials"
        );
    }

    #[test]
    fn test_url_with_credentials() {
        let endpoint = SequencerEndpoint::parse("http://user:password@localhost:3124").unwrap();

        // URL should be clean (credentials stripped)
        assert_eq!(
            endpoint.url.as_str(),
            "http://localhost:3124/",
            "URL should have credentials stripped"
        );
        assert_eq!(
            endpoint.url.username(),
            "",
            "URL username should be empty after stripping"
        );
        assert_eq!(
            endpoint.url.password(),
            None,
            "URL password should be None after stripping"
        );

        // Credentials should be extracted
        let creds = endpoint
            .credentials
            .as_ref()
            .expect("Credentials should be extracted");
        assert_eq!(
            creds.username, "user",
            "Username should be extracted correctly"
        );

        use secrecy::ExposeSecret;
        assert_eq!(
            creds.password.expose_secret(),
            "password",
            "Password should be extracted correctly"
        );
    }

    #[test]
    fn test_url_with_username_no_password() {
        let err = SequencerEndpoint::parse("http://user@localhost:3124").unwrap_err();
        assert!(
            err.to_string().contains("username requires a password"),
            "Error should indicate username without password: {err}",
        );
    }

    #[test]
    fn test_url_with_empty_password() {
        // Note: URL parsing treats "user:@host" the same as "user@host" - both have no password
        let err = SequencerEndpoint::parse("http://user:@localhost:3124").unwrap_err();
        assert!(
            err.to_string().contains("username requires a password"),
            "Error should indicate username without password: {err}",
        );
    }

    #[test]
    fn test_credentials_not_in_debug_output() {
        let endpoint = SequencerEndpoint::parse("http://user:secret123@localhost:3124").unwrap();
        let debug_output = format!("{endpoint:?}");

        // Should not contain actual password value
        assert!(
            !debug_output.contains("secret123"),
            "Debug output should not contain the actual password value. Got: {debug_output}"
        );

        // Username is credential metadata and must be redacted with the password.
        assert!(
            !debug_output.contains("\"user\""),
            "Debug output should not show the username. Got: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should mark configured credentials as redacted. Got: {debug_output}"
        );

        // URL should be clean
        assert!(
            debug_output.contains("http://localhost:3124"),
            "Debug output should contain the clean URL. Got: {debug_output}"
        );
    }

    // SYSCOIN: URL query/fragment values must never become an accidental logged secret channel.
    #[test]
    fn endpoint_rejects_query_and_fragment() {
        for url in [
            "https://sequencer.example/?token=secret",
            "https://sequencer.example/#secret",
        ] {
            let error = SequencerEndpoint::parse(url).unwrap_err();
            assert!(error.to_string().contains("query or fragment"));
            assert!(!error.to_string().contains("secret"));
        }
    }

    // SYSCOIN: Never silently discard malformed Basic Auth input, and never echo its userinfo in
    // the resulting configuration error.
    #[test]
    fn endpoint_rejects_malformed_userinfo_without_leaking_it() {
        for (url, secret) in [
            (
                "https://:password-secret@sequencer.example/",
                "password-secret",
            ),
            (
                "https://username-secret@sequencer.example/",
                "username-secret",
            ),
            (
                "https://username-secret:@sequencer.example/",
                "username-secret",
            ),
        ] {
            let error = SequencerEndpoint::parse(url).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("sequencer endpoint"));
            assert!(
                !message.contains(secret),
                "userinfo leaked through {message:?}"
            );
        }
    }

    // SYSCOIN: Opaque argument parsing is infallible and redacted; semantic errors happen only in
    // the explicit post-Clap conversion and never contain the source credential.
    #[test]
    fn opaque_endpoint_defers_validation_without_debug_or_error_disclosure() {
        let raw = "https://:opaque-password-secret@sequencer.example/";
        let opaque: OpaqueSequencerEndpoint = raw.parse().unwrap();
        assert!(!format!("{opaque:?}").contains("opaque-password-secret"));
        let error = parse_configured_sequencer_endpoints(vec![opaque]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("index 0"));
        assert!(!message.contains("opaque-password-secret"));
    }
}

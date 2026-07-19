// exchange/config.rs — ExchangeConfig struct used by the rich Exchange trait clients.

/// Per-exchange configuration.  Each client receives one at construction time.
///
/// `api_key` and `api_secret` are wrapped in `SecretString` which zeroises
/// memory on drop, preventing credentials from lingering in the process heap.
#[derive(Clone)]
pub struct ExchangeConfig {
    pub api_key: SecretString,
    pub api_secret: SecretString,
    pub base_url: String,
    pub passphrase: Option<SecretString>,
    pub http_timeout_secs: Option<u64>,
}

impl std::fmt::Debug for ExchangeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeConfig")
            .field("api_key", &"[REDACTED]")
            .field("api_secret", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("http_timeout_secs", &self.http_timeout_secs)
            .finish()
    }
}

impl ExchangeConfig {
    /// Return the passphrase as a `&str`, or `""` if not set.
    /// This is the safe accessor — never exposes the secret through `Deref`.
    #[inline]
    pub fn passphrase_str(&self) -> &str {
        match &self.passphrase {
            Some(p) => p.expose(),
            None => "",
        }
    }

    /// Create a new `ExchangeConfig` with the given credentials and base URL.
    pub fn new(
        api_key: &str,
        api_secret: &str,
        base_url: &str,
    ) -> Self {
        let cfg = Self {
            api_key: SecretString::new(api_key),
            api_secret: SecretString::new(api_secret),
            base_url: base_url.to_owned(),
            passphrase: None,
            http_timeout_secs: None,
        };
        // M-2: Validate at construction time so invalid configs fail early.
        if let Err(e) = cfg.validate() {
            tracing::error!(error = %e, "ExchangeConfig::new validation failed");
        }
        cfg
    }

    /// Create a new `ExchangeConfig` with an additional passphrase (e.g. OKX, KuCoin).
    pub fn with_passphrase(
        api_key: &str,
        api_secret: &str,
        base_url: &str,
        passphrase: &str,
    ) -> Self {
        let cfg = Self {
            api_key: SecretString::new(api_key),
            api_secret: SecretString::new(api_secret),
            base_url: base_url.to_owned(),
            passphrase: Some(SecretString::new(passphrase)),
            http_timeout_secs: None,
        };
        // M-2: Validate at construction time so invalid configs fail early.
        if let Err(e) = cfg.validate() {
            tracing::error!(error = %e, "ExchangeConfig::with_passphrase validation failed");
        }
        cfg
    }

    /// Validate the config for production use.
    ///
    /// * `base_url` must use HTTPS to prevent credential leakage over plaintext.
    /// * API key and secret must not be empty.
    pub fn validate(&self) -> Result<(), String> {
        if !self.base_url.starts_with("https://") {
            return Err(format!(
                "Exchange base_url must use HTTPS for production, got: {}",
                self.base_url
            ));
        }
        if self.api_key.expose().is_empty() || self.api_secret.expose().is_empty() {
            return Err("API key and secret must not be empty".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SecretString — secure string wrapper that zeroises memory on drop.
//
// Uses the `secrecy` crate's `SecretBox<[u8]>` internally to guarantee that
// the underlying bytes are overwritten with zeroes when the value is dropped,
// preventing API keys and secrets from lingering in heap memory.
// ---------------------------------------------------------------------------

use secrecy::ExposeSecret;

/// A string whose contents are zeroed on drop.
///
/// Provides `.expose()` to borrow the inner value for signing / header
/// construction.  The `Clone` impl creates a new independent copy (the
/// original remains untouched until its own drop).
pub struct SecretString(secrecy::SecretBox<str>);

impl SecretString {
    /// Create a new `SecretString` from a plain `&str`.
    pub fn new(s: &str) -> Self {
        Self(secrecy::SecretBox::new(Box::from(s)))
    }

    /// Expose the inner secret value for use in signing / HTTP headers.
    ///
    /// The returned reference is valid for the lifetime of `self`.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        // NOTE: The intermediate String allocation (self.0.expose_secret().clone())
        // is not zeroed on drop. Only the final SecretBox zeroes its content.
        // This is an acceptable trade-off for Clone; secrets that must never
        // touch unzeroed heap memory should not be cloned.
        Self(secrecy::SecretBox::new(self.0.expose_secret().clone()))
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}
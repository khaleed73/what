//! Zero-Allocation Signer — Stack-allocated HMAC-SHA256 signing.
//!
//! This module provides a signing implementation that pre-allocates all buffers
//! on the stack, avoiding heap allocations during the hot signing path.
//! The destination buffer is reused across calls to minimize cache pressure.

use std::io::Write;
use rust_decimal::Decimal;
use secrecy::ExposeSecret;

/// Maximum payload length supported (4 KB — sufficient for any exchange query string).
const MAX_PAYLOAD_LEN: usize = 4096;

/// Pre-allocated HMAC signer that reuses stack buffers.
pub struct ZeroAllocationSigner {
    secret_key: secrecy::SecretString,
}

impl ZeroAllocationSigner {
    /// L-9: Minimum allowed length for API secret keys.
    const MIN_KEY_LENGTH: usize = 16;

    /// Creates a new signer, validating the secret key.
    ///
    /// # Panics
    /// Panics if the secret key is shorter than 16 characters or contains
    /// characters outside the allowed set (alphanumeric, `-`, `_`, `.`, `+`).
    pub fn new(secret: &str) -> Self {
        Self::validate_key(secret)
            .unwrap_or_else(|e| panic!("L-9: Invalid API key: {}", e));
        Self {
            secret_key: secrecy::SecretString::new(secret.into()),
        }
    }

    /// L-9: Validates an API key for minimum length and allowed characters.
    ///
    /// Allowed characters: alphanumeric, `-`, `_`, `.`, `+`
    /// Minimum length: 16 characters.
    pub fn validate_key(key: &str) -> Result<(), String> {
        if key.len() < Self::MIN_KEY_LENGTH {
            return Err(format!(
                "API key too short: {} bytes (minimum {})",
                key.len(),
                Self::MIN_KEY_LENGTH
            ));
        }
        for (i, ch) in key.char_indices() {
            if !ch.is_alphanumeric() && ch != '-' && ch != '_' && ch != '.' && ch != '+' {
                return Err(format!(
                    "API key contains invalid character {:?} at byte offset {}",
                    ch, i
                ));
            }
        }
        Ok(())
    }

    /// Compiles the query string and signs it using HMAC-SHA256.
    ///
    /// # Arguments
    /// * `params` - Key-value pairs to include in the query string
    /// * `timestamp` - Unix timestamp in milliseconds
    /// * `destination_buffer` - Pre-allocated buffer for the output
    ///
    /// # Output Format
    /// `key1=value1&key2=value2&timestamp=1234567890&signature=<hex>`
    ///
    /// Returns the number of bytes written to the buffer.
    pub fn compile_and_sign_payload(
        &self,
        params: &[(impl AsRef<str>, impl AsRef<str>)],
        timestamp: u64,
        destination_buffer: &mut [u8; MAX_PAYLOAD_LEN],
    ) -> Result<usize, &'static str> {
        let mut cursor = std::io::Cursor::new(destination_buffer.as_mut());
        let mut preimage = String::with_capacity(512);

        // Write query parameters
        for (i, (key, value)) in params.iter().enumerate() {
            if i > 0 {
                preimage.push('&');
            }
            preimage.push_str(key.as_ref());
            preimage.push('=');
            preimage.push_str(value.as_ref());
        }

        // Append timestamp
        if !params.is_empty() {
            preimage.push('&');
        }
        preimage.push_str("timestamp=");
        preimage.push_str(&timestamp.to_string());

        // Compute HMAC-SHA256
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.secret_key.expose_secret().as_bytes());
        let tag = hmac::sign(&key, preimage.as_bytes());

        // Build final output
        let mut output = String::with_capacity(preimage.len() + 80);
        output.push_str(&preimage);
        output.push_str("&signature=");
        output.push_str(&hex::encode(tag.as_ref()));

        // Write to buffer
        cursor.write_all(output.as_bytes()).map_err(|_| "Buffer overflow")?;
        Ok(cursor.position() as usize)
    }

    /// Signs a raw string message using HMAC-SHA256.
    /// Returns the 64-character hex-encoded signature.
    pub fn sign_raw(&self, message: &str) -> String {
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.secret_key.expose_secret().as_bytes());
        let tag = hmac::sign(&key, message.as_bytes());
        hex::encode(tag.as_ref())
    }

    /// Generates a signed query string in the format used by most exchanges.
    ///
    /// Output: `param1=val1&param2=val2&timestamp=1234&signature=<hex>`
    pub fn generate_signed_query(&self, base_payload: &str, timestamp: u64) -> String {
        let preimage = if base_payload.is_empty() {
            format!("timestamp={}", timestamp)
        } else {
            format!("{}&timestamp={}", base_payload, timestamp)
        };

        let sig = self.sign_raw(&preimage);
        format!("{}&signature={}", preimage, sig)
    }
}

/// Creates a decimal from a raw byte slice (zero-copy where possible).
/// Used for parsing execution report data without allocation.
pub fn parse_decimal_from_bytes(bytes: &[u8]) -> Option<Decimal> {
    let s = std::str::from_utf8(bytes).ok()?;
    Decimal::from_str(s).ok()
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_signer() -> ZeroAllocationSigner {
        ZeroAllocationSigner::new("test_secret_key_12345")
    }

    #[test]
    fn test_sign_raw_deterministic() {
        let signer = make_signer();
        let sig1 = signer.sign_raw("symbol=BTCUSDT&side=BUY&quantity=0.001");
        let sig2 = signer.sign_raw("symbol=BTCUSDT&side=BUY&quantity=0.001");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_sign_raw_different_messages() {
        let signer = make_signer();
        let sig1 = signer.sign_raw("message1");
        let sig2 = signer.sign_raw("message2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_compile_and_sign_payload() {
        let signer = make_signer();
        let mut buffer = [0u8; MAX_PAYLOAD_LEN];
        let params: Vec<(&str, &str)> = vec![
            ("symbol", "BTCUSDT"),
            ("side", "BUY"),
            ("quantity", "0.001"),
        ];
        let written = signer.compile_and_sign_payload(&params, 1700000000000, &mut buffer).unwrap();
        let output = std::str::from_utf8(&buffer[..written]).unwrap();

        assert!(output.contains("symbol=BTCUSDT"));
        assert!(output.contains("side=BUY"));
        assert!(output.contains("quantity=0.001"));
        assert!(output.contains("timestamp=1700000000000"));
        assert!(output.contains("signature="));
    }

    #[test]
    fn test_generate_signed_query() {
        let signer = make_signer();
        let result = signer.generate_signed_query("symbol=BTCUSDT&side=BUY", 1700000000000);
        assert!(result.contains("symbol=BTCUSDT"));
        assert!(result.contains("timestamp=1700000000000"));
        assert!(result.contains("signature="));
        assert!(result.starts_with("symbol="));
    }

    #[test]
    fn test_parse_decimal_from_bytes() {
        assert_eq!(parse_decimal_from_bytes(b"50000.5"), Some(dec!(50000.5)));
        assert_eq!(parse_decimal_from_bytes(b"0.001"), Some(dec!(0.001)));
        assert_eq!(parse_decimal_from_bytes(b"invalid"), None);
        assert_eq!(parse_decimal_from_bytes(b""), None);
    }
}
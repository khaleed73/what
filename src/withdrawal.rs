// withdrawal.rs — Cross-Exchange Withdrawal Execution Module.
//
// Provides a unified `WithdrawalExecutor` that dispatches authenticated
// withdrawal requests to 9 different exchange REST APIs, each with
// its own signing convention (HMAC-SHA256 hex, HMAC-SHA256 base64,
// nonce-based, etc.).
//
// ## Relationship to `rebalancer.rs`
//
// The rebalancer detects capital drift and enqueues `RebalanceRequest`s
// on an MPSC channel.  This module is the **execution layer** that the
// rebalancer (or any other caller) invokes to actually fire the
// authenticated withdrawal HTTP request.
//
// ## Safety
//
// Withdrawal credentials are held as plain `String` inside
// `ExchangeCredentials` — the caller is responsible for ensuring
// that the parent process memory is protected (mlock, etc.) in
// production deployments.  The existing `SecretString` wrapper in
// `exchange::config` is intentionally NOT used here because
// withdrawal operations are infrequent and the `SecretString`
// borrow-checker constraints would complicate the async dispatch.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ring::hmac;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use crate::exchange::exchange_name_by_id;
use crate::signer::PrivateExchangeClient;

// ═══════════════════════════════════════════════════════════════════════════
//  ExchangeCredentials — raw API keys stored for withdrawal signing
// ═══════════════════════════════════════════════════════════════════════════

/// Raw API credentials for a single exchange.
///
/// Stored separately from `SecretString` because withdrawal operations
/// need synchronous access to the key material for HMAC signing in
/// async contexts without borrow-checker friction.
#[derive(Debug, Clone)]
pub struct ExchangeCredentials {
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: Option<String>,
}

impl ExchangeCredentials {
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self {
            api_key: api_key.to_owned(),
            api_secret: api_secret.to_owned(),
            passphrase: None,
        }
    }

    pub fn with_passphrase(api_key: &str, api_secret: &str, passphrase: &str) -> Self {
        Self {
            api_key: api_key.to_owned(),
            api_secret: api_secret.to_owned(),
            passphrase: Some(passphrase.to_owned()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  WithdrawalRequest / WithdrawalResult
// ═══════════════════════════════════════════════════════════════════════════

/// A request to withdraw funds from an exchange.
#[derive(Debug, Clone)]
pub struct WithdrawalRequest {
    /// Numeric exchange ID (see `exchange_name_by_id`).
    pub exchange_id: u16,
    /// Currency to withdraw (e.g. "USDT", "BTC").
    pub currency: String,
    /// Amount in the currency's smallest unit (exchange-dependent precision).
    pub amount: Decimal,
    /// On-chain destination address.
    pub address: String,
    /// Network / chain identifier (e.g. "ERC20", "TRC20", "Arbitrum One").
    pub network: String,
    /// Optional client-side order ID for idempotency.
    pub client_order_id: Option<String>,
}

/// The result of a withdrawal attempt.
#[derive(Debug, Clone)]
pub struct WithdrawalResult {
    pub success: bool,
    pub withdrawal_id: Option<String>,
    pub fee: Decimal,
    pub error: Option<String>,
}

impl Default for WithdrawalResult {
    fn default() -> Self {
        Self {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  WithdrawalExecutor
// ═══════════════════════════════════════════════════════════════════════════

/// Unified withdrawal executor that dispatches to exchange-specific
/// authenticated REST APIs.
///
/// Each exchange has a different:
/// * HTTP body format (form-encoded vs JSON vs form-urlencoded-in-query)
/// * Signature scheme (hex vs base64, different preimage layouts)
/// * Authentication headers
pub struct WithdrawalExecutor {
    /// Connection-pooled HTTP client.
    pub http_client: reqwest::Client,
    /// The main execution pool (for balance checks, not directly used
    /// in withdrawal dispatch but retained for potential pre-flight checks).
    pub execution_pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
    /// REST base URLs per exchange.
    pub rest_urls: HashMap<u16, String>,
    /// Raw API credentials per exchange for signing withdrawal payloads.
    pub credentials: HashMap<u16, ExchangeCredentials>,
}

impl std::fmt::Debug for WithdrawalExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithdrawalExecutor")
            .field("rest_urls", &self.rest_urls)
            .field("credentials", &format!("{} exchanges configured", self.credentials.len()))
            .finish()
    }
}

impl WithdrawalExecutor {
    /// Create a new withdrawal executor.
    ///
    /// # Parameters
    ///
    /// * `http_client` — Pre-built reqwest client.
    /// * `execution_pool` — Shared reference to the trading execution pool.
    /// * `rest_urls` — REST base URL per exchange ID.
    /// * `exchange_configs` — Validated exchange configs (cloned at construction).
    pub fn new(
        http_client: reqwest::Client,
        execution_pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
        rest_urls: HashMap<u16, String>,
        exchange_configs: &HashMap<u16, crate::configs::ValidatedExchangeConfig>,
    ) -> Self {
        let credentials: HashMap<u16, ExchangeCredentials> = exchange_configs
            .iter()
            .map(|(id, cfg)| {
                let creds = match &cfg.passphrase {
                    Some(pp) => ExchangeCredentials::with_passphrase(
                        &cfg.api_key,
                        &cfg.api_secret,
                        pp,
                    ),
                    None => ExchangeCredentials::new(&cfg.api_key, &cfg.api_secret),
                };
                (*id, creds)
            })
            .collect();

        Self {
            http_client,
            execution_pool,
            rest_urls,
            credentials,
        }
    }

    // -------------------------------------------------------------------
    //  Main dispatch
    // -------------------------------------------------------------------

    /// Execute a withdrawal request by dispatching to the appropriate
    /// exchange-specific implementation.
    pub async fn execute_withdrawal(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let exchange_name = exchange_name_by_id(req.exchange_id);
        info!(
            exchange = exchange_name,
            currency = %req.currency,
            amount = %req.amount,
            network = %req.network,
            "Executing withdrawal"
        );

        let result = match req.exchange_id {
            0 => self.withdraw_binance(req).await,
            1 => self.withdraw_bybit(req).await,
            2 => self.withdraw_okx(req).await,
            3 => self.withdraw_gateio(req).await,
            4 => self.withdraw_kucoin(req).await,
            6 => self.withdraw_bitget(req).await,
            9 => self.withdraw_htx(req).await,
            10 => self.withdraw_kraken(req).await,
            15 => self.withdraw_mexc(req).await,
            _ => Err(format!(
                "withdrawal not implemented for exchange {} (id {})",
                exchange_name, req.exchange_id
            )),
        };

        match &result {
            Ok(r) if r.success => {
                info!(
                    exchange = exchange_name,
                    withdrawal_id = ?r.withdrawal_id,
                    fee = %r.fee,
                    "Withdrawal accepted"
                );
            }
            Ok(r) => {
                warn!(
                    exchange = exchange_name,
                    error = ?r.error,
                    "Withdrawal rejected by exchange"
                );
            }
            Err(e) => {
                error!(
                    exchange = exchange_name,
                    error = %e,
                    "Withdrawal request failed"
                );
            }
        }

        result
    }

    /// Query the withdrawal fee for a given currency/network on an exchange.
    pub async fn get_withdrawal_fee(
        &self,
        exchange_id: u16,
        currency: &str,
        network: &str,
    ) -> Result<Decimal, String> {
        let creds = self
            .credentials
            .get(&exchange_id)
            .ok_or_else(|| format!("no credentials for exchange id {}", exchange_id))?;
        let base_url = self
            .rest_urls
            .get(&exchange_id)
            .ok_or_else(|| format!("no REST URL for exchange id {}", exchange_id))?;

        match exchange_id {
            0 => self.fee_binance(base_url, creds, currency, network).await,
            1 => self.fee_bybit(base_url, creds, currency, network).await,
            2 => self.fee_okx(base_url, creds, currency, network).await,
            3 => self.fee_gateio(base_url, creds, currency, network).await,
            4 => self.fee_kucoin(base_url, creds, currency, network).await,
            6 => self.fee_bitget(base_url, creds, currency, network).await,
            9 => self.fee_htx(base_url, creds, currency, network).await,
            10 => self.fee_kraken(base_url, creds, currency, network).await,
            15 => self.fee_binance(base_url, creds, currency, network).await, // MEXC is Binance-compatible
            _ => Err(format!(
                "fee query not implemented for exchange id {}",
                exchange_id
            )),
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Binance (id=0) — POST /sapi/v1/capital/withdraw/apply
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_binance(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no Binance credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no Binance REST URL")?;

        // Build query-string body: coin, network, address, amount, timestamp, signature
        let mut params: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        params.insert("coin".into(), req.currency.clone());
        params.insert("network".into(), req.network.clone());
        params.insert("address".into(), req.address.clone());
        params.insert("amount".into(), req.amount.to_string());
        if let Some(ref cid) = req.client_order_id {
            params.insert("withdrawOrderId".into(), cid.clone());
        }

        let base_query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let ts = epoch_millis();
        let query_with_ts = if base_query.is_empty() {
            format!("timestamp={}", ts)
        } else {
            format!("{}&timestamp={}", base_query, ts)
        };

        let signature = hmac_hex(&creds.api_secret, &query_with_ts);
        let signed_body = format!("{}&signature={}", query_with_ts, signature);

        let url = format!("{}/sapi/v1/capital/withdraw/apply", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("X-MBX-APIKEY", &creds.api_key)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await
            .map_err(|e| format!("Binance withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("Binance withdrawal read body: {}", e))?;

        parse_binance_withdrawal_response(&status, &body)
    }

    async fn fee_binance(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        _network: &str,
    ) -> Result<Decimal, String> {
        let ts = epoch_millis();
        let query = format!("timestamp={}", ts);
        let sig = hmac_hex(&creds.api_secret, &query);
        let signed = format!("{}&signature={}", query, sig);
        let url = format!(
            "{}/sapi/v1/capital/withdraw/fee?coin={}&{}",
            base_url, currency, signed
        );

        let resp = self
            .http_client
            .get(&url)
            .header("X-MBX-APIKEY", &creds.api_key)
            .send()
            .await
            .map_err(|e| format!("Binance fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("Binance fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("Binance fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("Binance fee JSON: {}", e))?;
        v.get("withdrawFee")
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| "Binance fee response missing withdrawFee".to_string())
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Bybit (id=1) — POST /v5/asset/withdraw/create
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_bybit(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no Bybit credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no Bybit REST URL")?;

        let body_map = json!({
            "coin": req.currency,
            "chain": req.network,
            "address": req.address,
            "amt": req.amount.to_string(),
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("Bybit body serialize: {}", e))?;

        let timestamp = epoch_millis().to_string();
        let recv_window = "5000".to_string();
        let preimage = format!(
            "{}{}{}{}",
            timestamp, creds.api_key, recv_window, body_str
        );
        let sign = hmac_hex(&creds.api_secret, &preimage);

        let url = format!("{}/v5/asset/withdraw/create", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("X-BAPI-API-KEY", &creds.api_key)
            .header("X-BAPI-SIGN", &sign)
            .header("X-BAPI-TIMESTAMP", &timestamp)
            .header("X-BAPI-RECV-WINDOW", &recv_window)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("Bybit withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("Bybit withdrawal read body: {}", e))?;

        parse_bybit_withdrawal_response(&status, &body)
    }

    async fn fee_bybit(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        network: &str,
    ) -> Result<Decimal, String> {
        let timestamp = epoch_millis().to_string();
        let recv_window = "5000".to_string();
        let param_str = format!("coin={}&chain={}", currency, network);
        let preimage = format!(
            "GET/api/v5/asset/coin/query-info{}{}{}{}",
            timestamp, creds.api_key, recv_window, param_str
        );
        let sign = hmac_hex(&creds.api_secret, &preimage);
        let url = format!(
            "{}/v5/asset/coin/query-info?coin={}&chain={}",
            base_url, currency, network
        );

        let resp = self
            .http_client
            .get(&url)
            .header("X-BAPI-API-KEY", &creds.api_key)
            .header("X-BAPI-SIGN", &sign)
            .header("X-BAPI-TIMESTAMP", &timestamp)
            .header("X-BAPI-RECV-WINDOW", &recv_window)
            .send()
            .await
            .map_err(|e| format!("Bybit fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("Bybit fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("Bybit fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("Bybit fee JSON: {}", e))?;
        v.get("result")
            .and_then(|r| r.get("rows"))
            .and_then(|rows| rows.as_array())
            .and_then(|arr| arr.first())
            .and_then(|row| row.get("withdrawFee"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| "Bybit fee response missing withdrawFee".to_string())
    }

    // ══════════════════════════════════════════════════════════════════════
    //  OKX (id=2) — POST /api/v5/asset/withdrawal
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_okx(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no OKX credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no OKX REST URL")?;

        let chain = format!("{}-{}", req.currency, req.network);
        let body_map = json!({
            "ccy": req.currency,
            "amt": req.amount.to_string(),
            "dest": "4",
            "toAddr": req.address,
            "chain": chain,
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("OKX body serialize: {}", e))?;

        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let method = "POST";
        let path = "/api/v5/asset/withdrawal";
        let preimage = format!("{}{}{}{}", timestamp, method, path, body_str);

        let signature = hmac_base64(&creds.api_secret, &preimage);
        let passphrase = creds.passphrase.as_deref().unwrap_or("");

        let url = format!("{}{}", base_url, path);

        let resp = self
            .http_client
            .post(&url)
            .header("OK-ACCESS-KEY", &creds.api_key)
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header("OK-ACCESS-PASSPHRASE", passphrase)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("OKX withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("OKX withdrawal read body: {}", e))?;

        parse_okx_withdrawal_response(&status, &body)
    }

    async fn fee_okx(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        network: &str,
    ) -> Result<Decimal, String> {
        let chain = format!("{}-{}", currency, network);
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let method = "GET";
        let path = "/api/v5/asset/currencies";
        let query = format!("ccy={}", currency);
        let preimage = format!("{}{}{}{}", timestamp, method, path, query);

        let signature = hmac_base64(&creds.api_secret, &preimage);
        let passphrase = creds.passphrase.as_deref().unwrap_or("");
        let url = format!("{}{}?{}", base_url, path, query);

        let resp = self
            .http_client
            .get(&url)
            .header("OK-ACCESS-KEY", &creds.api_key)
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header("OK-ACCESS-PASSPHRASE", passphrase)
            .send()
            .await
            .map_err(|e| format!("OKX fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("OKX fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("OKX fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("OKX fee JSON: {}", e))?;
        v.get("data")
            .and_then(|d| d.as_array())
            .and_then(|arr| {
                arr.iter().find(|item| {
                    item.get("chain")
                        .and_then(|c| c.as_str())
                        .map(|c| c == chain)
                        .unwrap_or(false)
                })
            })
            .and_then(|item| item.get("wdFee"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| format!("OKX fee response missing wdFee for chain {}", chain))
    }

    // ══════════════════════════════════════════════════════════════════════
    //  GateIO (id=3) — POST /api/v4/withdrawals
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_gateio(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no GateIO credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no GateIO REST URL")?;

        // GateIO uses short chain codes; map common network names.
        let chain = gateio_chain_code(&req.network);

        let body_map = json!({
            "currency": req.currency,
            "amount": req.amount.to_string(),
            "address": req.address,
            "chain": chain,
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("GateIO body serialize: {}", e))?;

        let timestamp = epoch_secs().to_string();
        let signature = hmac_hex(&creds.api_secret, &body_str);

        let url = format!("{}/api/v4/withdrawals", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("KEY", &creds.api_key)
            .header("SIGN", &signature)
            .header("Timestamp", &timestamp)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("GateIO withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("GateIO withdrawal read body: {}", e))?;

        parse_gateio_withdrawal_response(&status, &body)
    }

    async fn fee_gateio(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        _network: &str,
    ) -> Result<Decimal, String> {
        let timestamp = epoch_secs().to_string();
        let query = format!("currency={}", currency);
        let sign_payload = format!("GET/api/v4/withdrawal_fee?{}{}", query, timestamp);
        let signature = hmac_hex(&creds.api_secret, &sign_payload);

        let url = format!("{}/api/v4/withdrawal_fee?{}", base_url, query);

        let resp = self
            .http_client
            .get(&url)
            .header("KEY", &creds.api_key)
            .header("SIGN", &signature)
            .header("Timestamp", &timestamp)
            .send()
            .await
            .map_err(|e| format!("GateIO fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("GateIO fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("GateIO fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("GateIO fee JSON: {}", e))?;
        v.get("fee")
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| "GateIO fee response missing fee".to_string())
    }

    // ══════════════════════════════════════════════════════════════════════
    //  KuCoin (id=4) — POST /api/v1/withdrawals
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_kucoin(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no KuCoin credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no KuCoin REST URL")?;

        let body_map = json!({
            "currency": req.currency,
            "amount": req.amount.to_string(),
            "address": req.address,
            "chain": format!("{}_{}", req.network, req.network),
            "memo": "",
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("KuCoin body serialize: {}", e))?;

        let timestamp = epoch_millis().to_string();
        let method = "POST";
        let path = "/api/v1/withdrawals";
        let preimage = format!("{}{}{}{}", timestamp, method, path, body_str);
        let signature = hmac_base64(&creds.api_secret, &preimage);

        // KuCoin also signs the passphrase separately.
        let passphrase = creds.passphrase.as_deref().unwrap_or("");
        let passphrase_signature = hmac_base64(&creds.api_secret, passphrase);

        let url = format!("{}{}", base_url, path);

        let resp = self
            .http_client
            .post(&url)
            .header("KC-API-KEY", &creds.api_key)
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase_signature)
            .header("KC-API-KEY-VERSION", "2")
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("KuCoin withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("KuCoin withdrawal read body: {}", e))?;

        parse_kucoin_withdrawal_response(&status, &body)
    }

    async fn fee_kucoin(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        network: &str,
    ) -> Result<Decimal, String> {
        let timestamp = epoch_millis().to_string();
        let method = "GET";
        let path = "/api/v1/currencies";
        let query = format!("currency={}", currency);
        let preimage = format!("{}{}{}{}", timestamp, method, path, query);
        let signature = hmac_base64(&creds.api_secret, &preimage);

        let passphrase = creds.passphrase.as_deref().unwrap_or("");
        let passphrase_signature = hmac_base64(&creds.api_secret, passphrase);

        let url = format!("{}{}?{}", base_url, path, query);

        let resp = self
            .http_client
            .get(&url)
            .header("KC-API-KEY", &creds.api_key)
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase_signature)
            .header("KC-API-KEY-VERSION", "2")
            .send()
            .await
            .map_err(|e| format!("KuCoin fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("KuCoin fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("KuCoin fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("KuCoin fee JSON: {}", e))?;
        // Find the matching chain in the currency info array.
        let chain_name = format!("{}_{}", network, network);
        v.get("data")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.first())
            .and_then(|cur| cur.get("chains"))
            .and_then(|chains| chains.as_array())
            .and_then(|arr| {
                arr.iter().find(|c| {
                    c.get("chainName")
                        .and_then(|n| n.as_str())
                        .map(|n| n.contains(network))
                        .unwrap_or(false)
                })
            })
            .and_then(|c| c.get("withdrawalMinFee"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| {
                format!(
                    "KuCoin fee response missing withdrawalMinFee for {} on {}",
                    currency, network
                )
            })
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Bitget (id=6) — POST /api/v2/spot/wallet/withdrawal
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_bitget(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no Bitget credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no Bitget REST URL")?;

        let body_map = json!({
            "coin": req.currency,
            "chain": req.network,
            "address": req.address,
            "amount": req.amount.to_string(),
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("Bitget body serialize: {}", e))?;

        let timestamp = epoch_millis().to_string();
        let passphrase = creds.passphrase.as_deref().unwrap_or("");
        let preimage = format!("{}{}{}", timestamp, passphrase, body_str);
        let signature = hmac_base64(&creds.api_secret, &preimage);

        let url = format!("{}/api/v2/spot/wallet/withdrawal", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("ACCESS-KEY", &creds.api_key)
            .header("ACCESS-SIGN", &signature)
            .header("ACCESS-TIMESTAMP", &timestamp)
            .header("ACCESS-PASSPHRASE", passphrase)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("Bitget withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("Bitget withdrawal read body: {}", e))?;

        parse_bitget_withdrawal_response(&status, &body)
    }

    async fn fee_bitget(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        network: &str,
    ) -> Result<Decimal, String> {
        let timestamp = epoch_millis().to_string();
        let passphrase = creds.passphrase.as_deref().unwrap_or("");
        let preimage = format!("{}{}GET/api/v2/spot/wallet/coins?coin={}", timestamp, passphrase, currency);
        let signature = hmac_base64(&creds.api_secret, &preimage);

        let url = format!(
            "{}/api/v2/spot/wallet/coins?coin={}",
            base_url, currency
        );

        let resp = self
            .http_client
            .get(&url)
            .header("ACCESS-KEY", &creds.api_key)
            .header("ACCESS-SIGN", &signature)
            .header("ACCESS-TIMESTAMP", &timestamp)
            .header("ACCESS-PASSPHRASE", passphrase)
            .send()
            .await
            .map_err(|e| format!("Bitget fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("Bitget fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("Bitget fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("Bitget fee JSON: {}", e))?;
        v.get("data")
            .and_then(|d| d.get("chains"))
            .and_then(|chains| chains.as_array())
            .and_then(|arr| {
                arr.iter().find(|c| {
                    c.get("chain")
                        .and_then(|ch| ch.as_str())
                        .map(|ch| ch.eq_ignore_ascii_case(network))
                        .unwrap_or(false)
                })
            })
            .and_then(|c| c.get("withdrawFee"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| {
                format!(
                    "Bitget fee response missing withdrawFee for {} on {}",
                    currency, network
                )
            })
    }

    // ══════════════════════════════════════════════════════════════════════
    //  HTX (id=9) — POST /v1/dw/withdraw/api/create
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_htx(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no HTX credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no HTX REST URL")?;

        let body_map = json!({
            "currency": req.currency,
            "addr": req.address,
            "amount": req.amount.to_string(),
            "fee": "0",  // HTX auto-deducts fee
            "chain": req.network,
        });
        let body_str = serde_json::to_string(&body_map)
            .map_err(|e| format!("HTX body serialize: {}", e))?;

        let timestamp = epoch_millis().to_string();
        let preimage = format!("{}{}{}", timestamp, "POST", body_str);
        let signature = hmac_hex(&creds.api_secret, &preimage);

        let url = format!("{}/v1/dw/withdraw/api/create", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("AccessKeyId", &creds.api_key)
            .header("Signature", &signature)
            .header("Timestamp", &timestamp)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("HTX withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("HTX withdrawal read body: {}", e))?;

        parse_htx_withdrawal_response(&status, &body)
    }

    async fn fee_htx(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        _network: &str,
    ) -> Result<Decimal, String> {
        let timestamp = epoch_millis().to_string();
        let method = "GET";
        let path = format!("/v2/reference/currencies/{}", currency);
        let preimage = format!("{}{}{}", timestamp, method, "");
        let signature = hmac_hex(&creds.api_secret, &preimage);

        let url = format!("{}{}", base_url, path);

        let resp = self
            .http_client
            .get(&url)
            .header("AccessKeyId", &creds.api_key)
            .header("Signature", &signature)
            .header("Timestamp", &timestamp)
            .send()
            .await
            .map_err(|e| format!("HTX fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("HTX fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("HTX fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("HTX fee JSON: {}", e))?;
        v.get("data")
            .and_then(|d| d.get("chains"))
            .and_then(|chains| chains.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("transactFeeWithdraw"))
            .and_then(|f| f.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .ok_or_else(|| {
                format!(
                    "HTX fee response missing transactFeeWithdraw for {}",
                    currency
                )
            })
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Kraken (id=10) — POST /0/private/Withdraw
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_kraken(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no Kraken credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no Kraken REST URL")?;

        // Kraken uses nonce-based form-encoded POST.
        // The key is the Kraken asset name (e.g. "USDT").
        // Kraken Withdraw endpoint: asset, key (address), amount
        let nonce = epoch_millis().to_string();
        let mut form_params: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        form_params.insert("nonce".into(), nonce.clone());
        form_params.insert("asset".into(), req.currency.clone());
        form_params.insert("key".into(), req.address.clone());
        form_params.insert("amount".into(), req.amount.to_string());

        let form_body: String = form_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        // Kraken signs: HMAC-SHA256(secret, path + SHA256(nonce + body))
        // First, compute SHA256(nonce + form_body)
        use ring::digest;
        let nonce_body = format!("{}{}", nonce, form_body);
        let hash = digest::digest(&digest::SHA256, nonce_body.as_bytes());
        let hash_hex = hex::encode(hash.as_ref());

        // Then, sign path + hash_hex
        let sign_path = "/0/private/Withdraw";
        let preimage = format!("{}{}", sign_path, hash_hex);
        let signature_bytes = {
            let key = hmac::Key::new(hmac::HMAC_SHA256, creds.api_secret.as_bytes());
            hmac::sign(&key, preimage.as_bytes())
        };
        let signature = base64::engine::general_purpose::STANDARD.encode(signature_bytes.as_ref());

        let url = format!("{}{}", base_url, sign_path);

        let resp = self
            .http_client
            .post(&url)
            .header("API-Key", &creds.api_key)
            .header("API-Sign", &signature)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| format!("Kraken withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("Kraken withdrawal read body: {}", e))?;

        parse_kraken_withdrawal_response(&status, &body)
    }

    async fn fee_kraken(
        &self,
        base_url: &str,
        creds: &ExchangeCredentials,
        currency: &str,
        _network: &str,
    ) -> Result<Decimal, String> {
        let nonce = epoch_millis().to_string();
        let form_body = format!("nonce={}&asset={}", nonce, currency);

        use ring::digest;
        let nonce_body = format!("{}{}", nonce, format!("asset={}", currency));
        let hash = digest::digest(&digest::SHA256, nonce_body.as_bytes());
        let hash_hex = hex::encode(hash.as_ref());

        let sign_path = "/0/private/WithdrawInfo";
        let preimage = format!("{}{}", sign_path, hash_hex);
        let signature_bytes = {
            let key = hmac::Key::new(hmac::HMAC_SHA256, creds.api_secret.as_bytes());
            hmac::sign(&key, preimage.as_bytes())
        };
        let signature = base64::engine::general_purpose::STANDARD.encode(signature_bytes.as_ref());

        let url = format!("{}{}", base_url, sign_path);

        let resp = self
            .http_client
            .post(&url)
            .header("API-Key", &creds.api_key)
            .header("API-Sign", &signature)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| format!("Kraken fee query failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("Kraken fee read: {}", e))?;

        if !status.is_success() {
            return Err(format!("Kraken fee HTTP {}: {}", status, body));
        }

        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("Kraken fee JSON: {}", e))?;
        v.get("result")
            .and_then(|r| r.get("limit"))
            .and_then(|l| l.as_str())
            .and_then(|s| s.parse::<Decimal>().ok())
            .or_else(|| {
                // Some Kraken fee responses put fee info in "fee"
                v.get("result")
                    .and_then(|r| r.get("fee"))
                    .and_then(|f| f.as_str())
                    .and_then(|s| s.parse::<Decimal>().ok())
            })
            .ok_or_else(|| {
                format!(
                    "Kraken fee response missing fee/limit for {}",
                    currency
                )
            })
    }

    // ══════════════════════════════════════════════════════════════════════
    //  MEXC (id=15) — Binance-compatible: POST /api/v3/capital/withdraw/apply
    // ══════════════════════════════════════════════════════════════════════

    async fn withdraw_mexc(
        &self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalResult, String> {
        // MEXC uses the same Binance-style signing but with a different endpoint.
        let creds = self
            .credentials
            .get(&req.exchange_id)
            .ok_or("no MEXC credentials")?;
        let base_url = self
            .rest_urls
            .get(&req.exchange_id)
            .ok_or("no MEXC REST URL")?;

        let mut params: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        params.insert("coin".into(), req.currency.clone());
        params.insert("network".into(), req.network.clone());
        params.insert("address".into(), req.address.clone());
        params.insert("amount".into(), req.amount.to_string());

        let base_query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let ts = epoch_millis();
        let query_with_ts = format!("{}&timestamp={}", base_query, ts);
        let signature = hmac_hex(&creds.api_secret, &query_with_ts);
        let signed_body = format!("{}&signature={}", query_with_ts, signature);

        let url = format!("{}/api/v3/capital/withdraw/apply", base_url);

        let resp = self
            .http_client
            .post(&url)
            .header("X-MBX-APIKEY", &creds.api_key)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await
            .map_err(|e| format!("MEXC withdrawal request failed: {}", e))?;

        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .map_err(|e| format!("MEXC withdrawal read body: {}", e))?;

        // MEXC follows Binance response format
        parse_binance_withdrawal_response(&status, &body)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Response parsers (per-exchange)
// ═══════════════════════════════════════════════════════════════════════════

fn parse_binance_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    if !status.is_success() {
        let error_msg = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("msg").and_then(|m| m.as_str()).map(String::from))
            .unwrap_or_else(|| body.to_string());
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Binance withdrawal JSON: {}", e))?;

    let withdrawal_id = v
        .get("id")
        .map(|id| id.to_string());

    let fee = v
        .get("transactionFee")
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_bybit_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Bybit withdrawal JSON: {}", e))?;

    let ret_code = v
        .get("retCode")
        .and_then(|r| r.as_i64())
        .unwrap_or(-1);

    if ret_code != 0 || !status.is_success() {
        let error_msg = v
            .get("retMsg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let withdrawal_id = v
        .get("result")
        .and_then(|r| r.get("id"))
        .map(|id| id.to_string());

    let fee = v
        .get("result")
        .and_then(|r| r.get("fee"))
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_okx_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("OKX withdrawal JSON: {}", e))?;

    let code = v
        .get("code")
        .and_then(|c| c.as_str())
        .unwrap_or("5");

    if code != "0" || !status.is_success() {
        let error_msg = v
            .get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let withdrawal_id = v
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("wdId"))
        .map(|id| id.to_string());

    let fee = v
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("fee"))
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_gateio_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    if !status.is_success() {
        let error_msg = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
            .unwrap_or_else(|| body.to_string());
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("GateIO withdrawal JSON: {}", e))?;

    let withdrawal_id = v
        .get("id")
        .map(|id| id.to_string());

    let fee = v
        .get("fee")
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_kucoin_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("KuCoin withdrawal JSON: {}", e))?;

    let code = v
        .get("code")
        .and_then(|c| as_u64_safe(c))
        .unwrap_or(200000);

    if code != 200000 || !status.is_success() {
        let error_msg = v
            .get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let withdrawal_id = v
        .get("data")
        .and_then(|d| {
            if d.is_string() {
                d.as_str().map(String::from)
            } else if d.is_object() {
                d.get("withdrawalId")
                    .or_else(|| d.get("id"))
                    .map(|id| id.to_string())
            } else {
                Some(d.to_string())
            }
        });

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee: Decimal::ZERO, // KuCoin doesn't return fee in the response
        error: None,
    })
}

fn parse_bitget_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Bitget withdrawal JSON: {}", e))?;

    let code = v
        .get("code")
        .and_then(|c| c.as_str())
        .unwrap_or("00000");

    if code != "00000" || !status.is_success() {
        let error_msg = v
            .get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let withdrawal_id = v
        .get("data")
        .map(|id| id.to_string());

    let fee = v
        .get("data")
        .and_then(|d| d.get("fee"))
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_htx_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("HTX withdrawal JSON: {}", e))?;

    let code = v
        .get("code")
        .and_then(|c| c.as_i64())
        .unwrap_or(-1);

    if code != 200 || !status.is_success() {
        let error_msg = v
            .get("message")
            .and_then(|m| m.as_str())
            .or_else(|| v.get("msg").and_then(|m| m.as_str()))
            .unwrap_or("unknown error")
            .to_string();
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(error_msg),
        });
    }

    let withdrawal_id = v
        .get("data")
        .map(|id| id.to_string());

    let fee = v
        .get("data")
        .and_then(|d| d.get("fee"))
        .and_then(|f| f.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee,
        error: None,
    })
}

fn parse_kraken_withdrawal_response(
    status: &reqwest::StatusCode,
    body: &str,
) -> Result<WithdrawalResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Kraken withdrawal JSON: {}", e))?;

    // Kraken wraps errors in an "error" array.
    let errors = v
        .get("error")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !errors.is_empty() || !status.is_success() {
        return Ok(WithdrawalResult {
            success: false,
            withdrawal_id: None,
            fee: Decimal::ZERO,
            error: Some(errors.join("; ")),
        });
    }

    let withdrawal_id = v
        .get("result")
        .and_then(|r| r.get("refid"))
        .map(|id| id.to_string());

    Ok(WithdrawalResult {
        success: true,
        withdrawal_id,
        fee: Decimal::ZERO, // Kraken deducts fee from withdrawal amount
        error: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  Convenience: execute_rebalance_transfer
// ═══════════════════════════════════════════════════════════════════════════

/// Convenience function that logs the rebalance transfer and delegates
/// to `WithdrawalExecutor::execute_withdrawal`.
///
/// This is the recommended call-site for the rebalancer module to use
/// when it detects capital drift and needs to execute a transfer.
pub async fn execute_rebalance_transfer(
    executor: &WithdrawalExecutor,
    from_exchange: u16,
    to_exchange: u16,
    currency: &str,
    amount: Decimal,
    address: &str,
    network: &str,
) -> Result<WithdrawalResult, String> {
    let from_name = exchange_name_by_id(from_exchange);
    let to_name = exchange_name_by_id(to_exchange);

    info!(
        from = from_name,
        to = to_name,
        currency = currency,
        amount = %amount,
        network = network,
        "Initiating rebalance transfer"
    );

    let req = WithdrawalRequest {
        exchange_id: from_exchange,
        currency: currency.to_owned(),
        amount,
        address: address.to_owned(),
        network: network.to_owned(),
        client_order_id: Some(format!(
            "rebal_{}_{}_{}",
            from_exchange,
            to_exchange,
            epoch_millis()
        )),
    };

    let result = executor.execute_withdrawal(&req).await?;

    if result.success {
        info!(
            from = from_name,
            to = to_name,
            withdrawal_id = ?result.withdrawal_id,
            fee = %result.fee,
            "Rebalance transfer accepted — blockchain transit in progress"
        );
    } else {
        error!(
            from = from_name,
            to = to_name,
            error = ?result.error,
            "Rebalance transfer REJECTED"
        );
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helper functions
// ═══════════════════════════════════════════════════════════════════════════

/// HMAC-SHA256 signing returning hex-encoded signature.
fn hmac_hex(secret: &str, message: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    hex::encode(signature.as_ref())
}

/// HMAC-SHA256 signing returning base64-encoded signature.
fn hmac_base64(secret: &str, message: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
}

/// Current UNIX epoch in milliseconds.
fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Current UNIX epoch in seconds.
fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Map common network names to GateIO short chain codes.
fn gateio_chain_code(network: &str) -> String {
    let upper = network.to_uppercase();
    match upper.as_str() {
        "ARBITRUM ONE" | "ARBITRUM" | "ARB" => "ARBITRUM_ARB".to_string(),
        "ERC20" | "ETH" | "ETHEREUM" => "ETH".to_string(),
        "TRC20" | "TRON" | "TRX" => "TRC20".to_string(),
        "BSC" | "BEP20" => "BSC".to_string(),
        "SOL" | "SOLANA" => "SOL".to_string(),
        "OPTIMISM" | "OP" => "OPTIMISM".to_string(),
        "POLYGON" | "MATIC" => "POLYGON".to_string(),
        _ => upper,
    }
}

/// Safely extract a u64 from a JSON value (handles both string and number).
fn as_u64_safe(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()
    } else {
        v.as_u64()
    }
}
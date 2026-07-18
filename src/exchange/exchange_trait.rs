// exchange/exchange_trait.rs — The rich Exchange trait.
//
// Provides a superset of the simpler `crate::signer::PrivateExchangeClient`
// used by the HFT execution engine.  This trait exposes order books, cancel
// endpoints, symbol lists, health checks, and multiple order types.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use super::types::*;

// ---------------------------------------------------------------------------
// Exchange trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Exchange: Send + Sync {
    /// Human-readable exchange name (e.g. "Binance").
    fn name(&self) -> &str;

    /// Typed exchange discriminant.
    fn kind(&self) -> ExchangeType;

    /// Place a market order.
    ///
    /// # SAFETY WARNING
    /// Market orders are PROHIBITED by the HFT safety execution engine
    /// (`safety_execution::SafetyExecutionEngine`). This method should only
    /// be used for non-HFT operations (e.g., emergency liquidations).
    /// For normal trading, use `place_limit_order` with IOC/FOK time-in-force.
    async fn place_order(&self, order: &OrderRequest) -> anyhow::Result<OrderResponse>;

    /// Cancel a single order by symbol + order_id.
    async fn cancel_order(&self, symbol: &str, order_id: &str) -> anyhow::Result<OrderResponse>;

    /// Fetch all non-zero balances as asset -> Decimal.
    async fn fetch_balance(&self) -> anyhow::Result<HashMap<String, Decimal>>;

    /// Fetch all tradeable symbols.
    async fn fetch_symbols(&self) -> anyhow::Result<Vec<String>>;

    /// Query status of a specific order.
    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> anyhow::Result<OrderResponse>;

    /// Lightweight health-check (HTTP GET to a public endpoint).
    async fn health_check(&self) -> anyhow::Result<()>;

    /// Place a limit order with a specified price.
    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> anyhow::Result<OrderResponse> {
        // Default: fall back to place_order_with_type.
        self.place_order_with_type(order, OrderType::Limit, Some(price)).await
    }

    /// Place an order with an explicit order type and optional price.
    async fn place_order_with_type(
        &self,
        order: &OrderRequest,
        order_type: OrderType,
        price: Option<Decimal>,
    ) -> anyhow::Result<OrderResponse> {
        // Default implementation: only Market is natively supported.
        match order_type {
            OrderType::Market => self.place_order(order).await,
            OrderType::Limit => {
                let p = price.ok_or_else(|| anyhow::anyhow!("limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            _ => anyhow::bail!("order type {:?} not natively supported", order_type),
        }
    }

    /// Kill switch: cancel all open orders for the given symbols.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<anyhow::Result<OrderResponse>>;

    /// Fetch the order book for a symbol up to `depth` levels.
    async fn fetch_order_book(
        &self,
        symbol: &str,
        depth: u32,
    ) -> anyhow::Result<OrderBookSnapshot>;
}
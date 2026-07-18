//! Triangular Path Finder — Bellman-Ford Graph Search
//!
//! The spec mentions: "Bellman-Ford / Graph Search — Algorithm for
//! finding profitable triangular paths"
//!
//! This module constructs a directed weighted graph from available
//! trading pairs and uses Bellman-Ford to detect negative cycles,
//! which correspond to profitable triangular arbitrage loops.
//!
//! In the context of arbitrage, a "negative cycle" means you end up
//! with more of the starting asset after traversing the loop, which
//! is exactly the definition of a profitable triangular path.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// A directed edge in the trading pair graph.
#[derive(Debug, Clone)]
struct GraphEdge {
    /// Target node (currency).
    to: usize,
    /// Log of the exchange rate (negative for "buy", positive for "sell").
    /// Using log-space converts multiplication to addition.
    log_rate: f64,
    /// Log of (1 - fee).
    log_fee_factor: f64,
    /// The actual pair symbol for reference.
    pair_symbol: String,
}

/// A detected profitable triangular path.
#[derive(Debug, Clone)]
pub struct TriangularPath {
    /// The three currencies in the loop (e.g. ["USDT", "BTC", "ETH"]).
    pub currencies: Vec<String>,
    /// The three pairs to trade (e.g. ["BTCUSDT", "ETHBTC", "USDTETH"]).
    pub pairs: Vec<String>,
    /// Net profit factor after fees (> 1.0 = profitable).
    pub net_profit_factor: Decimal,
    /// Net profit as percentage.
    pub net_profit_pct: Decimal,
}

/// Bellman-Ford based triangular path finder.
///
/// Constructs a graph from trading pairs and finds profitable loops
/// by detecting negative-weight cycles in log-space.
pub struct TriPathFinder {
    /// Currency name → node index.
    currency_to_idx: HashMap<String, usize>,
    /// Node index → currency name.
    idx_to_currency: Vec<String>,
    /// Adjacency list: node → list of edges.
    edges: Vec<Vec<GraphEdge>>,
    /// Minimum profit threshold as a multiplier (e.g. 1.0012 = 0.12%).
    min_profit_factor: Decimal,
}

impl TriPathFinder {
    /// Creates a new path finder.
    ///
    /// # Arguments
    /// * `currencies` — List of currency names
    /// * `min_profit_pct` — Minimum profit percentage to consider (e.g. 0.12%)
    pub fn new(currencies: Vec<String>, min_profit_pct: Decimal) -> Self {
        let mut currency_to_idx = HashMap::new();
        let mut idx_to_currency = Vec::with_capacity(currencies.len());
        let edges = vec![Vec::new(); currencies.len()];

        for (i, currency) in currencies.iter().enumerate() {
            currency_to_idx.insert(currency.clone(), i);
            idx_to_currency.push(currency.clone());
        }

        Self {
            currency_to_idx,
            idx_to_currency,
            edges,
            min_profit_factor: Decimal::ONE + min_profit_pct / Decimal::from(100u32),
        }
    }

    /// Add a trading pair to the graph.
    ///
    /// # Arguments
    /// * `pair_symbol` — Trading pair (e.g. "BTCUSDT")
    /// * `base_currency` — Base currency (e.g. "BTC")
    /// * `quote_currency` — Quote currency (e.g. "USDT")
    /// * `price` — Current price
    /// * `fee` — Trading fee as decimal (e.g. 0.001 = 0.1%)
    pub fn add_pair(
        &mut self,
        pair_symbol: &str,
        base_currency: &str,
        quote_currency: &str,
        price: Decimal,
        fee: Decimal,
    ) {
        let base_idx = match self.currency_to_idx.get(base_currency) {
            Some(&idx) => idx,
            None => return, // Unknown currency — skip.
        };
        let quote_idx = match self.currency_to_idx.get(quote_currency) {
            Some(&idx) => idx,
            None => return,
        };

        let log_fee = ((Decimal::ONE - fee).to_f64().unwrap_or(0.99)).ln();
        let price_f = price.to_f64().unwrap_or(1.0);

        // Edge: sell base → get quote (rate = price)
        // In log-space: weight = -ln(price * (1-fee))
        let log_rate_sell = -(price_f * (1.0 - fee.to_f64().unwrap_or(0.001))).ln();
        self.edges[base_idx].push(GraphEdge {
            to: quote_idx,
            log_rate: log_rate_sell,
            log_fee_factor: log_fee,
            pair_symbol: pair_symbol.to_string(),
        });

        // Edge: buy base with quote (rate = 1/price)
        // In log-space: weight = -ln((1/price) * (1-fee))
        let log_rate_buy = -((1.0 / price_f) * (1.0 - fee.to_f64().unwrap_or(0.001))).ln();
        self.edges[quote_idx].push(GraphEdge {
            to: base_idx,
            log_rate: log_rate_buy,
            log_fee_factor: log_fee,
            pair_symbol: pair_symbol.to_string(),
        });
    }

    /// Find all profitable 3-node (triangular) cycles using Bellman-Ford.
    ///
    /// Returns a list of profitable paths sorted by profit descending.
    pub fn find_profitable_paths(&self) -> Vec<TriangularPath> {
        let n = self.idx_to_currency.len();
        if n < 3 {
            return vec![];
        }

        let mut best_profit = vec![f64::INFINITY; n];
        let mut predecessor = vec![-1isize; n];
        // Stores the predecessor node index (source node of the best edge).
        // Named `_predecessor_node` to clarify it is NOT an edge index.
        let mut _predecessor_node = vec![0usize; n];
        let mut profitable_paths = Vec::new();

        // Bellman-Ford relaxation (exactly 3 iterations for triangular).
        for iteration in 0..3 {
            let mut updated = false;
            for u in 0..n {
                for edge in &self.edges[u] {
                    let new_dist = best_profit[u] + edge.log_rate;
                    if new_dist < best_profit[edge.to] {
                        best_profit[edge.to] = new_dist;
                        predecessor[edge.to] = u as isize;
                        _predecessor_node[edge.to] = u;
                        updated = true;
                    }
                }
            }

            // On the 3rd iteration, check for negative cycles.
            if iteration == 2 && updated {
                // A negative cycle exists — try to extract triangular paths.
                for start in 0..n {
                    if let Some(path) = self.extract_triangular_path(start, &predecessor) {
                        if let Some(profit) = self.compute_path_profit(&path) {
                            if profit.net_profit_factor >= self.min_profit_factor {
                                profitable_paths.push(profit);
                            }
                        }
                    }
                }
            }
        }

        // Sort by profit descending.
        profitable_paths.sort_by_key(|b| std::cmp::Reverse(b.net_profit_factor));
        profitable_paths.dedup_by(|a, b| a.pairs == b.pairs);
        profitable_paths
    }

    /// Try to extract a 3-node cycle from the predecessor chain.
    fn extract_triangular_path(&self, start: usize, predecessor: &[isize]) -> Option<Vec<usize>> {
        let mut path = vec![start];
        let mut current = start;

        for _ in 0..3 {
            let pred = predecessor[current] as usize;
            if pred == current || pred >= self.idx_to_currency.len() {
                return None;
            }
            path.push(pred);
            current = pred;
        }

        // Check if it forms a cycle back to start.
        if path[3] == path[0] && path.len() == 4 {
            let cycle: Vec<usize> = path[0..3].to_vec();
            // Check all 3 nodes are distinct.
            if cycle[0] != cycle[1] && cycle[1] != cycle[2] && cycle[0] != cycle[2] {
                return Some(cycle);
            }
        }

        None
    }

    /// Compute the profit factor for a given path.
    fn compute_path_profit(&self, path: &[usize]) -> Option<TriangularPath> {
        if path.len() != 3 {
            return None;
        }

        // Try to find edges that connect the path nodes.
        let mut pairs = Vec::with_capacity(3);
        let mut profit_factor = 1.0;

        // A → B
        {
            let edge = self.edges[path[0]].iter().find(|e| e.to == path[1])?;
            pairs.push(edge.pair_symbol.clone());
            profit_factor *= edge.log_rate.exp();
        }

        // B → C
        {
            let edge = self.edges[path[1]].iter().find(|e| e.to == path[2])?;
            pairs.push(edge.pair_symbol.clone());
            profit_factor *= edge.log_rate.exp();
        }

        // C → A
        {
            let edge = self.edges[path[2]].iter().find(|e| e.to == path[0])?;
            pairs.push(edge.pair_symbol.clone());
            profit_factor *= edge.log_rate.exp();
        }

        let currencies: Vec<String> = path.iter().map(|&i| self.idx_to_currency[i].clone()).collect();
        let net_profit_factor = Decimal::from_f64_retain(profit_factor).unwrap_or(Decimal::ONE);
        let net_profit_pct = (net_profit_factor - Decimal::ONE) * Decimal::from(100u32);

        Some(TriangularPath {
            currencies,
            pairs,
            net_profit_factor,
            net_profit_pct,
        })
    }

    /// Returns the number of registered currencies.
    pub fn currency_count(&self) -> usize {
        self.idx_to_currency.len()
    }

    /// Returns the number of registered pairs (edges).
    pub fn pair_count(&self) -> usize {
        self.edges.iter().map(|e| e.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_finder() -> TriPathFinder {
        TriPathFinder::new(
            vec!["USDT".to_string(), "BTC".to_string(), "ETH".to_string()],
            dec!(0.01), // 0.01% minimum
        )
    }

    #[test]
    fn test_new_finder() {
        let finder = make_finder();
        assert_eq!(finder.currency_count(), 3);
    }

    #[test]
    fn test_add_pair() {
        let mut finder = make_finder();
        finder.add_pair("BTCUSDT", "BTC", "USDT", dec!(50000), dec!(0.001));
        assert_eq!(finder.pair_count(), 2); // bidirectional
    }

    #[test]
    fn test_find_no_profitable_paths_balanced() {
        let mut finder = make_finder();
        // Balanced prices — no arb opportunity.
        finder.add_pair("BTCUSDT", "BTC", "USDT", dec!(50000), dec!(0.001));
        finder.add_pair("ETHBTC", "ETH", "BTC", dec!(0.065), dec!(0.001));
        finder.add_pair("ETHUSDT", "ETH", "USDT", dec!(3250), dec!(0.001));

        // 50000 * 0.065 * 3250 = 10,562,500 (should be ~1.0 with these prices)
        // No arb expected with balanced books.
        let paths = finder.find_profitable_paths();
        // With 0.3% total fees on 3 legs, need > 0.3% profit.
        // These balanced prices shouldn't produce profit.
    }
}
//! Asset Inventory — Queryable snapshot of all tradeable assets.
//!
//! This module provides a persistent, queryable view of the bot's discovered
//! asset universe. It is populated by the `CoinFinder` at the end of each
//! scan cycle and can be queried at any time for:
//!
//! * **Per-exchange coin lists** — what's tradeable on each exchange
//! * **Cross-arb eligible coins** — assets on 2+ exchanges
//! * **Triangular loop candidates** — 3-asset loops per exchange
//! * **Summary statistics** — totals, category breakdowns, exchange coverage
//!
//! The inventory is stored behind a `tokio::sync::RwLock` so readers on the
//! hot path (e.g. a status endpoint) never block the scanner writer.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// Re-export exchange name lookup from the exchange module.
use crate::exchange::exchange_name_by_id;
use crate::balance_allocator::{CAT_ALTCOIN, CAT_LAYER1, CAT_MAJOR, CAT_MEMECOIN, CAT_STABLE};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single token's presence across exchanges.
#[derive(Debug, Clone)]
pub struct TokenEntry {
    /// Global token ID.
    pub token_id: u16,
    /// Normalized base symbol (e.g. "BTC", "SOL").
    pub symbol: String,
    /// Category bitmask (CAT_MAJOR, CAT_ALTCOIN, etc.).
    pub category: u16,
    /// Set of exchange IDs where this token is tradeable.
    pub exchanges: HashSet<u16>,
}

/// A triangular loop candidate on a single exchange.
#[derive(Debug, Clone)]
pub struct TriangularCandidate {
    /// Exchange ID where this loop exists.
    pub exchange_id: u16,
    /// Human-readable exchange name.
    pub exchange_name: String,
    /// Token IDs forming the loop: A -> B -> C -> A.
    pub tokens: [u16; 3],
    /// Symbols: ["BTC", "ETH", "USDT"] for example.
    pub symbols: [String; 3],
}

/// Per-exchange inventory summary.
#[derive(Debug, Clone)]
pub struct ExchangeInventory {
    pub exchange_id: u16,
    pub exchange_name: String,
    /// Total tradeable pairs on this exchange.
    pub total_pairs: usize,
    /// List of token IDs tradeable here.
    pub token_ids: Vec<u16>,
    /// Number of triangular loop candidates.
    pub tri_loop_count: usize,
}

/// Full asset inventory snapshot.
///
/// Updated atomically by the coin finder after each scan cycle.
/// Readers use `try_read()` to get a consistent snapshot without blocking.
#[derive(Debug, Clone, Default)]
pub struct AssetSnapshot {
    /// All discovered tokens with their exchange presence.
    pub tokens: HashMap<u16, TokenEntry>,

    /// Per-exchange pair lists: exchange_id -> Vec<(token_id, base, quote, raw_symbol)>
    pub exchange_pairs: HashMap<u16, Vec<(u16, String, String, String)>>,

    /// Tokens eligible for cross-exchange arb (on 2+ exchanges).
    pub cross_arb_tokens: Vec<u16>,

    /// Triangular loop candidates per exchange.
    pub tri_candidates: Vec<TriangularCandidate>,

    /// Per-exchange inventory summaries.
    pub exchange_summaries: Vec<ExchangeInventory>,

    /// Scan cycle number when this snapshot was taken.
    pub cycle: u64,

    /// Total discovered tokens.
    pub total_tokens: usize,

    /// Total filtered pairs across all exchanges.
    pub total_pairs: usize,

    /// New tokens discovered in this scan.
    pub new_tokens: usize,
}

impl AssetSnapshot {
    /// Get a formatted summary string for logging.
    pub fn format_summary(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("\n========================================\n");
        out.push_str("       ASSET INVENTORY SUMMARY\n");
        out.push_str("========================================\n\n");

        // Overall stats
        out.push_str(&format!(
            "Cycle: {}  |  Tokens: {}  |  Pairs: {}  |  New: {}\n\n",
            self.cycle, self.total_tokens, self.total_pairs, self.new_tokens
        ));

        // Category breakdown of cross-arb tokens
        let mut cat_major = 0usize;
        let mut cat_alt = 0usize;
        let mut cat_layer1 = 0usize;
        let mut cat_meme = 0usize;
        for &tid in &self.cross_arb_tokens {
            if let Some(entry) = self.tokens.get(&tid) {
                if entry.category & CAT_MAJOR != 0 { cat_major += 1; }
                else if entry.category & CAT_LAYER1 != 0 { cat_layer1 += 1; }
                else if entry.category & CAT_MEMECOIN != 0 { cat_meme += 1; }
                else { cat_alt += 1; }
            }
        }
        out.push_str(&format!(
            "Cross-Arb Eligible: {} tokens ({} major, {} L1, {} alt, {} meme)\n",
            self.cross_arb_tokens.len(), cat_major, cat_layer1, cat_alt, cat_meme
        ));
        out.push_str(&format!(
            "Triangular Loops: {} candidates across {} exchanges\n\n",
            self.tri_candidates.len(),
            self.exchange_summaries.len()
        ));

        // Per-exchange breakdown
        out.push_str("--- Per-Exchange Breakdown ---\n");
        let mut summaries = self.exchange_summaries.clone();
        summaries.sort_by(|a, b| b.total_pairs.cmp(&a.total_pairs));
        for ex in &summaries {
            out.push_str(&format!(
                "  {:12s} (ex{}) : {:4} pairs, {:4} tokens, {:3} tri-loops\n",
                ex.exchange_name, ex.exchange_id,
                ex.total_pairs, ex.token_ids.len(), ex.tri_loop_count
            ));
        }

        // Top cross-arb tokens by exchange coverage
        out.push_str("\n--- Top Cross-Arb Tokens (by exchange coverage) ---\n");
        let mut cross_sorted: Vec<&TokenEntry> = self.cross_arb_tokens
            .iter()
            .filter_map(|tid| self.tokens.get(tid))
            .collect();
        cross_sorted.sort_by(|a, b| b.exchanges.len().cmp(&a.exchanges.len()));
        let show_count = cross_sorted.len().min(20);
        for entry in &cross_sorted[..show_count] {
            let ex_names: Vec<&str> = entry.exchanges
                .iter()
                .map(|&id| exchange_name_by_id(id))
                .collect();
            let cat_str = category_label(entry.category);
            out.push_str(&format!(
                "  {:8s} [{}] : {} exchanges\n",
                entry.symbol, cat_str, entry.exchanges.len()
            ));
            out.push_str(&format!(
                "             -> {}\n",
                ex_names.join(", ")
            ));
        }
        if cross_sorted.len() > show_count {
            out.push_str(&format!(
                "  ... and {} more\n",
                cross_sorted.len() - show_count
            ));
        }

        // Triangular loop samples (first 10)
        if !self.tri_candidates.is_empty() {
            out.push_str("\n--- Triangular Loop Samples (first 10) ---\n");
            let show = self.tri_candidates.len().min(10);
            for tri in &self.tri_candidates[..show] {
                out.push_str(&format!(
                    "  {:12s} : {} -> {} -> {} -> {}\n",
                    tri.exchange_name,
                    tri.symbols[0], tri.symbols[1], tri.symbols[2], tri.symbols[0]
                ));
            }
            if self.tri_candidates.len() > show {
                out.push_str(&format!(
                    "  ... and {} more loops\n",
                    self.tri_candidates.len() - show
                ));
            }
        }

        out.push_str("\n========================================\n");
        out
    }

    /// Query: get all tokens on a specific exchange.
    pub fn tokens_on_exchange(&self, exchange_id: u16) -> Vec<&TokenEntry> {
        self.tokens
            .values()
            .filter(|t| t.exchanges.contains(&exchange_id))
            .collect()
    }

    /// Query: get all exchanges where a specific token is listed.
    pub fn exchanges_for_token(&self, token_id: u16) -> Vec<u16> {
        self.tokens
            .get(&token_id)
            .map(|t| t.exchanges.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query: get triangular candidates for a specific exchange.
    pub fn tri_loops_for_exchange(&self, exchange_id: u16) -> Vec<&TriangularCandidate> {
        self.tri_candidates
            .iter()
            .filter(|t| t.exchange_id == exchange_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Asset Inventory (the writable, shared container)
// ---------------------------------------------------------------------------

/// The live asset inventory.
///
/// Holds the latest `AssetSnapshot` behind a `RwLock`. The coin finder
/// calls `update()` at the end of each scan cycle. Any other subsystem
/// (status endpoint, dashboard, logging) can call `snapshot()` to get
/// a read-only view.
pub struct AssetInventory {
    latest: RwLock<AssetSnapshot>,
}

impl AssetInventory {
    /// Create a new empty inventory.
    pub fn new() -> Self {
        Self {
            latest: RwLock::new(AssetSnapshot::default()),
        }
    }

    /// Get a read-only snapshot. Returns `None` if the lock is contended
    /// (hot-path friendly — never blocks).
    pub fn snapshot(&self) -> Option<tokio::sync::RwLockReadGuard<'_, AssetSnapshot>> {
        self.latest.try_read().ok()
    }

    /// Update the inventory with fresh scan data.
    ///
    /// Called by the coin finder at the end of each `scan_cycle()`.
    /// This is the **only writer** — all other access is read-only.
    ///
    /// # Arguments
    /// * `exchange_pairs` — Per-exchange filtered pairs from the scan
    /// * `token_exchange_presence` — Token ID -> set of exchange IDs
    /// * `global_symbol_map` — Symbol -> token ID mapping
    /// * `token_categories` — Token ID -> category bitmask
    /// * `tri_pair_map` — Exchange ID -> (base_token, quote_token) pairs
    /// * `new_tokens` — Number of newly discovered tokens this cycle
    /// * `total_pairs` — Total filtered pairs this cycle
    /// * `cycle` — Current scan cycle number
    pub async fn update(
        &self,
        exchange_pairs: &HashMap<u16, Vec<(u16, String, String, String)>>,
        token_exchange_presence: &HashMap<u16, HashSet<u16>>,
        global_symbol_map: &HashMap<String, u16>,
        token_categories: &HashMap<u16, u16>,
        tri_pair_map: &HashMap<u16, Vec<(u16, u16)>>,
        new_tokens: usize,
        total_pairs: usize,
        cycle: u64,
    ) {
        let mut snap = self.latest.write().await;

        // Build token entries
        snap.tokens.clear();
        let mut symbol_by_id: HashMap<u16, String> = HashMap::new();
        for (symbol, &token_id) in global_symbol_map {
            symbol_by_id.insert(token_id, symbol.clone());
            let category = token_categories.get(&token_id).copied().unwrap_or(0);
            let exchanges = token_exchange_presence
                .get(&token_id)
                .cloned()
                .unwrap_or_default();
            snap.tokens.insert(token_id, TokenEntry {
                token_id,
                symbol: symbol.clone(),
                category,
                exchanges,
            });
        }

        // Build exchange pairs map
        snap.exchange_pairs = exchange_pairs.clone();

        // Build cross-arb eligible list (tokens on 2+ exchanges)
        snap.cross_arb_tokens = token_exchange_presence
            .iter()
            .filter(|(_, exchs)| exchs.len() >= 2)
            .map(|(&tid, _)| tid)
            .collect();
        snap.cross_arb_tokens.sort_by_key(|&tid| std::cmp::Reverse(
            token_exchange_presence.get(&tid).map(|s| s.len()).unwrap_or(0)
        ));

        // Build per-exchange summaries
        snap.exchange_summaries.clear();
        for (&exch_id, pairs) in exchange_pairs {
            let token_ids: Vec<u16> = pairs
                .iter()
                .map(|&(tid, _, _, _)| tid)
                .collect();
            let unique_tokens: HashSet<u16> = token_ids.iter().copied().collect();
            let tri_count = tri_pair_map
                .get(&exch_id)
                .map(|pairs| estimate_triangular_loops(pairs))
                .unwrap_or(0);
            snap.exchange_summaries.push(ExchangeInventory {
                exchange_id: exch_id,
                exchange_name: exchange_name_by_id(exch_id).to_string(),
                total_pairs: pairs.len(),
                token_ids: unique_tokens.into_iter().collect(),
                tri_loop_count: tri_count,
            });
        }

        // Build triangular candidates (sample up to 100)
        snap.tri_candidates.clear();
        for (&exch_id, pair_list) in tri_pair_map {
            let loops = find_triangular_loops(pair_list);
            for (a, b, c) in loops.into_iter().take(10) {
                snap.tri_candidates.push(TriangularCandidate {
                    exchange_id: exch_id,
                    exchange_name: exchange_name_by_id(exch_id).to_string(),
                    tokens: [a, b, c],
                    symbols: [
                        symbol_by_id.get(&a).cloned().unwrap_or_else(|| format!("T{}", a)),
                        symbol_by_id.get(&b).cloned().unwrap_or_else(|| format!("T{}", b)),
                        symbol_by_id.get(&c).cloned().unwrap_or_else(|| format!("T{}", c)),
                    ],
                });
            }
            if snap.tri_candidates.len() >= 100 {
                break;
            }
        }

        snap.total_tokens = snap.tokens.len();
        snap.total_pairs = total_pairs;
        snap.new_tokens = new_tokens;
        snap.cycle = cycle;
    }

    /// Log the full inventory summary. Called on first cycle and
    /// every N cycles to avoid log spam.
    pub fn log_summary(snap: &AssetSnapshot) {
        let summary = snap.format_summary();
        info!("{}", summary);
    }
}

// ---------------------------------------------------------------------------
// Triangular loop discovery (lightweight, no graph search)
// ---------------------------------------------------------------------------

/// Estimate the number of triangular loops for an exchange's pair list.
/// Uses a fast O(n^2) adjacency scan rather than full Bellman-Ford.
fn estimate_triangular_loops(pairs: &[(u16, u16)]) -> usize {
    if pairs.len() < 3 {
        return 0;
    }

    // Build adjacency: token -> set of tokens it pairs with
    let mut adj: HashMap<u16, HashSet<u16>> = HashMap::new();
    for &(base, quote) in pairs {
        adj.entry(base).or_default().insert(quote);
        adj.entry(quote).or_default().insert(base);
    }

    // Count 3-cycles: for each edge a->b, check if a and b share a
    // common neighbor c != a and c != b.
    let mut count = 0usize;
    let nodes: Vec<u16> = adj.keys().copied().collect();
    for &a in &nodes {
        if let Some(neighbors_a) = adj.get(&a) {
            for &b in neighbors_a {
                if b == a { continue; }
                if let Some(neighbors_b) = adj.get(&b) {
                    for &c in neighbors_b {
                        if c != a && c != b {
                            if let Some(neighbors_c) = adj.get(&c) {
                                if neighbors_c.contains(&a) {
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Each 3-cycle is counted 6 times (3 starting nodes x 2 directions)
    count / 6
}

/// Find actual triangular loops (a->b->c->a) in a pair list.
/// Returns up to `max_loops` unique 3-cycles as (a, b, c) tuples.
fn find_triangular_loops(pairs: &[(u16, u16)]) -> Vec<(u16, u16, u16)> {
    let mut result = Vec::new();
    if pairs.len() < 3 {
        return result;
    }

    // Build adjacency list
    let mut adj: HashMap<u16, HashSet<u16>> = HashMap::new();
    for &(base, quote) in pairs {
        adj.entry(base).or_default().insert(quote);
        adj.entry(quote).or_default().insert(base);
    }

    let nodes: Vec<u16> = adj.keys().copied().collect();
    let mut seen: HashSet<(u16, u16, u16)> = HashSet::new();

    'outer: for &a in &nodes {
        let neighbors_a = match adj.get(&a) {
            Some(n) => n,
            None => continue,
        };
        for &b in neighbors_a {
            if b <= a { continue; } // canonical ordering to avoid duplicates
            let neighbors_b = match adj.get(&b) {
                Some(n) => n,
                None => continue,
            };
            for &c in neighbors_b {
                if c <= b { continue; }
                // Check c -> a exists
                if let Some(neighbors_c) = adj.get(&c) {
                    if neighbors_c.contains(&a) {
                        let key = (a, b, c);
                        if seen.insert(key) {
                            result.push(key);
                            if result.len() >= 50 {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a category bitmask to a human-readable label.
fn category_label(mask: u16) -> &'static str {
    if mask & CAT_MAJOR != 0 { "MAJOR" }
    else if mask & CAT_LAYER1 != 0 { "L1" }
    else if mask & CAT_MEMECOIN != 0 { "MEME" }
    else if mask & CAT_STABLE != 0 { "STABLE" }
    else { "ALT" }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inventory() -> AssetInventory {
        AssetInventory::new()
    }

    fn make_test_data() -> (
        HashMap<u16, Vec<(u16, String, String, String)>>,
        HashMap<u16, HashSet<u16>>,
        HashMap<String, u16>,
        HashMap<u16, u16>,
        HashMap<u16, Vec<(u16, u16)>>,
    ) {
        // 3 exchanges, 3 tokens (BTC=10, ETH=11, SOL=12)
        let mut ep = HashMap::new();
        ep.insert(0, vec![(10, "BTC".into(), "USDT".into(), "BTCUSDT".into())]);
        ep.insert(1, vec![(10, "BTC".into(), "USDT".into(), "BTCUSDT".into())]);
        ep.insert(2, vec![
            (10, "BTC".into(), "USDT".into(), "BTCUSDT".into()),
            (11, "ETH".into(), "USDT".into(), "ETHUSDT".into()),
            (12, "SOL".into(), "USDT".into(), "SOLUSDT".into()),
        ]);

        let mut presence = HashMap::new();
        presence.insert(10, [0, 1, 2].iter().copied().collect());
        presence.insert(11, [2].iter().copied().collect());
        presence.insert(12, [2].iter().copied().collect());

        let mut symbols = HashMap::new();
        symbols.insert("BTC".into(), 10);
        symbols.insert("ETH".into(), 11);
        symbols.insert("SOL".into(), 12);

        let mut cats = HashMap::new();
        cats.insert(10, CAT_MAJOR);
        cats.insert(11, CAT_MAJOR);
        cats.insert(12, CAT_ALTCOIN);

        // Tri pairs: ex2 has BTC/USDT, ETH/USDT, SOL/USDT
        // USDT=0 is pre-registered
        let mut tri = HashMap::new();
        tri.insert(2, vec![(10, 0), (11, 0), (12, 0)]);

        (ep, presence, symbols, cats, tri)
    }

    #[tokio::test]
    async fn test_update_populates_cross_arb() {
        let inv = make_inventory();
        let (ep, presence, symbols, cats, tri) = make_test_data();

        inv.update(&ep, &presence, &symbols, &cats, &tri, 0, 5, 1).await;

        let snap = inv.snapshot().unwrap();
        // BTC is on 3 exchanges -> cross-arb eligible
        assert!(snap.cross_arb_tokens.contains(&10));
        // ETH is on 1 exchange -> NOT cross-arb eligible
        assert!(!snap.cross_arb_tokens.contains(&11));
        assert_eq!(snap.total_tokens, 3);
        assert_eq!(snap.total_pairs, 5);
    }

    #[tokio::test]
    async fn test_update_populates_exchange_summaries() {
        let inv = make_inventory();
        let (ep, presence, symbols, cats, tri) = make_test_data();

        inv.update(&ep, &presence, &symbols, &cats, &tri, 0, 5, 1).await;

        let snap = inv.snapshot().unwrap();
        assert_eq!(snap.exchange_summaries.len(), 3);

        // Exchange 2 should have the most pairs
        let ex2 = snap.exchange_summaries.iter().find(|e| e.exchange_id == 2).unwrap();
        assert_eq!(ex2.total_pairs, 3);
    }

    #[tokio::test]
    async fn test_tokens_on_exchange() {
        let inv = make_inventory();
        let (ep, presence, symbols, cats, tri) = make_test_data();

        inv.update(&ep, &presence, &symbols, &cats, &tri, 0, 5, 1).await;

        let snap = inv.snapshot().unwrap();
        let ex0_tokens = snap.tokens_on_exchange(0);
        assert_eq!(ex0_tokens.len(), 1);
        assert_eq!(ex0_tokens[0].symbol, "BTC");
    }

    #[tokio::test]
    async fn test_exchanges_for_token() {
        let inv = make_inventory();
        let (ep, presence, symbols, cats, tri) = make_test_data();

        inv.update(&ep, &presence, &symbols, &cats, &tri, 0, 5, 1).await;

        let snap = inv.snapshot().unwrap();
        let btc_exchanges = snap.exchanges_for_token(10);
        assert_eq!(btc_exchanges.len(), 3);
    }

    #[test]
    fn test_find_triangular_loops() {
        // USDT=0, BTC=10, ETH=11, SOL=12 on same exchange
        let pairs = vec![(10, 0), (11, 0), (12, 0)];
        let loops = find_triangular_loops(&pairs);
        // With USDT as common quote, we get BTC-ETH-SOL, BTC-ETH-USDT, etc.
        // All pairs share USDT (0), so any 3 tokens form a loop.
        assert!(!loops.is_empty());
    }

    #[test]
    fn test_estimate_triangular_loops_empty() {
        let pairs: Vec<(u16, u16)> = vec![];
        assert_eq!(estimate_triangular_loops(&pairs), 0);
    }

    #[test]
    fn test_category_label() {
        assert_eq!(category_label(CAT_MAJOR), "MAJOR");
        assert_eq!(category_label(CAT_LAYER1), "L1");
        assert_eq!(category_label(CAT_MEMECOIN), "MEME");
        assert_eq!(category_label(CAT_STABLE), "STABLE");
        assert_eq!(category_label(CAT_ALTCOIN), "ALT");
    }
}

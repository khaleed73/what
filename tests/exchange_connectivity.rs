//! Integration tests: verify each exchange client can reach its public REST API
//! health-check endpoint.  Uses dummy API keys since health_check only hits
//! public (unauthenticated) endpoints.

use rust_hft_arb::exchange::config::ExchangeConfig;
use rust_hft_arb::exchange::exchange_trait::Exchange;
use rust_hft_arb::exchange::{
    binance::BinanceClient,
    bitfinex::BitfinexClient,
    bitget::BitgetClient,
    bitmex::BitmexClient,
    bitstamp::BitstampExchange,
    bybit::BybitClient,
    coinbase::CoinbaseClient,
    delta::DeltaExchange,
    deribit::DeribitExchange,
    gateio::GateioClient,
    htx::HtxClient,
    ibank::IbankExchange,
    kraken::KrakenClient,
    kucoin::KucoinClient,
    lbank::LbankClient,
    mexc::MexcExchange,
    okx::OkxClient,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

const DUMMY_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DUMMY_SECRET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Create a config with dummy credentials for a given base URL.
fn dummy_config(base_url: &str) -> ExchangeConfig {
    ExchangeConfig::new(DUMMY_KEY, DUMMY_SECRET, base_url)
}

// ---------------------------------------------------------------------------
// Per-exchange tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_binance_health_check() {
    let cfg = dummy_config("https://api.binance.com");
    let client = BinanceClient::new("Binance".into(), cfg).expect("BinanceClient::new failed");
    println!("[Binance] running health_check ...");
    let result = client.health_check().await;
    println!("[Binance] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Binance health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_bybit_health_check() {
    let cfg = dummy_config("https://api.bybit.com");
    let client = BybitClient::new("Bybit".into(), cfg).expect("BybitClient::new failed");
    println!("[Bybit] running health_check ...");
    let result = client.health_check().await;
    println!("[Bybit] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Bybit health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_okx_health_check() {
    let cfg = dummy_config("https://www.okx.com");
    let client = OkxClient::new("OKX".into(), cfg).expect("OkxClient::new failed");
    println!("[OKX] running health_check ...");
    let result = client.health_check().await;
    println!("[OKX] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "OKX health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_gateio_health_check() {
    let cfg = dummy_config("https://api.gateio.ws");
    let client = GateioClient::new("GateIO".into(), cfg).expect("GateioClient::new failed");
    println!("[GateIO] running health_check ...");
    let result = client.health_check().await;
    println!("[GateIO] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "GateIO health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_kucoin_health_check() {
    let cfg = dummy_config("https://api.kucoin.com");
    let client = KucoinClient::new("KuCoin".into(), cfg).expect("KucoinClient::new failed");
    println!("[KuCoin] running health_check ...");
    let result = client.health_check().await;
    println!("[KuCoin] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "KuCoin health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_bitfinex_health_check() {
    let cfg = dummy_config("https://api.bitfinex.com");
    let client = BitfinexClient::new("Bitfinex".into(), cfg).expect("BitfinexClient::new failed");
    println!("[Bitfinex] running health_check ...");
    let result = client.health_check().await;
    println!("[Bitfinex] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Bitfinex health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_bitget_health_check() {
    let cfg = dummy_config("https://api.bitget.com");
    let client = BitgetClient::new("Bitget".into(), cfg).expect("BitgetClient::new failed");
    println!("[Bitget] running health_check ...");
    let result = client.health_check().await;
    println!("[Bitget] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Bitget health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_bitmex_health_check() {
    let cfg = dummy_config("https://www.bitmex.com");
    let client = BitmexClient::new("BitMEX".into(), cfg).expect("BitmexClient::new failed");
    println!("[BitMEX] running health_check ...");
    let result = client.health_check().await;
    println!("[BitMEX] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "BitMEX health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_coinbase_health_check() {
    let cfg = dummy_config("https://api.exchange.coinbase.com");
    let client = CoinbaseClient::new("Coinbase".into(), cfg).expect("CoinbaseClient::new failed");
    println!("[Coinbase] running health_check ...");
    let result = client.health_check().await;
    println!("[Coinbase] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Coinbase health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_htx_health_check() {
    let cfg = dummy_config("https://api.huobi.pro");
    let client = HtxClient::new("HTX".into(), cfg).expect("HtxClient::new failed");
    println!("[HTX] running health_check ...");
    let result = client.health_check().await;
    println!("[HTX] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "HTX health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_kraken_health_check() {
    let cfg = dummy_config("https://api.kraken.com");
    let client = KrakenClient::new("Kraken".into(), cfg).expect("KrakenClient::new failed");
    println!("[Kraken] running health_check ...");
    let result = client.health_check().await;
    println!("[Kraken] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Kraken health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_lbank_health_check() {
    let cfg = dummy_config("https://api.lbank.info");
    let client = LbankClient::new("LBank".into(), cfg).expect("LbankClient::new failed");
    println!("[LBank] running health_check ...");
    let result = client.health_check().await;
    println!("[LBank] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "LBank health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_bitstamp_health_check() {
    let cfg = dummy_config("https://www.bitstamp.net");
    let client = BitstampExchange::new("Bitstamp".into(), cfg).expect("BitstampExchange::new failed");
    println!("[Bitstamp] running health_check ...");
    let result = client.health_check().await;
    println!("[Bitstamp] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Bitstamp health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_deribit_health_check() {
    let cfg = dummy_config("https://www.deribit.com");
    let client = DeribitExchange::new("Deribit".into(), cfg).expect("DeribitExchange::new failed");
    println!("[Deribit] running health_check ...");
    let result = client.health_check().await;
    println!("[Deribit] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Deribit health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_delta_health_check() {
    let cfg = dummy_config("https://api.india.delta.exchange");
    let client = DeltaExchange::new("Delta".into(), cfg).expect("DeltaExchange::new failed");
    println!("[Delta] running health_check ...");
    let result = client.health_check().await;
    println!("[Delta] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Delta health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_mexc_health_check() {
    let cfg = dummy_config("https://api.mexc.com");
    let client = MexcExchange::new("MEXC".into(), cfg).expect("MexcExchange::new failed");
    println!("[MEXC] running health_check ...");
    let result = client.health_check().await;
    println!("[MEXC] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "MEXC health_check failed: {:?}", result.err());
}

#[tokio::test]
async fn test_ibank_health_check() {
    let cfg = dummy_config("https://api.independentreserve.com");
    let client = IbankExchange::new("Ibank".into(), cfg).expect("IbankExchange::new failed");
    println!("[Ibank] running health_check ...");
    let result = client.health_check().await;
    println!("[Ibank] health_check result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Ibank health_check failed: {:?}", result.err());
}

// ---------------------------------------------------------------------------
// Combined test: run all 17 in sequence and print a summary table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_all_exchanges_connectivity() {
    let exchanges: Vec<(&str, &str, Box<dyn Exchange>)> = vec![
        ("Binance",    "https://api.binance.com",              Box::new(BinanceClient::new("Binance".into(),    dummy_config("https://api.binance.com")).unwrap())),
        ("Bybit",      "https://api.bybit.com",               Box::new(BybitClient::new("Bybit".into(),      dummy_config("https://api.bybit.com")).unwrap())),
        ("OKX",        "https://www.okx.com",                 Box::new(OkxClient::new("OKX".into(),         dummy_config("https://www.okx.com")).unwrap())),
        ("GateIO",     "https://api.gateio.ws",                Box::new(GateioClient::new("GateIO".into(),    dummy_config("https://api.gateio.ws")).unwrap())),
        ("KuCoin",     "https://api.kucoin.com",              Box::new(KucoinClient::new("KuCoin".into(),    dummy_config("https://api.kucoin.com")).unwrap())),
        ("Bitfinex",   "https://api.bitfinex.com",            Box::new(BitfinexClient::new("Bitfinex".into(), dummy_config("https://api.bitfinex.com")).unwrap())),
        ("Bitget",     "https://api.bitget.com",              Box::new(BitgetClient::new("Bitget".into(),    dummy_config("https://api.bitget.com")).unwrap())),
        ("BitMEX",     "https://www.bitmex.com",              Box::new(BitmexClient::new("BitMEX".into(),    dummy_config("https://www.bitmex.com")).unwrap())),
        ("Coinbase",   "https://api.exchange.coinbase.com",   Box::new(CoinbaseClient::new("Coinbase".into(), dummy_config("https://api.exchange.coinbase.com")).unwrap())),
        ("HTX",        "https://api.huobi.pro",               Box::new(HtxClient::new("HTX".into(),         dummy_config("https://api.huobi.pro")).unwrap())),
        ("Kraken",     "https://api.kraken.com",              Box::new(KrakenClient::new("Kraken".into(),    dummy_config("https://api.kraken.com")).unwrap())),
        ("LBank",      "https://api.lbank.info",              Box::new(LbankClient::new("LBank".into(),     dummy_config("https://api.lbank.info")).unwrap())),
        ("Bitstamp",   "https://www.bitstamp.net",            Box::new(BitstampExchange::new("Bitstamp".into(), dummy_config("https://www.bitstamp.net")).unwrap())),
        ("Deribit",    "https://www.deribit.com",             Box::new(DeribitExchange::new("Deribit".into(), dummy_config("https://www.deribit.com")).unwrap())),
        ("Delta",      "https://api.india.delta.exchange",    Box::new(DeltaExchange::new("Delta".into(),   dummy_config("https://api.india.delta.exchange")).unwrap())),
        ("MEXC",       "https://api.mexc.com",                Box::new(MexcExchange::new("MEXC".into",     dummy_config("https://api.mexc.com")).unwrap())),
        ("Ibank",      "https://api.independentreserve.com",  Box::new(IbankExchange::new("Ibank".into",   dummy_config("https://api.independentreserve.com")).unwrap())),
    ];

    println!("\n{}
  Exchange Connectivity Test — {} exchanges
{}\n", "=".repeat(60), exchanges.len(), "=".repeat(60));

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut failures: Vec<(&str, String)> = Vec::new();

    for (name, url, client) in &exchanges {
        print!("  {:<12} ({:<38}) ... ", name, url);
        match client.health_check().await {
            Ok(()) => {
                passed += 1;
                println!("OK");
            }
            Err(e) => {
                failed += 1;
                let err_str = e.to_string();
                println!("FAILED — {}", err_str);
                failures.push((name, err_str));
            }
        }
    }

    println!("\n{}\n  Results: {} passed / {} failed / {} total", "=".repeat(60), passed, failed, exchanges.len());
    if !failures.is_empty() {
        println!("\n  Failed exchanges:");
        for (name, err) in &failures {
            println!("    - {}: {}", name, err);
        }
    }
    println!("{}\n", "=".repeat(60));

    // The combined test does NOT hard-assert so we always see the full
    // report.  Individual per-exchange tests above already assert is_ok().
    if failed > 0 {
        eprintln!(
            "WARNING: {}/{} exchanges failed health check (see above)",
            failed, exchanges.len()
        );
    }
}
//! Balance lookup through the modchain `modchain_assets` JSON-RPC method.

use std::time::Duration;

use crate::http;
use crate::json::{self, Value};

pub const DEFAULT_URL: &str = "https://rpc.modchain.net/chain/{chain}/rpc";
const BATCH: usize = 100;

#[derive(Debug, Clone)]
pub struct AddrBalance {
    pub address: String,
    /// Amount in base units (satoshis).
    pub amount: u128,
    pub decimals: u32,
    pub utxos: usize,
    pub error: Option<String>,
}

/// modchain chain name for one of our networks.
pub fn chain_name(network: &str) -> Option<&'static str> {
    Some(match network {
        "bitcoin" => "bitcoin",
        "testnet" => "bitcoin-testnet",
        "litecoin" => "litecoin",
        "dogecoin" => "dogecoin",
        "namecoin" => "namecoin",
        _ => return None,
    })
}

/// Formats a base-unit amount with `decimals` decimal places.
pub fn fmt_amount(amount: u128, decimals: u32) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let unit = 10u128.pow(decimals);
    format!("{}.{:0width$}", amount / unit, amount % unit, width = decimals as usize)
}

/// Parses a decimal string ("0.00029450") into base units.
fn parse_decimal(s: &str, decimals: u32) -> Option<u128> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > decimals as usize || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u128 = if int.is_empty() { 0 } else { int.parse().ok()? };
    for i in 0..decimals as usize {
        v = v.checked_mul(10)? + frac.as_bytes().get(i).map_or(0, |b| (b - b'0') as u128);
    }
    Some(v)
}

/// Extracts the native-asset balance from one `modchain_assets` result.
fn native_balance(result: &Value) -> Result<(u128, u32, usize), String> {
    let assets = result.get("assets").and_then(Value::as_array).ok_or("no assets in result")?;
    let Some(a) = assets.iter().find(|a| a.get("asset").and_then(Value::as_str) == Some("NATIVE")) else {
        return Ok((0, 8, 0));
    };
    let utxos = a
        .get("txo")
        .and_then(Value::as_array)
        .map_or(0, |t| t.iter().filter(|o| o.get("spent").is_none_or(Value::is_null)).count());
    // Prefer the exact integer form {"v": "29450", "e": 8}.
    if let Some(obj) = a.get("balance_obj")
        && let (Some(v), Some(e)) = (obj.get("v").and_then(Value::as_num_str), obj.get("e").and_then(Value::as_num_str))
        && let (Ok(v), Ok(e)) = (v.parse::<u128>(), e.parse::<u32>())
    {
        return Ok((v, e, utxos));
    }
    let decimals = a.get("decimals").and_then(Value::as_num_str).and_then(|d| d.parse().ok()).unwrap_or(8);
    let bal = a.get("balance").and_then(Value::as_num_str).ok_or("no balance in asset")?;
    let v = parse_decimal(bal, decimals).ok_or_else(|| format!("cannot parse balance {bal:?}"))?;
    Ok((v, decimals, utxos))
}

fn query_batch(url: &str, addrs: &[String], timeout: Duration) -> Result<Vec<AddrBalance>, String> {
    let calls: Vec<String> = addrs
        .iter()
        .enumerate()
        .map(|(i, a)| {
            format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"modchain_assets","params":[{}]}}"#, json::quote(a))
        })
        .collect();
    let body = http::post_json(url, &format!("[{}]", calls.join(",")), timeout)?;
    let text = String::from_utf8(body).map_err(|_| "response is not UTF-8")?;
    let resp = json::parse(&text)?;
    let items: Vec<&Value> = match &resp {
        Value::Array(a) => a.iter().collect(),
        // A single error object (e.g. the whole request was rejected).
        v => {
            let msg = v
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("unexpected response");
            return Err(msg.to_string());
        }
    };
    let mut out: Vec<AddrBalance> = addrs
        .iter()
        .map(|a| AddrBalance {
            address: a.clone(),
            amount: 0,
            decimals: 8,
            utxos: 0,
            error: Some("no answer".into()),
        })
        .collect();
    for it in items {
        let Some(slot) = it
            .get("id")
            .and_then(Value::as_num_str)
            .and_then(|i| i.parse::<usize>().ok())
            .and_then(|i| out.get_mut(i))
        else {
            continue;
        };
        if let Some(err) = it.get("error").filter(|e| !e.is_null()) {
            slot.error = Some(err.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
            continue;
        }
        match it.get("result").map(native_balance) {
            Some(Ok((amount, decimals, utxos))) => {
                *slot = AddrBalance { address: slot.address.clone(), amount, decimals, utxos, error: None }
            }
            Some(Err(e)) => slot.error = Some(e),
            None => slot.error = Some("no result".into()),
        }
    }
    Ok(out)
}

/// Looks up the balance of every address, `BATCH` per request.
/// `progress` is called after each batch with (done, total).
///
/// Fails outright if the very first request fails (bad endpoint, no
/// network...); later failures are reported per address.
pub fn check(
    url: &str,
    addrs: &[String],
    timeout: Duration,
    mut progress: impl FnMut(usize, usize),
) -> Result<Vec<AddrBalance>, String> {
    let mut out = Vec::with_capacity(addrs.len());
    for chunk in addrs.chunks(BATCH) {
        let res = query_batch(url, chunk, timeout).or_else(|_| query_batch(url, chunk, timeout));
        match res {
            Ok(r) => out.extend(r),
            Err(e) if out.is_empty() => return Err(e),
            Err(e) => out.extend(chunk.iter().map(|a| AddrBalance {
                address: a.clone(),
                amount: 0,
                decimals: 8,
                utxos: 0,
                error: Some(e.clone()),
            })),
        }
        progress(out.len(), addrs.len());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(fmt_amount(29450, 8), "0.00029450");
        assert_eq!(fmt_amount(2_100_000_000_000_000, 8), "21000000.00000000");
        assert_eq!(parse_decimal("0.00029450", 8), Some(29450));
        assert_eq!(parse_decimal("12", 8), Some(1_200_000_000));
        assert_eq!(parse_decimal("0.000000001", 8), None);
        assert_eq!(parse_decimal("-1", 8), None);
    }

    #[test]
    fn parse_result() {
        let v = json::parse(
            r#"{"assets":[{"asset":"NATIVE","balance":0.00029450,"balance_obj":{"v":"29450","e":8,"f":0.0002945},
            "decimals":8,"txo":[{"amt":0.0002945,"spent":null},{"amt":1,"spent":{"tx":"x"}}]}]}"#,
        )
        .unwrap();
        assert_eq!(native_balance(&v).unwrap(), (29450, 8, 1));
        let v = json::parse(r#"{"assets":[{"asset":"NATIVE","balance":1.5,"decimals":8,"txo":null}]}"#).unwrap();
        assert_eq!(native_balance(&v).unwrap(), (150_000_000, 8, 0));
    }
}

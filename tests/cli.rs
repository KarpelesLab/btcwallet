//! End-to-end tests against a wallet file produced by Berkeley DB 4.8's own
//! `db4.8_load` (fake random keys; 2-level btree with an overflow record).

use std::process::Command;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/encrypted-hd.dat");

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_btcwallet")).args(args).output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

#[test]
fn summary() {
    let (ok, out, err) = run(&[FIXTURE]);
    assert!(ok, "{err}");
    assert!(err.is_empty(), "unexpected warnings: {err}");
    for want in [
        "btree version 9 (4.8), page size 4096",
        "Database:       \"main\"",
        "Network:        bitcoin (guessed from address book)",
        "Wallet version: 139900",
        "Encrypted:      yes",
        "173402 iterations",
        "external counter 1000, internal counter 500",
        "Keys:           403 total, 403 encrypted (402 compressed, 1 uncompressed)",
        "Key pool:       50 keys (index 1..50), 25 external, 25 internal",
        "Transactions:   2",
        "Best block:     000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
}

#[test]
fn keys_and_labels() {
    let (ok, out, err) = run(&["-k", "-a", "-l", "-t", FIXTURE]);
    assert!(ok, "{err}");
    for want in [
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH   encrypted, label \"generator\"",
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm   encrypted, uncompressed",
        "HD seed",
        "pool #50 internal",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  76a914",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa          send      \"satoshi\"",
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
}

#[test]
fn salvage_matches_tree_walk() {
    let count = |out: &str| out.lines().find(|l| l.starts_with("Keys:")).unwrap().to_string();
    let (_, normal, _) = run(&[FIXTURE]);
    let (ok, salvaged, err) = run(&["--salvage", FIXTURE]);
    assert!(ok, "{err}");
    assert_eq!(count(&normal), count(&salvaged));
}

#[test]
fn testnet_override() {
    let (ok, out, _) = run(&["-k", "-n", "testnet", FIXTURE]);
    assert!(ok);
    // hash160(G) on testnet.
    assert!(out.contains("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"), "{out}");
}

#[test]
fn rejects_non_bdb() {
    let (ok, _, err) = run(&[concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")]);
    assert!(!ok);
    assert!(err.contains("not a Berkeley DB btree file") || err.contains("too small"), "{err}");
}

/// Hits the real balance API; run with `cargo test -- --ignored`.
#[test]
#[ignore = "needs network access"]
fn balance_live() {
    let (ok, out, err) = run(&["--balance", FIXTURE]);
    assert!(ok, "{err}");
    assert!(out.contains("Balance (1208 addresses, via rpc.modchain.net)"), "{out}");
    assert!(out.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "{out}");
    assert!(!out.contains("could not be checked"), "{out}");
}

#[test]
fn balance_bad_endpoint_fails_cleanly() {
    let (ok, _, err) = run(&["--balance", "--balance-url", "ftp://example.invalid/", FIXTURE]);
    assert!(!ok);
    assert!(err.contains("unsupported URL"), "{err}");
}

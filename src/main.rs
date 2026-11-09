mod addr;
mod balance;
mod bdb;
mod http;
mod json;
mod util;
mod wallet;

use std::collections::{HashMap, HashSet};
use std::process::ExitCode;

use addr::{Network, valid_pubkey};
use util::{fmt_time, hex, hex_rev};
use wallet::{KeyKind, Wallet, feature_name, record_type};

const USAGE: &str = "\
Usage: btcwallet [OPTIONS] <wallet.dat>

Show information about a legacy (Berkeley DB 4.8) bitcoin wallet file.
The file is only read; private keys are never printed.
Nothing is sent over the network unless --balance is given.

Options:
  -k, --keys          List keys with their addresses
  -l, --labels        List the address book
  -t, --txs           List wallet transaction ids
  -a, --all-types     With --keys, show every address type of compressed keys
  -r, --records       Dump every raw record as hex (private keys redacted)
  -n, --network NET   bitcoin, testnet, regtest, litecoin, dogecoin, namecoin
                      (default: guessed from the address book, else bitcoin)
  -d, --db NAME       Sub-database to read (default: main)
  -s, --salvage       Ignore the btree structure and scan every leaf page
                      (for damaged files; may include stale records)
  -b, --balance       Look up the balance of every wallet address online
                      (sends all the wallet's addresses to the balance API)
      --balance-url URL JSON-RPC endpoint; {chain} is replaced by the chain
                      name (default: https://rpc.modchain.net/chain/{chain}/rpc)
      --timeout SECS  Network timeout per request (default: 120)
  -h, --help          Show this help

HTTPS uses the system CA bundle (or SSL_CERT_FILE) and honours
https_proxy / no_proxy.
";

#[derive(Default)]
struct Opts {
    file: Option<String>,
    keys: bool,
    labels: bool,
    txs: bool,
    all_types: bool,
    records: bool,
    salvage: bool,
    network: Option<Network>,
    db: Option<String>,
    balance: bool,
    balance_url: Option<String>,
    timeout: Option<u64>,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-k" | "--keys" => o.keys = true,
            "-l" | "--labels" => o.labels = true,
            "-t" | "--txs" => o.txs = true,
            "-a" | "--all-types" => o.all_types = true,
            "-r" | "--records" => o.records = true,
            "-s" | "--salvage" => o.salvage = true,
            "-n" | "--network" => {
                let n = args.next().ok_or("--network needs a value")?;
                o.network = Some(Network::by_name(&n).ok_or_else(|| format!("unknown network {n:?}"))?);
            }
            "-d" | "--db" => o.db = Some(args.next().ok_or("--db needs a value")?),
            "-b" | "--balance" => o.balance = true,
            "--balance-url" => o.balance_url = Some(args.next().ok_or("--balance-url needs a value")?),
            "--timeout" => {
                let t = args.next().ok_or("--timeout needs a value")?;
                o.timeout = Some(t.parse().ok().filter(|&t| t > 0).ok_or_else(|| format!("bad timeout {t:?}"))?);
            }
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option {s}")),
            _ if o.file.is_some() => return Err("only one wallet file may be given".into()),
            _ => o.file = Some(a),
        }
    }
    Ok(o)
}

/// Die quietly on SIGPIPE (e.g. when piped into `head`) instead of panicking.
fn reset_sigpipe() {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        // SAFETY: restores the default disposition (SIG_DFL = 0) for SIGPIPE (13).
        unsafe {
            signal(13, 0);
        }
    }
}

fn main() -> ExitCode {
    reset_sigpipe();
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let Some(file) = opts.file.clone() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(&file, &opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {file}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(file: &str, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(file)?;
    let size = data.len();
    let mut db = bdb::BdbFile::open(data)?;

    println!("File:           {file} ({size} bytes)");
    println!(
        "Berkeley DB:    btree version {}{}, page size {}, {} pages, {}",
        db.meta.version,
        match db.meta.version {
            9 => " (4.8)",
            8 => " (4.6/4.7)",
            10 => " (5.x+)",
            _ => "",
        },
        db.page_size(),
        db.page_count(),
        if db.big_endian() { "big-endian" } else { "little-endian" }
    );

    let records = if opts.salvage {
        let r = db.salvage();
        println!("Database:       salvage scan, {} records recovered", r.len());
        r
    } else {
        let mut dbs = db.databases().map_err(|e| format!("{e} (try --salvage)"))?;
        let names: Vec<String> =
            dbs.iter().map(|d| d.name.clone().unwrap_or_else(|| "<unnamed>".into())).collect();
        let want = opts.db.as_deref().unwrap_or("main");
        let idx = dbs
            .iter()
            .position(|d| d.name.as_deref() == Some(want))
            .or_else(|| (opts.db.is_none() && dbs.len() == 1).then_some(0))
            .ok_or_else(|| format!("no sub-database {want:?} (found: {})", names.join(", ")))?;
        let d = dbs.swap_remove(idx);
        println!(
            "Database:       {} (meta page {}), {} records{}",
            d.name.as_deref().map_or("<unnamed>".into(), |n| format!("{n:?}")),
            d.meta.pgno,
            d.records.len(),
            if names.len() > 1 { format!(" [all: {}]", names.join(", ")) } else { String::new() }
        );
        d.records
    };
    for w in &db.warnings {
        eprintln!("warning: {w}");
    }

    let w = Wallet::from_records(&records);
    let (net, net_src) = match opts.network {
        Some(n) => (n, "given"),
        None => match w.names.keys().find_map(|a| Network::detect(a)) {
            Some(n) => (n, "guessed from address book"),
            None => (Network::by_name("bitcoin").unwrap(), "default"),
        },
    };
    println!("Network:        {} ({net_src})", net.name);
    println!();

    print_summary(&w, &net);
    if opts.keys {
        print_keys(&w, &net, opts.all_types);
    }
    if opts.labels {
        print_labels(&w, &net);
    }
    if opts.txs {
        println!("\nTransactions ({}):", w.txids.len());
        for t in &w.txids {
            println!("  {}", hex_rev(t));
        }
    }
    if opts.balance {
        print_balance(&w, &net, opts)?;
    }
    if opts.records {
        print_records(&records);
    }
    for e in &w.errors {
        eprintln!("warning: could not decode {e}");
    }
    Ok(())
}

/// Every address the wallet owns, mapped to its key/script description.
fn own_addresses(w: &Wallet, net: &Network) -> HashSet<String> {
    let mut own = HashSet::new();
    for k in w.keys.values() {
        own.extend(net.pubkey_addresses(&k.pubkey).all().map(str::to_owned));
    }
    for (h, _) in &w.scripts {
        own.insert(net.p2sh(h));
    }
    for s in &w.watch_only {
        own.extend(net.script_address(s));
    }
    own
}

fn print_summary(w: &Wallet, net: &Network) {
    let field = |name: &str, val: String| println!("{:<16}{val}", format!("{name}:"));

    match w.version {
        Some(v) => field(
            "Wallet version",
            format!(
                "{v} ({}){}",
                feature_name(v),
                w.min_version.map_or(String::new(), |m| format!(", minversion {m}"))
            ),
        ),
        None => field("Wallet version", "unknown (no version record)".into()),
    }
    if let Some(f) = w.flags {
        let mut names = Vec::new();
        for (bit, n) in [
            (0, "avoid_reuse"),
            (1, "key_origin_metadata"),
            (2, "last_hardened_xpub_cached"),
            (32, "disable_private_keys"),
            (33, "blank_wallet"),
            (34, "descriptors"),
            (35, "external_signer"),
        ] {
            if f & (1 << bit) != 0 {
                names.push(n);
            }
        }
        field("Flags", format!("{f:#x} [{}]", names.join(", ")));
    }

    if w.encrypted() {
        field("Encrypted", "yes".into());
        for m in &w.master_keys {
            let method = match m.method {
                0 => "EVP_BytesToKey/SHA-512 + AES-256-CBC".to_string(),
                x => format!("unknown method {x}"),
            };
            println!(
                "  master key #{}: {method}, {} iterations, salt {}, encrypted key {} bytes",
                m.id,
                m.iterations,
                hex(&m.salt),
                m.crypted_key.len()
            );
        }
        if w.master_keys.is_empty() {
            println!("  (encrypted keys present but no master key record!)");
        }
    } else {
        field("Encrypted", "no".into());
    }

    match &w.hd_chain {
        Some(hd) => {
            let mut s = format!(
                "yes (chain v{}), seed id {}, external counter {}",
                hd.version,
                hex_rev(&hd.seed_id),
                hd.external_counter
            );
            if let Some(i) = hd.internal_counter {
                s += &format!(", internal counter {i}");
            }
            if w.hd_seed_key().is_none() {
                s += " (seed key not found!)";
            }
            field("HD", s);
        }
        None => field("HD", "no".into()),
    }

    let count = |kind| w.keys.values().filter(|k| k.kind == kind).count();
    let compressed = w.keys.values().filter(|k| k.pubkey.len() == 33).count();
    let invalid = w.keys.values().filter(|k| !valid_pubkey(&k.pubkey)).count();
    let mut s = format!("{} total", w.keys.len());
    for (n, label) in [
        (count(KeyKind::Plain), "unencrypted"),
        (count(KeyKind::Crypted), "encrypted"),
        (count(KeyKind::WalletKey), "wkey"),
    ] {
        if n > 0 {
            s += &format!(", {n} {label}");
        }
    }
    s += &format!(" ({compressed} compressed, {} uncompressed)", w.keys.len() - compressed - invalid);
    if invalid > 0 {
        s += &format!(", {invalid} with an invalid public key");
    }
    field("Keys", s);

    let created: Vec<i64> =
        w.keys.values().filter_map(|k| k.meta.as_ref()).map(|m| m.create_time).filter(|&t| t > 1).collect();
    if let (Some(min), Some(max)) = (created.iter().min(), created.iter().max()) {
        field("Key times", format!("{} .. {} UTC", fmt_time(*min), fmt_time(*max)));
    }

    if w.pool.is_empty() {
        field("Key pool", "empty".into());
    } else {
        let internal = w.pool.iter().filter(|p| p.internal).count();
        let pre_split = w.pool.iter().filter(|p| p.pre_split).count();
        let missing = w.pool.iter().filter(|p| !w.keys.contains_key(&p.pubkey)).count();
        let mut s = format!(
            "{} keys (index {}..{}), {} external, {internal} internal",
            w.pool.len(),
            w.pool.first().unwrap().index,
            w.pool.last().unwrap().index,
            w.pool.len() - internal
        );
        if pre_split > 0 {
            s += &format!(", {pre_split} pre-split");
        }
        if missing > 0 {
            s += &format!(", {missing} without a matching key!");
        }
        field("Key pool", s);
        let times: Vec<i64> = w.pool.iter().map(|p| p.time).filter(|&t| t > 0).collect();
        if let (Some(min), Some(max)) = (times.iter().min(), times.iter().max()) {
            println!("  pool times {} .. {} UTC", fmt_time(*min), fmt_time(*max));
        }
    }
    if let Some(pk) = &w.default_key {
        field(
            "Default key",
            if valid_pubkey(pk) { net.pubkey_addresses(pk).p2pkh } else { format!("invalid ({})", hex(pk)) },
        );
    }

    let own = own_addresses(w, net);
    let own_named = w.names.keys().filter(|a| own.contains(*a)).count();
    field(
        "Address book",
        format!("{} entries ({own_named} own, {} other)", w.names.len(), w.names.len() - own_named),
    );
    field("Transactions", w.txids.len().to_string());
    if let Some(h) = w.best_block_hash() {
        field("Best block", h);
    }
    if !w.scripts.is_empty() || !w.watch_only.is_empty() {
        field("Scripts", format!("{} redeem scripts, {} watch-only", w.scripts.len(), w.watch_only.len()));
    }
    if !w.accounts.is_empty() || w.account_entries > 0 {
        field("Accounts", format!("{} accounts, {} accounting entries", w.accounts.len(), w.account_entries));
    }
    if !w.descriptors.is_empty() {
        field("Descriptors", w.descriptors.len().to_string());
        let active: HashMap<[u8; 32], bool> = w.active_spk.iter().map(|(int, _, id)| (*id, *int)).collect();
        for d in &w.descriptors {
            let act = match active.get(&d.id) {
                Some(true) => " [active internal]",
                Some(false) => " [active external]",
                None => "",
            };
            println!(
                "  {}{act}\n    created {}, range {}..{}, next index {}",
                d.descriptor,
                fmt_time(d.create_time as i64),
                d.range.0,
                d.range.1,
                d.next_index
            );
        }
    }
    let types: Vec<String> = w.type_counts.iter().map(|(t, n)| format!("{t}={n}")).collect();
    field("Record types", types.join(" "));
}

fn print_keys(w: &Wallet, net: &Network, all_types: bool) {
    let seed = w.hd_seed_key().map(|k| k.pubkey.clone());
    println!("\nKeys ({}):", w.keys.len());
    println!("  {:<19}  {:<4}  {:<35}  info", "created (UTC)", "type", "address");
    for k in w.sorted_keys() {
        if !valid_pubkey(&k.pubkey) {
            println!("  {:<19}  {:<4}  invalid public key {}", "-", "?", hex(&k.pubkey));
            continue;
        }
        let a = net.pubkey_addresses(&k.pubkey);
        let mut info = Vec::new();
        info.push(match k.kind {
            KeyKind::Plain => "unencrypted",
            KeyKind::Crypted => "encrypted",
            KeyKind::WalletKey => "wkey",
        });
        if k.pubkey.len() == 65 {
            info.push("uncompressed");
        }
        if seed.as_ref() == Some(&k.pubkey) {
            info.push("HD seed");
        }
        let mut extra = Vec::new();
        if let Some(path) = k.meta.as_ref().and_then(|m| m.hd_path.as_deref()).filter(|p| !p.is_empty()) {
            extra.push(path.to_string());
        }
        if let Some(p) = k.pool {
            extra.push(format!("pool #{}{}", p.index, if p.internal { " internal" } else { "" }));
        }
        let addrs: Vec<&str> = a.all().collect();
        // Primary address: the labelled one, else the native one for the key.
        let primary = addrs.iter().copied().find(|x| w.names.contains_key(*x)).unwrap_or(&a.p2pkh);
        if let Some(l) = w.names.get(primary) {
            extra.push(format!("label {l:?}"));
        }
        let created = k.meta.as_ref().map_or("-".into(), |m| fmt_time(m.create_time));
        let kind = if k.pubkey.len() == 33 { "comp" } else { "unc" };
        println!(
            "  {created:<19}  {kind:<4}  {primary:<35}  {}",
            info.into_iter().map(str::to_owned).chain(extra).collect::<Vec<_>>().join(", ")
        );
        if all_types {
            for x in addrs.into_iter().filter(|x| *x != primary) {
                println!("  {:<19}  {:<4}  {x}", "", "");
            }
        }
    }
    if !w.scripts.is_empty() {
        println!("\nRedeem scripts ({}):", w.scripts.len());
        for (h, s) in &w.scripts {
            println!("  {}  {}", net.p2sh(h), hex(s));
        }
    }
    if !w.watch_only.is_empty() {
        println!("\nWatch-only scripts ({}):", w.watch_only.len());
        for s in &w.watch_only {
            println!("  {}  {}", net.script_address(s).unwrap_or_else(|| "?".into()), hex(s));
        }
    }
}

fn print_labels(w: &Wallet, net: &Network) {
    let own = own_addresses(w, net);
    println!("\nAddress book ({}):", w.names.len());
    for (a, l) in &w.names {
        let purpose = w.purposes.get(a).map(String::as_str).unwrap_or(if own.contains(a) { "own" } else { "" });
        println!("  {a:<42}  {purpose:<8}  {l:?}");
    }
    for (name, pk) in &w.accounts {
        let a = if valid_pubkey(pk) { net.pubkey_addresses(pk).p2pkh } else { "-".into() };
        println!("  account {name:?}: {a}");
    }
}

fn print_records(records: &[bdb::Record]) {
    println!("\nRecords ({}):", records.len());
    for (k, v) in records {
        let t = record_type(k).unwrap_or_else(|| "?".into());
        let secret = matches!(t.as_str(), "key" | "wkey" | "walletdescriptorkey");
        let val = if secret { format!("<{} bytes redacted>", v.len()) } else { hex(v) };
        println!("  {t:<14} {} => {val}", hex(k));
    }
}

/// Every address the wallet can receive on, with a short description,
/// in display order (keys by creation time, then scripts).
fn balance_addresses(w: &Wallet, net: &Network) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut push = |a: String, what: String| {
        if seen.insert(a.clone()) {
            out.push((a, what));
        }
    };
    for k in w.sorted_keys().into_iter().filter(|k| valid_pubkey(&k.pubkey)) {
        let mut what = match k.meta.as_ref().and_then(|m| m.hd_path.as_deref()).filter(|p| !p.is_empty()) {
            Some(p) => p.to_string(),
            None => "key".to_string(),
        };
        if let Some(p) = k.pool {
            what += &format!(", pool #{}{}", p.index, if p.internal { " internal" } else { "" });
        }
        for a in net.pubkey_addresses(&k.pubkey).all() {
            push(a.to_string(), what.clone());
        }
    }
    // Public keys referenced without a key record (damaged/salvaged wallets,
    // or keys whose private part is missing): still worth checking.
    let orphans = w
        .pool
        .iter()
        .map(|p| (&p.pubkey, format!("pool #{} (no private key!)", p.index)))
        .chain(w.default_key.iter().map(|pk| (pk, "default key (no private key!)".to_string())))
        .chain(w.accounts.iter().map(|(n, pk)| (pk, format!("account {n:?} (no private key!)"))));
    for (pk, what) in orphans {
        if valid_pubkey(pk) && !w.keys.contains_key(pk) {
            for a in net.pubkey_addresses(pk).all() {
                push(a.to_string(), what.clone());
            }
        }
    }
    for (h, _) in &w.scripts {
        push(net.p2sh(h), "redeem script".into());
    }
    for s in &w.watch_only {
        if let Some(a) = net.script_address(s) {
            push(a, "watch-only".into());
        }
    }
    out
}

fn print_balance(w: &Wallet, net: &Network, opts: &Opts) -> Result<(), String> {
    let template = opts.balance_url.as_deref().unwrap_or(balance::DEFAULT_URL);
    let url = if template.contains("{chain}") {
        let chain = balance::chain_name(net.name)
            .ok_or_else(|| format!("no balance API chain for network {:?}; use --balance-url", net.name))?;
        template.replace("{chain}", chain)
    } else {
        template.to_string()
    };
    let unit = match net.name {
        "bitcoin" => "BTC",
        "testnet" | "regtest" => "tBTC",
        "litecoin" => "LTC",
        "dogecoin" => "DOGE",
        "namecoin" => "NMC",
        _ => "",
    };
    let addrs = balance_addresses(w, net);
    let host = http::Url::parse(&url).map(|u| u.host().to_string())?;
    println!("\nBalance ({} addresses, via {host}):", addrs.len());
    let list: Vec<String> = addrs.iter().map(|(a, _)| a.clone()).collect();
    let timeout = std::time::Duration::from_secs(opts.timeout.unwrap_or(120));
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let results = balance::check(&url, &list, timeout, |done, total| {
        if interactive {
            eprint!("\r  checked {done}/{total} addresses");
            if done == total {
                eprint!("\r\x1b[K");
            }
        }
    })
    .map_err(|e| {
        if interactive {
            eprint!("\r\x1b[K");
        }
        format!("balance lookup failed: {e}")
    })?;

    let mut total: u128 = 0;
    let mut decimals = 8;
    let (mut funded, mut utxos, mut failed) = (0, 0, Vec::new());
    for (r, (_, what)) in results.iter().zip(&addrs) {
        if let Some(e) = &r.error {
            failed.push((r.address.clone(), e.clone()));
            continue;
        }
        if r.amount == 0 {
            continue;
        }
        if funded == 0 {
            println!("  {:<42}  {:>20}  {:>5}  info", "address", format!("amount ({unit})"), "utxos");
            decimals = r.decimals;
        }
        funded += 1;
        utxos += r.utxos;
        total += r.amount;
        let label = w.names.get(&r.address).map(|l| format!(", label {l:?}")).unwrap_or_default();
        println!(
            "  {:<42}  {:>20}  {:>5}  {what}{label}",
            r.address,
            balance::fmt_amount(r.amount, r.decimals),
            r.utxos
        );
    }
    println!(
        "  Total: {} {unit} in {utxos} unspent output{} on {funded} address{}",
        balance::fmt_amount(total, decimals),
        if utxos == 1 { "" } else { "s" },
        if funded == 1 { "" } else { "es" },
    );
    if !failed.is_empty() {
        println!("  {} address{} could not be checked (total may be incomplete):", failed.len(),
            if failed.len() == 1 { "" } else { "es" });
        for (a, e) in failed.iter().take(10) {
            println!("    {a}: {e}");
        }
        if failed.len() > 10 {
            println!("    ... and {} more", failed.len() - 10);
        }
    }
    Ok(())
}

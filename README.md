# btcwallet

Inspect legacy bitcoin `wallet.dat` files (Berkeley DB 4.8, as written by
Bitcoin Core / Bitcoin-Qt and its forks) without Bitcoin Core,
without libdb, and without touching the file.

- Reads the Berkeley DB btree format directly (no libdb needed), including
  damaged or truncated files (`--salvage`).
- Decodes the wallet: version, encryption parameters, HD chain, keys and
  their addresses, key pool, address book, transactions, scripts,
  watch-only entries, accounts and descriptors.
- Optionally looks up the current balance of every wallet address.
- **Read-only, and never prints private keys.** Encrypted wallets are shown
  without needing the passphrase.

## Install

Requires Rust 1.95 or newer.

```sh
cargo install --git https://github.com/KarpelesLab/btcwallet
# or, from a checkout
cargo build --release   # binary: target/release/btcwallet
```

The only dependencies are [`outscript`](https://crates.io/crates/outscript)
(address encoding) and [`purecrypto`](https://crates.io/crates/purecrypto)
(hashing and TLS), both pure Rust.

## Usage

```
btcwallet [OPTIONS] <wallet.dat>

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
      --balance-url URL JSON-RPC endpoint; {chain} is replaced by the chain name
      --timeout SECS  Network timeout per request (default: 120)
```

Work on a copy of the wallet, and don't run the tool on a wallet that
Bitcoin Core currently has open: recent changes may still be in the
database log files and not yet in `wallet.dat`.

### Summary

```
$ btcwallet wallet.dat
File:           wallet.dat (159744 bytes)
Berkeley DB:    btree version 9 (4.8), page size 4096, 39 pages, little-endian
Database:       "main" (meta page 2), 871 records
Network:        bitcoin (guessed from address book)

Wallet version: 139900 (HD split (internal chain)), minversion 139900
Encrypted:      yes
  master key #1: EVP_BytesToKey/SHA-512 + AES-256-CBC, 173402 iterations, salt 1b2c174a704441ff, encrypted key 48 bytes
HD:             yes (chain v2), seed id 850d46a489d8c93c9a330d93f2e8d4874b059175, external counter 1000, internal counter 500
Keys:           403 total, 403 encrypted (402 compressed, 1 uncompressed)
Key times:      2017-07-14 02:40:00 .. 2017-07-14 09:22:00 UTC
Key pool:       50 keys (index 1..50), 25 external, 25 internal
Address book:   3 entries (3 own, 0 other)
Transactions:   2
Best block:     000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
...
```

### Keys

```
$ btcwallet -k wallet.dat
Keys (403):
  created (UTC)        type  address                              info
  2017-07-14 02:40:00  comp  1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH   encrypted, label "generator"
  2017-07-14 02:41:00  unc   1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm   encrypted, uncompressed
  2017-07-14 02:42:00  comp  1BidnfADyhyqS3MpCu9Gx4AuMHPVxjPYh4   encrypted, HD seed
  2017-07-14 02:43:00  comp  1DcLwRZ5dNPmvvWogBnCLfNDAD9iT4CBiz   encrypted, m/0'/1'/3'
  ...
```

Each key shows its legacy (P2PKH) address, or the labelled one if the
address book uses a segwit form. With `-a`, compressed keys also list their
P2SH-P2WPKH (`3...`) and P2WPKH (`bc1q...`) addresses.

### Balances

```
$ btcwallet -b wallet.dat
...
Balance (1209 addresses, via rpc.modchain.net):
  address                                             amount (BTC)  utxos  info
  bc1qv2vzlzmqdek9v4l2ff47z4az462ugs8vzyz5er            0.00029450      1  watch-only
  Total: 0.00029450 BTC in 1 unspent output on 1 address
```

`--balance` checks every address the wallet can receive on: all address
forms of every key (including key-pool keys), redeem scripts, watch-only
scripts, and public keys referenced without a private key (marked
`no private key!`). It uses the `modchain_assets` JSON-RPC method of
[modchain](https://rpc.modchain.net), 100 addresses per request.

**Privacy:** this sends every address of the wallet to the balance service.
Nothing is sent over the network unless `--balance` is given.

HTTPS uses the system CA bundle (override with `SSL_CERT_FILE`) and honours
`https_proxy` / `no_proxy`.

### Damaged wallets

If the btree is corrupted or the file is truncated, `--salvage` ignores the
tree structure and reads every leaf page in the file. It can recover keys
from partial files, but may also return stale records from freed pages.

## Development

```sh
cargo test                  # unit + CLI tests (offline)
cargo test -- --ignored     # also query the live balance API
```

`tests/data/encrypted-hd.dat` was generated with Berkeley DB 4.8's own
`db4.8_load` and contains random fake keys only.

## License

MIT, see [LICENSE](LICENSE).

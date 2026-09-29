# frame-sentinel

Static analysis for [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) FRAME pallets. It reads pallet source with `syn`, works out whether each piece of code is a dispatchable, a block hook or other runtime code, ignores what only runs in tests, benchmarks, try-runtime or native builds, and reports the constructs that repeatedly show up in FRAME audits.

```
$ frame-sentinel pallets/escrow-v0
pallets/escrow-v0/src/lib.rs:111:36: high FS001 [runtime-panic] in `release`: `.unwrap()` can panic
    let mut escrow = Escrows::<T>::get(id).unwrap();
pallets/escrow-v0/src/lib.rs:31:2: medium FS004 [unbounded-storage]: pallet opts out of storage bounds with `without_storage_info`
    #[pallet::without_storage_info]
...
```

## Rules

| Id | Name | Flags | Severity |
|---|---|---|---|
| FS001 | runtime-panic | `unwrap`, `expect`, `panic!`, `assert!`, `unreachable!`… | high in dispatchables and hooks, medium elsewhere, low for `expect("… qed")` |
| FS002 | unchecked-arithmetic | `+ - *` (wraps in release builds), `/ %` by a non-constant | medium in dispatchables and hooks, low elsewhere |
| FS003 | lossy-cast | `as u8/u16/u32/i*` | low |
| FS004 | unbounded-storage | `without_storage_info`, `#[pallet::unbounded]`, `Vec` in a storage type | medium |
| FS005 | missing-origin-check | dispatchable that neither checks nor forwards its origin | high; low when documented as permissionless |
| FS006 | zero-weight | `#[pallet::weight(0)]`, `Weight::zero()` | medium |
| FS007 | unbounded-iteration | `Storage::iter()`, `drain`, `translate`, unbounded `clear` | high in hooks without a weight meter, medium elsewhere; ignored when ended by `.next()`/`.take(n)` |
| FS008 | unchecked-indexing | `v[i]` | medium in dispatchables and hooks, low elsewhere |
| FS009 | unsafe-code | `unsafe` blocks | medium |
| FS010 | biasable-randomness | reads from a `Randomness` source | medium |

Silence a reviewed line with `// sentinel:allow(FS008)` on the line or the one above it.

## Usage

```
cargo install --git https://github.com/sonofnos/frame-sentinel
frame-sentinel [--format text|json|sarif] [--output file] [--fail-on low|medium|high|never] [--all-crates] <path>...
```

Directories are grouped by crate, and only crates that declare a FRAME pallet are scanned unless `--all-crates` is given. The process exits 1 when a finding reaches `--fail-on` (default `high`), so it can gate CI. `--format sarif` uploads straight to GitHub code scanning:

```yaml
- run: frame-sentinel pallets --format sarif --output sentinel.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: sentinel.sarif }
```

## Calibrated on polkadot-sdk

CI scans `substrate/frame` at `polkadot-stable2606-2` on every push. Hand-triaging the first run (59 high findings, 3,347 total) and turning each false-positive pattern into a rule change with a regression test brought it to **17 high findings, every one of them a deliberate choice with a written verdict**, and 2,289 total, most of them low-severity review items. The full triage, including one finding that looked exploitable until the bound three lines above it was read, is in [docs/POLKADOT_SDK_TRIAGE.md](docs/POLKADOT_SDK_TRIAGE.md).

## Tested against an audit target

[pallet-escrow](https://github.com/sonofnos/pallet-escrow) keeps its unreviewed first draft as an audit target. frame-sentinel finds its panic, overflow, bounds and weight problems (`tests/rules.rs::escrow_audit_target`) and nothing in the hardened rewrite. It does not find that draft's authorisation bugs: an arbiter paid to itself, or a cancelled escrow left live. Those are logic errors that need a spec, which is what that repository's spec-oracle fuzzing harness is for. The two tools cover different halves of the problem.

## Limits

- Syntax only: no type information, no call graph. A helper that panics is reported where it is written, not at each dispatchable that reaches it.
- Arithmetic is reported on every integer-looking operation. `Balance` types with saturating `Add` impls, and `Weight` arithmetic, are still reported.
- Macros are analysed by parsing their arguments as expressions; anything that does not parse that way is skipped.

## Development

```
cargo test
cargo run -- tests/fixtures/vulnerable.rs --all-crates
```

`tests/fixtures/vulnerable.rs` marks every line that must be reported with an `expect` comment naming the rule. The test fails on a miss or on any unmarked finding, so precision and recall on the fixture are both exact.

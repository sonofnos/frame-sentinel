# Running frame-sentinel on polkadot-sdk

Target: `substrate/frame` at tag `polkadot-stable2606-2`, scanned by the `polkadot-sdk` CI job on every push. The findings are published as a JSON/SARIF artifact on each run.

The point of this exercise was to calibrate the tool against code that has already been reviewed many times over, where almost every finding should turn out to be deliberate. The question for each finding was whether an auditor would want it in their review queue, and if not, what rule change removes it without hiding real bugs.

## How the numbers moved

| Round | Change | Findings | High | Medium panics (FS001) |
|---|---|---|---|---|
| 1 | First run | 3,347 | 59 | 855 |
| 2 | Honour `#[cfg(test)]` on statements; skip test-only directories (`conformance_tests`, `mock`, `test`, `test-utils`) and files (`build.rs`, `testing_utils.rs`); skip try-runtime migration checks by name; `.expect("… qed")` becomes a low-severity proof check; a storage iterator ended by `.next()`/`.take(n)` in the same expression is bounded; iteration in a hook that checks a `WeightMeter` drops to medium; documented permissionless calls drop to low | 2,471 | 25 | 224 |
| 3 | polkadot-sdk's own doc phrasings for permissionless origins ("Can be any kind of origin", "Can be executed by every `origin`", "All origins are allowed"); a call whose body is only `Err(..)` is inert | 2,470 | 17 | 224 |
| 4 | Skip modules declared behind a test/benchmark `cfg` in their parent (`#[cfg(feature = "runtime-benchmarks")] mod call_builder;`), `mock*` files, associated consts | 2,289 | 17 | 128 |

Each change has a fixture test in `tests/`, so it cannot silently regress.

## Every high finding, triaged

All 17 remaining high findings were read in context. None is an exploitable bug. That is the expected result for these pallets. What matters is that each one is a deliberate choice an auditor should confirm, not noise.

| Finding | Location | Verdict |
|---|---|---|
| `assert!`/`panic!` in `on_initialize` (×3) | `aura` | **Intended.** Slot must increase; a block that breaks this must fail to import. |
| `panic!` in `on_finalize` | `babe` | **Intended.** Consensus invariant. |
| `assert!` in `on_finalize` and `set` (×3) | `timestamp` | **Intended.** The timestamp inherent must be set exactly once per block. The canonical example of a panicking hook. |
| `assert!` in `on_finalize` | `transaction-storage` | **Intended.** Block-validity check for storage proofs. |
| `.expect(error_message)`, `assert!` in `submit_unsigned` (×6) | `election-provider-multi-phase`, `election-provider-multi-block` | **Intended.** Unsigned solution already validated in `ValidateUnsigned`; a panic here means a block that includes an invalid solution fails to import. |
| `.unwrap()` in `report_offence` | `root-offences` | **Minor, root-only.** A failing report panics instead of returning an error. Only `Root` can call it. |
| Origin never checked: `bloat` | `glutton` | **Intended.** Testing pallet for filling blocks on test networks. Not documented as permissionless, which is why it stays high. |
| Origin never checked: `do_task` | `system` | **Intended.** Authorisation is `task.is_valid()`; experimental feature. |

Dropped along the way as permissionless by documentation (now low): `broker::drop_region`, `drop_contribution`, `drop_history`, `drop_renewal` ("Can be any kind of origin"; they only delete expired records), `system::remark` ("Can be executed by every `origin`"), `system::apply_authorized_upgrade` ("All origins are allowed"; the code hash was authorised by root), `meta_tx::dispatch` (authorisation is the signed meta-transaction). Dropped as inert: `revive::eth_transact`, whose body is only `Err(CallFiltered)`. The real call is produced by a transaction extension.

## One that looked real and was not

A medium finding in `revive/src/precompiles/builtin/modexp.rs` looked promising at first: `exp_len_big.to_usize().expect("exp_len out of bounds")` on attacker-controlled precompile input. Reading the function shows all three lengths are compared against 1024 a few lines earlier, with a comment saying so. It is safe. The tool cannot see that bound, which is why medium and low findings are a review queue, not bug reports.

## What the medium findings are

A random sample of 24 medium `FS001` findings from round 3:

- 7 were in `revive/src/exec/mock_ext.rs`, a test mock inside `src/`. Fixed in round 4.
- 2 were `NonZero::new(..).unwrap()` in associated constants (evaluated at compile time). Fixed in round 4.
- 1 was in `revive/src/call_builder.rs`, compiled only for benchmarks via its parent's `cfg`. Fixed in round 4.
- 4 were native-only dev tooling or genesis helpers (`remote_mining.rs`, dev-account derivation, `on_genesis_session`).
- 10 were runtime code panicking on an invariant, such as inherent-data decoding or a precompile length already bounded above. These are the review items the rule exists for.

Unchecked arithmetic (`FS002`) and indexing (`FS008`) are deliberately reported at low severity outside dispatchables and hooks: they are numerous, mostly safe, and only worth reading when a pallet is under audit.

## The small rules, in full

These rules fire rarely, so every hit is listed.

| Rule | Hits | What they are |
|---|---|---|
| FS006 zero weight | `glutton::bloat`, `root-testing::trigger_defensive` | Both are testing pallets for test networks. Correct hits, intended there. |
| FS010 biasable randomness | `lottery::generate_random_number`, `society` `on_initialize`, `contracts` random host function, `babe` randomness provider | Lottery winners and society candidate selection are drawn from on-chain randomness. That is the case the rule exists for; both pallets document it as an accepted trade-off. |
| FS009 unsafe | `revive` EVM interpreter bytecode pointer (5), `support::storage::stream_iter` (6), `contracts` unchecked module loading (1) | Performance-critical code with safety comments; each needs a reviewer who knows the invariants, which is what the rule asks for. |

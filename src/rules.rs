//! Rule catalogue. Each rule names one class of FRAME footgun that has caused real incidents
//! or audit findings, with the fix an auditor would ask for.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
	Low,
	Medium,
	High,
}

impl Severity {
	pub fn parse(s: &str) -> Option<Self> {
		match s {
			"low" => Some(Self::Low),
			"medium" => Some(Self::Medium),
			"high" => Some(Self::High),
			_ => None,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Low => "low",
			Self::Medium => "medium",
			Self::High => "high",
		}
	}

	/// SARIF result level.
	pub fn sarif_level(self) -> &'static str {
		match self {
			Self::High => "error",
			Self::Medium => "warning",
			Self::Low => "note",
		}
	}
}

#[derive(Clone, Copy, Debug)]
pub struct Rule {
	pub id: &'static str,
	pub name: &'static str,
	pub summary: &'static str,
	pub help: &'static str,
}

pub const PANIC: Rule = Rule {
	id: "FS001",
	name: "runtime-panic",
	summary: "Code that can panic inside the runtime.",
	help: "A panic while applying an extrinsic aborts its execution without charging the fee, so \
	       a caller who can trigger it gets free block-builder work, and a panic in a hook \
	       (`on_initialize`, `on_finalize`) makes the block itself unbuildable. Return a \
	       `DispatchError` instead (`ok_or(Error::<T>::X)?`), or use `defensive!`/`defensive_*` \
	       for states that should be impossible.",
};

pub const ARITHMETIC: Rule = Rule {
	id: "FS002",
	name: "unchecked-arithmetic",
	summary: "Arithmetic that can overflow or divide by zero.",
	help: "Runtimes are built in release mode, where integer overflow wraps silently; division by \
	       zero panics in every build. Use `checked_*` and return an error, or `saturating_*` \
	       where clamping is the correct behaviour.",
};

pub const CAST: Rule = Rule {
	id: "FS003",
	name: "lossy-cast",
	summary: "`as` cast to a narrower integer type.",
	help: "`as` truncates silently. Use `TryFrom`/`try_into()` and handle the error, or \
	       `saturated_into()` where clamping is correct.",
};

pub const UNBOUNDED_STORAGE: Rule = Rule {
	id: "FS004",
	name: "unbounded-storage",
	summary: "Storage without a maximum encoded length.",
	help: "Unbounded storage values make proof size impossible to bound and let callers grow \
	       state at a fixed fee. Replace `Vec` with `BoundedVec<_, T::MaxX>` and remove \
	       `#[pallet::without_storage_info]` / `#[pallet::unbounded]`.",
};

pub const ORIGIN: Rule = Rule {
	id: "FS005",
	name: "missing-origin-check",
	summary: "Dispatchable that never inspects its origin.",
	help: "Every dispatchable must decide who may call it: `ensure_signed`, `ensure_root`, a \
	       configured `EnsureOrigin`, or `ensure_none` with a `ValidateUnsigned` implementation. \
	       An unused origin means any account can call it.",
};

pub const ZERO_WEIGHT: Rule = Rule {
	id: "FS006",
	name: "zero-weight",
	summary: "Dispatchable declared with zero weight.",
	help: "A zero-weight call is free block space. Benchmark it and use the generated \
	       `T::WeightInfo`; for calls that are genuinely free, also make them unsigned-only or \
	       rate-limited.",
};

pub const UNBOUNDED_ITERATION: Rule = Rule {
	id: "FS007",
	name: "unbounded-iteration",
	summary: "Iteration over a whole storage map, or an unbounded clear.",
	help: "The cost grows with state that other users control. In a hook it can exceed the block \
	       weight and stall the chain. Bound the loop (`.take(n)`), paginate with a cursor, or \
	       move the work into `on_idle` with a weight check per item.",
};

pub const INDEXING: Rule = Rule {
	id: "FS008",
	name: "unchecked-indexing",
	summary: "Slice or vector indexing that panics when out of bounds.",
	help: "Use `.get(i)` and return an error when the index is missing.",
};

pub const UNSAFE: Rule = Rule {
	id: "FS009",
	name: "unsafe-code",
	summary: "`unsafe` in runtime code.",
	help: "Runtime code has no reason for `unsafe`; memory safety bugs in the runtime are \
	       consensus bugs. Remove it or move it behind a reviewed host function.",
};

pub const RANDOMNESS: Rule = Rule {
	id: "FS010",
	name: "biasable-randomness",
	summary: "On-chain randomness used in runtime logic.",
	help: "Block authors can predict or bias on-chain randomness (and `RandomnessCollectiveFlip` \
	       is predictable outright). Use BABE's VRF-based randomness from a past epoch, and only \
	       where a biased outcome is acceptable.",
};

pub const ALL: [Rule; 10] = [
	PANIC,
	ARITHMETIC,
	CAST,
	UNBOUNDED_STORAGE,
	ORIGIN,
	ZERO_WEIGHT,
	UNBOUNDED_ITERATION,
	INDEXING,
	UNSAFE,
	RANDOMNESS,
];

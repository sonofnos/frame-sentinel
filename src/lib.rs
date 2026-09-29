//! frame-sentinel: static analysis for Polkadot SDK FRAME pallets.
//!
//! The analyzer parses each file with `syn`, works out whether code is a dispatchable, a block
//! hook or other runtime code, skips anything that only runs in tests, benchmarks, try-runtime
//! or native `std` builds, and reports the constructs listed in [`rules`].

pub mod analyzer;
pub mod report;
pub mod rules;

pub use analyzer::{Finding, Scope};

use std::{
	collections::{BTreeMap, HashSet},
	fs,
	path::{Path, PathBuf},
};

/// Files that never run in the on-chain runtime, by name.
const SKIP_FILES: [&str; 8] = [
	"tests.rs",
	"mock.rs",
	"benchmarking.rs",
	"weights.rs",
	"build.rs",
	"test_utils.rs",
	"testing_utils.rs",
	"integration_test.rs",
];
/// Directories that never run in the on-chain runtime.
const SKIP_DIRS: [&str; 14] = [
	"target",
	"tests",
	"test",
	"benches",
	"fuzz",
	"examples",
	"benchmarking",
	"procedural",
	"mock",
	"mock-network",
	"conformance_tests",
	"test-utils",
	"test_utils",
	"integration-tests",
];

#[derive(Debug, Default)]
pub struct Scan {
	pub findings: Vec<Finding>,
	pub files: usize,
	pub pallets: usize,
	pub parse_errors: Vec<(PathBuf, String)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
	/// Scan every Rust file, not only files in crates that declare a FRAME pallet.
	pub all_crates: bool,
}

/// Analyze one source string. `path` is only used for reporting.
pub fn analyze_source(path: &str, source: &str) -> Result<Vec<Finding>, syn::Error> {
	let file = syn::parse_file(source)?;
	let storage = analyzer::storage_items(&file);
	Ok(analyze_parsed(path, source, &file, &storage))
}

fn analyze_parsed(
	path: &str,
	source: &str,
	file: &syn::File,
	storage: &HashSet<String>,
) -> Vec<Finding> {
	use syn::visit::Visit;
	let mut a = analyzer::Analyzer::new(path, source, storage);
	a.visit_file(file);
	a.finish()
}

/// Scan files and directories. Directories are grouped by crate so storage items declared in
/// `lib.rs` are recognised when another file of the same pallet iterates them.
pub fn scan(paths: &[PathBuf], opts: Options) -> Scan {
	let mut crates: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
	for path in paths {
		let mut files = Vec::new();
		collect_rs(path, &mut files);
		for file in files {
			crates.entry(crate_root(&file)).or_default().push(file);
		}
	}

	let mut out = Scan::default();
	for (_root, files) in crates {
		let parsed: Vec<(PathBuf, String, syn::File)> = files
			.into_iter()
			.filter_map(|f| {
				let source = fs::read_to_string(&f).ok()?;
				match syn::parse_file(&source) {
					Ok(ast) => Some((f, source, ast)),
					Err(e) => {
						out.parse_errors.push((f, e.to_string()));
						None
					},
				}
			})
			.collect();

		let is_pallet = parsed.iter().any(|(_, src, _)| declares_pallet(src));
		if !is_pallet && !opts.all_crates {
			continue;
		}
		out.pallets += usize::from(is_pallet);

		let mut storage = HashSet::new();
		for (_, _, ast) in &parsed {
			storage.extend(analyzer::storage_items(ast));
		}
		for (path, source, ast) in &parsed {
			out.files += 1;
			let shown = path.to_string_lossy();
			out.findings.extend(analyze_parsed(&shown, source, ast, &storage));
		}
	}
	out.findings.sort_by(|a, b| {
		b.severity.cmp(&a.severity).then(a.file.cmp(&b.file)).then(a.line.cmp(&b.line))
	});
	out
}

fn declares_pallet(source: &str) -> bool {
	source.contains("#[frame_support::pallet")
		|| source.contains("#[frame::pallet")
		|| source.contains("#[pallet::pallet]")
}

fn collect_rs(path: &Path, out: &mut Vec<PathBuf>) {
	if path.is_file() {
		if path.extension().is_some_and(|e| e == "rs") {
			out.push(path.to_path_buf());
		}
		return;
	}
	let Ok(entries) = fs::read_dir(path) else { return };
	let mut entries: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
	entries.sort();
	for entry in entries {
		let name = entry.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
		if entry.is_dir() {
			if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
				collect_rs(&entry, out);
			}
		} else if entry.extension().is_some_and(|e| e == "rs")
			&& !SKIP_FILES.contains(&name.as_str())
			&& !name.ends_with("_tests.rs")
			&& !name.ends_with("_test.rs")
		{
			out.push(entry);
		}
	}
}

/// Nearest ancestor directory holding a `Cargo.toml`.
fn crate_root(file: &Path) -> PathBuf {
	let mut dir = file.parent();
	while let Some(d) = dir {
		if d.join("Cargo.toml").is_file() {
			return d.to_path_buf();
		}
		dir = d.parent();
	}
	file.parent().map(Path::to_path_buf).unwrap_or_default()
}

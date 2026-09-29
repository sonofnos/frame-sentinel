use frame_sentinel::{analyze_source, rules::Severity, scan, Options, Scope};
use std::{collections::BTreeSet, path::PathBuf};

fn fixture(name: &str) -> (String, String) {
	let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
	let source = std::fs::read_to_string(&path).expect("fixture exists");
	(path, source)
}

/// `(line, rule)` pairs declared with `expect: FSxxx` markers.
fn expected(source: &str) -> BTreeSet<(usize, String)> {
	source
		.lines()
		.enumerate()
		.flat_map(|(i, line)| {
			line.split("expect: ")
				.skip(1)
				.map(move |rest| (i + 1, rest.split_whitespace().next().unwrap_or("").to_string()))
		})
		.collect()
}

#[test]
fn reports_exactly_the_marked_lines() {
	let (path, source) = fixture("vulnerable.rs");
	let findings = analyze_source(&path, &source).expect("fixture parses");
	let got: BTreeSet<(usize, String)> =
		findings.iter().map(|f| (f.line, f.rule.to_string())).collect();
	let want = expected(&source);
	let missed: Vec<_> = want.difference(&got).collect();
	let extra: Vec<_> = got.difference(&want).collect();
	assert!(missed.is_empty() && extra.is_empty(), "missed {missed:?}\nextra {extra:?}");
}

#[test]
fn clean_pallet_and_offchain_code_are_silent() {
	let (path, source) = fixture("clean.rs");
	let findings = analyze_source(&path, &source).expect("fixture parses");
	assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn severity_depends_on_where_code_runs() {
	let (path, source) = fixture("vulnerable.rs");
	let findings = analyze_source(&path, &source).unwrap();
	let find = |rule: &str, func: &str| {
		findings
			.iter()
			.find(|f| f.rule == rule && f.function.as_deref() == Some(func))
			.unwrap_or_else(|| panic!("{rule} in {func}"))
	};
	// Unwrap in a dispatchable is high, in a helper medium.
	assert_eq!(find("FS001", "split").severity, Severity::High);
	assert_eq!(find("FS001", "payout").severity, Severity::Medium);
	assert_eq!(find("FS001", "payout").scope, Scope::Helper);
	// Unbounded iteration is high in a block hook.
	assert_eq!(find("FS007", "on_initialize").severity, Severity::High);
	assert_eq!(find("FS007", "on_initialize").scope, Scope::Hook);
	assert_eq!(find("FS005", "wipe").severity, Severity::High);
	// Refinements from triaging polkadot-sdk (see docs/POLKADOT_SDK_TRIAGE.md):
	// a documented permissionless call and a proof-carrying expect are review items, not alarms,
	assert_eq!(find("FS005", "reap").severity, Severity::Low);
	assert_eq!(find("FS001", "reap").severity, Severity::Low);
	// and iteration guarded by a weight meter is not a chain-halting hook.
	assert_eq!(find("FS007", "on_idle").severity, Severity::Medium);
}

#[test]
fn storage_declared_in_another_file_is_recognised() {
	let dir = std::env::temp_dir().join(format!("sentinel-crate-{}", std::process::id()));
	let src = dir.join("src");
	std::fs::create_dir_all(&src).unwrap();
	std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
	std::fs::write(
		src.join("lib.rs"),
		"#[frame_support::pallet]\npub mod pallet {\n#[pallet::storage]\npub type Queue<T> = StorageMap<_, Twox64Concat, u32, u32>;\n}\n",
	)
	.unwrap();
	std::fs::write(
		src.join("impls.rs"),
		"impl<T: Config> Pallet<T> {\nfn drain_all() {\nfor _ in Queue::<T>::iter() {}\n}\n}\n",
	)
	.unwrap();
	// Test files in the crate are skipped entirely.
	std::fs::write(src.join("tests.rs"), "fn t() { None::<u8>.unwrap(); }\n").unwrap();

	let result = scan(std::slice::from_ref(&dir), Options::default());
	std::fs::remove_dir_all(&dir).ok();
	let rules: Vec<_> = result.findings.iter().map(|f| (f.rule, f.line)).collect();
	assert_eq!(rules, vec![("FS007", 3)], "{:#?}", result.findings);
	assert_eq!(result.pallets, 1);
}

#[test]
fn non_pallet_crates_are_skipped_unless_asked() {
	let dir = std::env::temp_dir().join(format!("sentinel-plain-{}", std::process::id()));
	std::fs::create_dir_all(dir.join("src")).unwrap();
	std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"q\"\n").unwrap();
	std::fs::write(dir.join("src/lib.rs"), "pub fn f(x: Option<u8>) -> u8 { x.unwrap() }\n")
		.unwrap();

	let default = scan(std::slice::from_ref(&dir), Options::default());
	let all = scan(std::slice::from_ref(&dir), Options { all_crates: true });
	std::fs::remove_dir_all(&dir).ok();
	assert!(default.findings.is_empty());
	assert_eq!(all.findings.len(), 1);
}

#[test]
fn sarif_output_is_well_formed() {
	let (path, _) = fixture("vulnerable.rs");
	let result = scan(&[PathBuf::from(&path)], Options { all_crates: true });
	let sarif = frame_sentinel::report::sarif(&result);
	assert_eq!(sarif["version"], "2.1.0");
	let run = &sarif["runs"][0];
	assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 10);
	let results = run["results"].as_array().unwrap();
	assert_eq!(results.len(), result.findings.len());
	for r in results {
		let idx = r["ruleIndex"].as_u64().unwrap() as usize;
		assert_eq!(run["tool"]["driver"]["rules"][idx]["id"], r["ruleId"]);
		assert!(r["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap() > 0);
	}
}

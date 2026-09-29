//! Output formats: human text, JSON, and SARIF 2.1.0 for GitHub code scanning.

use crate::{rules, Finding, Scan};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn text(scan: &Scan) -> String {
	let mut out = String::new();
	for f in &scan.findings {
		let func = f.function.as_deref().map(|n| format!(" in `{n}`")).unwrap_or_default();
		out.push_str(&format!(
			"{}:{}:{}: {} {} [{}]{}: {}\n    {}\n",
			f.file,
			f.line,
			f.column,
			f.severity.as_str(),
			f.rule,
			f.name,
			func,
			f.message,
			f.snippet
		));
	}
	out.push_str(&summary(scan));
	out
}

pub fn summary(scan: &Scan) -> String {
	let mut by_rule: BTreeMap<(&str, &str), [usize; 3]> = BTreeMap::new();
	for f in &scan.findings {
		by_rule.entry((f.rule, f.name)).or_default()[f.severity as usize] += 1;
	}
	let mut out = format!(
		"\n{} findings in {} files ({} pallet crates)\n",
		scan.findings.len(),
		scan.files,
		scan.pallets
	);
	for ((id, name), [low, medium, high]) in by_rule {
		out.push_str(&format!("  {id} {name:<22} high {high:>4}  medium {medium:>4}  low {low:>4}\n"));
	}
	for (path, err) in &scan.parse_errors {
		out.push_str(&format!("  could not parse {}: {err}\n", path.display()));
	}
	out
}

pub fn json(scan: &Scan) -> Value {
	json!({
		"files": scan.files,
		"pallets": scan.pallets,
		"findings": scan.findings,
		"parse_errors": scan.parse_errors.iter()
			.map(|(p, e)| json!({"file": p.to_string_lossy(), "error": e}))
			.collect::<Vec<_>>(),
	})
}

pub fn sarif(scan: &Scan) -> Value {
	let rules: Vec<Value> = rules::ALL
		.iter()
		.map(|r| {
			json!({
				"id": r.id,
				"name": r.name,
				"shortDescription": { "text": r.summary },
				"fullDescription": { "text": r.help },
				"help": { "text": r.help },
			})
		})
		.collect();
	let results: Vec<Value> = scan.findings.iter().map(sarif_result).collect();
	json!({
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": {
				"name": "frame-sentinel",
				"informationUri": "https://github.com/sonofnos/frame-sentinel",
				"version": env!("CARGO_PKG_VERSION"),
				"rules": rules,
			}},
			"results": results,
		}],
	})
}

fn sarif_result(f: &Finding) -> Value {
	let index = rules::ALL.iter().position(|r| r.id == f.rule).unwrap_or(0);
	json!({
		"ruleId": f.rule,
		"ruleIndex": index,
		"level": f.severity.sarif_level(),
		"message": { "text": f.message },
		"locations": [{
			"physicalLocation": {
				"artifactLocation": { "uri": f.file.trim_start_matches("./") },
				"region": { "startLine": f.line, "startColumn": f.column },
			}
		}],
		"properties": { "scope": f.scope, "function": f.function, "severity": f.severity },
	})
}

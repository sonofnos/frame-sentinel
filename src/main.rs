use frame_sentinel::{report, rules::Severity, scan, Options};
use std::{path::PathBuf, process::ExitCode};

const USAGE: &str = "\
frame-sentinel: static analysis for FRAME pallets

usage: frame-sentinel [options] <path>...

options:
  --format <text|json|sarif>   output format (default: text)
  --output <file>              write the report to a file instead of stdout
  --fail-on <low|medium|high|never>
                               exit 1 if any finding is at or above this severity (default: high)
  --all-crates                 scan every crate, not only crates that declare a pallet
  --rules                      list the rules and exit
";

fn main() -> ExitCode {
	let mut format = "text".to_string();
	let mut output: Option<PathBuf> = None;
	let mut fail_on = Some(Severity::High);
	let mut opts = Options::default();
	let mut paths = Vec::new();

	let mut args = std::env::args().skip(1);
	while let Some(arg) = args.next() {
		match arg.as_str() {
			"--format" => format = args.next().unwrap_or_default(),
			"--output" => output = args.next().map(PathBuf::from),
			"--fail-on" => {
				let level = args.next().unwrap_or_default();
				fail_on = match level.as_str() {
					"never" => None,
					other => match Severity::parse(other) {
						Some(s) => Some(s),
						None => return usage_error(&format!("unknown severity `{other}`")),
					},
				};
			},
			"--all-crates" => opts.all_crates = true,
			"--rules" => {
				for r in frame_sentinel::rules::ALL {
					println!("{} {:<22} {}", r.id, r.name, r.summary);
				}
				return ExitCode::SUCCESS;
			},
			"-h" | "--help" => {
				print!("{USAGE}");
				return ExitCode::SUCCESS;
			},
			flag if flag.starts_with("--") => {
				return usage_error(&format!("unknown flag `{flag}`"))
			},
			path => paths.push(PathBuf::from(path)),
		}
	}
	if paths.is_empty() {
		return usage_error("no paths given");
	}

	let result = scan(&paths, opts);
	let rendered = match format.as_str() {
		"text" => report::text(&result),
		"json" => serde_json::to_string_pretty(&report::json(&result)).expect("serializable"),
		"sarif" => serde_json::to_string_pretty(&report::sarif(&result)).expect("serializable"),
		other => return usage_error(&format!("unknown format `{other}`")),
	};
	match &output {
		Some(path) => {
			if let Err(e) = std::fs::write(path, rendered) {
				eprintln!("frame-sentinel: cannot write {}: {e}", path.display());
				return ExitCode::from(2);
			}
			eprint!("{}", report::summary(&result));
		},
		None => print!("{rendered}"),
	}

	let failing = fail_on.is_some_and(|min| result.findings.iter().any(|f| f.severity >= min));
	if failing {
		ExitCode::from(1)
	} else {
		ExitCode::SUCCESS
	}
}

fn usage_error(msg: &str) -> ExitCode {
	eprintln!("frame-sentinel: {msg}\n\n{USAGE}");
	ExitCode::from(2)
}

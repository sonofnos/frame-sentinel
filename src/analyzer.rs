//! The syntax-tree pass. One [`Analyzer`] walks one file and records findings with the scope
//! they were found in, because the same construct is worse in a hook than in a helper.

use crate::rules::{self, Rule, Severity};
use proc_macro2::Span;
use quote::ToTokens;
use serde::Serialize;
use std::collections::HashSet;
use syn::{
	punctuated::Punctuated,
	visit::{self, Visit},
	Attribute, BinOp, Expr, ExprLit, FnArg, ImplItemFn, ItemFn, ItemImpl, ItemMod, Lit, Pat, Token,
	Type,
};

/// Where a piece of runtime code runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
	/// A dispatchable in `#[pallet::call]`.
	Call,
	/// `on_initialize`, `on_finalize`, `on_idle`, `on_poll`, `on_runtime_upgrade`.
	Hook,
	/// Any other runtime code: helpers, trait impls, migrations.
	Helper,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
	pub rule: &'static str,
	pub name: &'static str,
	pub severity: Severity,
	pub file: String,
	pub line: usize,
	pub column: usize,
	pub function: Option<String>,
	pub scope: Scope,
	pub message: String,
	pub snippet: String,
}

const HOOKS: [&str; 5] =
	["on_initialize", "on_finalize", "on_idle", "on_poll", "on_runtime_upgrade"];

/// Functions that only run in tests, benchmarks, try-runtime checks or at genesis, where a
/// panic is the intended failure mode. Matched as name prefixes.
const EXEMPT_FN_PREFIXES: [&str; 9] = [
	"integrity_test",
	"try_state",
	"do_try_state",
	"pre_upgrade",
	"post_upgrade",
	"pre_migrat",
	"post_migrat",
	"assimilate_storage",
	"build",
];

fn is_exempt_fn(name: &str) -> bool {
	EXEMPT_FN_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Doc-comment phrases that say a dispatchable is meant to be callable by anyone. Taken from
/// how polkadot-sdk documents its own permissionless calls.
const PERMISSIONLESS_DOCS: [&str; 9] = [
	"any origin",
	"any kind of origin",
	"every origin",
	"all origins",
	"anyone",
	"any account",
	"permissionless",
	"any signed",
	"origin: any",
];

const PANIC_MACROS: [&str; 7] =
	["panic", "unreachable", "todo", "unimplemented", "assert", "assert_eq", "assert_ne"];

const ITER_FNS: [&str; 8] = [
	"iter",
	"iter_keys",
	"iter_values",
	"drain",
	"iter_prefix",
	"iter_prefix_values",
	"iter_key_prefix",
	"translate",
];

const NARROW_INTS: [&str; 7] = ["u8", "u16", "u32", "i8", "i16", "i32", "i64"];

const ORIGIN_CHECKS: [&str; 7] = [
	"ensure_signed",
	"ensure_root",
	"ensure_none",
	"ensure_signed_or_root",
	"ensure_origin",
	"ensure_origin_or_root",
	"try_origin",
];

pub struct Analyzer<'a> {
	file: &'a str,
	lines: Vec<&'a str>,
	storage_items: &'a HashSet<String>,
	findings: Vec<Finding>,
	scope: Vec<(Scope, Option<String>)>,
	/// Depth of test/benchmark/try-runtime/std-only code; nothing is reported inside it.
	exempt: usize,
	/// Set while inside an `impl` block with this pallet attribute.
	impl_kind: Vec<ImplKind>,
	/// Storage iterators consumed by `.next()`/`.take(n)`/`.nth(i)` in the same expression.
	bounded_iters: HashSet<(usize, usize)>,
	/// Whether the current function checks a weight meter, which bounds its loops.
	weight_metered: Vec<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImplKind {
	Call,
	Hooks,
	GenesisBuild,
	Other,
}

impl<'a> Analyzer<'a> {
	pub fn new(file: &'a str, source: &'a str, storage_items: &'a HashSet<String>) -> Self {
		Self {
			file,
			lines: source.lines().collect(),
			storage_items,
			findings: Vec::new(),
			scope: Vec::new(),
			exempt: 0,
			impl_kind: Vec::new(),
			bounded_iters: HashSet::new(),
			weight_metered: Vec::new(),
		}
	}

	pub fn finish(self) -> Vec<Finding> {
		self.findings
	}

	fn current(&self) -> (Scope, Option<String>) {
		self.scope.last().cloned().unwrap_or((Scope::Helper, None))
	}

	fn suppressed(&self, line: usize, rule: &Rule) -> bool {
		let marker = format!("sentinel:allow({})", rule.id);
		let this = self.lines.get(line.wrapping_sub(1)).copied().unwrap_or("");
		let above = self.lines.get(line.wrapping_sub(2)).copied().unwrap_or("");
		this.contains(&marker) || above.contains(&marker)
	}

	fn report(&mut self, rule: Rule, severity: Severity, span: Span, message: impl Into<String>) {
		if self.exempt > 0 {
			return;
		}
		let start = span.start();
		if self.suppressed(start.line, &rule) {
			return;
		}
		let (scope, function) = self.current();
		let snippet = self
			.lines
			.get(start.line.wrapping_sub(1))
			.map(|l| l.trim().to_string())
			.unwrap_or_default();
		self.findings.push(Finding {
			rule: rule.id,
			name: rule.name,
			severity,
			file: self.file.to_string(),
			line: start.line,
			column: start.column + 1,
			function,
			scope,
			message: message.into(),
			snippet,
		});
	}

	/// Severity for rules whose impact depends on where the code runs.
	fn by_scope(&self, call_or_hook: Severity, helper: Severity) -> Severity {
		match self.current().0 {
			Scope::Call | Scope::Hook => call_or_hook,
			Scope::Helper => helper,
		}
	}

	fn check_origin(&mut self, f: &ImplItemFn) {
		let Some(FnArg::Typed(first)) = f.sig.inputs.first() else { return };
		let origin_name = match &*first.pat {
			Pat::Ident(p) => p.ident.to_string(),
			Pat::Wild(_) => "_".to_string(),
			_ => return,
		};
		// A call whose whole body is `Err(..)` cannot do anything, whoever calls it; such calls
		// exist so a transaction extension can rewrite them (e.g. `pallet_revive::eth_transact`).
		if let [syn::Stmt::Expr(Expr::Call(c), None)] = f.block.stmts.as_slice() {
			if matches!(&*c.func, Expr::Path(p) if p.path.is_ident("Err")) {
				return;
			}
		}
		let body = f.block.to_token_stream().to_string();
		let checked = ORIGIN_CHECKS.iter().any(|c| body.contains(c));
		let used = origin_name != "_"
			&& !origin_name.starts_with('_')
			&& body.split(|c: char| !c.is_alphanumeric() && c != '_').any(|t| t == origin_name);
		if !checked && !used {
			let name = f.sig.ident.to_string();
			let docs = doc_text(&f.attrs).to_lowercase().replace('`', "");
			if PERMISSIONLESS_DOCS.iter().any(|p| docs.contains(p)) {
				self.report(
					rules::ORIGIN,
					Severity::Low,
					f.sig.ident.span(),
					format!(
						"dispatchable `{name}` is documented as callable by anyone; confirm fees \
						 and deposits make that safe"
					),
				);
			} else {
				self.report(
					rules::ORIGIN,
					Severity::High,
					f.sig.ident.span(),
					format!("dispatchable `{name}` never checks or forwards its origin"),
				);
			}
		}
	}

	fn check_weight(&mut self, attrs: &[Attribute]) {
		for attr in attrs {
			if !path_is(attr.path(), &["pallet", "weight"]) {
				continue;
			}
			let Ok(expr) = attr.parse_args::<Expr>() else { continue };
			if is_zero_weight(&expr) {
				self.report(
					rules::ZERO_WEIGHT,
					Severity::Medium,
					span_of(attr),
					"dispatchable is declared with zero weight",
				);
			}
		}
	}

	/// Visit the expressions inside a macro call, which `syn` leaves as raw tokens.
	fn visit_macro_body(&mut self, mac: &syn::Macro) {
		if let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
			for arg in &args {
				self.visit_expr(arg);
			}
		}
	}

	fn check_macro(&mut self, mac: &syn::Macro) {
		let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string()) else { return };
		if PANIC_MACROS.contains(&name.as_str()) {
			let severity = self.by_scope(Severity::High, Severity::Medium);
			self.report(rules::PANIC, severity, span_of(mac), format!("`{name}!` can panic"));
		}
		self.visit_macro_body(mac);
	}
}

fn doc_text(attrs: &[Attribute]) -> String {
	attrs
		.iter()
		.filter(|a| a.path().is_ident("doc"))
		.filter_map(|a| match &a.meta {
			syn::Meta::NameValue(nv) => match &nv.value {
				Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => Some(s.value()),
				_ => None,
			},
			_ => None,
		})
		.collect::<Vec<_>>()
		.join(" ")
}

/// Attributes on the statement-level expressions that commonly carry `#[cfg(test)]`.
fn expr_attrs(e: &Expr) -> &[Attribute] {
	match e {
		Expr::Block(x) => &x.attrs,
		Expr::Call(x) => &x.attrs,
		Expr::MethodCall(x) => &x.attrs,
		Expr::Macro(x) => &x.attrs,
		Expr::If(x) => &x.attrs,
		Expr::ForLoop(x) => &x.attrs,
		Expr::While(x) => &x.attrs,
		Expr::Loop(x) => &x.attrs,
		Expr::Match(x) => &x.attrs,
		Expr::Assign(x) => &x.attrs,
		Expr::Unsafe(x) => &x.attrs,
		_ => &[],
	}
}

/// `.expect("... qed")`: Substrate's convention for a panic that carries a written proof that
/// it cannot happen.
fn has_qed_proof(args: &Punctuated<Expr, Token![,]>) -> bool {
	args.iter().any(|a| match a {
		Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => s.value().to_lowercase().contains("qed"),
		_ => false,
	})
}

/// The call at the root of a method chain such as `Queue::<T>::iter_keys().filter(..).next()`.
fn chain_root(mut e: &Expr) -> Option<&syn::ExprCall> {
	loop {
		match e {
			Expr::MethodCall(m) => e = &m.receiver,
			Expr::Call(c) => return Some(c),
			Expr::Paren(p) => e = &p.expr,
			_ => return None,
		}
	}
}

fn position(span: Span) -> (usize, usize) {
	let s = span.start();
	(s.line, s.column)
}

fn span_of<T: ToTokens>(node: &T) -> Span {
	node.to_token_stream().into_iter().next().map(|t| t.span()).unwrap_or_else(Span::call_site)
}

fn path_is(path: &syn::Path, want: &[&str]) -> bool {
	let got: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
	got.len() >= want.len() && got[got.len() - want.len()..].iter().zip(want).all(|(a, b)| a == b)
}

fn has_pallet_attr(attrs: &[Attribute], name: &str) -> bool {
	attrs.iter().any(|a| path_is(a.path(), &["pallet", name]))
}

/// `#[cfg(test)]`, `#[cfg(feature = "runtime-benchmarks")]`, `#[cfg(feature = "try-runtime")]`,
/// `#[cfg(feature = "std")]`, `#[test]`: code that never runs inside the on-chain runtime.
fn is_exempt(attrs: &[Attribute]) -> bool {
	attrs.iter().any(|a| {
		if a.path().is_ident("test") {
			return true;
		}
		if !a.path().is_ident("cfg") {
			return false;
		}
		let cfg = a.meta.to_token_stream().to_string().replace(' ', "");
		!cfg.contains("not(")
			&& (cfg.contains("(test")
				|| cfg.contains(",test")
				|| cfg.contains("runtime-benchmarks")
				|| cfg.contains("try-runtime")
				|| cfg.contains("feature=\"std\""))
	})
}

fn int_literal(expr: &Expr) -> Option<u128> {
	match expr {
		Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => i.base10_parse::<u128>().ok(),
		Expr::Paren(p) => int_literal(&p.expr),
		_ => None,
	}
}

fn is_literal(expr: &Expr) -> bool {
	matches!(expr, Expr::Lit(_)) || matches!(expr, Expr::Paren(p) if is_literal(&p.expr))
}

fn is_zero_weight(expr: &Expr) -> bool {
	if int_literal(expr) == Some(0) {
		return true;
	}
	let text = expr.to_token_stream().to_string().replace(' ', "");
	text == "Weight::zero()"
		|| text.ends_with("Weight::from_parts(0,0)")
		|| text.starts_with("(0,")
		|| text.starts_with("(Weight::zero(),")
}

impl<'ast> Visit<'ast> for Analyzer<'_> {
	fn visit_item_mod(&mut self, m: &'ast ItemMod) {
		let exempt = is_exempt(&m.attrs) || m.ident == "tests" || m.ident == "benchmarks";
		self.exempt += usize::from(exempt);
		visit::visit_item_mod(self, m);
		self.exempt -= usize::from(exempt);
	}

	fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
		if let Some(attr) =
			s.attrs.iter().find(|a| path_is(a.path(), &["pallet", "without_storage_info"]))
		{
			self.report(
				rules::UNBOUNDED_STORAGE,
				Severity::Medium,
				span_of(attr),
				"pallet opts out of storage bounds with `without_storage_info`",
			);
		}
		visit::visit_item_struct(self, s);
	}

	fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
		if has_pallet_attr(&t.attrs, "storage") && !is_exempt(&t.attrs) {
			if has_pallet_attr(&t.attrs, "unbounded") {
				self.report(
					rules::UNBOUNDED_STORAGE,
					Severity::Medium,
					t.ident.span(),
					format!("storage item `{}` is marked `#[pallet::unbounded]`", t.ident),
				);
			} else if type_has_bare_vec(&t.ty) {
				self.report(
					rules::UNBOUNDED_STORAGE,
					Severity::Medium,
					t.ident.span(),
					format!("storage item `{}` holds an unbounded `Vec`", t.ident),
				);
			}
		}
		visit::visit_item_type(self, t);
	}

	fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
		let exempt = is_exempt(&i.attrs);
		self.exempt += usize::from(exempt);
		let kind = if has_pallet_attr(&i.attrs, "call") {
			ImplKind::Call
		} else if has_pallet_attr(&i.attrs, "hooks") {
			ImplKind::Hooks
		} else if has_pallet_attr(&i.attrs, "genesis_build") {
			ImplKind::GenesisBuild
		} else {
			ImplKind::Other
		};
		self.impl_kind.push(kind);
		self.exempt += usize::from(kind == ImplKind::GenesisBuild);
		visit::visit_item_impl(self, i);
		self.exempt -= usize::from(kind == ImplKind::GenesisBuild);
		self.impl_kind.pop();
		self.exempt -= usize::from(exempt);
	}

	fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
		let name = f.sig.ident.to_string();
		let exempt = is_exempt(&f.attrs) || is_exempt_fn(&name);
		self.exempt += usize::from(exempt);
		let scope = match self.impl_kind.last() {
			Some(ImplKind::Call) => Scope::Call,
			Some(ImplKind::Hooks) if HOOKS.contains(&name.as_str()) => Scope::Hook,
			_ => Scope::Helper,
		};
		self.scope.push((scope, Some(name)));
		self.weight_metered.push(is_weight_metered(&f.block));
		if scope == Scope::Call {
			self.check_origin(f);
			self.check_weight(&f.attrs);
		}
		visit::visit_impl_item_fn(self, f);
		self.weight_metered.pop();
		self.scope.pop();
		self.exempt -= usize::from(exempt);
	}

	fn visit_item_fn(&mut self, f: &'ast ItemFn) {
		let name = f.sig.ident.to_string();
		let exempt = is_exempt(&f.attrs) || is_exempt_fn(&name);
		self.exempt += usize::from(exempt);
		self.scope.push((Scope::Helper, Some(name)));
		self.weight_metered.push(is_weight_metered(&f.block));
		visit::visit_item_fn(self, f);
		self.weight_metered.pop();
		self.scope.pop();
		self.exempt -= usize::from(exempt);
	}

	fn visit_stmt(&mut self, s: &'ast syn::Stmt) {
		let attrs: &[Attribute] = match s {
			syn::Stmt::Local(l) => &l.attrs,
			syn::Stmt::Macro(m) => &m.attrs,
			syn::Stmt::Expr(e, _) => expr_attrs(e),
			syn::Stmt::Item(_) => &[],
		};
		let exempt = is_exempt(attrs);
		self.exempt += usize::from(exempt);
		visit::visit_stmt(self, s);
		self.exempt -= usize::from(exempt);
	}

	fn visit_item_const(&mut self, _: &'ast syn::ItemConst) {
		// Evaluated at compile time: a panic there is a build error, not a runtime one.
	}

	fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
		let method = m.method.to_string();
		if method == "expect" && has_qed_proof(&m.args) {
			self.report(
				rules::PANIC,
				Severity::Low,
				m.method.span(),
				"`.expect()` with a written proof (qed); check the proof still holds",
			);
		} else if method == "unwrap" || method == "expect" {
			let severity = self.by_scope(Severity::High, Severity::Medium);
			self.report(
				rules::PANIC,
				severity,
				m.method.span(),
				format!("`.{method}()` can panic"),
			);
		}
		if matches!(method.as_str(), "next" | "take" | "nth") {
			if let Some(root) = chain_root(&m.receiver) {
				self.bounded_iters.insert(position(span_of(root)));
			}
		}
		visit::visit_expr_method_call(self, m);
	}

	fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
		if let Expr::Path(p) = &*c.func {
			let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
			if let [.., owner, last] = segs.as_slice() {
				let iterates =
					ITER_FNS.contains(&last.as_str()) && self.storage_items.contains(owner);
				let clears_all = (last == "remove_all"
					&& c.args.first().map(|a| a.to_token_stream().to_string())
						== Some("None".into()))
					|| ((last == "clear" || last == "clear_prefix")
						&& c.args.iter().any(|a| {
							a.to_token_stream().to_string().replace(' ', "") == "u32::MAX"
						}));
				let bounded = self.bounded_iters.contains(&position(span_of(c)));
				if !bounded && (iterates || (clears_all && self.storage_items.contains(owner))) {
					let metered = self.weight_metered.last().copied().unwrap_or(false);
					let severity = match self.current().0 {
						Scope::Hook if !metered => Severity::High,
						_ => Severity::Medium,
					};
					self.report(
						rules::UNBOUNDED_ITERATION,
						severity,
						span_of(c),
						format!("`{owner}::{last}` walks the whole storage item"),
					);
				}
				if (last == "random" || last == "random_seed")
					&& segs.iter().any(|s| s.contains("Randomness"))
				{
					self.report(
						rules::RANDOMNESS,
						Severity::Medium,
						span_of(c),
						"randomness read from chain state can be predicted or biased",
					);
				}
			}
		}
		visit::visit_expr_call(self, c);
	}

	fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
		let op = match b.op {
			BinOp::Add(_) | BinOp::AddAssign(_) => Some("+"),
			BinOp::Sub(_) | BinOp::SubAssign(_) => Some("-"),
			BinOp::Mul(_) | BinOp::MulAssign(_) => Some("*"),
			BinOp::Div(_) | BinOp::DivAssign(_) => Some("/"),
			BinOp::Rem(_) | BinOp::RemAssign(_) => Some("%"),
			_ => None,
		};
		let both_literal = is_literal(&b.left) && is_literal(&b.right);
		if let (Some(op), false) = (op, both_literal) {
			let divides = op == "/" || op == "%";
			let safe_divisor = divides && int_literal(&b.right).is_some_and(|d| d != 0);
			if !safe_divisor {
				let severity = self.by_scope(Severity::Medium, Severity::Low);
				let message = if divides {
					format!("`{op}` panics if the divisor is zero")
				} else {
					format!("`{op}` wraps on overflow in a release build")
				};
				self.report(rules::ARITHMETIC, severity, span_of(&b.op), message);
			}
		}
		visit::visit_expr_binary(self, b);
	}

	fn visit_expr_cast(&mut self, c: &'ast syn::ExprCast) {
		if let Type::Path(p) = &*c.ty {
			if let Some(ty) = p.path.get_ident().map(|i| i.to_string()) {
				if NARROW_INTS.contains(&ty.as_str()) && int_literal(&c.expr).is_none() {
					self.report(
						rules::CAST,
						Severity::Low,
						span_of(&c.ty),
						format!("`as {ty}` truncates silently"),
					);
				}
			}
		}
		visit::visit_expr_cast(self, c);
	}

	fn visit_expr_index(&mut self, i: &'ast syn::ExprIndex) {
		let severity = self.by_scope(Severity::Medium, Severity::Low);
		self.report(
			rules::INDEXING,
			severity,
			span_of(&i.index),
			"indexing panics when out of bounds",
		);
		visit::visit_expr_index(self, i);
	}

	fn visit_expr_unsafe(&mut self, u: &'ast syn::ExprUnsafe) {
		self.report(
			rules::UNSAFE,
			Severity::Medium,
			span_of(u),
			"`unsafe` block in runtime code; needs a documented safety argument and review",
		);
		visit::visit_expr_unsafe(self, u);
	}

	fn visit_expr_macro(&mut self, m: &'ast syn::ExprMacro) {
		self.check_macro(&m.mac);
		visit::visit_expr_macro(self, m);
	}

	fn visit_stmt_macro(&mut self, m: &'ast syn::StmtMacro) {
		self.check_macro(&m.mac);
		visit::visit_stmt_macro(self, m);
	}
}

fn is_weight_metered(block: &syn::Block) -> bool {
	let body = block.to_token_stream().to_string();
	["WeightMeter", "try_consume", "can_consume", "remaining_weight"]
		.iter()
		.any(|w| body.contains(w))
}

fn type_has_bare_vec(ty: &Type) -> bool {
	struct Finder(bool);
	impl<'ast> Visit<'ast> for Finder {
		fn visit_path_segment(&mut self, s: &'ast syn::PathSegment) {
			if s.ident == "Vec" {
				self.0 = true;
			}
			visit::visit_path_segment(self, s);
		}
	}
	let mut f = Finder(false);
	f.visit_type(ty);
	f.0
}

/// Names of every `#[pallet::storage]` item in a file, used to recognise storage iteration.
pub fn storage_items(file: &syn::File) -> HashSet<String> {
	struct Collector(HashSet<String>);
	impl<'ast> Visit<'ast> for Collector {
		fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
			if has_pallet_attr(&t.attrs, "storage") {
				self.0.insert(t.ident.to_string());
			}
		}
	}
	let mut c = Collector(HashSet::new());
	c.visit_file(file);
	c.0
}

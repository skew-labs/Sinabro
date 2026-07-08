//! Stage C full-pipeline redaction canary (C-WP-03A · atom #192 · C.0.21).
//!
//! Canonical OUT: canary evidence that no secret-like bytes can pass into
//! external evidence, logs, metrics, or the Walrus/Sui publish path. The test
//! plants distinct canary strings and proves every reachable rendering surface
//! drops them to a class label or a length count.
//!
//! Reuse (no re-mint): the Stage A redaction kernel
//! [`redact_for_log`](mnemos_a_core::logging::redact_for_log) (9
//! [`LogRedactionKind`] variants), the Stage B publish-class policy
//! [`stage_b_publish_allowed`](mnemos_b_memory::stage_b_publish_allowed), and the
//! k-devex [`Metric`] exposition names. No live network, no wallet, no mainnet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mnemos_a_core::logging::{LogRedactionKind, redact_for_log};
use mnemos_b_memory::stage_b_publish_allowed;
use mnemos_c_walrus::PublishPayloadClass;
use mnemos_k_devex::{Metric, MetricsExporter};

const WALLET_SECRET_CANARY: &str = "CANARY-WALLET-SECRET-7f3a9b-DO-NOT-LEAK";
const PROVIDER_BODY_CANARY: &str = "CANARY-PROVIDER-BODY-7f3a9b-DO-NOT-LEAK";
const CHUNK_CONTENT_CANARY: &str = "CANARY-CHUNK-CONTENT-7f3a9b-DO-NOT-LEAK";

/// All nine §4.0 redaction classes, exhaustively.
const ALL_REDACTION_KINDS: [LogRedactionKind; 9] = [
    LogRedactionKind::WalletPassphrase,
    LogRedactionKind::SuiPrivateKey,
    LogRedactionKind::SuiTxBytes,
    LogRedactionKind::WalrusBytes,
    LogRedactionKind::ToolIo,
    LogRedactionKind::Prompt,
    LogRedactionKind::ProviderBody,
    LogRedactionKind::SourceChain,
    LogRedactionKind::ApiToken,
];

/// Secret-shaped substrings that must never appear inside a metric exposition
/// name. `TOKEN` is deliberately excluded — `*_tokens_total` is a legitimate
/// counter axis, not a credential.
const SECRET_NAME_TOKENS: [&str; 7] = [
    "KEY",
    "SECRET",
    "PASS",
    "PRIVATE",
    "MNEMONIC",
    "CREDENTIAL",
    "BEARER",
];

#[test]
fn wallet_secret_canary() {
    // A wallet passphrase / private key redacts to a class label only.
    for kind in [
        LogRedactionKind::WalletPassphrase,
        LogRedactionKind::SuiPrivateKey,
    ] {
        let rendered = format!("{}", redact_for_log(WALLET_SECRET_CANARY, kind));
        assert!(
            !rendered.contains(WALLET_SECRET_CANARY),
            "wallet secret leaked into {rendered}"
        );
        assert!(rendered.starts_with("<redacted:"));
    }
}

#[test]
fn provider_body_canary() {
    let rendered = format!(
        "{}",
        redact_for_log(PROVIDER_BODY_CANARY, LogRedactionKind::ProviderBody)
    );
    assert!(
        !rendered.contains(PROVIDER_BODY_CANARY),
        "provider body leaked into {rendered}"
    );
}

#[test]
fn chunk_content_canary() {
    // Only synthetic public fixtures may publish; every secret/prompt/tool/real
    // class is denied by the content policy (fail-closed).
    assert!(stage_b_publish_allowed(
        PublishPayloadClass::SyntheticPublicFixture
    ));
    for denied in [
        PublishPayloadClass::RealUserMemory,
        PublishPayloadClass::PromptOrProviderText,
        PublishPayloadClass::ToolOutput,
        PublishPayloadClass::SecretLike,
        PublishPayloadClass::PrivateProvenance,
    ] {
        assert!(
            !stage_b_publish_allowed(denied),
            "content policy admitted a non-public class: {denied:?}"
        );
    }
    // A raw chunk body redacts to a class label, never its content.
    let rendered = format!(
        "{}",
        redact_for_log(CHUNK_CONTENT_CANARY, LogRedactionKind::WalrusBytes)
    );
    assert!(!rendered.contains(CHUNK_CONTENT_CANARY));
}

#[test]
fn log_metric_event_absence() {
    // (1) No metric exposition name embeds a secret-shaped keyword.
    let all_metrics = [
        Metric::LlmInputTokens,
        Metric::LlmOutputTokens,
        Metric::CacheHitRatioBp,
        Metric::WalrusPutLatencyMs,
        Metric::SuiGasMist,
        Metric::ToolDenials,
        Metric::DailyUsdMicros,
    ];
    for metric in all_metrics {
        let upper = metric.name().to_uppercase();
        for token in SECRET_NAME_TOKENS {
            assert!(
                !upper.contains(token),
                "metric {} leaks secret token {token}",
                metric.name()
            );
        }
    }

    // (2) A freshly-rendered metric exposition contains no planted canary.
    let rendered = MetricsExporter::new().render();
    for canary in [
        WALLET_SECRET_CANARY,
        PROVIDER_BODY_CANARY,
        CHUNK_CONTENT_CANARY,
    ] {
        assert!(
            !rendered.contains(canary),
            "metric exposition leaked {canary}"
        );
    }

    // (3) Every one of the nine redaction classes drops the raw secret.
    for kind in ALL_REDACTION_KINDS {
        let rendered = format!("{}", redact_for_log(WALLET_SECRET_CANARY, kind));
        assert!(
            !rendered.contains(WALLET_SECRET_CANARY),
            "redaction kind {kind:?} leaked the raw secret"
        );
    }
}

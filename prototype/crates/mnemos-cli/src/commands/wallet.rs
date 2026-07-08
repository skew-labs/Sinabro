//! `sinabro wallet` — wallet connect / identity status for the memory-owner
//! identity.
//!
//! Status-only projection. The CLI shows *which* auth method backs the wallet
//! (zkLogin / passkey / local encrypted keystore / session / disconnected) and
//! the redacted owner address, **without ever loading, cloning, `Debug`-printing
//! or networking key material**. Three structural invariants live here:
//!
//! * **No key material.** Owner identity is a 32-byte PUBLIC key, always shown as
//!   a [`redact16`] 16-hex prefix. Any keystore secret is referenced through the
//!   canonical [`SecretRefView`] (`value_never_loaded == true`), never read.
//!   [`WalletStatusView::key_material_loaded`] is the invariant `false`.
//! * **Owner is never silently replaced by the sponsor.** The memory-owner
//!   identity used for chunk/root intent signing is explicit; the sponsor gas
//!   authority is a *separate* key, surfaced by
//!   [`MemoryOwnerBinding::owner_is_not_sponsor`] (the owner/sponsor separation
//!   rule, re-asserted at the wallet surface).
//! * **No live signing.** This module connects/reports status only; the
//!   sign/simulate surface is [`crate::commands::wallet_sign`], and even there
//!   signing is preview-only in Stage F.
//!
//! Reuse (no reinvention): the signer backend taxonomy is the canonical
//! [`mnemos_g_wallet::SignerBackendKind`] (KMS / HSM / TEE / signing daemon — the
//! API process is always on the other side of the boundary); the secret-custody
//! primitive is [`crate::secrets::SecretRefView`]; the leak detector reuses
//! [`crate::secrets::scan_inline_secret`] (a-core `looks_like_secret`).

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use crate::secrets::{SecretRefView, classify_reference, scan_inline_secret};
use mnemos_g_wallet::SignerBackendKind;

/// First 16 hex characters of a 32-byte digest/pubkey — a redacted, display-only
/// prefix that never reveals a full key or address.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// How the memory-owner wallet is connected. A closed enum: an unknown auth
/// method is unrepresentable, and `Disconnected` is explicit (never a silent
/// "connected" default).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletAuthKind {
    /// zkLogin (OAuth-derived) identity.
    ZkLogin = 1,
    /// WebAuthn / passkey identity.
    Passkey = 2,
    /// A local, at-rest-encrypted keystore (seed sealed; only the public address
    /// is read on the hot path).
    LocalKeystore = 3,
    /// An already-authenticated session (re-using a prior connect).
    Session = 4,
    /// No wallet connected.
    Disconnected = 5,
}

impl WalletAuthKind {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this auth kind represents a live, authenticated connection.
    #[must_use]
    pub const fn is_connected(self) -> bool {
        !matches!(self, Self::Disconnected)
    }
}

/// The memory-owner identity binding. The owner is bound from a 32-byte PUBLIC
/// key; the optional sponsor key (who pays gas) is always a *different* key —
/// [`owner_is_not_sponsor`](Self::owner_is_not_sponsor) is the surfaced proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryOwnerBinding {
    owner_pubkey_32: [u8; 32],
    sponsor_pubkey_32: Option<[u8; 32]>,
}

impl MemoryOwnerBinding {
    /// Bind an owner public key and an optional sponsor public key.
    #[must_use]
    pub const fn new(owner_pubkey_32: [u8; 32], sponsor_pubkey_32: Option<[u8; 32]>) -> Self {
        Self {
            owner_pubkey_32,
            sponsor_pubkey_32,
        }
    }

    /// Whether the memory owner is a separate key from the gas sponsor. `true`
    /// when there is no sponsor, or when the sponsor key differs from the owner
    /// key. A `false` here is a custody violation (sponsor would own the memory).
    #[must_use]
    pub fn owner_is_not_sponsor(&self) -> bool {
        match self.sponsor_pubkey_32 {
            Some(s) => s != self.owner_pubkey_32,
            None => true,
        }
    }

    /// Redacted 16-hex prefix of the owner public key.
    #[must_use]
    pub fn owner_redacted(&self) -> String {
        redact16(&self.owner_pubkey_32)
    }

    /// Redacted 16-hex prefix of the sponsor public key, or `"none"`.
    #[must_use]
    pub fn sponsor_redacted(&self) -> String {
        match self.sponsor_pubkey_32 {
            Some(s) => redact16(&s),
            None => "none".to_string(),
        }
    }
}

/// A status-only view of the wallet connection. Holds NO key material: only the
/// auth kind, the redacted owner address, the (optional) signer backend, the
/// session flag, and a [`SecretRefView`] for the keystore reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletStatusView {
    /// How the wallet is connected.
    pub auth_kind: WalletAuthKind,
    /// The memory-owner identity binding (owner vs sponsor).
    pub owner: MemoryOwnerBinding,
    /// Where the signer lives for a local keystore (KMS / HSM / TEE / daemon);
    /// `None` for zkLogin / passkey / session / disconnected.
    pub signer_backend: Option<SignerBackendKind>,
    /// Whether a live, authenticated session is present.
    pub session_active: bool,
    /// A status-only reference to the keystore secret (value never loaded).
    pub keystore_secret_ref: SecretRefView,
    /// Invariant `false`: the CLI never loads / clones / Debug-prints key
    /// material to build this view.
    pub key_material_loaded: bool,
}

impl WalletStatusView {
    /// Connect a wallet of `auth_kind` for the given owner binding. A keystore
    /// reference string (e.g. `keychain:wallet` / `kms:...` / empty) is
    /// classified into a [`SecretRefView`] without loading the value. The signer
    /// backend is recorded only for a local keystore.
    #[must_use]
    pub fn connect(
        auth_kind: WalletAuthKind,
        owner: MemoryOwnerBinding,
        signer_backend: Option<SignerBackendKind>,
        keystore_reference: &str,
    ) -> Self {
        Self {
            auth_kind,
            owner,
            signer_backend: match auth_kind {
                WalletAuthKind::LocalKeystore => signer_backend,
                _ => None,
            },
            session_active: auth_kind.is_connected(),
            keystore_secret_ref: classify_reference("wallet_keystore", keystore_reference),
            key_material_loaded: false,
        }
    }

    /// A disconnected wallet status (the explicit no-connection state).
    #[must_use]
    pub fn disconnected(owner: MemoryOwnerBinding) -> Self {
        Self {
            auth_kind: WalletAuthKind::Disconnected,
            owner,
            signer_backend: None,
            session_active: false,
            keystore_secret_ref: classify_reference("wallet_keystore", ""),
            key_material_loaded: false,
        }
    }

    /// The command risk of *reading* wallet status: pure read, no side effect.
    #[must_use]
    pub const fn status_risk(&self) -> CommandRisk {
        CommandRisk::ReadOnly
    }

    /// The approval gate that any wallet *signing* action would require (always
    /// [`ApprovalRequirement::TypedPhrase`], via the canonical
    /// [`approval_for`]`(`[`CommandRisk::WalletSign`]`)` mapping). Surfaced here
    /// so the status view documents the live boundary even though signing is
    /// preview-only in Stage F.
    #[must_use]
    pub fn sign_approval(&self) -> ApprovalRequirement {
        approval_for(CommandRisk::WalletSign)
    }

    /// The secret-custody invariant: the keystore value is never loaded and no
    /// key material is held. Always `true` by construction.
    #[must_use]
    pub const fn secret_custody_ok(&self) -> bool {
        self.keystore_secret_ref.value_never_loaded && !self.key_material_loaded
    }

    /// Redacted, colorless status lines bounded by `rows`. Field labels avoid any
    /// raw-secret marker substring so the render itself passes [`key_leak_scan`].
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let backend = match self.signer_backend {
            Some(b) => (b as u8).to_string(),
            None => "none".to_string(),
        };
        let lines = vec![
            format!("auth_kind_u8={}", self.auth_kind.tag()),
            format!("owner={}", self.owner.owner_redacted()),
            format!("sponsor={}", self.owner.sponsor_redacted()),
            format!("owner_is_not_sponsor={}", self.owner.owner_is_not_sponsor()),
            format!("signer_backend_u8={backend}"),
            format!("session_active={}", self.session_active),
            format!(
                "secret_location_u8={}",
                self.keystore_secret_ref.location as u8
            ),
            format!(
                "value_never_loaded={}",
                self.keystore_secret_ref.value_never_loaded
            ),
            format!("key_material_loaded={}", self.key_material_loaded),
            format!("sign_approval_u8={}", self.sign_approval() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Scan rendered / log lines for live-shaped secret material — the key
/// leak scan. Returns `true` if ANY line looks like a raw key (reuses the a-core
/// detector via [`crate::secrets::scan_inline_secret`]). A clean status render
/// returns `false`.
#[must_use]
pub fn key_leak_scan(lines: &[String]) -> bool {
    lines.iter().any(|l| scan_inline_secret(l))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn owner_only() -> MemoryOwnerBinding {
        MemoryOwnerBinding::new(key(1), None)
    }

    fn owner_sponsor() -> MemoryOwnerBinding {
        MemoryOwnerBinding::new(key(1), Some(key(2)))
    }

    #[test]
    fn connect_zklogin_fixture() {
        let v = WalletStatusView::connect(WalletAuthKind::ZkLogin, owner_only(), None, "");
        assert_eq!(v.auth_kind, WalletAuthKind::ZkLogin);
        assert!(v.session_active);
        assert!(v.signer_backend.is_none());
        assert!(v.secret_custody_ok());
        assert!(!v.key_material_loaded);
    }

    #[test]
    fn connect_passkey_fixture() {
        let v = WalletStatusView::connect(WalletAuthKind::Passkey, owner_only(), None, "");
        assert_eq!(v.auth_kind, WalletAuthKind::Passkey);
        assert!(v.auth_kind.is_connected());
        assert!(v.signer_backend.is_none());
    }

    #[test]
    fn connect_local_encrypted_keystore_fixture() {
        // A local encrypted keystore records WHERE the signer lives (KMS), and a
        // status-only reference to the keystore secret — never the value.
        let v = WalletStatusView::connect(
            WalletAuthKind::LocalKeystore,
            owner_only(),
            Some(SignerBackendKind::Kms),
            "kms:projects/x/keys/wallet",
        );
        assert_eq!(v.signer_backend, Some(SignerBackendKind::Kms));
        assert!(v.keystore_secret_ref.value_never_loaded);
        assert!(v.secret_custody_ok());
    }

    #[test]
    fn connect_fixture_all_signer_backends() {
        for b in [
            SignerBackendKind::Kms,
            SignerBackendKind::Hsm,
            SignerBackendKind::Tee,
            SignerBackendKind::SigningDaemon,
        ] {
            let v =
                WalletStatusView::connect(WalletAuthKind::LocalKeystore, owner_only(), Some(b), "");
            assert_eq!(v.signer_backend, Some(b));
        }
    }

    #[test]
    fn disconnected_is_explicit() {
        let v = WalletStatusView::disconnected(owner_only());
        assert_eq!(v.auth_kind, WalletAuthKind::Disconnected);
        assert!(!v.session_active);
        assert!(!v.auth_kind.is_connected());
        assert!(v.signer_backend.is_none());
    }

    #[test]
    fn sponsor_not_owner_fixture() {
        // Separate owner / sponsor keys => owner is not sponsor (custody safe).
        assert!(owner_sponsor().owner_is_not_sponsor());
        assert!(owner_only().owner_is_not_sponsor());
        // owner == sponsor is a custody violation, surfaced as false.
        let collision = MemoryOwnerBinding::new(key(7), Some(key(7)));
        assert!(!collision.owner_is_not_sponsor());
    }

    #[test]
    fn sign_action_requires_typed_phrase() {
        let v = WalletStatusView::connect(WalletAuthKind::ZkLogin, owner_only(), None, "");
        assert_eq!(v.sign_approval(), ApprovalRequirement::TypedPhrase);
        assert_eq!(v.status_risk(), CommandRisk::ReadOnly);
    }

    #[test]
    fn key_leak_scan_detects_raw_key_but_not_redacted_render() {
        // A live-shaped private key is detected.
        assert!(key_leak_scan(&[
            "owner_key = \"suiprivkey1qexamplenotreal\"".to_string()
        ]));
        // A clean, redacted status render leaks nothing.
        let v = WalletStatusView::connect(
            WalletAuthKind::LocalKeystore,
            owner_sponsor(),
            Some(SignerBackendKind::Hsm),
            "keychain:wallet",
        );
        assert!(
            !key_leak_scan(&v.render(32)),
            "redacted render must not leak"
        );
    }

    #[test]
    fn status_render_is_bounded() {
        let v = WalletStatusView::connect(WalletAuthKind::Session, owner_only(), None, "");
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 10);
    }

    #[test]
    fn wallet_status_p95_within_30ms() {
        let v = WalletStatusView::connect(
            WalletAuthKind::LocalKeystore,
            owner_sponsor(),
            Some(SignerBackendKind::Tee),
            "kms:wallet",
        );
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 30, "wallet status p95 {p95}ms exceeds 30ms budget");
    }
}

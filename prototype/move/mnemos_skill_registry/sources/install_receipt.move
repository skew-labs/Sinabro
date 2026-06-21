// atom #282 · D.2.6 — InstallReceipt struct (matches §4.3 `InstallReceiptView`).
// atom #283 · D.2.7 — record_install entry (-> InstallState::Installed).
// atom #284 · D.2.8 — install state check (Rust+Move parity; runtime-usable).
// atom #285 · D.2.9 — enable/disable/remove/revoke install entries.
//
// The receipt points to user, package digest, capability-approval hash, local
// install digest, and state. It NEVER stores a payment, checkout, key, or secret
// field (no-commerce + no-secret law). A browser redirect or a local flag cannot
// create install state: record_install requires a signed-package digest, a
// non-zero dry-run/local-install digest, a non-zero capability-approval hash,
// and the user == signer.
//
// State discriminants are byte-pinned to the Rust e-skill `InstallState`
// (§4.3): None=1, DryRun=2, Installed=3, Enabled=4, Disabled=5, Removed=6,
// Revoked=7. Runtime use requires Installed or Enabled; Disabled/Removed/Revoked
// always deny. Disable/remove/revoke are explicit, evented, and idempotent.
//
// Offline-only: `sui move test`; no live network egress; mainnet locked; no live
// on-chain action this WorkPackage.
#[allow(lint(public_entry))]
module mnemos_skill_registry::install_receipt;

use mnemos_skill_registry::events;

// InstallState discriminants — MUST match Rust e-skill `InstallState` (§4.3).
const STATE_INSTALLED: u8 = 3;
const STATE_ENABLED: u8 = 4;
const STATE_DISABLED: u8 = 5;
const STATE_REMOVED: u8 = 6;
const STATE_REVOKED: u8 = 7;

const E_BAD_DIGEST_LEN: u64 = 1;
const E_USER_NOT_SENDER: u64 = 2;
const E_MISSING_DRY_RUN_HASH: u64 = 3;
const E_MISSING_CAPABILITY_APPROVAL: u64 = 4;
const E_USER_MISMATCH: u64 = 5;
const E_TERMINAL_STATE: u64 = 6;

/// Owned install record. `has key` only (no `store`): not arbitrarily wrappable.
public struct InstallReceipt has key {
    id: sui::object::UID,
    skill: u16,
    package: vector<u8>,
    user: address,
    local_install_digest: vector<u8>,
    capability_approval_hash: vector<u8>,
    state: u8,
    recorded_epoch: u64,
}

fun is_zero_32(v: &vector<u8>): bool {
    let mut i = 0u64;
    let n = v.length();
    while (i < n) {
        if (*v.borrow(i) != 0u8) return false;
        i = i + 1;
    };
    true
}

/// #283 — mint the first install receipt (state = Installed). Requires non-zero
/// dry-run and capability-approval hashes; user must equal the signer.
public entry fun record_install(
    skill: u16,
    package: vector<u8>,
    user: address,
    local_install_digest: vector<u8>,
    capability_approval_hash: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(local_install_digest.length() == 32, E_BAD_DIGEST_LEN);
    assert!(capability_approval_hash.length() == 32, E_BAD_DIGEST_LEN);
    assert!(user == ctx.sender(), E_USER_NOT_SENDER);
    assert!(!is_zero_32(&local_install_digest), E_MISSING_DRY_RUN_HASH);
    assert!(!is_zero_32(&capability_approval_hash), E_MISSING_CAPABILITY_APPROVAL);
    let receipt = InstallReceipt {
        id: sui::object::new(ctx),
        skill,
        package,
        user,
        local_install_digest,
        capability_approval_hash,
        state: STATE_INSTALLED,
        recorded_epoch: ctx.epoch(),
    };
    events::emit_install_recorded(sui::object::id(&receipt), skill, package, user, STATE_INSTALLED);
    sui::transfer::transfer(receipt, user);
}

/// #285 enable — Installed/Disabled -> Enabled. Idempotent if already Enabled.
public entry fun enable_install(receipt: &mut InstallReceipt, ctx: &mut TxContext) {
    assert!(ctx.sender() == receipt.user, E_USER_MISMATCH);
    let old = receipt.state;
    assert!(old != STATE_REMOVED && old != STATE_REVOKED, E_TERMINAL_STATE);
    if (old == STATE_ENABLED) return;
    receipt.state = STATE_ENABLED;
    events::emit_install_enabled(sui::object::id(receipt), receipt.user, old, STATE_ENABLED);
}

/// #285 disable — Installed/Enabled -> Disabled. Idempotent if already Disabled.
public entry fun disable_install(receipt: &mut InstallReceipt, ctx: &mut TxContext) {
    assert!(ctx.sender() == receipt.user, E_USER_MISMATCH);
    let old = receipt.state;
    assert!(old != STATE_REMOVED && old != STATE_REVOKED, E_TERMINAL_STATE);
    if (old == STATE_DISABLED) return;
    receipt.state = STATE_DISABLED;
    events::emit_install_disabled(sui::object::id(receipt), receipt.user, old, STATE_DISABLED);
}

/// #285 remove — non-revoked -> Removed (terminal). Idempotent if already Removed.
public entry fun remove_install(receipt: &mut InstallReceipt, ctx: &mut TxContext) {
    assert!(ctx.sender() == receipt.user, E_USER_MISMATCH);
    let old = receipt.state;
    assert!(old != STATE_REVOKED, E_TERMINAL_STATE);
    if (old == STATE_REMOVED) return;
    receipt.state = STATE_REMOVED;
    events::emit_install_removed(sui::object::id(receipt), receipt.user, old, STATE_REMOVED);
}

/// #285 revoke — any -> Revoked (terminal). Idempotent if already Revoked.
public entry fun revoke_install(receipt: &mut InstallReceipt, ctx: &mut TxContext) {
    assert!(ctx.sender() == receipt.user, E_USER_MISMATCH);
    let old = receipt.state;
    if (old == STATE_REVOKED) return;
    receipt.state = STATE_REVOKED;
    events::emit_install_revoked(sui::object::id(receipt), receipt.user, old, STATE_REVOKED);
}

/// #284 — runtime use requires Installed or Enabled; everything else denies.
public fun is_runtime_usable(receipt: &InstallReceipt): bool {
    receipt.state == STATE_INSTALLED || receipt.state == STATE_ENABLED
}

public fun state(receipt: &InstallReceipt): u8 { receipt.state }
public fun user(receipt: &InstallReceipt): address { receipt.user }
public fun skill(receipt: &InstallReceipt): u16 { receipt.skill }
public fun package(receipt: &InstallReceipt): vector<u8> { receipt.package }
public fun recorded_epoch(receipt: &InstallReceipt): u64 { receipt.recorded_epoch }

public fun state_installed(): u8 { STATE_INSTALLED }
public fun state_enabled(): u8 { STATE_ENABLED }
public fun state_disabled(): u8 { STATE_DISABLED }
public fun state_removed(): u8 { STATE_REMOVED }
public fun state_revoked(): u8 { STATE_REVOKED }

//! Stage C hosted/self/none sponsor-mode config.
//!
//! Provides a [`GasSponsorMode`]-mirroring sponsor-mode config.
//!
//! # Design invariants
//!
//! * **Explicit hosted / self-hosted / none.** The open-source client ships
//!   exactly three modes. `Hosted` and `SelfHosted` carry only an endpoint URL
//!   and a policy reference; `None` disables the sponsor path entirely (and may
//!   carry no URL).
//! * **URL / policy only, never a sponsor key.** [`SponsorModeConfig`] has *no
//!   field that can hold key material*. The public, open-source config surface
//!   is therefore secret-free by construction. Construction additionally
//!   *rejects* any URL / policy value that is shaped like a secret or an env
//!   interpolation that would pull one ([`SponsorModeConfigError::SecretShapedValue`]),
//!   so a sponsor key can never be smuggled into the config text.
//!
//! # Reuse map
//!
//! * **reuse** — this config mirrors the
//!   [`GasSponsorMode`](SponsorMode) discriminants. The authoritative
//!   `GasSponsorMode` enum lives in `mnemos-g-wallet`
//!   (`stage_c_gas_policy::GasSponsorMode`). `a-core` cannot depend on
//!   `g-wallet` (that edge would be a dependency cycle: `g-wallet -> a-core`
//!   already exists), so this module defines a **value-mirror** whose
//!   discriminants are byte-identical (`Hosted=1`, `SelfHosted=2`, `None=3`).
//!   The mirror is asserted against those exact values in tests; it is not a
//!   re-minted canonical *base* type (it carries config, not policy).
//!
//! No live action: parsing produces a typed, secret-free config value. No
//! egress, no signing. `MainnetExecutionState` stays `Locked`.

/// Whether/how a sponsor pays — a byte-exact value-mirror of the g-wallet
/// `GasSponsorMode` discriminants, usable from `a-core` without a
/// dependency cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SponsorMode {
    /// Hosted official sponsor (requires safety-kernel attestation downstream).
    Hosted = 1,
    /// Operator self-hosts the sponsor.
    SelfHosted = 2,
    /// No sponsorship — the sponsor path is disabled.
    None = 3,
}

impl SponsorMode {
    /// The raw discriminant (byte-identical to `GasSponsorMode::as_u8`).
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Hosted),
            2 => Some(Self::SelfHosted),
            3 => Some(Self::None),
            _ => None,
        }
    }

    /// Whether this mode sponsors at all (`None` does not).
    #[inline]
    #[must_use]
    pub const fn is_sponsoring(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// The secret-free sponsor-mode config. No field can hold key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SponsorModeConfig {
    mode: SponsorMode,
    endpoint_url: Option<String>,
    policy_ref: Option<String>,
}

/// Sponsor-mode config construction error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SponsorModeConfigError {
    /// The mode discriminant byte was not 1/2/3.
    UnknownMode = 1,
    /// `Hosted` / `SelfHosted` requires an endpoint URL.
    EndpointUrlRequired = 2,
    /// `None` must not carry an endpoint URL (it disables the sponsor path).
    NoneMustNotSponsor = 3,
    /// A URL / policy value was shaped like a secret or a secret env
    /// interpolation — refused so a sponsor key cannot be smuggled in.
    SecretShapedValue = 4,
}

impl core::fmt::Display for SponsorModeConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnknownMode => "stage_c sponsor mode: unknown mode discriminant",
            Self::EndpointUrlRequired => "stage_c sponsor mode: hosted/self requires endpoint url",
            Self::NoneMustNotSponsor => "stage_c sponsor mode: none must not carry an endpoint url",
            Self::SecretShapedValue => "stage_c sponsor mode: secret-shaped value refused",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SponsorModeConfigError {}

/// Whether a config string is shaped like a secret or an env interpolation that
/// would pull one. High-precision: matches raw key formats and `${...}`
/// interpolations naming a secret-class token. A plain `https://…` URL or a
/// filesystem policy path does not match.
#[must_use]
pub fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // Raw key material formats.
    const RAW_KEY_MARKERS: [&str; 6] = [
        "suiprivkey1",
        "age-secret-key-1",
        "-----begin",
        "privkey",
        "private_key",
        "secret_key",
    ];
    for marker in RAW_KEY_MARKERS {
        if lower.contains(marker) {
            return true;
        }
    }
    // Env interpolation `${...}` naming a secret-class token.
    if value.contains("${") {
        const SECRET_TOKENS: [&str; 6] = ["key", "secret", "private", "token", "mnemonic", "pass"];
        for token in SECRET_TOKENS {
            if lower.contains(token) {
                return true;
            }
        }
    }
    false
}

impl SponsorModeConfig {
    /// Build a config from a mode byte and optional URL / policy reference,
    /// rejecting secret-shaped values and mode/URL inconsistencies.
    ///
    /// # Errors
    ///
    /// [`SponsorModeConfigError::UnknownMode`] for a bad discriminant,
    /// [`SponsorModeConfigError::SecretShapedValue`] for a secret-shaped URL /
    /// policy, [`SponsorModeConfigError::EndpointUrlRequired`] when a sponsoring
    /// mode has no URL, and [`SponsorModeConfigError::NoneMustNotSponsor`] when
    /// `None` carries a URL.
    pub fn from_parts(
        mode_byte: u8,
        endpoint_url: Option<String>,
        policy_ref: Option<String>,
    ) -> Result<Self, SponsorModeConfigError> {
        let mode = SponsorMode::from_u8(mode_byte).ok_or(SponsorModeConfigError::UnknownMode)?;
        if let Some(url) = endpoint_url.as_deref() {
            if looks_like_secret(url) {
                return Err(SponsorModeConfigError::SecretShapedValue);
            }
        }
        if let Some(policy) = policy_ref.as_deref() {
            if looks_like_secret(policy) {
                return Err(SponsorModeConfigError::SecretShapedValue);
            }
        }
        match mode {
            SponsorMode::Hosted | SponsorMode::SelfHosted => {
                if endpoint_url.is_none() {
                    return Err(SponsorModeConfigError::EndpointUrlRequired);
                }
            }
            SponsorMode::None => {
                if endpoint_url.is_some() {
                    return Err(SponsorModeConfigError::NoneMustNotSponsor);
                }
            }
        }
        Ok(Self {
            mode,
            endpoint_url,
            policy_ref,
        })
    }

    /// The sponsor mode.
    #[inline]
    #[must_use]
    pub const fn mode(&self) -> SponsorMode {
        self.mode
    }

    /// The endpoint URL, if any.
    #[inline]
    #[must_use]
    pub fn endpoint_url(&self) -> Option<&str> {
        self.endpoint_url.as_deref()
    }

    /// The policy reference, if any.
    #[inline]
    #[must_use]
    pub fn policy_ref(&self) -> Option<&str> {
        self.policy_ref.as_deref()
    }

    /// Whether this config enables the sponsor path at all.
    #[inline]
    #[must_use]
    pub const fn sponsor_enabled(&self) -> bool {
        self.mode.is_sponsoring()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn discriminants_mirror_gas_sponsor_mode() {
        // Byte-exact value-mirror lock against the GasSponsorMode values.
        assert_eq!(SponsorMode::Hosted.as_u8(), 1);
        assert_eq!(SponsorMode::SelfHosted.as_u8(), 2);
        assert_eq!(SponsorMode::None.as_u8(), 3);
        assert_eq!(SponsorMode::from_u8(0), None);
        assert_eq!(SponsorMode::from_u8(4), None);
    }

    #[test]
    fn hosted_url_no_key() {
        let cfg = SponsorModeConfig::from_parts(
            1,
            Some("https://sponsor.example/v1".to_string()),
            Some("ops/gas-station/policy.schema.json".to_string()),
        )
        .expect("hosted with url + policy");
        assert_eq!(cfg.mode(), SponsorMode::Hosted);
        assert!(cfg.sponsor_enabled());
    }

    #[test]
    fn self_url_no_key() {
        let cfg = SponsorModeConfig::from_parts(
            2,
            Some("http://127.0.0.1:9000/sponsor".to_string()),
            None,
        )
        .expect("self with url");
        assert_eq!(cfg.mode(), SponsorMode::SelfHosted);
        assert!(cfg.sponsor_enabled());
    }

    #[test]
    fn none_disables_sponsor_path() {
        let cfg = SponsorModeConfig::from_parts(3, None, None).expect("none disables");
        assert_eq!(cfg.mode(), SponsorMode::None);
        assert!(!cfg.sponsor_enabled());
        // None with a URL is rejected.
        assert_eq!(
            SponsorModeConfig::from_parts(3, Some("https://x".to_string()), None),
            Err(SponsorModeConfigError::NoneMustNotSponsor)
        );
        // Sponsoring modes require a URL.
        assert_eq!(
            SponsorModeConfig::from_parts(1, None, None),
            Err(SponsorModeConfigError::EndpointUrlRequired)
        );
    }

    #[test]
    fn env_secret_reject() {
        // Env interpolation pulling a secret.
        assert_eq!(
            SponsorModeConfig::from_parts(
                1,
                Some("https://x?auth=${SPONSOR_PRIVATE_KEY}".to_string()),
                None
            ),
            Err(SponsorModeConfigError::SecretShapedValue)
        );
        // Raw key material in the policy ref.
        assert_eq!(
            SponsorModeConfig::from_parts(
                2,
                Some("https://x".to_string()),
                // Short, non-scannable marker (contains the `suiprivkey1`
                // substring `looks_like_secret` keys on, but not the 40+ char
                // body the repo secret scanner matches — so this negative
                // fixture cannot itself trip the repo secret scan).
                Some("suiprivkey1-fake-not-a-real-key".to_string())
            ),
            Err(SponsorModeConfigError::SecretShapedValue)
        );
        // A plain URL + path is NOT flagged.
        assert!(!looks_like_secret("https://sponsor.example/v1"));
        assert!(!looks_like_secret("ops/gas-station/policy.schema.json"));
    }
}

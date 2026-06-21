//! Security corpus collectors (atoms #371–#373).
//!
//! Three **separate-source-class** collectors: the source schema (#371), the
//! audit-finding parser plus the §4.4 `SecuritySignal` aggregate (#372), and the
//! exploit-repro + regression-fixture signal (#373). Every type in this module
//! tree carries hashes, counts, and booleans only — never a raw exploit payload
//! or a secret byte. Open high/critical findings and unfixed exploits are
//! quarantine/negative context, never positive reward.
pub mod audit_finding;
pub mod repro;
pub mod source;

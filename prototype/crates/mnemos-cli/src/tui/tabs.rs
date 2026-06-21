//! §4.3 cockpit tab router (atom #420 F.2.3).
//!
//! Every cockpit tab maps to exactly one closed [`CliNamespace`] — there is no
//! dead decorative tab. Two display tabs have no dedicated namespace and are
//! mapped to the namespace that owns their surface, documented inline:
//! `Web` → `Tool` (web research is a tool-adapter capability) and `Budget` →
//! `Agent` (the agent namespace owns bounded-turn / budget / kill). Keyboard
//! navigation wraps; selection is bounds-checked.

use crate::grammar::CliNamespace;
use crate::tui::RenderTruth;
use crate::{StageFTraceLink, sha256_32};

/// §4.3 — the cockpit tabs, in display order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CockpitTab {
    /// Agent turn surface.
    Agent = 1,
    /// Command trace / audit surface.
    Trace = 2,
    /// Memory ownership / replay surface.
    Memory = 3,
    /// Skill discovery / use surface.
    Skill = 4,
    /// Skill registry / provenance surface.
    Registry = 5,
    /// Tool adapter surface.
    Tool = 6,
    /// Web research surface (owned by the tool adapter).
    Web = 7,
    /// Train doctor/prepare/dashboard surface.
    Train = 8,
    /// Eval harness surface.
    Eval = 9,
    /// Chain env / gate surface.
    Chain = 10,
    /// Gas sponsor / quota / drain surface.
    Gas = 11,
    /// Budget / kill surface (owned by the agent namespace).
    Budget = 12,
    /// Feature profile / toggle surface.
    Features = 13,
    /// Privacy / egress surface.
    Privacy = 14,
}

/// The number of cockpit tabs.
pub const TAB_COUNT: usize = 14;

/// Every cockpit tab, in display order. Used by the router + coverage tests.
pub const ALL_TABS: [CockpitTab; TAB_COUNT] = [
    CockpitTab::Agent,
    CockpitTab::Trace,
    CockpitTab::Memory,
    CockpitTab::Skill,
    CockpitTab::Registry,
    CockpitTab::Tool,
    CockpitTab::Web,
    CockpitTab::Train,
    CockpitTab::Eval,
    CockpitTab::Chain,
    CockpitTab::Gas,
    CockpitTab::Budget,
    CockpitTab::Features,
    CockpitTab::Privacy,
];

impl CockpitTab {
    /// The closed [`CliNamespace`] this tab drives. Total: every tab resolves to
    /// a namespace in [`crate::grammar::ALL`] (no dead tab).
    #[must_use]
    pub const fn namespace(self) -> CliNamespace {
        match self {
            Self::Agent => CliNamespace::Agent,
            Self::Trace => CliNamespace::Trace,
            Self::Memory => CliNamespace::Memory,
            Self::Skill => CliNamespace::Skill,
            Self::Registry => CliNamespace::Registry,
            Self::Tool | Self::Web => CliNamespace::Tool,
            Self::Train => CliNamespace::Train,
            Self::Eval => CliNamespace::Eval,
            Self::Chain => CliNamespace::Chain,
            Self::Gas => CliNamespace::Gas,
            Self::Budget => CliNamespace::Agent,
            Self::Features => CliNamespace::Feature,
            Self::Privacy => CliNamespace::Privacy,
        }
    }
}

/// §4.3 — the projected state of one selected tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CockpitTabState {
    /// SHA-256 of the tab's canonical namespace name (stable tab identity).
    pub tab_hash_32: [u8; 32],
    /// The render truth of the surface this tab projects.
    pub truth: RenderTruth,
    /// The trace currently selected within the tab.
    pub selected_trace: StageFTraceLink,
}

impl CockpitTabState {
    /// Build the projected state for `tab`, hashing its namespace name for a
    /// stable identity.
    #[must_use]
    pub fn for_tab(tab: CockpitTab, truth: RenderTruth, selected_trace: StageFTraceLink) -> Self {
        Self {
            tab_hash_32: sha256_32(tab.namespace().canonical_name().as_bytes()),
            truth,
            selected_trace,
        }
    }
}

/// The tab router: tracks the selected tab index and supports wrapping
/// keyboard navigation. Holds no business state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TabRouter {
    selected: usize,
}

impl TabRouter {
    /// A router selecting the first tab.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of tabs.
    #[must_use]
    pub const fn tab_count(self) -> usize {
        TAB_COUNT
    }

    /// The currently selected tab.
    #[must_use]
    pub fn selected_tab(self) -> CockpitTab {
        ALL_TABS[self.selected % TAB_COUNT]
    }

    /// The selected index.
    #[must_use]
    pub const fn selected_index(self) -> usize {
        self.selected
    }

    /// Advance to the next tab (wraps to the first after the last).
    pub const fn next(&mut self) {
        self.selected = (self.selected + 1) % TAB_COUNT;
    }

    /// Go to the previous tab (wraps to the last before the first).
    pub const fn prev(&mut self) {
        self.selected = (self.selected + TAB_COUNT - 1) % TAB_COUNT;
    }

    /// Select a tab by index. Returns `false` (no change) if out of bounds.
    pub const fn select(&mut self, index: usize) -> bool {
        if index < TAB_COUNT {
            self.selected = index;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar;

    #[test]
    fn every_tab_maps_into_the_closed_namespace_set() {
        for tab in ALL_TABS {
            let ns = tab.namespace();
            assert!(
                grammar::ALL.contains(&ns),
                "{tab:?} -> {ns:?} not in closed set"
            );
        }
    }

    #[test]
    fn documented_overflow_tab_mappings() {
        assert_eq!(CockpitTab::Web.namespace(), CliNamespace::Tool);
        assert_eq!(CockpitTab::Budget.namespace(), CliNamespace::Agent);
        // direct ones
        assert_eq!(CockpitTab::Privacy.namespace(), CliNamespace::Privacy);
        assert_eq!(CockpitTab::Features.namespace(), CliNamespace::Feature);
    }

    #[test]
    fn all_tabs_has_14_and_unique() {
        assert_eq!(ALL_TABS.len(), TAB_COUNT);
        for (i, t) in ALL_TABS.iter().enumerate() {
            assert_eq!(*t as u8, (i as u8) + 1);
        }
    }

    #[test]
    fn keyboard_navigation_wraps() {
        let mut r = TabRouter::new();
        assert_eq!(r.selected_tab(), CockpitTab::Agent);
        r.prev();
        assert_eq!(r.selected_tab(), CockpitTab::Privacy);
        r.next();
        assert_eq!(r.selected_tab(), CockpitTab::Agent);
        for _ in 0..TAB_COUNT {
            r.next();
        }
        assert_eq!(r.selected_tab(), CockpitTab::Agent);
    }

    #[test]
    fn select_is_bounds_checked() {
        let mut r = TabRouter::new();
        assert!(r.select(5));
        assert_eq!(r.selected_tab(), CockpitTab::Tool);
        assert!(!r.select(TAB_COUNT));
        assert_eq!(r.selected_tab(), CockpitTab::Tool);
    }

    #[test]
    fn tab_state_hash_is_stable_per_namespace() {
        let trace = StageFTraceLink::new([0u8; 32], 420, 420);
        let a = CockpitTabState::for_tab(CockpitTab::Tool, RenderTruth::Green, trace);
        let b = CockpitTabState::for_tab(CockpitTab::Web, RenderTruth::Green, trace);
        // Web and Tool share the Tool namespace, so their tab identity matches.
        assert_eq!(a.tab_hash_32, b.tab_hash_32);
    }
}

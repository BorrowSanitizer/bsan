// Ported from Miri's `diagnostics.rs`
// Won't be used exactly as it is used in Miri or at all
// but nice to port in case there are any similar behaviors / as a starting point
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::ops::Range;

use bsan_shared::diagnostics::*;
use bsan_shared::{Size, *};

use crate::borrow_tracker::tree::{AllocRange, LocationState, Tree};
use crate::borrow_tracker::unimap::UniIndex;
use crate::span::*;
use crate::{println, AllocId, BorTag};

/// Cause of an access: either a real access or one
/// inserted by Tree Borrows due to a reborrow or a deallocation.
#[derive(Clone, Copy, Debug)]
pub enum AccessCause {
    Explicit(AccessKind),
    Reborrow,
    Dealloc,
    FnExit(AccessKind),
}

impl fmt::Display for AccessCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit(kind) => write!(f, "{kind}"),
            Self::Reborrow => write!(f, "reborrow"),
            Self::Dealloc => write!(f, "deallocation"),
            // This is dead code, since the protector release access itself can never
            // cause UB (while the protector is active, if some other access invalidates
            // further use of the protected tag, that is immediate UB).
            // Describing the cause of UB is the only time this function is called.
            Self::FnExit(_) => unreachable!("protector accesses can never be the source of UB"),
        }
    }
}

impl AccessCause {
    fn print_as_access(self, is_foreign: bool) -> String {
        let rel = if is_foreign { "foreign" } else { "child" };
        match self {
            Self::Explicit(kind) => format!("{rel} {kind}"),
            Self::Reborrow => format!("reborrow (acting as a {rel} read access)"),
            Self::Dealloc => format!("deallocation (acting as a {rel} write access)"),
            Self::FnExit(kind) => {
                format!("protector release (acting as a {rel} {kind})")
            }
        }
    }
}

/// Complete data for an event:
#[derive(Clone, Debug)]
pub struct Event {
    /// Transformation of permissions that occurred because of this event.
    pub transition: PermTransition,
    /// Kind of the access that triggered this event.
    pub access_cause: AccessCause,

    /// Relative position of the tag to the one used for the access.
    pub is_foreign: bool,
    /// User-visible range of the access.
    /// `None` means that this is an implicit access to the entire allocation
    /// (used for the implicit read on protector release).
    // MIR specfic
    pub access_range: Option<AllocRange>,
    /// The transition recorded by this event only occurred on a subrange of
    /// `access_range`: a single access on `access_range` triggers several events,
    /// each with their own mutually disjoint `transition_range`. No-op transitions
    /// should not be recorded as events, so the union of all `transition_range` is not
    /// necessarily the entire `access_range`.
    ///
    /// No data from any `transition_range` should ever be user-visible, because
    /// both the start and end of `transition_range` are entirely dependent on the
    /// internal representation of `RangeMap` which is supposed to be opaque.
    /// What will be shown in the error message is the first byte `error_offset` of
    /// the `TbError`, which should satisfy
    /// `event.transition_range.contains(error.error_offset)`.
    pub transition_range: Range<u64>,
    /// Line of code that triggered this event.
    pub span: Span,
}

/// List of all events that affected a tag.
/// NOTE: not all of these events are relevant for a particular location,
/// the events should be filtered before the generation of diagnostics.
/// Available filtering methods include `History::forget` and `History::extract_relevant`.
#[derive(Clone, Debug)]
pub struct History {
    tag: BorTag,
    created: (Span, Permission),
    events: Vec<Event>,
}

/// History formatted for use by `src/diagnostics.rs`.
///
/// NOTE: needs to be `Send` because of a bound on `MachineStopType`, hence
/// the use of `SpanData` rather than `Span`.
#[derive(Debug, Clone, Default)]
pub struct HistoryData {
    pub events: Vec<(Option<SpanData>, String)>, // includes creation
}

impl History {
    /// Record an additional event to the history.
    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }
}

impl HistoryData {
    // Format events from `new_history` into those recorded by `self`.
    //
    // NOTE: also converts `Span` to `SpanData`.
    fn extend(&mut self, new_history: History, tag_name: &'static str, show_initial_state: bool) {
        let History { tag, created, events } = new_history;
        let this = format!("the {tag_name} tag {tag:?}");
        let msg_initial_state = format!(", in the initial state {}", created.1);
        let msg_creation = format!(
            "{this} was created here{maybe_msg_initial_state}",
            maybe_msg_initial_state = if show_initial_state { &msg_initial_state } else { "" },
        );

        self.events.push((Some(created.0.data().into()), msg_creation));
        for &Event {
            transition,
            is_foreign,
            access_cause,
            access_range,
            span,
            transition_range: _,
        } in &events
        {
            // NOTE: `transition_range` is explicitly absent from the error message, it has no significance
            // to the user. The meaningful one is `access_range`.
            let access = access_cause.print_as_access(is_foreign);
            // let access_range_text = match access_range {
            //     Some(r) => format!("at offsets {r:?}"),
            //     None => format!("on every location previously accessed by this tag"),
            // };
            self.events.push((
                Some(span.data().into()),
                format!(
                    //"{this} later transitioned to {endpoint} due to a {access} {access_range_text}",
                    "{this} later transitioned due to a {access}",
                ),
            ));
            self.events
                .push((None, format!("this transition corresponds to {}", transition.summary())));
        }
    }
}

/// Some information that is irrelevant for the algorithm but very
/// convenient to know about a tag for debugging and testing.
#[derive(Clone, Debug)]
pub struct NodeDebugInfo {
    /// The tag in question.
    pub tag: BorTag,
    /// Name(s) that were associated with this tag (comma-separated).
    /// Typically the name of the variable holding the corresponding
    /// pointer in the source code.
    /// Helps match tag numbers to human-readable names.
    pub name: Option<String>,
    /// Notable events in the history of this tag, used for
    /// diagnostics.
    ///
    /// NOTE: by virtue of being part of `NodeDebugInfo`,
    /// the history is automatically cleaned up by the GC.
    /// NOTE: this is `!Send`, it needs to be converted before displaying
    /// the actual diagnostics because `src/diagnostics.rs` requires `Send`.
    pub history: History,
}

impl NodeDebugInfo {
    /// Information for a new node. By default it has no
    /// name and an empty history.
    pub fn new(tag: BorTag, initial: Permission, span: Span) -> Self {
        let history = History { tag, created: (span, initial), events: Vec::new() };
        Self { tag, name: None, history }
    }

    /// Add a name to the tag. If a same tag is associated to several pointers,
    /// it can have several names which will be separated by commas.
    pub fn add_name(&mut self, name: &str) {
        if let Some(prev_name) = &mut self.name {
            prev_name.push_str(", ");
            prev_name.push_str(name);
        } else {
            self.name = Some(String::from(name));
        }
    }
}

impl fmt::Display for NodeDebugInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.name {
            write!(f, "{tag:?} ({name})", tag = self.tag)
        } else {
            write!(f, "{tag:?}", tag = self.tag)
        }
    }
}

impl<'tcx> Tree {
    /// Climb the tree to get the tag of a distant ancestor.
    /// Allows operations on tags that are unreachable by the program
    /// but still exist in the tree. Not guaranteed to perform consistently
    /// if `provenance-gc=1`.
    fn nth_parent(&self, tag: BorTag, nth_parent: u8) -> Option<BorTag> {
        let mut idx = self.tag_mapping.get(&tag).unwrap();
        for _ in 0..nth_parent {
            let node = self.nodes.get(idx).unwrap();
            idx = node.parent?;
        }
        Some(self.nodes.get(idx).unwrap().tag)
    }

    /// Debug helper: assign name to tag.
    // FIXME: Refacotor return type to Result-like object if ported
    pub fn give_pointer_debug_name(&mut self, tag: BorTag, nth_parent: u8, name: &str) -> bool {
        let tag = self.nth_parent(tag, nth_parent).unwrap();
        let idx = self.tag_mapping.get(&tag).unwrap();
        if let Some(node) = self.nodes.get_mut(idx) {
            node.debug_info.add_name(name);
        } else {
            println!("Tag {tag:?} (to be named '{name}') not found!");
        }
        true
    }

    /// Debug helper: determines if the tree contains a tag.
    pub fn is_allocation_of(&self, tag: BorTag) -> bool {
        self.tag_mapping.contains_key(&tag)
    }
}
impl History {
    /// Keep only the tag and creation
    fn forget(&self) -> Self {
        History { events: Vec::new(), created: self.created, tag: self.tag }
    }

    /// Reconstruct the history relevant to `error_offset` by filtering
    /// only events whose range contains the offset we are interested in.
    fn extract_relevant(&self, error_offset: u64, error_kind: TransitionError) -> Self {
        History {
            events: self
                .events
                .iter()
                .filter(|e| e.transition_range.contains(&error_offset))
                // removed some of Miri's additional information as it is not neccessary to bsan
                // .filter(|e| e.transition.is_relevant(error_kind))
                .cloned()
                .collect::<Vec<_>>(),
            created: self.created,
            tag: self.tag,
        }
    }
}

/// Failures that can occur during the execution of Tree Borrows procedures.
pub(super) struct TbError<'node> {
    /// What failure occurred.
    pub error_kind: TransitionError,
    /// The allocation in which the error is happening.
    pub alloc_id: AllocId,
    /// The offset (into the allocation) at which the conflict occurred.
    pub error_offset: u64,
    /// The tag on which the error was triggered.
    /// On protector violations, this is the tag that was protected.
    /// On accesses rejected due to insufficient permissions, this is the
    /// tag that lacked those permissions.
    pub conflicting_info: &'node NodeDebugInfo,
    // What kind of access caused this error (read, write, reborrow, deallocation)
    pub access_cause: AccessCause,
    /// Which tag the access that caused this error was made through, i.e.
    /// which tag was used to read/write/deallocate.
    pub accessed_info: &'node NodeDebugInfo,
}

type S = &'static str;
/// Pretty-printing details
///
/// Example:
/// ```rust,ignore (private type)
/// DisplayFmtWrapper {
///     top: '>',
///     bot: '<',
///     warning_text: "Some tags have been hidden",
/// }
/// ```
/// will wrap the entire text with
/// ```text
/// >>>>>>>>>>>>>>>>>>>>>>>>>>
/// Some tags have been hidden
///
/// [ main display here ]
///
/// <<<<<<<<<<<<<<<<<<<<<<<<<<
/// ```
struct DisplayFmtWrapper {
    /// Character repeated to make the upper border.
    top: char,
    /// Character repeated to make the lower border.
    bot: char,
    /// Warning about some tags (unnamed) being hidden.
    warning_text: S,
}

/// Formatting of the permissions on each range.
///
/// Example:
/// ```rust,ignore (private type)
/// DisplayFmtPermission {
///     open: "[",
///     sep: "|",
///     close: "]",
///     uninit: "___",
///     range_sep: "..",
/// }
/// ```
/// will show each permission line as
/// ```text
/// 0.. 1.. 2.. 3.. 4.. 5
/// [Act|Res|Frz|Dis|___]
/// ```
struct DisplayFmtPermission {
    /// Text that starts the permission block.
    open: S,
    /// Text that separates permissions on different ranges.
    sep: S,
    /// Text that ends the permission block.
    close: S,
    /// Text to show when a permission is not initialized.
    /// Should have the same width as a `Permission`'s `.short_name()`, i.e.
    /// 3 if using the `Res/Act/Frz/Dis` notation.
    uninit: S,
    /// Text to separate the `start` and `end` values of a range.
    range_sep: S,
}

/// Formatting of the tree structure.
///
/// Example:
/// ```rust,ignore (private type)
/// DisplayFmtPadding {
///     join_middle: "|-",
///     join_last: "'-",
///     join_haschild: "-+-",
///     join_default: "---",
///     indent_middle: "| ",
///     indent_last: "  ",
/// }
/// ```
/// will show the tree as
/// ```text
/// -+- root
///  |--+- a
///  |  '--+- b
///  |     '---- c
///  |--+- d
///  |  '---- e
///  '---- f
/// ```
struct DisplayFmtPadding {
    /// Connector for a child other than the last.
    join_middle: S,
    /// Connector for the last child. Should have the same width as `join_middle`.
    join_last: S,
    /// Connector for a node that itself has a child.
    join_haschild: S,
    /// Connector for a node that does not have a child. Should have the same width
    /// as `join_haschild`.
    join_default: S,
    /// Indentation when there is a next child.
    indent_middle: S,
    /// Indentation for the last child.
    indent_last: S,
}
/// How to show whether a location has been accessed
///
/// Example:
/// ```rust,ignore (private type)
/// DisplayFmtAccess {
///     yes: " ",
///     no: "?",
///     meh: "_",
/// }
/// ```
/// will show states as
/// ```text
///  Act
/// ?Res
/// ____
/// ```
struct DisplayFmtAccess {
    /// Used when `State.initialized = true`.
    yes: S,
    /// Used when `State.initialized = false`.
    /// Should have the same width as `yes`.
    no: S,
    /// Used when there is no `State`.
    /// Should have the same width as `yes`.
    meh: S,
}

/// All parameters to determine how the tree is formatted.
struct DisplayFmt {
    wrapper: DisplayFmtWrapper,
    perm: DisplayFmtPermission,
    padding: DisplayFmtPadding,
    accessed: DisplayFmtAccess,
}
impl DisplayFmt {
    /// Print the permission with the format
    /// ` Res`/` Re*`/` Act`/` Frz`/` Dis` for accessed locations
    /// and `?Res`/`?Re*`/`?Act`/`?Frz`/`?Dis` for unaccessed locations.
    fn print_perm(&self, perm: Option<LocationState>) -> String {
        if let Some(perm) = perm {
            format!(
                "{ac}",
                ac = if perm.is_accessed() { self.accessed.yes } else { self.accessed.no },
            )
        } else {
            format!("{}{}", self.accessed.meh, self.perm.uninit)
        }
    }

    /// Print the tag with the format `<XYZ>` if the tag is unnamed,
    /// and `<XYZ=name>` if the tag is named.
    fn print_tag(&self, tag: BorTag, name: &Option<String>) -> String {
        let printable_tag = tag.get();
        if let Some(name) = name {
            format!("<{printable_tag}={name}>")
        } else {
            format!("<{printable_tag}>")
        }
    }

    /// Print extra text if the tag has a protector.
    fn print_protector(&self, protector: Option<&ProtectorKind>) -> &'static str {
        protector
            .map(|p| match *p {
                ProtectorKind::WeakProtector => " Weakly protected",
                ProtectorKind::StrongProtector => " Strongly protected",
                ProtectorKind::NoProtector => " Not protected",
            })
            .unwrap_or("")
    }
}

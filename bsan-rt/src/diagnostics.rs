// Ported from Miri's `diagnostics.rs`
// Won't be used exactly as it is used in Miri or at all
// but nice to port in case there are any similar behaviors / as a starting point
#![allow(unused)]
use alloc::alloc::Global;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::alloc::Allocator;
use core::fmt;
use core::marker::PhantomData;
use core::ops::Range;

use bsan_shared::diagnostics::TransitionError;
use bsan_shared::{AccessKind, PermTransition, Permission, ProtectorKind};
use hashbrown::HashMap;

use crate::borrow_tracker::tree::{AllocRange, LocationState, Tree};
use crate::borrow_tracker::unimap::UniIndex;
use crate::errors::{BorsanResult, UBResult};
use crate::{println, AllocId, BorTag, Span};

/// Cause of an access: either a real access or one
/// inserted by Tree Borrows due to a reborrow or a deallocation.
#[derive(Clone, Copy, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct History<A: Allocator = Global> {
    tag: BorTag,
    created: (Span, Permission),
    events: Vec<Event, A>,
}

/// History formatted for use by `src/diagnostics.rs`.
///
/// NOTE: needs to be `Send` because of a bound on `MachineStopType`, hence
/// the use of `SpanData` rather than `Span`.
#[derive(Debug, Clone)]
pub struct HistoryData<A: Allocator = Global> {
    pub events: Vec<(Option<Span>, String), A>, // includes creation
}

impl<A> History<A>
where
    A: Allocator,
{
    /// Record an additional event to the history.
    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    /// Return the last recorded event, if any.
    pub fn last_event(&self) -> Option<&Event> {
        self.events.last()
    }
}

impl<A> HistoryData<A>
where
    A: Allocator,
{
    // Format events from `new_history` into those recorded by `self`.
    //
    #[allow(unused)]
    fn extend(
        &mut self,
        new_history: History<A>,
        tag_name: &'static str,
        show_initial_state: bool,
    ) {
        let History { tag, created, events } = new_history;
        let this = format!("the {tag_name} tag {tag:?}");
        let msg_initial_state = format!(", in the initial state {}", created.1);
        let msg_creation = format!(
            "{this} was created here{maybe_msg_initial_state}",
            maybe_msg_initial_state = if show_initial_state { &msg_initial_state } else { "" },
        );

        self.events.push((Some(created.0), msg_creation));
        for &Event {
            transition,
            is_foreign,
            access_cause,
            access_range: _,
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
                Some(span),
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
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDebugInfo<A: Allocator = Global> {
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
    pub history: History<A>,
}

impl NodeDebugInfo<Global> {
    pub fn new(tag: BorTag, initial: Permission, span: Span) -> Self {
        let history = History { tag, created: (span, initial), events: Vec::new_in(Global) };
        Self { tag, name: None, history }
    }
}

impl<A> NodeDebugInfo<A>
where
    A: Allocator,
{
    /// Information for a new node. By default it has no
    /// name and an empty history. Uses custom allocator.
    pub fn new_in(tag: BorTag, initial: Permission, span: Span, alloc: A) -> Self {
        let history = History { tag, created: (span, initial), events: Vec::new_in(alloc) };
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

impl<A> fmt::Display for NodeDebugInfo<A>
where
    A: Allocator,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.name {
            write!(f, "{tag:?} ({name})", tag = self.tag)
        } else {
            write!(f, "{tag:?}", tag = self.tag)
        }
    }
}

impl<A> Tree<A>
where
    A: Allocator,
{
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
    pub fn give_pointer_debug_name(
        &mut self,
        tag: BorTag,
        nth_parent: u8,
        name: &str,
    ) -> UBResult<()> {
        let tag = self.nth_parent(tag, nth_parent).unwrap();
        let idx = self.tag_mapping.get(&tag).unwrap();
        if let Some(node) = self.nodes.get_mut(idx) {
            node.debug_info.add_name(name);
        } else {
            println!("Tag {tag:?} (to be named '{name}') not found!");
        }
        Ok(())
    }

    /// Debug helper: determines if the tree contains a tag.
    pub fn is_allocation_of(&self, tag: BorTag) -> bool {
        self.tag_mapping.contains_key(&tag)
    }
}

#[allow(unused)]
impl<A> History<A>
where
    A: Allocator,
{
    /// Keep only the tag and creation
    fn forget(&self, alloc: A) -> Self {
        History { events: Vec::new_in(alloc), created: self.created, tag: self.tag }
    }

    /// Reconstruct the history relevant to `error_offset` by filtering
    /// only events whose range contains the offset we are interested in.
    fn extract_relevant(&self, error_offset: u64, _error_kind: TransitionError, alloc: A) -> Self {
        let filtered_events =
            self.events.iter().filter(|e| e.transition_range.contains(&error_offset)).cloned();
        // removed some of Miri's additional information as it is not neccessary to bsan
        // .filter(|e| e.transition.is_relevant(error_kind))

        let mut events_vec = Vec::new_in(alloc);
        events_vec.extend(filtered_events);

        History { events: events_vec, created: self.created, tag: self.tag }
    }
}

/// Failures that can occur during the execution of Tree Borrows procedures.
pub(super) struct TbError<'node, A: Allocator = Global> {
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
    pub conflicting_info: &'node NodeDebugInfo<A>,
    // What kind of access caused this error (read, write, reborrow, deallocation)
    pub access_cause: AccessCause,
    /// Which tag the access that caused this error was made through, i.e.
    /// which tag was used to read/write/deallocate.
    pub accessed_info: &'node NodeDebugInfo<A>,
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
                "{ac}{st}",
                ac = if perm.is_accessed() { self.accessed.yes } else { self.accessed.no },
                st = perm.permission().short_name(),
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
            })
            .unwrap_or("")
    }
}

/// Track the indentation of the tree.
struct DisplayIndent {
    curr: String,
}
impl DisplayIndent {
    fn new() -> Self {
        Self { curr: "    ".to_string() }
    }

    /// Increment the indentation by one. Note: need to know if this
    /// is the last child or not because the presence of other children
    /// changes the way the indentation is shown.
    fn increment(&mut self, formatter: &DisplayFmt, is_last: bool) {
        self.curr.push_str(if is_last {
            formatter.padding.indent_last
        } else {
            formatter.padding.indent_middle
        });
    }

    /// Pop the last level of indentation.
    fn decrement(&mut self, formatter: &DisplayFmt) {
        for _ in 0..formatter.padding.indent_last.len() {
            let _ = self.curr.pop();
        }
    }

    /// Print the current indentation.
    fn write(&self, s: &mut String) {
        s.push_str(&self.curr);
    }
}

/// Repeat a character a number of times.
fn char_repeat(c: char, n: usize) -> String {
    core::iter::once(c).cycle().take(n).collect::<String>()
}

/// Extracted information from the tree, in a form that is readily accessible
/// for printing. I.e. resolve parent-child pointers into an actual tree,
/// zip permissions with their tag, remove wrappers, stringify data.
struct DisplayRepr {
    tag: BorTag,
    name: Option<String>,
    rperm: Vec<Option<LocationState>>,
    children: Vec<DisplayRepr>,
}

fn extraction_aux<A: Allocator>(
    tree: &Tree<A>,
    idx: UniIndex,
    show_unnamed: bool,
    acc: &mut Vec<DisplayRepr>,
) {
    let node = tree.nodes.get(idx).unwrap();
    let name = node.debug_info.name.clone();
    let children_sorted = {
        let mut children = node.children.iter().cloned().collect::<Vec<_>>();
        children.sort_by_key(|idx| tree.nodes.get(*idx).unwrap().tag);
        children
    };
    if !show_unnamed && name.is_none() {
        // We skip this node
        for child_idx in children_sorted {
            extraction_aux(tree, child_idx, show_unnamed, acc);
        }
    } else {
        // We take this node
        let rperm = tree
            .rperms
            .iter_all()
            .map(move |(_offset, perms)| {
                let perm = perms.get(idx);
                perm.cloned()
            })
            .collect::<Vec<_>>();
        let mut children = Vec::new();
        for child_idx in children_sorted {
            extraction_aux(tree, child_idx, show_unnamed, &mut children);
        }
        acc.push(DisplayRepr { tag: node.tag, name, rperm, children });
    }
}

impl DisplayRepr {
    fn from<A: Allocator>(tree: &Tree<A>, show_unnamed: bool) -> Option<Self> {
        let mut v = Vec::new();
        extraction_aux(tree, tree.root, show_unnamed, &mut v);
        let Some(root) = v.pop() else {
            if show_unnamed {
                unreachable!(
                    "This allocation contains no tags, not even a root. This should not happen."
                );
            }
            crate::eprintln!(
                "This allocation does not contain named tags. Use `miri_print_borrow_state(_, true)` to also print unnamed tags."
            );
            return None;
        };
        assert!(v.is_empty());
        return Some(root);
    }

    fn print(
        &self,
        fmt: &DisplayFmt,
        indenter: &mut DisplayIndent,
        protected_tags: &HashMap<BorTag, ProtectorKind>,
        ranges: Vec<Range<u64>>,
        print_warning: bool,
    ) {
        let mut block = Vec::new();
        // Push the header and compute the required paddings for the body.
        // Header looks like this: `0.. 1.. 2.. 3.. 4.. 5.. 6.. 7.. 8`,
        // and is properly aligned with the `|` of the body.
        let (range_header, range_padding) = {
            let mut header_top = String::new();
            header_top.push_str("0..");
            let mut padding = Vec::new();
            for (i, range) in ranges.iter().enumerate() {
                if i > 0 {
                    header_top.push_str(fmt.perm.range_sep);
                }
                let s = range.end.to_string();
                let l = s.chars().count() + fmt.perm.range_sep.chars().count();
                {
                    let target_len =
                        fmt.perm.uninit.chars().count() + fmt.accessed.yes.chars().count() + 1;
                    let tot_len = target_len.max(l);
                    let header_top_pad_len = target_len.saturating_sub(l);
                    let body_pad_len = tot_len.saturating_sub(target_len);
                    header_top.push_str(&format!("{}{}", char_repeat(' ', header_top_pad_len), s));
                    padding.push(body_pad_len);
                }
            }
            ([header_top], padding)
        };
        for s in range_header {
            block.push(s);
        }
        // This is the actual work
        self.print_aux(
            &range_padding,
            fmt,
            indenter,
            protected_tags,
            true, /* root _is_ the last child */
            &mut block,
        );
        // Then it's just prettifying it with a border of dashes.
        {
            let wr = &fmt.wrapper;
            let max_width = {
                let block_width = block.iter().map(|s| s.chars().count()).max().unwrap();
                if print_warning {
                    block_width.max(wr.warning_text.chars().count())
                } else {
                    block_width
                }
            };
            crate::eprintln!("{}", char_repeat(wr.top, max_width));
            if print_warning {
                crate::eprintln!("{}", wr.warning_text,);
            }
            for line in block {
                crate::eprintln!("{line}");
            }
            crate::eprintln!("{}", char_repeat(wr.bot, max_width));
        }
    }

    // Here is the function that does the heavy lifting
    fn print_aux(
        &self,
        padding: &[usize],
        fmt: &DisplayFmt,
        indent: &mut DisplayIndent,
        protected_tags: &HashMap<BorTag, ProtectorKind>,
        is_last_child: bool,
        acc: &mut Vec<String>,
    ) {
        let mut line = String::new();
        // Format the permissions on each range.
        // Looks like `| Act| Res| Res| Act|`.
        line.push_str(fmt.perm.open);
        for (i, (perm, &pad)) in self.rperm.iter().zip(padding.iter()).enumerate() {
            if i > 0 {
                line.push_str(fmt.perm.sep);
            }
            let show_perm = fmt.print_perm(*perm);
            line.push_str(&format!("{}{}", char_repeat(' ', pad), show_perm));
        }
        line.push_str(fmt.perm.close);
        // Format the tree structure.
        // Main difficulty is handling the indentation properly.
        indent.write(&mut line);
        {
            // padding
            line.push_str(if is_last_child {
                fmt.padding.join_last
            } else {
                fmt.padding.join_middle
            });
            line.push_str(fmt.padding.join_default);
            line.push_str(if self.children.is_empty() {
                fmt.padding.join_default
            } else {
                fmt.padding.join_haschild
            });
            line.push_str(fmt.padding.join_default);
            line.push_str(fmt.padding.join_default);
        }
        line.push_str(&fmt.print_tag(self.tag, &self.name));
        let protector = protected_tags.get(&self.tag);
        line.push_str(fmt.print_protector(protector));
        // Push the line to the accumulator then recurse.
        acc.push(line);
        let nb_children = self.children.len();
        for (i, child) in self.children.iter().enumerate() {
            indent.increment(fmt, is_last_child);
            child.print_aux(padding, fmt, indent, protected_tags, i + 1 == nb_children, acc);
            indent.decrement(fmt);
        }
    }
}

const DEFAULT_FORMATTER: DisplayFmt = DisplayFmt {
    wrapper: DisplayFmtWrapper {
        top: '─',
        bot: '─',
        warning_text: "Warning: this tree is indicative only. Some tags may have been hidden.",
    },
    perm: DisplayFmtPermission { open: "|", sep: "|", close: "|", uninit: "----", range_sep: ".." },
    padding: DisplayFmtPadding {
        join_middle: "├",
        join_last: "└",
        indent_middle: "│ ",
        indent_last: "  ",
        join_haschild: "┬",
        join_default: "─",
    },
    accessed: DisplayFmtAccess { yes: " ", no: "?", meh: "-" },
};

pub trait PrintTree {
    fn print_tree(
        &self,
        protected_tags: &HashMap<BorTag, ProtectorKind>,
        show_unnamed: bool,
    ) -> BorsanResult<()>;
}

impl<A: Allocator> PrintTree for Tree<A> {
    /// Display the contents of the tree.
    fn print_tree(
        &self,
        protected_tags: &HashMap<BorTag, ProtectorKind>,
        show_unnamed: bool,
    ) -> BorsanResult<()> {
        let mut indenter = DisplayIndent::new();
        let ranges = self.rperms.iter_all().map(|(range, _perms)| range).collect::<Vec<_>>();
        if let Some(repr) = DisplayRepr::from(self, show_unnamed) {
            repr.print(
                &DEFAULT_FORMATTER,
                &mut indenter,
                protected_tags,
                ranges,
                /* print warning message about tags not shown */ !show_unnamed,
            );
        }
        Ok(())
    }
}

pub fn print_tree_diff<A: Allocator + Clone>(
    new_tree: &Tree<A>,
    old_tree: &Tree<A>,
    _protected_tags: &HashMap<BorTag, ProtectorKind>,
) -> BorsanResult<()> {
    let mut new_tags = Vec::new();
    let mut changed_tags = Vec::new();

    let mut all_tags: Vec<BorTag> = new_tree.tag_mapping.mapping.keys().copied().collect();
    all_tags.sort();

    for tag in all_tags {
        let new_idx = new_tree.tag_mapping.get(&tag).unwrap();

        if let Some(old_idx) = old_tree.tag_mapping.get(&tag) {
            let mut diffs = Vec::new();
            for (range, map) in new_tree.rperms.iter_all() {
                let new_perm = map.get(new_idx).copied();
                
                // Find permission in old_tree for this range (sampling at start)
                let old_perm_at_start = if let Some((_, old_map)) = old_tree.rperms.iter(bsan_shared::Size::from_bytes(range.start), bsan_shared::Size::from_bytes(1)).next() {
                     old_map.get(old_idx).copied()
                } else {
                     None
                };

                if new_perm != old_perm_at_start {
                     diffs.push((range, old_perm_at_start, new_perm));
                }
            }
            if !diffs.is_empty() {
                changed_tags.push((tag, diffs));
            }
        } else {
            new_tags.push(tag);
        }
    }

    if !new_tags.is_empty() {
        crate::println!("New Tags:");
        for tag in new_tags {
             crate::println!("  {:?}", tag);
        }
    }

    if !changed_tags.is_empty() {
        crate::println!("Permission Changes:");
        for (tag, diffs) in changed_tags {
            crate::println!("  {:?}:", tag);
            for (range, old, new) in diffs {
                 let old_s = old.map(|p| p.to_string()).unwrap_or("None".to_string());
                 let new_s = new.map(|p| p.to_string()).unwrap_or("None".to_string());
                 crate::println!("    [{}..{}): {} -> {}", range.start, range.end, old_s, new_s);
            }
        }
    }
    Ok(())
}

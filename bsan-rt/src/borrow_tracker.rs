// Components in this library were ported from Miri and then modified by our team.
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use spin::MutexGuard;

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::{AccessType, DedupRangeMap};
use crate::tree_borrows::diagnostics::AccessCause;
use crate::tree_borrows::perms::{AccessKind, Permission};
use crate::tree_borrows::tree::LocationState;
use crate::tree_borrows::{IdempotentForeignAccess, NewPermission, Tree, TreeImpl, VisitCounter};
use crate::{AllocId, AllocInfo, BorTag, GlobalCtx, Provenance, RetagFlags, RetagInfo};

// A reference to an instance of `AllocInfo`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct AllocInfoPtr(NonNull<AllocInfo>);

// A pointer to an instance of `AllocInfo`.
impl AllocInfoPtr {
    fn state<'b>(self) -> AllocStateGuard<'b> {
        let info: &'b AllocInfo = unsafe { self.0.as_ref() };
        AllocStateGuard(info.state.lock())
    }
}

impl Deref for AllocInfoPtr {
    type Target = AllocInfo;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl From<NonNull<AllocInfo>> for AllocInfoPtr {
    fn from(value: NonNull<AllocInfo>) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub struct AllocState {
    pub alloc_id: AllocId,
    pub base_addr: Size,
    tree: Option<TreeImpl>,
}

impl AllocState {
    pub fn new(root_tag: BorTag, base_addr: Size, size: Size, span: Span) -> Self {
        Self {
            alloc_id: AllocId::default(),
            base_addr,
            tree: Some(TreeImpl::new(root_tag, size, span)),
        }
    }

    pub unsafe fn tree_unchecked(&self) -> &TreeImpl {
        debug_assert!(self.tree.is_some());
        unsafe { self.tree.as_ref().unwrap_unchecked() }
    }

    pub unsafe fn tree_unchecked_mut(&mut self) -> &mut TreeImpl {
        debug_assert!(self.tree.is_some());
        unsafe { self.tree.as_mut().unwrap_unchecked() }
    }

    pub fn tree_opt(&self) -> Option<&TreeImpl> {
        self.tree.as_ref()
    }

    pub fn tree_opt_mut(&mut self) -> Option<&mut TreeImpl> {
        self.tree.as_mut()
    }

    fn take_tree(&mut self) -> Option<TreeImpl> {
        self.tree.take()
    }
}

impl Default for AllocState {
    fn default() -> Self {
        Self { alloc_id: AllocId::ZERO, base_addr: Size::ZERO, tree: None }
    }
}

// A guard over the `Tree` for an allocation.
#[derive(Debug)]
struct AllocStateGuard<'b>(MutexGuard<'b, AllocState>);

impl Deref for AllocStateGuard<'_> {
    type Target = AllocState;
    fn deref(&self) -> &AllocState {
        &self.0
    }
}

impl DerefMut for AllocStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut AllocState {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct BorrowTracker<'a> {
    bor_tag: BorTag,
    alloc_info: AllocInfoPtr,
    range: AllocRange,
    state: AllocStateGuard<'a>,
}

impl<'b> BorrowTracker<'b> {
    fn tree(&self) -> &TreeImpl {
        unsafe { self.state.tree_unchecked() }
    }

    fn tree_mut(&mut self) -> &mut TreeImpl {
        unsafe { self.state.tree_unchecked_mut() }
    }

    pub fn for_alloc<T, F>(prov: Provenance, f: F) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        let bor_tag = prov.bor_tag;
        if bor_tag == BorTag::OMNIVALID || bor_tag == BorTag::WILDCARD {
            // Only concrete provenance values have `AllocInfo` that we can
            // access directly. This API is intended to have an affect in this case,
            // so we also skip wildcard provenance.
            Ok(T::default())
        } else if bor_tag == BorTag::INVALID {
            Err(UBInfo::UseAfterFree)
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not omnivalid, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());
            let alloc_info: AllocInfoPtr =
                unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
            let state = alloc_info.state();
            let size = state.tree_opt().ok_or(UBInfo::UseAfterFree)?.size();
            let range = AllocRange { start: Size::ZERO, size };
            f(Self { bor_tag, alloc_info, range, state })
        }
    }

    pub fn for_alloc_weak<T, F>(prov: Provenance, f: F) -> T
    where
        F: FnOnce(Self) -> T,
        T: Default,
    {
        let bor_tag = prov.bor_tag;
        if !bor_tag.is_concrete() {
            return T::default();
        }
        let alloc_info: AllocInfoPtr = unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
        let state = alloc_info.state();
        if let Some(tree) = state.tree_opt() {
            let size = tree.size();
            let range = AllocRange { start: Size::ZERO, size };
            f(Self { bor_tag, alloc_info, range, state })
        } else {
            T::default()
        }
    }

    /// # Safety
    /// The caller must provide concrete provenance whose allocation metadata is
    /// valid and live, and `start..start + access_size` must be in-bounds.
    pub unsafe fn for_access_unchecked<T, F>(
        _: &GlobalCtx,
        prov: Provenance,
        start: Size,
        size: Size,
        f: F,
    ) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        let alloc_info: AllocInfoPtr = unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
        let state = alloc_info.state();
        debug_assert!(state.tree_opt().is_some());
        let base_addr = state.base_addr;
        let offset = Size::from_bytes(start.bytes().wrapping_sub(base_addr.bytes()));
        let range = AllocRange { start: offset, size };
        f(Self { bor_tag: prov.bor_tag, alloc_info, range, state })
    }

    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub fn for_access<T, F>(
        global_ctx: &GlobalCtx,
        prov: Provenance,
        start: Size,
        access_size: Option<Size>,
        f: F,
    ) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        if prov.bor_tag == BorTag::OMNIVALID {
            Ok(T::default())
        } else if prov.bor_tag == BorTag::INVALID {
            if access_size == Some(Size::ZERO) {
                Ok(T::default())
            } else {
                Err(UBInfo::UseAfterFree)
            }
        } else {
            let alloc_info: AllocInfoPtr = if prov.bor_tag == BorTag::WILDCARD {
                let size = access_size.unwrap_or(Size::ZERO);
                let range = AllocRange { start, size };
                if let Some(exposed) = global_ctx.get_exposed_provenance(range) {
                    exposed
                } else {
                    // We cannot resolve this wildcard access to an exposed
                    // allocation. The access may target an allocation that we
                    // do not track at all (e.g. a global, which has omnivalid
                    // provenance and so is never registered as exposed), so we
                    // permit it to avoid false positives.
                    return Ok(T::default());
                }
            } else {
                debug_assert!(!prov.alloc_info.is_null());
                unsafe { NonNull::new_unchecked(prov.alloc_info).into() }
            };

            let state = alloc_info.state();
            let is_zero_sized_access = access_size == Some(Size::ZERO);

            // If there is no tree for this allocation, then this is a UAF,
            // unless this is a zero-sized access.
            let Some(tree) = state.tree_opt() else {
                return if is_zero_sized_access {
                    Ok(T::default())
                } else {
                    Err(UBInfo::UseAfterFree)
                };
            };

            // If the tree does not contain the borrow tag that we are using to
            // validate the access, then this is also a UAF, unless this is a
            // zero-sized access, or we have a wildcard tag.
            if !tree.contains_tag(prov.bor_tag) && prov.bor_tag.is_concrete() {
                return if is_zero_sized_access {
                    Ok(T::default())
                } else {
                    Err(UBInfo::UseAfterFree)
                };
            }

            let alloc_id = state.alloc_id;
            let base_addr = state.base_addr;
            let alloc_size = tree.size();
            let access_size = access_size.unwrap_or(alloc_size);

            // At this point, we know that we are accessing a valid allocation, but we cannot
            // tell if our access is in-bounds. It is crucial for this to be a wrapping sub here,
            // since we want to accurately model the effect of applying an oversized offset on
            // the allocation.
            let offset = Size::from_bytes(start.bytes().wrapping_sub(base_addr.bytes()));
            if start < base_addr || (offset + access_size > alloc_size) {
                return if access_size != Size::ZERO {
                    Err(UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset })
                } else {
                    Ok(T::default())
                };
            }

            let range = AllocRange { start: offset, size: access_size };
            f(Self { bor_tag: prov.bor_tag, alloc_info, range, state })
        }
    }

    pub fn retag(
        &mut self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<Provenance> {
        let alloc_id = self.state.alloc_id;
        let parent_tag = self.bor_tag;
        let new_tag = BorTag::default();
        // A wildcard parent is never present in the tree: retagging it adds
        // the new tag as a fresh wildcard root instead.
        if !(parent_tag == BorTag::WILDCARD) && !self.tree().contains_tag(parent_tag) {
            return Err(UBInfo::UseAfterFree);
        }
        let new_perm: NewPermission = NewPermission::new(retag_info);

        let protected = new_perm.protector.is_some();

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let perm = if frozen { new_perm.freeze_perm } else { new_perm.nonfreeze_perm };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if perm.associated_access().is_some() {
                assert!(perm.associated_access().unwrap() == AccessKind::Read);
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };

        let mut inside_perms = DedupRangeMap::new(
            retag_info.size,
            LocationState::new_accessed(Permission::new_disabled(), IdempotentForeignAccess::None),
        );

        let mut cursor = Size::ZERO;
        if let Some(im_layout) = retag_info.im_layout {
            for &[offset, size] in im_layout {
                if cursor != offset {
                    for (_loc_range, loc) in inside_perms.iter_mut(cursor, offset - cursor) {
                        *loc = loc_state(true);
                    }
                }
                for (_loc_range, loc) in inside_perms.iter_mut(offset, size) {
                    *loc = loc_state(false);
                }
                cursor = offset + size
            }
            if cursor < retag_info.size {
                let width = retag_info.size - cursor;
                for (_loc_range, loc) in inside_perms.iter_mut(cursor, width) {
                    *loc = loc_state(true);
                }
            }
        } else if retag_info.size > Size::ZERO {
            let perm = loc_state(retag_info.flags.contains(RetagFlags::IS_FREEZE));
            for (_loc_range, loc) in inside_perms.iter_mut(Size::ZERO, retag_info.size) {
                *loc = perm;
            }
        }

        let base_offset = self.range.start;
        let visits = VisitCounter::new();
        for (perm_range, loc_state) in inside_perms.iter_all() {
            if let Some(access_kind) = loc_state.permission().associated_access() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                // Perform the access (update the Tree Borrows FSM)
                self.tree_mut().perform_access(
                    global_ctx,
                    parent_tag,
                    range_in_alloc,
                    access_kind,
                    AccessCause::Reborrow,
                    alloc_id,
                    span,
                    visits.cell(),
                )?;
            }
        }

        // base offset should be the offset, from zero, where the retag is taking place within the allocation.
        self.tree_mut().new_child(
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            new_perm.outside_perm,
            new_perm.protector,
            span,
        )?;

        Ok(Provenance { alloc_info: self.alloc_info.0.as_ptr(), bor_tag: new_tag })
    }

    pub fn protector_end(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let visits = VisitCounter::new();
        let tag = self.bor_tag;
        let alloc_id = self.state.alloc_id;
        self.tree_mut().perform_protector_end_access(global_ctx, tag, alloc_id, span, visits.cell())
    }

    /// Increments the reference count, returning `true` if the count went from
    /// zero to one.
    pub fn increment(prov: Provenance) -> bool {
        if prov.bor_tag.is_concrete() {
            debug_assert!(!prov.alloc_info.is_null());
            let alloc_info: AllocInfoPtr =
                unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
            let mut state = alloc_info.state();
            if let Some(tree) = state.tree_opt_mut() {
                //alloc_info.rc.increment_nonatomic();
                return tree.increment(prov.bor_tag);
            }
        }
        false
    }

    /// Decrements the reference count, returning `true` if the count reached
    /// zero.
    pub fn decrement(prov: Provenance) -> bool {
        if prov.bor_tag.is_concrete() {
            debug_assert!(!prov.alloc_info.is_null());
            let alloc_info: AllocInfoPtr =
                unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
            let mut state = alloc_info.state();
            if let Some(tree) = state.tree_opt_mut() {
                //alloc_info.rc.decrement_nonatomic();
                return tree.decrement(prov.bor_tag);
            }
        }
        false
    }

    pub fn access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        let visits = VisitCounter::new();
        let (tag, range) = (self.bor_tag, self.range);
        let alloc_id = self.state.alloc_id;
        self.tree_mut().perform_access(
            global_ctx,
            tag,
            range,
            access_kind,
            AccessCause::Explicit(access_kind),
            alloc_id,
            span,
            visits.cell(),
        )
    }

    pub fn dealloc(mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let visits = VisitCounter::new();
        let alloc_id = self.state.alloc_id;
        let base_addr = self.state.base_addr;
        let mut tree = unsafe { self.state.take_tree().unwrap_unchecked() };
        let size = tree.size();
        let range = AllocRange { start: Size::ZERO, size };
        tree.dealloc(global_ctx, self.bor_tag, range, alloc_id, span, visits.cell())?;
        global_ctx.remove_exposed_provenance(AllocRange { start: base_addr, size }, true);
        Ok(())
    }

    pub fn expose_tag(&mut self, global_ctx: &GlobalCtx) -> UBResult<()> {
        if !global_ctx.flags.wildcard {
            return Ok(());
        }
        let tag = self.bor_tag;
        let range = AllocRange { start: self.state.base_addr, size: self.tree().size() };

        // Ranges in the mapping must be non-empty, and a wildcard access can
        // never resolve to a zero-sized allocation anyway.
        if range.size > Size::ZERO {
            let mut exposed = global_ctx.exposed_provenance();
            if let AccessType::Empty(pos) = exposed.access_type(range) {
                exposed.insert_at_pos(pos, range, self.alloc_info);
            }
        }

        let tree = self.tree_mut();
        if tree.contains_tag(tag) {
            let protected = tree.get_protector_kind(tag).is_some();
            tree.expose_tag(tag, protected);
        }
        Ok(())
    }

    pub fn debug_take_snapshot(&self, ctx: &GlobalCtx) {
        ctx.take_snapshot(self.state.alloc_id, self.tree().clone());
    }

    pub fn debug_print_diff(&self, ctx: &GlobalCtx) {
        ctx.with_snapshot(self.state.alloc_id, |old_tree: &TreeImpl| {
            self.tree().print_tree_diff(old_tree);
        });
    }

    pub fn debug_print_tree(&self, show_unnamed: bool) {
        self.tree().print_tree(show_unnamed);
    }

    pub fn debug_tree_size(&self) -> usize {
        self.tree().node_count()
    }
}

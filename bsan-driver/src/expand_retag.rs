use std::marker::PhantomData;

use bsan_shared::{Permission, ProtectorKind, RetagInfo};
use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, LayoutData, VariantIdx, Variants};
use rustc_index::IndexVec;
use rustc_middle::mir::{Place, RetagKind};
use rustc_middle::ty::layout::{HasTyCtxt, TyAndLayout};
use rustc_middle::ty::{self, Mutability};
use rustc_session::config::LLVMRetagFields;
use tracing::trace;

use super::operand::OperandValue;
use super::place::PlaceValue;
use super::{BuilderMethods, FunctionCx, LocalRef};
use crate::mir::place::PlaceRef;
use crate::traits::MiscCodegenMethods;

// When we retag a Place, we need to traverse through all of its fields
// and/or variants and emit retags for all of the sub-places that contain references,
// Boxes, and other types that require retagging. Calculating a sub-place requires cg-ing pointer offsets
// from the initial place and branching on variants. Not all sub-places need to be retagged, so we cannot
// compute them eagerly. Instead, when traversing a place, we store unevaluated subplaces as "modifiers"
// from an initial place. Once we find a subplace that needs to be retagged, we apply all current modifiers
// to the "base" place that we started with. We store the intermediate results from calculating all subplaces
// along the "path" to the subplace we're visiting, so that when we traverse back up the path, we don't need to
// repeat work. For example, if a variant of an enum contains N sub-places that need retagging,
// then we only want to have to branch that variant once, instead of N times for each sub-place.

static VARIANT_BLOCK: &str = "v";

#[allow(dead_code)]
static VARIANT_DEFAULT_BLOCK: &str = "v_def";

#[allow(dead_code)]
static VARIANT_TERMINATOR: &str = "v_t";

/// Either a variant or a field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum Modifier<'tcx> {
    Variant(TyAndLayout<'tcx>),
    Field(FieldIdx),
}

impl<'tcx> Modifier<'tcx> {
    fn apply_to<'a, Bx: BuilderMethods<'a, 'tcx>>(
        self,
        bx: &mut Bx,
        place: &mut PlaceRef<'tcx, Bx::Value>,
    ) -> (PlaceRef<'tcx, Bx::Value>, Option<Bx::BasicBlock>) {
        match self {
            Modifier::Variant(layout) => {
                let block = Some(bx.append_sibling_block(VARIANT_BLOCK));
                place.layout = layout;
                (*place, block)
            }
            Modifier::Field(field_idx) => (place.project_field(bx, field_idx.as_usize()), None),
        }
    }
}

#[allow(dead_code)]
struct RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> {
    kind: RetagKind,
    root_place: PlaceRef<'tcx>,
    places: Vec<PlaceRef<'tcx>>,
    root_block: mir::BasicBlock,
    blocks: Vec<mir::BasicBlock>,
    modifiers: Vec<Modifier<'tcx>>,
    terminator_block: Option<mir::BasicBlock>,
    data: PhantomData<&'a ()>,
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> RetagCx<'a, 'tcx, Bx> {
    #[inline]
    fn curr_place(&self) -> PlaceRef<'tcx, Bx::Value> {
        *self.places.last().unwrap_or(&self.root_place)
    }

    #[inline]
    #[allow(dead_code)]
    fn curr_block(&self) -> Bx::BasicBlock {
        *self.blocks.last().unwrap_or(&self.root_block)
    }

    fn visit(
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        base: PlaceRef<'tcx, Bx::Value>,
        kind: RetagKind,
    ) {
        let mut visitor = Self {
            kind,
            root_place: base,
            places: vec![],
            root_block: bx.llbb(),
            blocks: vec![],
            terminator_block: None,
            modifiers: vec![],
            data: PhantomData,
        };
        visitor.visit_value(fx, bx, base.layout);
    }

    /// Applies each of the current modifiers to the base PlaceRef, cg-ing along the way.
    #[allow(dead_code)]
    fn crystallize(&mut self, bx: &mut Bx) -> PlaceRef<'tcx, Bx::Value> {
        let mut curr_subplace = self.curr_place();
        for modifier in self.modifiers.drain(..) {
            let (subplace, block) = modifier.apply_to(bx, &mut curr_subplace);
            curr_subplace = subplace;
            if let Some(block) = block {
                bx.switch_to_block(block);
                self.blocks.push(block);
            }
            self.places.push(curr_subplace);
        }
        curr_subplace
    }

    // Recursive actions, ready to be overloaded.
    /// Visits the given value, dispatching as appropriate to more specialized visitors.
    #[inline(always)]
    fn visit_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
    ) -> bool {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recursion early.
        // This optimization is crucial for ZSTs, because they can contain way more fields
        // than we can ever visit.
        if layout.is_sized() && layout.size < bx.tcx().data_layout.pointer_size {
            return true;
        }

        // Check the type of this value to see what to do with it (retag, or recurse).
        match layout.ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            ty::Dynamic(_data, _, ty::Dyn) => false,
            ty::Dynamic(_data, _, ty::DynStar) => false,
            &ty::Ref(_, _, mutability) => {
                let place = self.crystallize(bx);
                self.retag_ref_ty(bx, place, mutability);
                false
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
                false
            }

            ty::Adt(adt, _) if adt.is_box() => {
                // Recurse for boxes, they require some tricky handling and will end up in `visit_box` above.
                // (Yes this means we technically also recursively retag the allocator itself
                // even if field retagging is not enabled. *shrug*)
                self.walk_value(fx, bx, layout)
            }
            _ => {
                // Not a reference/pointer/box. Only recurse if configured appropriately.
                let recurse = match bx.cx().sess().opts.unstable_opts.llvm_retag_fields {
                    LLVMRetagFields::None => false,
                    LLVMRetagFields::All => true,
                    LLVMRetagFields::Scalar => {
                        // Matching `ArgAbi::new` at the time of writing, only fields of
                        // `Scalar` and `ScalarPair` ABI are considered.
                        matches!(
                            layout.backend_repr,
                            BackendRepr::Scalar(..) | BackendRepr::ScalarPair(..)
                        )
                    }
                };
                if recurse { self.walk_value(fx, bx, layout) } else { false }
            }
        }
    }

    /// Called each time we recurse down to a field of a "product-like" aggregate
    /// (structs, tuples, arrays and the like, but not enums), passing in old (outer)
    /// and new (inner) value.
    /// This gives the visitor the chance to track the stack of nested fields that
    /// we are descending through.
    #[inline(always)]
    fn visit_field(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        idx: FieldIdx,
    ) -> bool {
        self.modifiers.push(Modifier::Field(idx));
        let branched = self.visit_value(fx, bx, layout.field(bx.cx(), idx.as_usize()));
        if self.modifiers.is_empty() {
            self.places.pop().expect("A place should have been evaluated.");
        } else {
            self.modifiers.pop().expect("An unevaluated modifier should be present.");
        }
        branched
    }
    /// Called when recursing into an enum variant.
    /// This gives the visitor the chance to track the stack of nested fields that
    /// we are descending through.
    #[inline(always)]
    #[allow(dead_code)]
    fn visit_variants(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        this: TyAndLayout<'tcx>,
        variants: &IndexVec<VariantIdx, LayoutData<FieldIdx, VariantIdx>>,
    ) {
        let mut cases: Vec<(u128, Bx::BasicBlock)> = vec![];
        for (vidx, data) in variants.indices().zip(&variants.raw) {
            let layout = bx.tcx().mk_layout(data.clone());
            let variant_layout = TyAndLayout { ty: this.ty, layout };

            self.modifiers.push(Modifier::Variant(variant_layout));
            let branched = self.visit_value(fx, bx, variant_layout);

            if self.modifiers.is_empty() {
                if self.terminator_block.is_none() {
                    self.terminator_block = Some(bx.append_sibling_block(VARIANT_TERMINATOR))
                }

                let terminator_block = self.terminator_block.unwrap();

                let discr = this
                    .ty
                    .discriminant_for_variant(bx.cx().tcx(), vidx)
                    .expect("Invalid variant.");

                let block = self.blocks.pop().expect("A block should have been resolved.");

                if !branched {
                    bx.switch_to_block(block);
                    bx.br(terminator_block);
                }
                bx.switch_to_block(self.curr_block());

                cases.push((discr.val, block))
            } else {
                self.modifiers.pop();
            }
        }

        if !cases.is_empty() {
            let current_block = self.curr_block();
            let current_place = self.curr_place();
            bx.switch_to_block(current_block);

            let discr_ty = this.ty.discriminant_ty(bx.cx().tcx());
            let place_operand = bx.load_operand(current_place);
            let discr_value = place_operand.codegen_get_discr(fx, bx, discr_ty);

            let sibling = bx.append_sibling_block(VARIANT_DEFAULT_BLOCK);

            let terminator_block = self.terminator_block.unwrap();

            bx.switch_to_block(sibling);
            bx.br(terminator_block);

            bx.switch_to_block(current_block);
            bx.switch(discr_value, sibling, cases.drain(..));

            bx.switch_to_block(terminator_block);
        }
    }

    fn inner_ptr_of_unique(
        &mut self,
        bx: &mut Bx,
        unique_ptr: PlaceRef<'tcx, Bx::Value>,
    ) -> PlaceRef<'tcx, Bx::Value> {
        // Unfortunately there is some type junk in the way here: `unique_ptr` is a `Unique`...
        // (which means another 2 fields, the second of which is a `PhantomData`)
        assert_eq!(unique_ptr.layout.fields.count(), 2);
        let phantom = unique_ptr.layout.field(bx.cx(), 1);
        assert!(
            phantom.ty.ty_adt_def().is_some_and(|adt| adt.is_phantom_data()),
            "2nd field of `Unique` should be PhantomData but is {:?}",
            phantom.ty,
        );
        let nonnull_ptr = unique_ptr.project_field(bx, 0);
        // ... that contains a `NonNull`... (gladly, only a single field here)
        assert_eq!(nonnull_ptr.layout.fields.count(), 1);
        // ... whose only field finally is a raw ptr
        nonnull_ptr.project_field(bx, 0)
    }

    fn retag_ref_ty(
        &mut self,
        bx: &mut Bx,
        pointee: PlaceRef<'tcx, Bx::Value>,
        mutability: Mutability,
    ) {
        let ty_is_freeze = pointee.layout.ty.is_freeze(bx.tcx(), bx.typing_env());
        let ty_is_unpin = pointee.layout.ty.is_unpin(bx.tcx(), bx.typing_env());
        let is_protected = self.kind == RetagKind::FnEntry;

        let perm_kind = match mutability {
            Mutability::Not if ty_is_unpin => Permission::new_reserved(ty_is_freeze, is_protected),
            Mutability::Mut if ty_is_freeze => Permission::new_frozen(),
            // Raw pointers never enter this function so they are not handled.
            // However raw pointers are not the only pointers that take the parent
            // tag, this also happens for `!Unpin` `&mut`s and interior mutable
            // `&`s, which are excluded above.
            _ => return,
        };

        let size = pointee.layout.size.bytes_usize();

        let protector_kind =
            if is_protected { ProtectorKind::StrongProtector } else { ProtectorKind::NoProtector };
        let perm = RetagInfo::new(size, perm_kind, protector_kind);
        bx.retag(pointee.val, perm);
    }

    /// Compute permission for `Box`-like type (`Box` always, and also `Unique` if enabled).
    /// These pointers allow deallocation so need a different kind of protector not handled
    /// by `from_ref_ty`.
    fn retag_unique_ty(&mut self, bx: &mut Bx, place: PlaceRef<'tcx, Bx::Value>) {
        let ty = place.layout.ty;
        let ty_is_unpin = ty.is_unpin(bx.tcx(), bx.typing_env());
        if ty_is_unpin {
            let ty_is_freeze = ty.is_freeze(bx.tcx(), bx.typing_env());
            let is_protected = self.kind == RetagKind::FnEntry;
            let size = place.layout.size.bytes_usize();
            let protector_kind: ProtectorKind = if is_protected {
                ProtectorKind::WeakProtector
            } else {
                ProtectorKind::NoProtector
            };

            let perm_kind = Permission::new_reserved(ty_is_freeze, is_protected);
            let perm = RetagInfo::new(size, perm_kind, protector_kind);
            bx.retag(place.val, perm);
        }
    }

    /// Traversal logic; should not be overloaded.
    fn walk_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
    ) -> bool {
        let ty = layout.ty;

        trace!("walk_value: type: {ty}");

        // Special treatment for special types, where the (static) layout is not sufficient.
        let branched_special = match *ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            // ty placement with length 0, so we enter the `Array` case below which
            // indirectly uses the metadata to determine the actual length.

            // However, `Box`... let's talk about `Box`.
            ty::Adt(def, ..) if def.is_box() => {
                // `Box` has two fields: the pointer we care about, and the allocator.
                assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");

                if ty.is_box_global(bx.tcx()) {
                    let current_place = self.crystallize(bx);
                    let unique_ptr = current_place.project_field(bx, 0);
                    let inner_ptr = self.inner_ptr_of_unique(bx, unique_ptr);
                    self.retag_unique_ty(bx, inner_ptr);
                }

                // The second `Box` field is the allocator, which we recursively check for validity
                // like in regular structs.
                self.visit_field(fx, bx, layout, FieldIdx::from_usize(1))
            }
            // The rest is handled below.
            _ => false,
        };

        // Visit the fields of this value.
        let branched_last_field = match &layout.fields {
            FieldsShape::Primitive => branched_special,
            FieldsShape::Arbitrary { memory_index, .. } => memory_index
                .indices()
                .map(|idx| self.visit_field(fx, bx, layout, idx))
                .last()
                .unwrap_or(branched_special),
            FieldsShape::Array { .. } => layout
                .fields
                .index_by_increasing_offset()
                .map(|idx| self.visit_field(fx, bx, layout, FieldIdx::from_usize(idx)))
                .last()
                .unwrap_or(branched_special),
            _ => branched_special,
        };

        match &layout.variants {
            Variants::Multiple { variants, .. } => {
                self.visit_variants(fx, bx, layout, variants);
                true
            }
            Variants::Single { .. } | Variants::Empty => branched_last_field,
        }
    }
}

pub(crate) fn retag_place(&mut self, tcx: TyCxtxAt<'tcx>, place: &Place<'tcx>, kind: RetagKind) {
    RetagCx::visit(self, bx, place, kind)
}

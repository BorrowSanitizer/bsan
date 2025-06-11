use rustc_abi::{
    BackendRepr, FieldIdx, FieldsShape, HasDataLayout, LayoutData, VariantIdx, Variants,
};
use rustc_index::IndexVec;
use rustc_middle::mir::{
    self, BasicBlockData, Body, Location, Place, RetagKind, Statement, StatementKind, SwitchTargets,
};
use rustc_middle::ty::layout::{HasTyCtxt, HasTypingEnv, TyAndLayout};
use rustc_middle::ty::{self, TyCtxt, TypingEnv};

use crate::cx::Pass;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RetagFields {
    Scalar,
    None,
    All,
}

pub struct ExpandRetags;

impl<'tcx> ExpandRetags {
    pub fn run_pass(tcx: TyCtxt<'tcx>, body: &mut Body<'tcx>, retag_fields: RetagFields) {
        let retag_locations = body
            .basic_blocks
            .indices()
            .flat_map(|block| {
                body.basic_blocks[block].statements.iter().enumerate().filter_map(
                    move |(idx, stmt)| {
                        matches!(stmt.kind, StatementKind::Retag(_, _))
                            .then_some(Location { block, statement_index: idx })
                    },
                )
            })
            .collect::<Vec<Location>>();
        for location in retag_locations {
            println!("{location:?}");
        }
    }
}

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

struct RetagCx<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    env: TypingEnv<'tcx>,
    body: &'a mut mir::Body<'tcx>,
    info: mir::SourceInfo,
    root_cursor: Location,
    cursor: Option<Location>,
    kind: RetagKind,
    otherwise: Option<mir::BasicBlock>,
    final_block: Option<mir::BasicBlock>,
    retag_fields: RetagFields,
}

impl<'a, 'tcx> HasDataLayout for RetagCx<'a, 'tcx> {
    fn data_layout(&self) -> &rustc_abi::TargetDataLayout {
        &self.tcx.data_layout
    }
}

impl<'a, 'tcx> HasTypingEnv<'tcx> for RetagCx<'a, 'tcx> {
    fn typing_env(&self) -> TypingEnv<'tcx> {
        self.env
    }
}

impl<'a, 'tcx> HasTyCtxt<'tcx> for RetagCx<'a, 'tcx> {
    fn tcx(&self) -> TyCtxt<'tcx> {
        self.tcx
    }
}

impl<'a, 'tcx> Pass<'tcx> for RetagCx<'a, 'tcx> {
    fn body_mut(&mut self) -> &mut mir::Body<'tcx> {
        self.body
    }

    fn body(&self) -> &mir::Body<'tcx> {
        self.body
    }
}

impl<'a, 'tcx> RetagCx<'a, 'tcx> {
    fn retag_place(
        tcx: TyCtxt<'tcx>,
        body: &'a mut Body<'tcx>,
        cursor: Location,
        root_place: Place<'tcx>,
        kind: RetagKind,
        retag_fields: RetagFields,
    ) {
        let info = *body.source_info(cursor);
        let env = body.typing_env(tcx);

        let mut ctx = RetagCx {
            tcx,
            env,
            body,
            kind,
            root_cursor: cursor,
            cursor: None,
            info,
            otherwise: None,
            final_block: None,
            retag_fields,
        };

        let root_place_layout = ctx.layout_of(root_place);
        if let ty::Ref(_, _, _) = root_place_layout.ty.kind() {
        } else {
            // remove the existing retag
            ctx.remove_statement(cursor);

            ctx.visit_place(root_place, root_place_layout);
        }
    }

    fn inner_ptr_of_box(
        &mut self,
        box_place: Place<'tcx>,
        box_layout: TyAndLayout<'tcx>,
    ) -> Place<'tcx> {
        let (unique_place, unique_layout) = self.project_field(box_place, box_layout, 0);
        // Unfortunately there is some type junk in the way here: `unique_ptr` is a `Unique`...
        // (which means another 2 fields, the second of which is a `PhantomData`)
        assert_eq!(unique_layout.fields.count(), 2);
        let phantom = unique_layout.field(self, 1);
        assert!(
            phantom.ty.ty_adt_def().is_some_and(|adt| adt.is_phantom_data()),
            "2nd field of `Unique` should be PhantomData but is {:?}",
            phantom.ty,
        );

        let (nonnull_place, nonnull_layout) = self.project_field(unique_place, unique_layout, 0);

        // ... that contains a `NonNull`... (gladly, only a single field here)
        assert_eq!(nonnull_layout.fields.count(), 1);

        let (ptr_place, _) = self.project_field(nonnull_place, nonnull_layout, 0);
        ptr_place
    }

    fn visit_place(&mut self, place: Place<'tcx>, layout: TyAndLayout<'tcx>) {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recursion early.
        // This optimization is crucial for ZSTs, because they can contain way more fields
        // than we can ever visit.
        if layout.is_sized() && layout.size < self.tcx.data_layout.pointer_size {
            return;
        }

        match layout.ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            ty::Dynamic(_data, _, ty::Dyn) => todo!(),
            ty::Dynamic(_data, _, ty::DynStar) => todo!(),
            &ty::Ref(_, _, _) => {
                self.retag(place);
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
            }

            ty::Adt(adt, _) if adt.is_box() => {
                // Recurse for boxes, they require some tricky handling and will end up in `visit_box` above.
                // (Yes this means we technically also recursively retag the allocator itself
                // even if field retagging is not enabled. *shrug*)
                self.walk_value(place, layout);
            }
            _ => {
                // Not a reference/pointer/box. Only recurse if configured appropriately.
                let recurse = match self.retag_fields {
                    RetagFields::None => false,
                    RetagFields::All => true,
                    RetagFields::Scalar => {
                        // Matching `ArgAbi::new` at the time of writing, only fields of
                        // `Scalar` and `ScalarPair` ABI are considered.
                        matches!(
                            layout.backend_repr,
                            BackendRepr::Scalar(..) | BackendRepr::ScalarPair(..)
                        )
                    }
                };
                if recurse {
                    self.walk_value(place, layout);
                }
            }
        }
    }

    fn walk_value(&mut self, place: Place<'tcx>, layout: TyAndLayout<'tcx>) {
        // Special treatment for special types, where the (static) layout is not sufficient.
        match layout.ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            // ty placement with length 0, so we enter the `Array` case below which
            // indirectly uses the metadata to determine the actual length.

            // However, `Box`... let's talk about `Box`.
            ty::Adt(def, ..) if def.is_box() => {
                // `Box` has two fields: the pointer we care about, and the allocator.
                assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");

                if layout.ty.is_box_global(self.tcx()) {
                    let inner = self.inner_ptr_of_box(place, layout);
                    self.retag(inner);
                }

                let (alloc_place, alloc_layout) = self.project_field(place, layout, 1);
                self.visit_place(alloc_place, alloc_layout);
            }
            // The rest is handled below.
            _ => {}
        };

        match &layout.fields {
            FieldsShape::Primitive | FieldsShape::Union(_) => {}
            FieldsShape::Arbitrary { .. } | FieldsShape::Array { .. } => {
                layout.fields.index_by_increasing_offset().for_each(|idx: usize| {
                    let (place, layout) = self.project_field(place, layout, idx);
                    self.visit_place(place, layout);
                });
            }
        }

        match &layout.variants {
            Variants::Multiple { tag_field, variants, .. } => {
                self.visit_variants(place, layout, *tag_field, variants);
            }
            Variants::Single { .. } | Variants::Empty => {}
        }
    }

    /// Called when recursing into an enum variant.
    /// This gives the visitor the chance to track the stack of nested fields that
    /// we are descending through.
    #[inline(always)]
    #[allow(dead_code)]
    fn visit_variants(
        &mut self,
        place: Place<'tcx>,
        this: TyAndLayout<'tcx>,
        tag_field: usize,
        variants: &IndexVec<VariantIdx, LayoutData<FieldIdx, VariantIdx>>,
    ) {
        let prev_cursor = self.cursor.unwrap_or(self.root_cursor);

        let mut cases: Vec<(u128, mir::BasicBlock)> = vec![];

        for (vidx, data) in variants.indices().zip(&variants.raw) {
            let layout = self.tcx().mk_layout(data.clone());
            let variant_layout = TyAndLayout { ty: this.ty, layout };
            self.visit_place(place, variant_layout);

            if let Some(location) = self.cursor.take() {
                let discr =
                    this.ty.discriminant_for_variant(self.tcx(), vidx).expect("Invalid variant.");
                cases.push((discr.val, location.block))
            }
        }

        if !cases.is_empty() {
            let should_patch_terminator = self.otherwise.is_none();

            let otherwise = self.otherwise.unwrap_or_else(|| self.new_empty_block());

            if should_patch_terminator {
                cases.iter().for_each(|(_, block)| {
                    self.set_terminator(
                        *block,
                        mir::Terminator {
                            source_info: self.info,
                            kind: mir::TerminatorKind::Goto { target: otherwise },
                        },
                    )
                });
            }

            let targets: SwitchTargets = SwitchTargets::new(cases.drain(..), otherwise);

            // the first time we branch, we need to split the starting block.
            if self.final_block.is_none() {
                let split = self.split_block(prev_cursor);
                self.final_block.replace(split);
            }

            let (tag_place, _) = self.project_field(place, this, tag_field);

            self.set_terminator(
                prev_cursor.block,
                mir::Terminator {
                    source_info: self.info,
                    kind: mir::TerminatorKind::SwitchInt {
                        discr: mir::Operand::Copy(tag_place),
                        targets,
                    },
                },
            )
        }
    }

    fn retag(&mut self, place: Place<'tcx>) {
        let location = *self.cursor.get_or_insert_with(|| {
            let block = self.body.basic_blocks_mut().push(BasicBlockData::new(None, false));
            mir::Location { block, statement_index: 0 }
        });

        let next = self.insert_statement(
            location,
            Statement {
                source_info: self.info,
                kind: mir::StatementKind::Retag(self.kind, Box::new(place)),
            },
        );

        self.cursor.replace(next);
    }
}

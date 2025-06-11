use rustc_abi::{FieldIdx, HasDataLayout};
use rustc_middle::mir::{
    self, BasicBlock, BasicBlockData, Location, Place, PlaceTy, ProjectionElem, Terminator,
};
use rustc_middle::ty::layout::{HasTyCtxt, HasTypingEnv, TyAndLayout};

pub trait Pass<'tcx>: HasTyCtxt<'tcx> + HasDataLayout + HasTypingEnv<'tcx> + Sized {
    fn body_mut(&mut self) -> &mut mir::Body<'tcx>;

    fn body(&self) -> &mir::Body<'tcx>;

    fn ty_of(&self, place: Place<'tcx>) -> PlaceTy<'tcx> {
        place.ty(&self.body().local_decls, self.tcx())
    }

    fn layout_of(&self, place: Place<'tcx>) -> TyAndLayout<'tcx> {
        self.tcx()
            .layout_of(self.typing_env().as_query_input(self.ty_of(place).ty))
            .expect("Unable to compute layout for place.")
    }

    fn project_field(
        &self,
        place: Place<'tcx>,
        layout: TyAndLayout<'tcx>,
        idx: usize,
    ) -> (Place<'tcx>, TyAndLayout<'tcx>) {
        let layout = layout.field(self, idx);
        let projection = ProjectionElem::Field(FieldIdx::from_usize(idx), layout.ty);
        let place = place.project_deeper(&[projection], self.tcx());
        (place, layout)
    }

    fn remove_statement(&mut self, location: Location) {
        let blocks = self.body_mut().basic_blocks_mut();
        let block_data = &mut blocks[location.block];

        block_data.statements.remove(location.statement_index);
    }

    fn insert_statement(&mut self, location: Location, stmt: mir::Statement<'tcx>) -> Location {
        let blocks = self.body_mut().basic_blocks_mut();
        let block_data = &mut blocks[location.block];

        block_data.statements.insert(location.statement_index, stmt);
        location.successor_within_block()
    }

    fn new_empty_block(&mut self) -> BasicBlock {
        let blocks = self.body_mut().basic_blocks_mut();
        blocks.push(BasicBlockData::new(None, false))
    }

    fn set_terminator(&mut self, index: BasicBlock, terminator: Terminator<'tcx>) {
        let blocks = self.body_mut().basic_blocks_mut();
        blocks.get_mut(index).unwrap().terminator.replace(terminator);
    }

    fn split_block(&mut self, location: Location) -> BasicBlock {
        let blocks = self.body_mut().basic_blocks_mut();
        let block_data = &mut blocks[location.block];

        // Drain every statement after this one and move the current terminator to a new basic block.
        let new_block = BasicBlockData {
            statements: block_data.statements.split_off(location.statement_index),
            terminator: block_data.terminator.take(),
            is_cleanup: block_data.is_cleanup,
        };

        blocks.push(new_block)
    }
}

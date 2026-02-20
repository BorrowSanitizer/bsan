use core::ptr::NonNull;

use crate::borrow_tracker::tree::NodeInner;
use crate::borrow_tracker::{Node, Tree};
use crate::memory::Slab;

#[derive(Default)]
pub struct Forest {
    nodes: Slab<NodeInner>,
    trees: Slab<Tree>,
}

impl Forest {
    pub fn new_node(&self) -> Node {
        Node(self.nodes.alloc())
    }

    pub fn new_tree(&self) -> NonNull<Tree> {
        self.trees.alloc()
    }

    pub unsafe fn free_node(&self, node: Node) {
        unsafe { self.nodes.dealloc(node.0) }
    }

    pub unsafe fn free_tree(&self, tree: NonNull<Tree>) {
        unsafe { self.trees.dealloc(tree) };
    }
}

use core::mem;
use core::sync::atomic::Ordering::Relaxed;

use crate::global::{CURRENT_GC_INTERVAL, MAX_COMPACTED_CHILDREN};
use crate::BorTag;
use super::data_structures::UniIndex;
use super::perms::Permission;
use super::tree::EagerTree;

/// Results of the last garbage collection pass
pub struct GcStats {
    pub kept: usize,
    pub removed: usize,
}

/// Adjusts `CURRENT_GC_INTERVAL` based on how productive this GC pass was.
/// Passes finding a larger dead-node fraction than `TARGET_DEAD_RATIO` shrink the
/// interval (collect sooner); passes finding less grow it. The adjustment is damped
/// to at most 2x per pass in either direction, and the resulting interval is clamped
/// to `[MIN_GC_INTERVAL, MAX_GC_INTERVAL]`.
pub fn update_current_gc_interval(stats: &GcStats) {
    const TARGET_DEAD_RATIO: f64 = 0.5;
    const MIN_GC_INTERVAL: usize = 1000;
    const MAX_GC_INTERVAL: usize = 10_000_000;

    let current = CURRENT_GC_INTERVAL.load(Relaxed);
    if current == 0 {
        return;
    }

    let total = stats.kept + stats.removed;
    if total == 0 {
        return;
    }

    let dead_ratio = stats.removed as f64 / total as f64;
    let adjust = (TARGET_DEAD_RATIO / dead_ratio.max(0.01)).clamp(0.5, 2.0);
    let new_interval = ((current as f64 * adjust) as usize)
        .clamp(MIN_GC_INTERVAL, MAX_GC_INTERVAL);

    CURRENT_GC_INTERVAL.store(new_interval, Relaxed);
}

/// Checks whether a dead node can be replaced by its only child.
/// The caller iterates the dead tags directly, so `idx` is already known to be dead
/// and there is no membership check — only the shape and permission conditions remain.
fn can_be_replaced_by_single_child(tree: &EagerTree, idx: UniIndex) -> bool {
    let node = tree.nodes.get(idx).unwrap();
    if node.parent.is_none() {
        return false;
    }
    let [child_idx] = node.children[..] else { return false };

    let child = tree.nodes.get(child_idx).unwrap();
    tree.locations.iter_all().all(|(_range, loc)| {
        let parent_perm =
            loc.perms.get(idx).map(|x| x.permission).unwrap_or(node.default_initial_perm);
        let child_perm = loc
            .perms
            .get(child_idx)
            .map(|x| x.permission)
            .unwrap_or(child.default_initial_perm);
        parent_perm.can_be_replaced_by_child(child_perm)
    })
}

/// Like [`can_be_replaced_by_single_child`], but for a node with more than one child.
/// This requires the stronger [`Permission::can_be_replaced_by_children`] check, and
/// it must hold for every child at every location.
fn can_be_replaced_by_children(tree: &EagerTree, idx: UniIndex) -> bool {
    let node = tree.nodes.get(idx).unwrap();
    let Some(parent_idx) = node.parent else { return false };
    if node.default_initial_perm.is_reserved_im() {
        return false;
    }

    let parent_width = tree.nodes.get(parent_idx).unwrap().children.len();
    if parent_width + node.children.len() - 1 > MAX_COMPACTED_CHILDREN.load(Relaxed) {
        return false;
    }

    let children: smallvec::SmallVec<[(UniIndex, Permission); 4]> = node
        .children
        .iter()
        .map(|&child_idx| (child_idx, tree.nodes.get(child_idx).unwrap().default_initial_perm))
        .collect();
    tree.locations.iter_all().all(|(_range, loc)| {
        let parent_perm =
            loc.perms.get(idx).map(|x| x.permission).unwrap_or(node.default_initial_perm);
        children.iter().all(|&(child_idx, child_default)| {
            let child_perm =
                loc.perms.get(child_idx).map(|x| x.permission).unwrap_or(child_default);
            parent_perm.can_be_replaced_by_children(child_perm)
        })
    })
}

/// Properly removes a node.
/// The node to be removed should not otherwise be usable. It also
/// should have no children, but this is not checked, so that nodes
/// whose children were rotated somewhere else can be deleted without
/// having to first modify them to clear that array.
fn remove_useless_node(tree: &mut EagerTree, this: UniIndex) {
    let node = tree.nodes.remove(this).unwrap();
    for (_range, loc) in tree.locations.iter_mut_all() {
        loc.perms.remove(this);
        loc.exposed_cache.remove(this);
    }
    tree.tag_mapping.remove(&node.tag);
}

/// Removes from the tree the nodes for the given *dead* tags, wherever possible.
///
/// This cleanup must be bottom-up; a dead node can only be deleted as a leaf once its
/// dead descendants are gone, so we must process a node before its parent. Since
/// borrow tags are distributed with a monotonic global counter, `dead_tags` is guaranteed
/// to be sorted in ascending order. Since a child must be allocated after its parent,
/// we maintain the following invariant: `child.tag > parent.tag`. Iterating through
/// `dead_tags` in reverse gives a valid reverse-topological (bottom-up) traversal.
///
/// Each entry in `dead_tags` is zeroed out (set to [`BorTag::omnivalid`]) once its tag
/// no longer needs to be tracked: either the node was removed, or it is guaranteed to
/// re-enter a zero-count table before it can next become prunable. Entries left nonzero
/// are dead nodes that could not be pruned yet.
///
/// When `compact` is false, dead interior nodes are left in place (their entries stay
/// nonzero) instead of being coalesced into their parent. Dead *leaves* are still
/// removed unconditionally, so the pending set continues to drain and a tree that dies
/// entirely still empties out. This lets small trees skip the per-location permission
/// checks that compaction requires.
///
/// Roots only ever leave the tree as leaves; a dead root with children is never
/// replaced by them. Since a child's tag is always greater than its parent's,
/// promoting a child into the roots could break the ascending-tag order of
/// roots, which other traversals rely on. This retains at most one dead root per tree,
/// and only until its subtree dies (or is compacted away), at which point it is removed as a leaf.
pub fn remove_useless_children(
    tree: &mut EagerTree,
    dead_tags: &mut [BorTag],
    compact: bool,
) -> GcStats {
    let node_count_before = tree.tag_mapping.len();
    for entry in dead_tags.iter_mut().rev() {
        let tag = *entry;
        let Some(idx) = tree.tag_mapping.get(&tag) else {
            *entry = BorTag::omnivalid();
            continue;
        };
        let node = tree.nodes.get(idx).unwrap();

        if node.refcount.get() != 0 {
            *entry = BorTag::omnivalid();
            continue;
        }

        if node.is_exposed {
            *entry = BorTag::omnivalid();
            continue;
        }

        let parent = node.parent;

        match node.children.len() {
            0 => {
                match parent {
                    Some(parent_idx) => {
                        let children = &mut tree.nodes.get_mut(parent_idx).unwrap().children;
                        let pos = children.iter().position(|&c| c == idx).unwrap();
                        children.swap_remove(pos);
                    }
                    None => {
                        let pos = tree.roots.iter().position(|&r| r == idx).unwrap();
                        tree.roots.remove(pos);
                    }
                }
                remove_useless_node(tree, idx);
                *entry = BorTag::omnivalid();
            }
            1 if compact && can_be_replaced_by_single_child(tree, idx) => {
                let child_idx = tree.nodes.get(idx).unwrap().children[0];
                let parent_idx = parent.unwrap();
                let siblings = &mut tree.nodes.get_mut(parent_idx).unwrap().children;
                let pos = siblings.iter().position(|&c| c == idx).unwrap();
                siblings[pos] = child_idx;
                tree.nodes.get_mut(child_idx).unwrap().parent = parent;
                remove_useless_node(tree, idx);
                *entry = BorTag::omnivalid();
            }
            _ if compact && can_be_replaced_by_children(tree, idx) => {
                let parent_idx = parent.unwrap();
                let children = mem::take(&mut tree.nodes.get_mut(idx).unwrap().children);
                for i in 0..children.len() {
                    tree.nodes.get_mut(children[i]).unwrap().parent = Some(parent_idx);
                }
                let siblings = &mut tree.nodes.get_mut(parent_idx).unwrap().children;
                let pos = siblings.iter().position(|&c| c == idx).unwrap();
                siblings.swap_remove(pos);
                for i in 0..children.len() {
                    siblings.push(children[i]);
                }
                remove_useless_node(tree, idx);
                *entry = BorTag::omnivalid();
            }
            _ => {}
        }
    }
    let node_count_after = tree.tag_mapping.len();
    GcStats { kept: node_count_after, removed: node_count_before - node_count_after }
}

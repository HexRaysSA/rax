//! Native splay-tree operations on guest RTL_SPLAY_LINKS records.

use std::collections::HashSet;

use super::super::hle::{ApiErr, ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::MemFault;
use crate::error::MemoryAccessKind;

pub(super) static EXPORTS: &[Export] = &[
    Export::func("RtlSplay", Stdcall, &[Ptr], splay),
    Export::func("RtlDelete", Stdcall, &[Ptr], delete_and_splay),
    Export::func("RtlDeleteNoSplay", Stdcall, &[Ptr, Ptr], delete_no_splay),
];

const PARENT: u64 = 0;
const LEFT: u64 = 1;
const RIGHT: u64 = 2;

fn field(c: &Ctx, node: u64, link: u64) -> u64 {
    node.wrapping_add(link * c.psize())
}

fn link(c: &Ctx, node: u64, index: u64) -> Result<u64, MemFault> {
    c.read_ptr(field(c, node, index))
}

fn side(c: &Ctx, node: u64, parent: u64) -> Result<u64, ApiErr> {
    if link(c, parent, LEFT)? == node {
        Ok(LEFT)
    } else if link(c, parent, RIGHT)? == node {
        Ok(RIGHT)
    } else {
        Err(c.unsupported("RTL_SPLAY_LINKS parent does not reference child"))
    }
}

fn publish(c: &Ctx, updates: &[(u64, u64)]) -> Result<(), ApiErr> {
    for (address, _) in updates {
        c.mem()
            .probe(*address, c.psize() as usize, MemoryAccessKind::Write)
            .map_err(|fault| MemFault {
                addr: fault.address,
                write: true,
            })?;
    }
    for (address, value) in updates {
        c.write_ptr(*address, *value)?;
    }
    Ok(())
}

fn rotate(c: &Ctx, node: u64, parent: u64, direction: u64) -> Result<(), ApiErr> {
    let grandparent = link(c, parent, PARENT)?;
    let opposite = LEFT + RIGHT - direction;
    let subtree = link(c, node, opposite)?;
    let mut updates = [(0, 0); 6];
    updates[..4].copy_from_slice(&[
        (field(c, parent, direction), subtree),
        (field(c, node, opposite), parent),
        (field(c, parent, PARENT), node),
        (
            field(c, node, PARENT),
            if grandparent == parent {
                node
            } else {
                grandparent
            },
        ),
    ]);
    let mut count = 4;
    if subtree != 0 {
        updates[count] = (field(c, subtree, PARENT), parent);
        count += 1;
    }
    if grandparent != parent {
        updates[count] = (field(c, grandparent, side(c, parent, grandparent)?), node);
        count += 1;
    }
    publish(c, &updates[..count])
}

fn splay(c: &mut Ctx) -> ApiResult {
    Flow::ret(splay_node(c, c.ptr(0)?)?)
}

fn splay_node(c: &Ctx, node: u64) -> Result<u64, ApiErr> {
    let mut visited = HashSet::new();
    loop {
        let parent = link(c, node, PARENT)?;
        if parent == node && node != 0 {
            return Ok(node);
        }
        if parent == 0 || !visited.insert(parent) {
            return Err(c.unsupported("invalid RTL_SPLAY_LINKS parent chain"));
        }
        let direction = side(c, node, parent)?;
        let grandparent = link(c, parent, PARENT)?;
        if parent == grandparent {
            rotate(c, node, parent, direction)?;
        } else if side(c, parent, grandparent)? == direction {
            rotate(c, parent, grandparent, direction)?;
            rotate(c, node, parent, direction)?;
        } else {
            rotate(c, node, parent, direction)?;
            let direction = side(c, node, grandparent)?;
            rotate(c, node, grandparent, direction)?;
        }
    }
}

fn predecessor(c: &Ctx, left: u64) -> Result<u64, ApiErr> {
    let mut node = left;
    let mut visited = HashSet::new();
    loop {
        let right = link(c, node, RIGHT)?;
        if right == 0 {
            return Ok(node);
        }
        if !visited.insert(node) {
            return Err(c.unsupported("invalid RTL_SPLAY_LINKS subtree"));
        }
        node = right;
    }
}

fn remove(c: &Ctx, node: u64, root: Option<u64>) -> Result<u64, ApiErr> {
    let parent = link(c, node, PARENT)?;
    let left = link(c, node, LEFT)?;
    let right = link(c, node, RIGHT)?;
    let is_root = parent == node;
    let mut updates = Vec::with_capacity(9);
    let (replacement, splay_target) = if left != 0 && right != 0 {
        let predecessor = predecessor(c, left)?;
        let predecessor_parent = link(c, predecessor, PARENT)?;
        if predecessor_parent != node {
            let child = link(c, predecessor, LEFT)?;
            updates.push((field(c, predecessor_parent, RIGHT), child));
            if child != 0 {
                updates.push((field(c, child, PARENT), predecessor_parent));
            }
            updates.push((field(c, predecessor, LEFT), left));
            updates.push((field(c, left, PARENT), predecessor));
        }
        updates.push((field(c, predecessor, RIGHT), right));
        updates.push((field(c, right, PARENT), predecessor));
        let splay_target = if predecessor_parent == node {
            predecessor
        } else {
            predecessor_parent
        };
        (predecessor, splay_target)
    } else {
        let child = if left != 0 { left } else { right };
        (child, if is_root { child } else { parent })
    };
    if replacement != 0 {
        updates.push((
            field(c, replacement, PARENT),
            if is_root { replacement } else { parent },
        ));
    }
    if is_root {
        if let Some(out) = root {
            updates.push((out, replacement));
        }
    } else {
        updates.push((field(c, parent, side(c, node, parent)?), replacement));
    }
    publish(c, &updates)?;
    Ok(splay_target)
}

fn delete_and_splay(c: &mut Ctx) -> ApiResult {
    let target = remove(c, c.ptr(0)?, None)?;
    if target == 0 {
        return Flow::ret(0);
    }
    Flow::ret(splay_node(c, target)?)
}

fn delete_no_splay(c: &mut Ctx) -> ApiResult {
    remove(c, c.ptr(0)?, Some(c.ptr(1)?))?;
    Flow::void()
}

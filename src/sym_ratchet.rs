use std::{collections::BTreeMap, panic};

use crate::treemath::{self, LeafCount, LeafIndex, NodeIndex};

#[derive(Debug)]
pub enum Error {
	//
}

pub struct Chain;

// pub enum Secret {
// 	// Node(Hash),
// 	// Leaf(Chain),
// }
type Secret = u32;

#[derive(Debug)]
pub struct SecretTree {
	pub group_size: LeafCount,
	pub root: NodeIndex,
	pub secrets: BTreeMap<u32, Secret>, // use NodeIndex as a key instead?
}

impl SecretTree {
	// TODO: check if size is > 0
	pub fn new(size: u32, root_secret: u32) -> Self {
		let root = treemath::NodeIndex::root(LeafCount(size)).unwrap();
		let mut secrets = BTreeMap::new();

		secrets.insert(root.0, root_secret);

		Self {
			group_size: LeafCount(size),
			root,
			secrets,
		}
	}

	// TODO: add generation
	// TODO: return Result instead
	pub fn get(&mut self, leaf: LeafIndex) -> Secret {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
		let sender = NodeIndex::from(leaf);
		let mut dirpath = sender.dirpath_for_group_size(self.group_size).unwrap(); // TODO: do not unwrap or check in advance?

		dirpath.insert(0, sender);
		dirpath.push(self.root);

		let mut curr = 0;
		// TODO: replace with (curr..dirpath.len())
		while curr < dirpath.len() {
			let idx = dirpath.get(curr).unwrap();
			if self.secrets.get(&idx.0).is_some() {
				break;
			} else {
				curr += 1;
			}
		}

		if curr > dirpath.len() {
			panic!("No secret found to derive base key");
		}

		while curr > 0 {
			//
			let curr_node = dirpath.get(curr).unwrap();
			let left = curr_node.left().unwrap(); // TODO: do not unwrap or check in advance?
			let right = curr_node.right_for_group_size(self.group_size).unwrap(); // TODO: do not unwrap or check in advance
			let secret = self.secrets.get(&curr_node.0).unwrap();

			let left_secret = left.0; // TODO: kdf-expand with secret^ instead; TODO: do not unwrap?
			let right_secret = right.0; // TODO: kdf-expand with secret^ instead; TODO: do not unwrap?

			self.secrets.insert(left.0, left_secret);
			self.secrets.insert(right.0, right_secret);

			curr -= 1;
		}

		let out = *self.secrets.get(&sender.0).unwrap();
		dirpath.into_iter().for_each(|idx| {
			self.secrets.remove(&idx.0);
		});

		return out;
	}
}

#[cfg(test)]
mod tests {
	use super::SecretTree;
	use crate::treemath::LeafIndex;

	#[test]
	fn test_get() {
		let mut sr = SecretTree::new(1, 0);
		let o0 = sr.get(LeafIndex(0));

		println!("{}", o0);
		println!("{:?}", sr);
	}
}

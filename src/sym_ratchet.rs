use std::collections::BTreeMap;

use crate::treemath::{self, LeafCount, LeafIndex, NodeIndex};

#[derive(Debug, PartialEq)]
pub enum Error {
	LeafOutOfRange { idx: LeafIndex, r: LeafCount },
	NoEmptyTreeAllowed,
	SecretHasBeenUsed { idx: LeafIndex },
}

impl From<treemath::Error> for Error {
	fn from(err: treemath::Error) -> Self {
		use self::Error::*;

		match err {
			treemath::Error::NodeCountNotOdd => unreachable!(),
			treemath::Error::LeafNotEvenInNodeSpace => unreachable!(),
			treemath::Error::NoRootForEmptyTree => NoEmptyTreeAllowed,
			treemath::Error::LeafCantHaveChildren => unreachable!(),
			treemath::Error::NodeOutOfRange { n, r } => LeafOutOfRange {
				idx: LeafIndex::try_from(n).unwrap(),
				r: LeafCount::try_from(r).unwrap(),
			},
			treemath::Error::RootCantHaveParent => unreachable!(),
		}
	}
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
	// no empty tree allowed, hence Result
	pub fn try_new(size: u32, root_secret: u32) -> Result<Self, Error> {
		let group_size = LeafCount(size);
		let root = treemath::NodeIndex::root(group_size)?;
		let mut secrets = BTreeMap::new();

		secrets.insert(root.0, root_secret);

		Ok(Self {
			group_size,
			root,
			secrets,
		})
	}

	pub fn get(&mut self, leaf: LeafIndex) -> Result<Secret, Error> {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
		let sender = NodeIndex::from(leaf);
		let mut dirpath = sender.dirpath_for_group_size(self.group_size)?;

		dirpath.insert(0, sender);

		let mut curr = 0;

		while curr < dirpath.len() {
			let idx = dirpath.get(curr).unwrap();
			if self.secrets.get(&idx.0).is_some() {
				break;
			} else {
				curr += 1;
			}
		}

		if curr == dirpath.len() {
			Err(Error::SecretHasBeenUsed { idx: leaf })
		} else {
			while curr > 0 {
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

			Ok(out)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::SecretTree;
	use crate::{
		sym_ratchet::Error,
		treemath::{LeafCount, LeafIndex},
	};

	#[test]
	#[rustfmt::skip]
	fn test_get() {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
		let mut s = SecretTree::try_new(8, 0).unwrap();

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![2, 5, 11]);
		assert_eq!(s.get(LeafIndex(0)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(0) }));

		assert_eq!(s.get(LeafIndex(20)).err(), Some(Error::LeafOutOfRange { idx: LeafIndex(20), r: LeafCount(8) }));

		assert_eq!(s.get(LeafIndex(1)).ok(), Some(2));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![5, 11]);
		assert_eq!(s.get(LeafIndex(1)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(1) }));

		assert_eq!(s.get(LeafIndex(4)).ok(), Some(8));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![5, 10, 13]);
		assert_eq!(s.get(LeafIndex(4)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(4) }));

		assert_eq!(s.get(LeafIndex(2)).ok(), Some(4));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![6, 10, 13]);

		assert_eq!(s.get(LeafIndex(3)).ok(), Some(6));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![10, 13]);

		assert_eq!(s.get(LeafIndex(7)).ok(), Some(14));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![10, 12]);

		assert_eq!(s.get(LeafIndex(6)).ok(), Some(12));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![10]);
		
		assert_eq!(s.get(LeafIndex(5)).ok(), Some(10));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![]);
		assert_eq!(s.get(LeafIndex(5)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(5) }));

		////
		let mut s = SecretTree::try_new(2, 0).unwrap();

		assert_eq!(s.get(LeafIndex(1)).ok(), Some(2));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![0]);
		assert_eq!(s.get(LeafIndex(1)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(1) }));

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![]);

		////
		let mut s = SecretTree::try_new(1, 0).unwrap();

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![]);
		assert_eq!(s.get(LeafIndex(0)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(0) }));

		////
		let s = SecretTree::try_new(0, 0);

		assert!(s.is_err());

		////
		let mut s = SecretTree::try_new(5, 0).unwrap();

		assert_eq!(s.get(LeafIndex(1)).ok(), Some(2));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![0, 5, 8]);
		assert_eq!(s.get(LeafIndex(1)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(1) }));

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![5, 8]);

		assert_eq!(s.get(LeafIndex(3)).ok(), Some(6));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![4, 8]);

		assert_eq!(s.get(LeafIndex(4)).ok(), Some(8));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![4]);
	}
}

use std::{collections::BTreeMap, fmt::Debug};

use crate::{
	hash, hkdf, hmac,
	treemath::{self, LeafCount, LeafIndex, NodeIndex},
};

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

#[derive(Clone)]
pub struct SecretTree<Secret, KDF> {
	pub group_size: LeafCount,
	pub root: NodeIndex,
	pub secrets: BTreeMap<NodeIndex, Secret>,
	pub kdf: KDF,
}

impl<Secret, KDF> SecretTree<Secret, KDF>
where
	Secret: Copy,
	KDF: Fn(&Secret, NodeIndex, &[u8]) -> Secret,
{
	// no empty tree allowed, therefore Result
	pub fn try_new(size: u32, root_secret: Secret, kdf: KDF) -> Result<Self, Error> {
		let group_size = LeafCount(size);
		let root = treemath::NodeIndex::root(group_size)?;
		let mut secrets = BTreeMap::new();

		secrets.insert(root, root_secret);

		Ok(Self {
			group_size,
			root,
			secrets,
			kdf,
		})
	}

	pub fn get(&mut self, leaf: LeafIndex) -> Result<Secret, Error> {
		let sender = NodeIndex::from(leaf);
		let mut dirpath = sender.dirpath_for_group_size(self.group_size)?;

		dirpath.insert(0, sender);

		let mut curr = 0;

		while curr < dirpath.len() {
			let idx = dirpath.get(curr).unwrap();
			if self.secrets.get(&idx).is_some() {
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
				let left = curr_node.left().unwrap();
				let right = curr_node.right_for_group_size(self.group_size).unwrap();
				let secret = self.secrets.get(&curr_node).unwrap();

				let left_secret = (self.kdf)(secret, left, b"left");
				let right_secret = (self.kdf)(secret, right, b"right");

				self.secrets.insert(left, left_secret);
				self.secrets.insert(right, right_secret);

				curr -= 1;
			}

			let out = *self.secrets.get(&sender).unwrap();

			dirpath.into_iter().for_each(|idx| {
				self.secrets.remove(&idx);
			});

			Ok(out)
		}
	}
}

const HKDF_SALT: &[u8; hmac::Key::SIZE] = b"SecretTreeSecretTreeSecretTreeSe";

pub fn hkdf(ikm: &hash::Hash, idx: NodeIndex, info: &[u8]) -> hash::Hash {
	hkdf::Hkdf::from_ikm_salted(ikm, HKDF_SALT)
		.expand::<{ hash::SIZE }>(&[info, &vec![idx.0 as u8]].concat())
}

pub type HkdfTree = SecretTree<hash::Hash, fn(&hash::Hash, NodeIndex, &[u8]) -> hash::Hash>;

impl PartialEq for HkdfTree {
	fn eq(&self, other: &Self) -> bool {
		self.group_size == other.group_size
			&& self.root == other.root
			&& self.secrets == other.secrets
	}
}

impl Debug for HkdfTree {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SecretTree")
			.field("group_size", &self.group_size)
			.field("root", &self.root)
			.field("secrets", &self.secrets)
			.finish()
	}
}

impl HkdfTree {
	pub fn try_new_for_root_secret(size: u32, root_secret: hash::Hash) -> Result<Self, Error> {
		Self::try_new(size, root_secret, hkdf)
	}
}

#[cfg(test)]
mod tests {
	use super::{HkdfTree, SecretTree};
	use crate::{
		secret_tree::Error,
		treemath::{LeafCount, LeafIndex, NodeIndex},
	};

	#[test]
	#[rustfmt::skip]
	fn test_node_derivation_on_get() {
		fn nokdf(_: &u32, idx: NodeIndex, _: &[u8]) -> u32 {
			// don't derive a new secret, but just return this node's index
			idx.0
		}
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
		let mut s = SecretTree::try_new(8, 0, nokdf).unwrap();

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

		let mut s = SecretTree::try_new(2, 0, nokdf).unwrap();

		assert_eq!(s.get(LeafIndex(1)).ok(), Some(2));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![0]);
		assert_eq!(s.get(LeafIndex(1)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(1) }));

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![]);

		let mut s = SecretTree::try_new(1, 0, nokdf).unwrap();

		assert_eq!(s.get(LeafIndex(0)).ok(), Some(0));
		assert_eq!(s.secrets.values().cloned().collect::<Vec<u32>>(), vec![]);
		assert_eq!(s.get(LeafIndex(0)).err(), Some(Error::SecretHasBeenUsed { idx: LeafIndex(0) }));

		let s = SecretTree::try_new(0, 0, nokdf);

		assert!(s.is_err());

		let mut s = SecretTree::try_new(5, 0, nokdf).unwrap();

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

	#[test]
	fn test_hkdf_tree_ensures_unique_secrets_for_leafes() {
		let rs = [42u8; 32];

		let mut s = HkdfTree::try_new_for_root_secret(1, rs).unwrap();
		// no need to derive anything when it's just one node
		assert_eq!(s.get(LeafIndex(0)).ok(), Some(rs));

		let mut s_one = HkdfTree::try_new_for_root_secret(5, rs).unwrap();
		// derivation takes place
		let n0_one = s_one.get(LeafIndex(0));
		let n1_one = s_one.get(LeafIndex(1));
		let n2_one = s_one.get(LeafIndex(2));

		assert_ne!(n0_one, n1_one);
		assert_ne!(n0_one, n2_one);
		assert_ne!(n1_one, n2_one);
		assert_ne!(n2_one.ok(), Some(rs));
		assert_ne!(n1_one.ok(), Some(rs));
		assert!(n0_one.is_ok());

		// make sure changing the root secret changes the leaf secrets completely
		let mut s_two = HkdfTree::try_new_for_root_secret(5, [41u8; 32]).unwrap();
		// derivation takes place
		let n0_two = s_two.get(LeafIndex(0));

		assert_ne!(n0_one, n0_two);
	}
}

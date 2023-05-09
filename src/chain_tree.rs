use std::collections::BTreeMap;

use crate::{
	chain::{self, Chain, DetachedKey},
	hash,
	secret_tree::{self, HkdfTree},
	treemath::{LeafCount, LeafIndex},
};

#[derive(Debug, PartialEq)]
pub enum Error {
	NoEmptyTreeAllowed,
	LeafOutOfRange { idx: LeafIndex, r: LeafCount },
	// lost message (generation) key
	KeyHasBeenUsed { idx: u32 },
	TooManyKeysSkipped,
	// chain was more likely properly initialized previously, but wasn't persisted; not recovery possible
	ChainLost { idx: LeafIndex },
}

impl From<chain::Error> for Error {
	fn from(err: chain::Error) -> Self {
		use self::Error::*;

		match err {
			chain::Error::KeyHasBeenUsed(idx) => KeyHasBeenUsed { idx }, // message key is lost
			chain::Error::TooManyKeysSkipped => TooManyKeysSkipped,
		}
	}
}

impl From<secret_tree::Error> for Error {
	fn from(err: secret_tree::Error) -> Self {
		use self::Error::*;

		match err {
			secret_tree::Error::LeafOutOfRange { idx, r } => LeafOutOfRange { idx, r },
			secret_tree::Error::NoEmptyTreeAllowed => NoEmptyTreeAllowed,
			secret_tree::Error::SecretHasBeenUsed { idx } => ChainLost { idx },
		}
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainTree {
	pub(crate) chains: BTreeMap<LeafIndex, Chain>,
	pub(crate) secret_tree: HkdfTree,
	pub(crate) max_keys_to_skip: u32,
}

impl ChainTree {
	pub fn try_new(
		size: u32,
		root_secret: hash::Hash,
		max_keys_to_skip: u32,
	) -> Result<Self, Error> {
		// should I check group_size > 0?
		Ok(Self {
			chains: BTreeMap::new(),
			secret_tree: HkdfTree::try_new_for_root_secret(size, root_secret)?,
			max_keys_to_skip,
		})
	}

	pub fn get(&mut self, node: LeafIndex, gen: u32) -> Result<DetachedKey, Error> {
		if let Some(chain) = self.chains.get_mut(&node) {
			Ok(chain.get(gen)?)
		} else {
			let new_chain_head = self.secret_tree.get(node)?;
			let new_chain = Chain::new(new_chain_head, self.max_keys_to_skip);

			self.chains.insert(node, new_chain);

			Ok(self.chains.get_mut(&node).unwrap().get(gen)?)
		}
	}

	pub fn get_next(&mut self, node: LeafIndex) -> Result<(DetachedKey, u32), Error> {
		if let Some(chain) = self.chains.get_mut(&node) {
			Ok(chain.get_next()?)
		} else {
			Ok((self.get(node, 0)?, 0))
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::{
		chain_tree::{ChainTree, Error},
		treemath::{LeafCount, LeafIndex},
	};

	#[test]
	fn test_new() {
		assert_eq!(
			ChainTree::try_new(0, [42u8; 32], 10).err(),
			Some(Error::NoEmptyTreeAllowed)
		);
		assert!(ChainTree::try_new(5, [42u8; 32], 10).is_ok());
		assert!(ChainTree::try_new(15, [42u8; 32], 0).is_ok());
	}

	#[test]
	fn test_get() {
		//          X
		//    X
		// X     X     X
		// 0  1  2  3  4
		let mut ct = ChainTree::try_new(3, [42u8; 32], 10).unwrap();
		let n0g0 = ct.get(LeafIndex(0), 0).unwrap();
		let n0g1 = ct.get(LeafIndex(0), 1).unwrap();
		let n0g2 = ct.get(LeafIndex(0), 2).unwrap();

		assert_ne!(n0g0, n0g1);
		assert_ne!(n0g1, n0g2);
		assert_ne!(n0g2, n0g0);

		let n2g8 = ct.get(LeafIndex(2), 8).unwrap();
		let n2g2 = ct.get(LeafIndex(2), 2).unwrap();

		// all is good for skipped keys as well
		assert_ne!(n2g8, n2g2);
	}

	#[test]
	fn test_errors() {
		let mut ct = ChainTree::try_new(3, [42u8; 32], 10).unwrap();

		assert_eq!(
			ct.get(LeafIndex(5), 0).err(),
			Some(Error::LeafOutOfRange {
				idx: LeafIndex(5),
				r: LeafCount(3)
			})
		);
		assert_eq!(
			ct.get(LeafIndex(0), 100).err(),
			Some(Error::TooManyKeysSkipped)
		);
		assert!(ct.get(LeafIndex(0), 1).is_ok());
		assert_eq!(
			ct.get(LeafIndex(0), 1).err(),
			Some(Error::KeyHasBeenUsed { idx: 1 })
		);

		// imitate state loss
		ct.chains.remove(&LeafIndex(0));
		assert_eq!(
			ct.get(LeafIndex(0), 1).err(),
			Some(Error::ChainLost { idx: LeafIndex(0) })
		);
	}
}

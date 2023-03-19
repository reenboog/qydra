pub(crate) const MAX_TREE_SIZE: u32 = 1 << 30;
pub(crate) const MIN_TREE_SIZE: u32 = 1;

fn log2(x: u32) -> usize {
	if x == 0 {
		return 0;
	}
	let mut k = 0;
	while (x >> k) > 0 {
		k += 1
	}
	k - 1
}

pub struct NodeCount(u32);

// answers "given N leaves, how many nodes would this tree have?"
// TODO: introduce an explicit function instead?
impl From<LeafCount> for NodeCount {
	fn from(lc: LeafCount) -> Self {
		if lc.0 == 0 {
			Self(0)
		} else {
			Self(2 * (lc.0 - 1) + 1)
		}
	}
}

#[derive(Debug, PartialEq)]
pub struct LeafCount(u32);

#[derive(Debug, PartialEq)]
pub enum Error {
	NodeCountNotOdd,
	LeafIdxNotOddInNodeSpace,
	NoRootForEmptyTree,
}

impl LeafCount {
	// rounds leaf count to the closest power of two, ie to the size of a "full" tree
	pub fn full(lc: LeafCount) -> LeafCount {
		let mut nodes = 1;

		while nodes < lc.0 {
			nodes <<= 1;
		}

		LeafCount(nodes)
	}
}

// answers "given N nodes, how many leaves would such a tree have?"
// TODO: introduce an explicit function instead?
impl TryFrom<NodeCount> for LeafCount {
	type Error = Error;

	fn try_from(nc: NodeCount) -> Result<Self, Self::Error> {
		if nc.0 == 0 {
			Ok(Self(0))
		} else if nc.0 % 2 == 0 {
			Err(Error::NodeCountNotOdd)
		} else {
			Ok(Self((nc.0 >> 1) + 1))
		}
	}
}

// describes leaf index in the local (among leaves only) leaf space, eg [0, 1, 2, 3..]
#[derive(Clone, Copy)]
pub struct LeafIndex(u32);

// FIXME: to I need this actually?
impl TryFrom<NodeIndex> for LeafIndex {
	type Error = Error;

	fn try_from(ni: NodeIndex) -> Result<Self, Self::Error> {
		if ni.0 % 2 == 1 {
			Err(Error::LeafIdxNotOddInNodeSpace)
		} else {
			Ok(Self(ni.0 >> 1))
		}
	}
}

impl LeafIndex {
	pub fn ancestor(&self, other: LeafIndex) -> NodeIndex {
		let mut ln = NodeIndex::from(*self);
		let mut rn = NodeIndex::from(other);

		if ln == rn {
			return ln;
		}

		let mut k: u8 = 0;
		while ln != rn {
			ln.0 >>= 1;
			rn.0 >>= 1;
			k += 1;
		}
		let pref = ln.0 << k;
		let stop = 1 << u8::from(k - 1);

		NodeIndex(pref + (stop - 1))
	}
}

// describes node index in the global node space
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct NodeIndex(u32);

impl From<LeafIndex> for NodeIndex {
	fn from(li: LeafIndex) -> Self {
		Self(li.0 * 2)
	}
}

impl NodeIndex {
	pub fn root(lc: LeafCount) -> Result<NodeIndex, Error> {
		if lc.0 == 0 {
			Err(Error::NoRootForEmptyTree)
		} else {
			Ok(NodeIndex((1 << log2(NodeCount::from(lc).0)) - 1))
		}
	}

	pub fn is_leaf(&self) -> bool {
		self.0 % 2 == 0
	}

	fn level(&self) -> u32 {
		if self.0 % 2 == 0 {
			0
		} else {
			let mut k = 0;
			while (self.0 >> k) % 2 == 1 {
				k += 1;
			}

			k
		}
	}

	// whether self is in a subtree of other
	pub fn is_in_subtree(&self, other: NodeIndex) -> bool {
		// if other == self?
		let lx = self.level();
		let ly = other.level();

		lx <= ly && (self.0 >> (ly + 1) == other.0 >> (ly + 1))
	}

	pub fn left(&self) -> NodeIndex {
		if self.is_leaf() {
			*self
		} else {
			NodeIndex(self.0 ^ (0x01 << (self.level() - 1)))
		}
	}

	pub fn right(&self) -> NodeIndex {
		if self.is_leaf() {
			*self
		} else {
			NodeIndex(self.0 ^ (0x03 << (self.level() - 1)))
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::treemath::{log2, Error, LeafCount, LeafIndex, NodeCount, NodeIndex};

	#[test]
	fn test_log2() {
		assert_eq!(log2(0), 0);
		assert_eq!(log2(1), 0);
		assert_eq!(log2(2), 1);
		assert_eq!(log2(3), 1);
		assert_eq!(log2(4), 2);
		assert_eq!(log2(5), 2);
		assert_eq!(log2(6), 2);
		assert_eq!(log2(7), 2);
		assert_eq!(log2(8), 3);
		assert_eq!(log2(9), 3);
		assert_eq!(log2(10), 3);
		assert_eq!(log2(11), 3);
		assert_eq!(log2(100), 6);
		assert_eq!(log2(1000), 9);
		assert_eq!(log2(10000), 13);
		assert_eq!(log2(100000), 16);
		assert_eq!(log2(1000000), 19);
	}

	#[test]
	fn test_node_count_from_leaf_count() {
		assert_eq!(NodeCount::from(LeafCount(0)).0, 0);
		assert_eq!(NodeCount::from(LeafCount(1)).0, 1);
		assert_eq!(NodeCount::from(LeafCount(2)).0, 3);
		assert_eq!(NodeCount::from(LeafCount(3)).0, 5);
		assert_eq!(NodeCount::from(LeafCount(4)).0, 7);
		assert_eq!(NodeCount::from(LeafCount(5)).0, 9);
		assert_eq!(NodeCount::from(LeafCount(6)).0, 11);
	}

	#[test]
	fn test_try_leaf_count_from_node_count() {
		assert_eq!(LeafCount::try_from(NodeCount(0)).ok(), Some(LeafCount(0)));
		assert_eq!(LeafCount::try_from(NodeCount(1)).ok(), Some(LeafCount(1)));
		assert_eq!(LeafCount::try_from(NodeCount(3)).ok(), Some(LeafCount(2)));

		// even tree sizes are not allowed
		(2..100001).filter(|i| i % 2 == 0).for_each(|i| {
			assert_eq!(
				LeafCount::try_from(NodeCount(i)).err(),
				Some(Error::NodeCountNotOdd)
			);
		});

		assert_eq!(LeafCount::try_from(NodeCount(5)).ok(), Some(LeafCount(3)));
		assert_eq!(LeafCount::try_from(NodeCount(7)).ok(), Some(LeafCount(4)));
		assert_eq!(LeafCount::try_from(NodeCount(9)).ok(), Some(LeafCount(5)));
		assert_eq!(LeafCount::try_from(NodeCount(11)).ok(), Some(LeafCount(6)));
		// even tree sizes are not allowed
		(13..10000).filter(|i| i % 2 != 0).for_each(|i| {
			assert!(LeafCount::try_from(NodeCount(i)).is_ok());
		});
	}

	#[test]
	fn test_leaf_count_full() {
		assert_eq!(LeafCount::full(LeafCount(0)).0, 1);
		assert_eq!(LeafCount::full(LeafCount(1)).0, 1);
		assert_eq!(LeafCount::full(LeafCount(2)).0, 2);
		assert_eq!(LeafCount::full(LeafCount(3)).0, 4);
		assert_eq!(LeafCount::full(LeafCount(4)).0, 4);
		assert_eq!(LeafCount::full(LeafCount(5)).0, 8);
		assert_eq!(LeafCount::full(LeafCount(6)).0, 8);
		assert_eq!(LeafCount::full(LeafCount(7)).0, 8);
		assert_eq!(LeafCount::full(LeafCount(8)).0, 8);
		assert_eq!(LeafCount::full(LeafCount(9)).0, 16);
		assert_eq!(LeafCount::full(LeafCount(100)).0, 128);
		assert_eq!(LeafCount::full(LeafCount(1000)).0, 1024);
	}

	#[test]
	fn test_leaf_index_from_node_index() {
		(0..100).for_each(|i| {
			if i % 2 == 0 {
				assert!(LeafIndex::try_from(NodeIndex(i)).is_ok());
			} else {
				assert!(LeafIndex::try_from(NodeIndex(i)).is_err());
			}
		});
	}

	#[test]
	#[rustfmt::skip]
	fn test_leaf_ancestor() {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20			node index
		// 0     1     2     3     4     5     6     7     8     9    10			leaf index
		let solutions = vec![
			// direct (l.ancestor(r)) order from 0 to 10
			(0u32, 0u32, 0u32), (0, 1, 1), (0, 2, 3), (0, 3, 3), (0, 4, 7), (0, 5, 7), (0, 6, 7), (0, 7, 7), (0, 8, 15), (0, 9, 15), (0, 10, 15),
			// reveresed (r.ancestor(l)) order from 10 to 0
			(1, 0, 1), (2, 0, 3), (3, 0, 3), (4, 0, 7), (5, 0, 7), (6, 0, 7), (7, 0, 7), (8, 0, 15), (9, 0, 15), (10, 0, 15),
			// random values from the middle
			(1, 1, 2), (1, 2, 3), (1, 3, 3), (1, 4, 7), (1, 5, 7), (1, 6, 7), (1, 7, 7), (1, 8, 15), (1, 9, 15), (1, 10, 15),
			(2, 1, 3), (2, 2, 4), (2, 3, 5), (2, 4, 7), (2, 5, 7), (2, 6, 7), (2, 7, 7), (2, 8, 15), (2, 9, 15), (2, 10, 15),
			(3, 1, 3), (3, 2, 5), (3, 3, 6), (3, 4, 7), (3, 5, 7), (3, 6, 7), (3, 7, 7), (3, 8, 15), (3, 9, 15), (3, 10, 15),
			(4, 1, 7), (4, 1, 7), (4, 3, 7), (4, 4, 8), (4, 5, 9), (4, 6, 11), (4, 7, 11), (4, 8, 15), (4, 9, 15), (4, 10, 15),
			(5, 4, 9), (5, 5, 10), (5, 6, 11), (5, 7, 11), (5, 8, 15), (5, 9, 15), (5, 10, 15),
			(6, 5, 11), (6, 6, 12), (6, 7, 13), (6, 8, 15), (6, 9, 15), (6, 10, 15),
			(7, 5, 11), (7, 6, 13), (7, 7, 14), (7, 8, 15), (7, 9, 15), (7, 10, 15),
			(8, 7, 15), (8, 8, 16), (8, 9, 17), (8, 10, 19),
			(9, 8, 17), (9, 9, 18), (9, 10, 19),
			(10, 9, 19), (10, 10, 20)
		];

		solutions.into_iter().for_each(|(l, r, a)| {
			assert_eq!(LeafIndex(l).ancestor(LeafIndex(r)).0, a);
		});
	}

	#[test]
	#[rustfmt::skip]
	fn test_root() {
		let solutions = vec![
			(1u32, 0u32), (2, 1), (3, 3), (4, 3), (5, 7), (6, 7), (7, 7), (8, 7), (9, 15), (10, 15), (11, 15), (12, 15), (13, 15), (14, 15), (15, 15), (16, 15)
		];

		solutions.into_iter().for_each(|(lc, r )| {
			assert_eq!(NodeIndex::root(LeafCount(lc)).ok(), Some(NodeIndex(r)));
		});

		assert_eq!(NodeIndex::root(LeafCount(0)).err(), Some(Error::NoRootForEmptyTree));
	}

	#[test]
	fn test_is_leaf() {
		(0..1000)
			.filter(|i| i % 2 == 0)
			.for_each(|i| assert!(NodeIndex(i).is_leaf()));

		(0..1000)
			.filter(|i| i % 2 != 0)
			.for_each(|i| assert!(!NodeIndex(i).is_leaf()));
	}

	#[test]
	fn test_level() {
		let solutions = vec![
			0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0,
		];

		solutions.into_iter().enumerate().for_each(|(idx, v)| {
			assert_eq!(NodeIndex(idx as u32).level(), v);
		});
	}

	#[test]
	#[rustfmt::skip]
	fn test_is_in_subtree() {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20

		let solutions = vec![
			(0, 0), (0, 1), (0, 3), (0, 7), (0, 15),
			(1, 1), (1, 3), (1, 7), (1, 15),
			(2, 1), (2, 2), (2, 3), (2, 7), (2, 15),
			(3, 3), (3, 7), (3, 15),
			(4, 3), (4, 4), (4, 5), (4, 7), (4, 15),
			(5, 3), (5, 5), (5, 7), (5, 15),
			(6, 3), (6, 5), (6, 6), (6, 7), (6, 15),
			(7, 7), (7, 15),
			(8, 7), (8, 8), (8, 9), (8, 11), (8, 15),
			(9, 7), (9, 9), (9, 11), (9, 15),
			(10, 7), (10, 9), (10, 10), (10, 11), (10, 15),
			(11, 7), (11, 11), (11, 15),
			(12, 7), (12, 11), (12, 12), (12, 13), (12, 15),
			(13, 7), (13, 11), (13, 13), (13, 15),
			(14, 7), (14, 11), (14, 13), (14, 14), (14, 15),
			(15, 15),
			(16, 15), (16, 16), (16, 17), (16, 19),
			(17, 15), (17, 17), (17, 19),
			(18, 15), (18, 17), (18, 18), (18, 19),
			(19, 15), (19, 19),
			(20, 15), (20, 19), (20, 20)
		];

		for i in 0..=20 {
			for j in 0..20 {
				assert_eq!(NodeIndex(i).is_in_subtree(NodeIndex(j)), solutions.contains(&(i, j)));
			}
		}
	}

	#[test]
	fn test_left() {
		let solutions = vec![
			0, 0, 2, 1, 4, 4, 6, 3, 8, 8, 10, 9, 12, 12, 14, 7, 16, 16, 18, 17, 20,
		];

		solutions.into_iter().enumerate().for_each(|(idx, v)| {
			assert_eq!(NodeIndex(idx as u32).left().0, v);
		});
	}

	#[test]
	fn test_right() {
		let solutions = vec![
			0, 2, 2, 5, 4, 6, 6, 11, 8, 10, 10, 13, 12, 14, 14, 23, 16, 18, 18, 21, 20,
		];

		solutions.into_iter().enumerate().for_each(|(idx, v)| {
			assert_eq!(NodeIndex(idx as u32).right().0, v);
		});
	}
}

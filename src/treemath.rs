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

#[derive(Debug, PartialEq)]
pub struct NodeCount(u32);

/// "given N leaves, how many nodes would this tree have?"
impl From<LeafCount> for NodeCount {
	fn from(lc: LeafCount) -> Self {
		if lc.0 == 0 {
			Self(0)
		} else {
			Self(((lc.0 - 1) << 1) + 1)
		}
	}
}

#[derive(Debug, PartialEq, Clone, Copy)]
// a tree of size 1 is a one-leaf tree without intermediate nodes
pub struct LeafCount(pub u32);

#[derive(Debug, PartialEq)]
pub enum Error {
	EmptyTree,
	NodeCountNotOdd,
	LeafNotEvenInNodeSpace,
	NoRootForEmptyTree,
	LeafCantHaveChildren,
	NodeOutOfRange { n: NodeIndex, r: NodeCount },
	RootCantHaveParent,
}

// "given N nodes, how many leaves would such a tree have?"
impl TryFrom<NodeCount> for LeafCount {
	type Error = Error;

	fn try_from(nc: NodeCount) -> Result<Self, Self::Error> {
		if nc.0 == 0 {
			Ok(Self(0))
		} else if nc.0 & 1 == 0 {
			Err(Error::NodeCountNotOdd)
		} else {
			// if nc == 1, it's a one-leaf tree (no intermediate nodes)
			Ok(Self((nc.0 >> 1) + 1))
		}
	}
}

// describes leaf index in the local (among leaves only) leaf space, eg [0, 1, 2, 3..]
#[derive(Clone, Copy)]
pub struct LeafIndex(pub u32);

impl TryFrom<NodeIndex> for LeafIndex {
	type Error = Error;

	fn try_from(ni: NodeIndex) -> Result<Self, Self::Error> {
		if ni.0 & 1 == 1 {
			Err(Error::LeafNotEvenInNodeSpace)
		} else {
			Ok(Self(ni.0 >> 1))
		}
	}
}

impl LeafIndex {
	// can be implemented for NodeIndex actually, but not required for now
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
pub struct NodeIndex(pub u32);

impl From<LeafIndex> for NodeIndex {
	fn from(li: LeafIndex) -> Self {
		Self(li.0 << 1)
	}
}

impl NodeIndex {
	pub fn root(lc: LeafCount) -> Result<NodeIndex, Error> {
		if lc.0 == 0 {
			Err(Error::NoRootForEmptyTree)
		} else {
			// for a tree of size 1 (the tree is a leaf), root is the leaf itself = 0
			Ok(NodeIndex((1 << log2(NodeCount::from(lc).0)) - 1))
		}
	}

	pub fn is_leaf(&self) -> bool {
		self.0 & 1 == 0
	}

	pub fn level(&self) -> u32 {
		if self.0 & 1 == 0 {
			0
		} else {
			let mut k = 0;
			while (self.0 >> k) & 1 == 1 {
				k += 1;
			}

			k
		}
	}

	// whether self is in a subtree of other; true if self == other
	pub fn is_in_subtree(&self, other: &NodeIndex) -> bool {
		let lx = self.level();
		let ly = other.level();

		lx <= ly && (self.0 >> (ly + 1) == other.0 >> (ly + 1))
	}

	pub fn left(&self) -> Result<NodeIndex, Error> {
		if self.is_leaf() {
			Err(Error::LeafCantHaveChildren)
		} else {
			Ok(NodeIndex(self.0 ^ (1 << (self.level() - 1))))
		}
	}

	pub fn right_for_group_size(&self, lc: LeafCount) -> Result<NodeIndex, Error> {
		let nc = NodeCount::from(lc);

		if nc.0 > self.0 {
			if self.is_leaf() {
				Err(Error::LeafCantHaveChildren)
			} else {
				let mut r = self.0 ^ (0x03 << (self.level() - 1));

				while r >= NodeCount::from(lc).0 {
					r = NodeIndex(r).left()?.0;
				}

				Ok(NodeIndex(r))
			}
		} else {
			Err(Error::NodeOutOfRange { n: *self, r: nc })
		}
	}

	// returns node's direct parent, if the subtree is complete (there's an ancestor)
	fn immediate_parent(&self) -> NodeIndex {
		let k = self.level();

		NodeIndex((self.0 | (1 << k)) & !(1 << (k + 1)))
	}

	pub fn parent_for_group_size(&self, lc: LeafCount) -> Result<NodeIndex, Error> {
		if *self == Self::root(lc)? {
			Err(Error::RootCantHaveParent)
		} else {
			let nc = NodeCount::from(lc);

			if nc.0 > self.0 {
				let mut p = self.immediate_parent();
				while p.0 >= NodeCount::from(lc).0 {
					p = p.immediate_parent();
				}

				Ok(p)
			} else {
				Err(Error::NodeOutOfRange { n: *self, r: nc })
			}
		}
	}

	pub fn sibling_for_group_size(&self, lc: LeafCount) -> Result<NodeIndex, Error> {
		let p = self.parent_for_group_size(lc)?;

		if self.0 < p.0 {
			p.right_for_group_size(lc)
		} else {
			p.left()
		}
	}

	pub fn dirpath_for_group_size(&self, lc: LeafCount) -> Result<Vec<NodeIndex>, Error> {
		let mut x = *self;
		let r = Self::root(lc)?;
		let mut dp = Vec::new();

		while x != r {
			x = x.parent_for_group_size(lc)?;
			dp.push(x);
		}

		Ok(dp)
	}

	pub fn copath_for_group_size(&self, lc: LeafCount) -> Result<Vec<NodeIndex>, Error> {
		if *self == Self::root(lc)? {
			Ok(vec![])
		} else {
			let mut dp = self.dirpath_for_group_size(lc)?;
			dp.insert(0, *self);
			dp.pop();

			dp.into_iter()
				.map(|idx| idx.sibling_for_group_size(lc))
				.collect()
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
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20			node index
		// 0     1     2     3     4     5     6     7     8     9    10			leaf index
		assert_eq!(NodeCount::from(LeafCount(0)).0, 0);
		assert_eq!(NodeCount::from(LeafCount(1)).0, 1);
		assert_eq!(NodeCount::from(LeafCount(2)).0, 3);
		assert_eq!(NodeCount::from(LeafCount(3)).0, 5);
		assert_eq!(NodeCount::from(LeafCount(4)).0, 7);
		assert_eq!(NodeCount::from(LeafCount(5)).0, 9);
		assert_eq!(NodeCount::from(LeafCount(6)).0, 11);
		assert_eq!(NodeCount::from(LeafCount(9)).0, 17);
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

			// when one is an ancestor of another?
		];

		solutions.into_iter().for_each(|(l, r, a)| {
			assert_eq!(LeafIndex(l).ancestor(LeafIndex(r)).0, a);
		});
	}

	#[test]
	#[rustfmt::skip]
	fn test_root() {
		let solutions = vec![
			(1, 0), (2, 1), (3, 3), (4, 3), (5, 7), (6, 7), (7, 7), (8, 7), (9, 15), (10, 15), (11, 15), (12, 15), (13, 15), (14, 15), (15, 15), (16, 15)
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
				assert_eq!(NodeIndex(i).is_in_subtree(&NodeIndex(j)), solutions.contains(&(i, j)));
			}
		}
	}

	#[test]
	fn test_left() {
		let odd_solutions = vec![
			0, 1, 4, 3, 8, 9, 12, 7, 16, 17,
		];

		odd_solutions.into_iter().enumerate().for_each(|(idx, v)| {
			let left = NodeIndex(idx as u32 * 2 + 1).left().map(|op| op.0);
			assert_eq!(left, Ok(v));
		});

		(0..1000).filter(|i| i % 2 == 0).into_iter().for_each(|idx| {
			let left = NodeIndex(idx as u32).left();

			assert_eq!(left, Err(Error::LeafCantHaveChildren));
		});
	}

	#[test]
	fn test_right_for_group_size() {
		//                                              X
		//                      X
		//          X                       X                       X
		//    X           X           X           X           X
		// X     X     X     X     X     X     X     X     X     X     X
		// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20

		// TODO: test other cases

		assert_eq!(NodeIndex(7).right_for_group_size(LeafCount(4)).err(), Some(Error::NodeOutOfRange { n: NodeIndex(7), r: NodeCount(7) }));
		assert_eq!(NodeIndex(8).right_for_group_size(LeafCount(4)).err(), Some(Error::NodeOutOfRange { n: NodeIndex(8), r: NodeCount(7) }));

		assert_eq!(NodeIndex(0).right_for_group_size(LeafCount(0)).err(), Some(Error::NodeOutOfRange { n: NodeIndex(0), r: NodeCount(0) }));
		assert_eq!(NodeIndex(0).right_for_group_size(LeafCount(1)).err(), Some(Error::LeafCantHaveChildren));
		assert_eq!(NodeIndex(0).right_for_group_size(LeafCount(4)).err(), Some(Error::LeafCantHaveChildren));
		assert_eq!(NodeIndex(2).right_for_group_size(LeafCount(4)).err(), Some(Error::LeafCantHaveChildren));
		assert_eq!(NodeIndex(4).right_for_group_size(LeafCount(4)).err(), Some(Error::LeafCantHaveChildren));
		assert_eq!(NodeIndex(6).right_for_group_size(LeafCount(4)).err(), Some(Error::LeafCantHaveChildren));

		assert_eq!(NodeIndex(3).right_for_group_size(LeafCount(3)).map(|op| op.0), Ok(4));
		assert_eq!(NodeIndex(3).right_for_group_size(LeafCount(4)).map(|op| op.0), Ok(5));
		assert_eq!(NodeIndex(7).right_for_group_size(LeafCount(5)).map(|op| op.0), Ok(8));
		assert_eq!(NodeIndex(7).right_for_group_size(LeafCount(6)).map(|op| op.0), Ok(9));
		assert_eq!(NodeIndex(7).right_for_group_size(LeafCount(7)).map(|op| op.0), Ok(11));
		assert_eq!(NodeIndex(7).right_for_group_size(LeafCount(8)).map(|op| op.0), Ok(11));
		assert_eq!(NodeIndex(11).right_for_group_size(LeafCount(7)).map(|op| op.0), Ok(12));
		assert_eq!(NodeIndex(11).right_for_group_size(LeafCount(8)).map(|op| op.0), Ok(13));
		assert_eq!(NodeIndex(15).right_for_group_size(LeafCount(9)).map(|op| op.0), Ok(16));
		assert_eq!(NodeIndex(15).right_for_group_size(LeafCount(10)).map(|op| op.0), Ok(17));
		assert_eq!(NodeIndex(15).right_for_group_size(LeafCount(11)).map(|op| op.0), Ok(19));
	}

	#[test]
	fn test_parent_for_group_size() {
		// TODO: test other cases
		assert_eq!(NodeIndex(0).parent_for_group_size(LeafCount(0)).err(), Some(Error::NoRootForEmptyTree));

		assert_eq!(NodeIndex(7).parent_for_group_size(LeafCount(8)).err(), Some(Error::RootCantHaveParent));

		assert_eq!(NodeIndex(7).parent_for_group_size(LeafCount(4)).err(), Some(Error::NodeOutOfRange { n: NodeIndex(7), r: NodeCount(7) }));

		assert_eq!(NodeIndex(0).parent_for_group_size(LeafCount(2)).map(|op| op.0), Ok(1));
		assert_eq!(NodeIndex(2).parent_for_group_size(LeafCount(2)).map(|op| op.0), Ok(1));
		assert_eq!(NodeIndex(4).parent_for_group_size(LeafCount(3)).map(|op| op.0), Ok(3));
		assert_eq!(NodeIndex(4).parent_for_group_size(LeafCount(4)).map(|op| op.0), Ok(5));
		assert_eq!(NodeIndex(8).parent_for_group_size(LeafCount(5)).map(|op| op.0), Ok(7));
		assert_eq!(NodeIndex(8).parent_for_group_size(LeafCount(6)).map(|op| op.0), Ok(9));
		assert_eq!(NodeIndex(9).parent_for_group_size(LeafCount(6)).map(|op| op.0), Ok(7));
		assert_eq!(NodeIndex(9).parent_for_group_size(LeafCount(7)).map(|op| op.0), Ok(11));
		assert_eq!(NodeIndex(12).parent_for_group_size(LeafCount(7)).map(|op| op.0), Ok(11));
		assert_eq!(NodeIndex(12).parent_for_group_size(LeafCount(8)).map(|op| op.0), Ok(13));
		assert_eq!(NodeIndex(16).parent_for_group_size(LeafCount(9)).map(|op| op.0), Ok(15));
		assert_eq!(NodeIndex(16).parent_for_group_size(LeafCount(10)).map(|op| op.0), Ok(17));
	}

	#[test]
	fn test_immediate_parent() {
		let solutions = vec![
			1, 3, 1, 7, 5, 3, 5, 15, 9, 11, 9, 7, 13, 11, 13, 31, 17, 19, 17, 23, 21,
		];

		solutions.into_iter().enumerate().for_each(|(idx, v)| {
			assert_eq!(NodeIndex(idx as u32).immediate_parent().0, v);
		});
	}

	#[test]
	fn test_sibling_for_group_size() {
		// TODO: test other cases

		assert_eq!(NodeIndex(0).sibling_for_group_size(LeafCount(2)).map(|op| op.0), Ok(2));
		assert_eq!(NodeIndex(2).sibling_for_group_size(LeafCount(2)).map(|op| op.0), Ok(0));
		assert_eq!(NodeIndex(4).sibling_for_group_size(LeafCount(3)).map(|op| op.0), Ok(1));
		assert_eq!(NodeIndex(1).sibling_for_group_size(LeafCount(3)).map(|op| op.0), Ok(4));
		assert_eq!(NodeIndex(4).sibling_for_group_size(LeafCount(4)).map(|op| op.0), Ok(6));
		assert_eq!(NodeIndex(6).sibling_for_group_size(LeafCount(4)).map(|op| op.0), Ok(4));
		assert_eq!(NodeIndex(3).sibling_for_group_size(LeafCount(5)).map(|op| op.0), Ok(8));
		assert_eq!(NodeIndex(8).sibling_for_group_size(LeafCount(5)).map(|op| op.0), Ok(3));
		assert_eq!(NodeIndex(8).sibling_for_group_size(LeafCount(6)).map(|op| op.0), Ok(10));
		assert_eq!(NodeIndex(10).sibling_for_group_size(LeafCount(6)).map(|op| op.0), Ok(8));
		assert_eq!(NodeIndex(16).sibling_for_group_size(LeafCount(9)).map(|op| op.0), Ok(7));
		assert_eq!(NodeIndex(7).sibling_for_group_size(LeafCount(9)).map(|op| op.0), Ok(16));
		assert_eq!(NodeIndex(17).sibling_for_group_size(LeafCount(10)).map(|op| op.0), Ok(7));
		assert_eq!(NodeIndex(19).sibling_for_group_size(LeafCount(13)).map(|op| op.0), Ok(24));
	}

	#[test]
	fn test_copath_for_group_size() {
		// TODO: test other cases

		let solutions = vec![
			(0, 2, vec![2]),
			(0, 4, vec![2, 5]),
			(0, 3, vec![2, 4]),
			(2, 2, vec![0]),
			(4, 3, vec![1]),
			(4, 4, vec![6, 1]),
			(6, 4, vec![4, 1]),
			(8, 5, vec![3]),
			(8, 6, vec![10, 3]),
			(16, 9, vec![7]),
			(16, 11, vec![18, 20, 7]),
		];

		solutions.into_iter().for_each(|(i, sz, v)| {
			assert_eq!(
				NodeIndex(i)
					.copath_for_group_size(LeafCount(sz))
					.unwrap()
					.into_iter()
					.map(|idx| idx.0)
					.collect::<Vec<u32>>(),
				v
			);
		});
	}

	#[test]
	fn test_dirpath_for_group_size() {
		// TODO: test other cases
		assert_eq!(NodeIndex(7).dirpath_for_group_size(LeafCount(8)).ok(), Some(vec![]));

		let solutions = vec![
			(0, 2, vec![1]),
			(2, 2, vec![1]),
			(4, 3, vec![3]),
			(4, 4, vec![5, 3]),
			(6, 4, vec![5, 3]),
			(8, 5, vec![7]),
			(8, 6, vec![9, 7]),
			(10, 6, vec![9, 7]),
			(10, 7, vec![9, 11, 7]),
			(12, 7, vec![11, 7]),
			(16, 9, vec![15]),
			(16, 10, vec![17, 15]),
			(20, 11, vec![19, 15]),
		];

		solutions.into_iter().for_each(|(i, sz, v)| {
			assert_eq!(
				NodeIndex(i)
					.dirpath_for_group_size(LeafCount(sz))
					.unwrap()
					.into_iter()
					.map(|idx| idx.0)
					.collect::<Vec<u32>>(),
				v
			);
		});
	}
}

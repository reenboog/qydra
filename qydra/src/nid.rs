pub type Cid = [u8; 8];

// basically, 9 bytes is enough to encode cid + device_id (u8 for device_id which gives 255 devices)
// do I actually need all this here? the protocol is not concerned with cids at all – just nids
#[derive(Hash, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Nid {
	id: Cid,  // eg 192FF6B2
	node: u8, // 1-255
}

impl Nid {
	pub fn new(id: &Cid, node: u8) -> Self {
		Self {
			id: id.to_owned(),
			node,
		}
	}

	pub fn as_bytes(&self) -> Vec<u8> {
		// TODO: replace with a CID-based implementation & respect case (in)sensitivity
		[self.id.as_slice(), &[self.node]].concat()
	}

	// is this the same account, but different device? CIDs currently are represented by strings, so case is to be respected
	pub fn is_same_id(&self, nid: &Nid) -> bool {
		self.id == nid.id
	}
}

impl TryFrom<Vec<u8>> for Nid {
	type Error = std::array::TryFromSliceError;

	// FIXME: not the same as instantiating from a string for `:` is not included

	fn try_from(val: Vec<u8>) -> Result<Self, Self::Error> {
		let slice: [u8; 9] = val.as_slice().try_into()?;

		Ok(Self {
			id: slice[..8].try_into()?,
			node: slice[8],
		})
	}
}

// returns nids with unique id, eg (0, 0), (0, 1), (1, 0), (2, 0), (2, 1) -> (0, 0), (1, 0), (2, 0)
pub fn filter_unique_by_ids(nids: &[Nid]) -> Vec<Nid> {
	nids.iter().fold(vec![], |mut acc, nid| {
		if !acc.iter().any(|x| x.is_same_id(&nid)) {
			acc.push(nid.clone());
		}
		acc
	})
}

#[cfg(test)]
mod tests {
	use crate::nid::{filter_unique_by_ids, Nid};

	#[test]
	fn test_unify_by_ids() {
		assert_eq!(
			filter_unique_by_ids(&vec![
				Nid::new(b"abcdefgh", 0),
				Nid::new(b"abcdefgh", 1),
				Nid::new(b"abcdefgh", 2),
				Nid::new(b"zxcvbnm,", 0),
				Nid::new(b"zxcvbnm,", 2),
				Nid::new(b"qwertyu,", 3),
			]),
			vec![
				Nid::new(b"abcdefgh", 0),
				Nid::new(b"zxcvbnm,", 0),
				Nid::new(b"qwertyu,", 3),
			]
		);
	}

	#[test]
	fn test_as_bytes() {
		assert_eq!(
			Nid::new(b"abcdefgh", 1).as_bytes(),
			b"\x61\x62\x63\x64\x65\x66\x67\x68\x01"
		);
	}

	#[test]
	fn test_try_from() {
		assert_eq!(
			Nid::new(b"abcdefgh", 1),
			Nid::try_from(b"\x61\x62\x63\x64\x65\x66\x67\x68\x01".to_vec()).unwrap()
		);
		assert!(Nid::try_from(b"abc".to_vec()).is_err());
	}
}

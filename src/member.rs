use crate::{hash::Hashable, key_package::KeyPackage, nid::Nid};

#[derive(Clone, PartialEq, Debug)]
pub struct Member {
	pub id: Nid,
	pub kp: KeyPackage,
}

impl Member {
	pub fn new(id: Nid, kp: KeyPackage) -> Self {
		Self { id, kp }
	}
}

impl Hashable for Member {
	fn hash(&self) -> crate::hash::Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest([self.id.as_bytes().as_slice(), self.kp.hash().as_slice()].concat()).into()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_from_member() {
		// TODO: implement
	}

	#[test]
	fn test_hash() {
		// TODO: implement
	}
}

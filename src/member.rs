use crate::{hash::Hashable, key_package::KeyPackage};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Id(pub [u8; Self::SIZE]);

impl Id {
	pub const SIZE: usize = 32;
}

impl Id {
	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

#[derive(Clone)]
pub struct Member {
	pub id: Id,
	pub kp: KeyPackage,
}

impl Member {
	pub fn new(id: Id, kp: KeyPackage) -> Self {
		Self { id, kp }
	}
}

impl Hashable for Member {
	fn hash(&self) -> crate::hash::Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest([self.id.0, self.kp.hash()].concat()).into()
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

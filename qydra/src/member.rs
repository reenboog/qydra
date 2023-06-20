use crate::{hash::Hashable, key_package::PublicKey, nid::Nid};

#[derive(Clone, PartialEq, Debug)]
pub struct Member {
	pub id: Nid,
	pub kp: PublicKey,
	pub joined_at_epoch: u64,
}

impl Member {
	pub fn new(id: Nid, kp: PublicKey, joined_at_epoch: u64) -> Self {
		Self {
			id,
			kp,
			joined_at_epoch,
		}
	}
}

impl Hashable for Member {
	fn hash(&self) -> crate::hash::Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest(
			[
				self.id.as_bytes().as_slice(),
				self.kp.hash().as_slice(),
				self.joined_at_epoch.to_be_bytes().as_slice(),
			]
			.concat(),
		)
		.into()
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

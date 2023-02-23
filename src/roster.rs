use std::collections::BTreeMap;

use crate::{
	hash::{Hash, Hashable},
	member::{Id, Member},
};

pub struct Roster {
	// order is important, hence BTreeMap instead of HashMap
	members: BTreeMap<Id, Member>,
}

impl Roster {
	pub fn new() -> Self {
		Self {
			members: BTreeMap::new(),
		}
	}

	pub fn add(&mut self, member: Member) {
		self.members.insert(member.id, member);
	}
}

impl From<Member> for Roster {
	fn from(member: Member) -> Self {
		let mut r = Roster::new();
		r.add(member);

		r
	}
}

impl Hashable for Roster {
	fn hash(&self) -> Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest(
			self.members
				.values()
				.map(|m| m.hash())
				.collect::<Vec<Hash>>()
				.concat(),
		)
		.into()
	}
}

#[cfg(test)]
mod tests {
	use super::Roster;
	use crate::{
		dilithium::{PublicKey, Signature},
		hash::Hashable,
		key_package::KeyPackage,
		member::{Id, Member},
	};

	#[test]
	fn test_hash() {
		let mut r1 = Roster::new();

		r1.add(Member::new(
			Id([12u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		r1.add(Member::new(
			Id([34u8; 32]),
			KeyPackage {
				ek: [56u8; 768],
				svk: PublicKey::new([78u8; 2592]),
				signature: Signature::new([90u8; 4595]),
			},
		));

		let mut r2 = Roster::new();

		r2.add(Member::new(
			Id([34u8; 32]),
			KeyPackage {
				ek: [56u8; 768],
				svk: PublicKey::new([78u8; 2592]),
				signature: Signature::new([90u8; 4595]),
			},
		));

		r2.add(Member::new(
			Id([12u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		// ensure sorting
		assert_eq!(r1.hash(), r2.hash());

		// and non-zeroes
		assert_ne!(r1.hash(), [0u8; 32]);
	}
}

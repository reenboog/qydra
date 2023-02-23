use std::collections::BTreeMap;

use crate::{
	hash::{Hash, Hashable},
	member::{Id, Member, self},
};

pub struct Roster {
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
	use crate::{key_package::KeyPackage, member::{Member, Id}, dilithium::{PublicKey, Signature}, hash::Hashable};
	use super::Roster;

	#[test]
	fn test_hash_non_zeroes() {
		//
		let mut r = Roster::new();

		r.add(Member::new(Id([12u8; 32]), KeyPackage { ek: [34u8; 768], svk: PublicKey::new([56u8; 2592]), signature: Signature::new([78u8; 4595]) }));
	}
}

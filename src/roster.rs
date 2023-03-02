use std::collections::BTreeMap;

use crate::{
	hash::{Hash, Hashable},
	key_package::KeyPackage,
	member::{Id, Member},
};

#[derive(Clone)]
pub struct Roster {
	// order is important, hence BTreeMap instead of HashMap
	members: BTreeMap<Id, Member>,
}

pub enum Error {
	AlreadyExists,
}

impl Roster {
	pub fn new() -> Self {
		Self {
			members: BTreeMap::new(),
		}
	}

	pub fn add(&mut self, member: Member) -> Result<(), Error> {
		self.members
			.insert(member.id, member)
			.map_or(Ok(()), |_| Err(Error::AlreadyExists))
	}

	pub fn contains(&self, id: &Id) -> bool {
		self.members.contains_key(id)
	}

	pub fn get(&self, id: &Id) -> Option<&Member> {
		self.members.get(id)
	}

	// sets kp for id and returns prev_kp, if any, or nil
	pub fn set(&mut self, id: &Id, kp: &KeyPackage) -> Option<Member> {
		self.members
			.insert(id.clone(), Member::new(id.clone(), kp.clone()))
	}

	pub fn ids(&self) -> Vec<Id> {
		self.members.keys().map(|k| *k).collect()
	}
}

impl From<Member> for Roster {
	fn from(member: Member) -> Self {
		let mut r = Roster::new();
		_ = r.add(member);

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
	fn test_add() {
		let mut roster = Roster::new();

		assert!(roster
			.add(Member::new(
				Id([12u8; 32]),
				KeyPackage {
					ek: [34u8; 768],
					svk: PublicKey::new([56u8; 2592]),
					signature: Signature::new([78u8; 4595]),
				},
			))
			.is_ok());

		assert!(roster
			.add(Member::new(
				Id([12u8; 32]),
				KeyPackage {
					ek: [56u8; 768],
					svk: PublicKey::new([78u8; 2592]),
					signature: Signature::new([90u8; 4595]),
				},
			))
			.is_err());
	}

	#[test]
	fn test_get() {
		//
	}

	#[test]
	fn test_set() {
		//
	}

	#[test]
	fn test_contains() {
		let mut roster = Roster::new();

		assert!(!roster.contains(&Id([12u8; 32])));

		_ = roster.add(Member::new(
			Id([12u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		assert!(roster.contains(&Id([12u8; 32])));
		assert!(!roster.contains(&Id([34u8; 32])));

		_ = roster.add(Member::new(
			Id([34u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		assert!(roster.contains(&Id([34u8; 32])));
		assert!(!roster.contains(&Id([45u8; 32])));
	}

	#[test]
	fn test_hash() {
		let mut r1 = Roster::new();

		// add two elements with keys 12 and 34 to r1
		_ = r1.add(Member::new(
			Id([12u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		_ = r1.add(Member::new(
			Id([34u8; 32]),
			KeyPackage {
				ek: [56u8; 768],
				svk: PublicKey::new([78u8; 2592]),
				signature: Signature::new([90u8; 4595]),
			},
		));

		let mut r2 = Roster::new();

		// add two elements with keys 23 and 12 to r2
		_ = r2.add(Member::new(
			Id([34u8; 32]),
			KeyPackage {
				ek: [56u8; 768],
				svk: PublicKey::new([78u8; 2592]),
				signature: Signature::new([90u8; 4595]),
			},
		));

		_ = r2.add(Member::new(
			Id([12u8; 32]),
			KeyPackage {
				ek: [34u8; 768],
				svk: PublicKey::new([56u8; 2592]),
				signature: Signature::new([78u8; 4595]),
			},
		));

		// ensure sorting is respected when hashing
		assert_eq!(r1.hash(), r2.hash());

		// and non-zeroes
		assert_ne!(r1.hash(), [0u8; 32]);
	}
}

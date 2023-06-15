use std::collections::BTreeMap;

use crate::{
	hash::{Hash, Hashable},
	key_package::KeyPackage,
	member::Member,
	nid::Nid,
};

#[derive(Clone, PartialEq, Debug)]
pub struct Roster {
	// order is important, hence BTreeMap instead of HashMap
	// TODO: make private
	pub(crate) members: BTreeMap<Nid, Member>,
}

#[derive(Debug)]
pub enum Error {
	AlreadyExists,
	DoesNotExist,
}

impl Roster {
	pub fn new() -> Self {
		Self {
			members: BTreeMap::new(),
		}
	}

	pub fn len(&self) -> u32 {
		self.members.len() as u32
	}

	// returns idx of a member with id = id
	pub fn idx(&self, id: Nid) -> Result<u32, Error> {
		Ok(self
			.ids()
			.iter()
			.enumerate()
			.find(|(_, i)| **i == id)
			.map(|(idx, _)| idx)
			.ok_or(Error::DoesNotExist)? as u32)
	}

	pub fn add(&mut self, member: Member) -> Result<(), Error> {
		self.members
			.insert(member.id, member)
			.map_or(Ok(()), |_| Err(Error::AlreadyExists))
	}

	pub fn remove(&mut self, id: &Nid) -> Result<(), Error> {
		self.members
			.remove(id)
			.map_or(Err(Error::DoesNotExist), |_| Ok(()))
	}

	pub fn contains(&self, id: &Nid) -> bool {
		self.members.contains_key(id)
	}

	pub fn get(&self, id: &Nid) -> Option<&Member> {
		self.members.get(id)
	}

	// sets kp for id and returns prev_kp, if any, or nil
	pub fn set_kp(&mut self, id: &Nid, kp: &KeyPackage) {
		self.members.entry(*id).and_modify(|m| {
			m.kp = kp.clone();
		});
	}

	pub fn ids(&self) -> Vec<Nid> {
		self.members.keys().map(|k| *k).collect()
	}

	pub fn verify_keys(&self) -> bool {
		self.members.values().all(|m| m.kp.verify())
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
		ed25519::{PublicKey, Signature, KeyPair},
		hash::Hashable,
		key_package::KeyPackage,
		member::Member,
		nid::Nid,
		x448,
	};

	#[test]
	fn test_from_member() {
		let r = Roster::from(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			0,
		));

		assert!(r.contains(&Nid::new(b"abcdefgh", 0)));
		assert!(!r.contains(&Nid::new(b"ijklmnop", 1)));
	}

	#[test]
	fn test_add() {
		let mut roster = Roster::new();

		assert!(roster
			.add(Member::new(
				Nid::new(b"abcdefgh", 0),
				KeyPackage {
					ilum_ek: [34u8; 768],
					x448_ek: x448::PublicKey::from(&[1u8; 56]),
					svk: PublicKey::new([56u8; KeyPair::PUB]),
					sig: Signature::new([78u8; Signature::SIZE]),
				},
				1
			))
			.is_ok());

		assert!(roster
			.add(Member::new(
				Nid::new(b"abcdefgh", 0),
				KeyPackage {
					ilum_ek: [56u8; 768],
					x448_ek: x448::PublicKey::from(&[1u8; 56]),
					svk: PublicKey::new([78u8; KeyPair::PUB]),
					sig: Signature::new([90u8; Signature::SIZE]),
				},
				0
			))
			.is_err());
	}

	#[test]
	fn test_remove() {
		let mut roster = Roster::from(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			22,
		));

		_ = roster.add(Member::new(
			Nid::new(b"ijklmnop", 0),
			KeyPackage {
				ilum_ek: [22u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([33u8; KeyPair::PUB]),
				sig: Signature::new([77u8; Signature::SIZE]),
			},
			0,
		));

		assert!(roster.remove(&Nid::new(b"abcdefgh", 0)).is_ok());
		assert!(roster.remove(&Nid::new(b"abcdefgh", 0)).is_err());
		assert!(roster.remove(&Nid::new(b"jjjjjjjj", 22)).is_err());
		assert!(roster.remove(&Nid::new(b"ijklmnop", 0)).is_ok());
		assert!(roster.remove(&Nid::new(b"ijklmnop", 0)).is_err());
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

		assert!(!roster.contains(&Nid::new(b"abcdefgh", 0)));

		_ = roster.add(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			0,
		));

		assert!(roster.contains(&Nid::new(b"abcdefgh", 0)));
		assert!(!roster.contains(&Nid::new(b"kkkkkkkk", 0)));

		_ = roster.add(Member::new(
			Nid::new(b"abcdwxyz", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			0,
		));

		assert!(roster.contains(&Nid::new(b"abcdwxyz", 0)));
		assert!(!roster.contains(&Nid::new(b"tttttttt", 10)));
	}

	#[test]
	fn test_hash() {
		let mut r1 = Roster::new();

		// add two elements with keys 12 and 34 to r1
		_ = r1.add(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			21,
		));

		_ = r1.add(Member::new(
			Nid::new(b"abcdwxyz", 0),
			KeyPackage {
				ilum_ek: [56u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([78u8; KeyPair::PUB]),
				sig: Signature::new([90u8; Signature::SIZE]),
			},
			1,
		));

		let mut r2 = Roster::new();

		// add two elements with keys 23 and 12 to r2
		_ = r2.add(Member::new(
			Nid::new(b"abcdwxyz", 0),
			KeyPackage {
				ilum_ek: [56u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([78u8; KeyPair::PUB]),
				sig: Signature::new([90u8; Signature::SIZE]),
			},
			1,
		));

		_ = r2.add(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			21,
		));

		// ensure sorting is respected when hashing
		assert_eq!(r1.hash(), r2.hash());

		// and non-zeroes
		assert_ne!(r1.hash(), [0u8; 32]);

		// same as r2, but some joined_at_epoch values are different, so should be the hashes
		let mut r3 = Roster::new();

		_ = r3.add(Member::new(
			Nid::new(b"abcdwxyz", 0),
			KeyPackage {
				ilum_ek: [56u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([78u8; KeyPair::PUB]),
				sig: Signature::new([90u8; Signature::SIZE]),
			},
			4,
		));

		_ = r3.add(Member::new(
			Nid::new(b"abcdefgh", 0),
			KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::PublicKey::from(&[1u8; 56]),
				svk: PublicKey::new([56u8; KeyPair::PUB]),
				sig: Signature::new([78u8; Signature::SIZE]),
			},
			1,
		));

		assert_ne!(r2.hash(), r3.hash());
	}
}

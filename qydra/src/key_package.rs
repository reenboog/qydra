use sha2::{Digest, Sha256};

use crate::{
	ed25519::{self, Signature},
	hash::Hashable,
	id::{Id, Identifiable},
	x448,
};

// no life time is specified; by default, such keys are non expiring
// no key scheme is specifid; a predefined set of keys is used instead

// a public keys package signed with a ecc (to be implemented)
#[derive(Clone, PartialEq, Debug)]
pub struct KeyPackage {
	pub ilum_ek: ilum::PublicKey,
	pub x448_ek: x448::PublicKey,
	pub svk: ed25519::PublicKey,
	pub sig: ed25519::Signature,
}

struct IdentityKey {
	// pub ed25519: ed448::PublicKey,
	// pub dilithium: dilithium::PublicKey,
}

// a KeyPackage signed with a static identity
// struct PreKey {
// 	kp: KeyPackage,
// 	// signs (kp.sig + kp.hash())
// 	sig: dilithium::Signature,
// }

// impl PreKey {
// 	// init keys are signed with an identity (never changes) dilithium key
// 	fn generate(ilum_seed: &ilum::Seed, identity_ssk: &dilithium::PrivateKey) -> Self {
// 		Self {
// 			kp: todo!(),
// 			sig: todo!(),
// 		}
// 	}
// }

impl KeyPackage {
	pub fn new(
		ilum_ek: &ilum::PublicKey,
		x448_ek: &x448::PublicKey,
		svk: &ed25519::PublicKey,
		ssk: &ed25519::PrivateKey,
	) -> Self {
		Self {
			ilum_ek: ilum_ek.clone(),
			x448_ek: x448_ek.clone(),
			svk: svk.clone(),
			sig: sign(ilum_ek, x448_ek, svk, ssk),
		}
	}
}

impl KeyPackage {
	pub fn verify(&self) -> bool {
		verify(&self.ilum_ek, &self.x448_ek, &self.svk, &self.sig)
	}
}

pub fn sign(
	ilum_ek: &ilum::PublicKey,
	x448_ek: &x448::PublicKey,
	svk: &ed25519::PublicKey,
	ssk: &ed25519::PrivateKey,
) -> Signature {
	let bytes = Sha256::digest(pack(ilum_ek, x448_ek, svk));

	ssk.sign(&bytes)
}

// private keys + public KeyPackage
pub struct KeyBundle {
	pub ilum_dk: ilum::SecretKey,
	pub ilum_ek: ilum::PublicKey,
	pub x448_dk: x448::PrivateKey,
	pub x448_ek: x448::PublicKey,
	pub ssk: ed25519::PrivateKey,
	pub svk: ed25519::PublicKey,
	pub sig: ed25519::Signature,
}

impl KeyBundle {
	pub fn generate(ilum_seed: &ilum::Seed) -> Self {
		let ssk = ed25519::KeyPair::generate();

		Self::generate_with_ssk(ilum_seed, ssk)
	}

	pub fn generate_with_ssk(ilum_seed: &ilum::Seed, ssk: ed25519::KeyPair) -> Self {
		let ilum = ilum::gen_keypair(ilum_seed);
		let x448 = x448::KeyPair::generate();
		let kp = KeyPackage::new(&ilum.pk, &x448.public, &ssk.public, &ssk.private);
		Self {
			ilum_dk: ilum.sk,
			ilum_ek: ilum.pk,
			x448_dk: x448.private,
			x448_ek: x448.public,
			ssk: ssk.private,
			svk: ssk.public,
			sig: kp.sig,
		}
	}
}

pub fn verify(
	ilum_ek: &ilum::PublicKey,
	x448_ek: &x448::PublicKey,
	svk: &ed25519::PublicKey,
	sig: &Signature,
) -> bool {
	let bytes = Sha256::digest(pack(ilum_ek, x448_ek, svk));

	svk.verify(&bytes, sig)
}

fn pack(ilum_ek: &ilum::PublicKey, x448_ek: &x448::PublicKey, svk: &ed25519::PublicKey) -> Vec<u8> {
	[ilum_ek.as_slice(), x448_ek.as_bytes(), svk.as_bytes()].concat()
}

impl Hashable for KeyPackage {
	fn hash(&self) -> crate::hash::Hash {
		Sha256::digest(
			[
				self.ilum_ek.as_slice(),
				self.x448_ek.as_bytes(),
				self.svk.as_bytes(),
				self.sig.as_bytes(),
			]
			.concat(),
		)
		.into()
	}
}

impl Identifiable for KeyPackage {
	fn id(&self) -> Id {
		Id(self.hash())
	}
}

#[cfg(test)]
mod tests {
	use super::KeyPackage;
	use crate::{
		ed25519::{self, Signature},
		hash::{Hash, Hashable},
		x448,
	};
	use ilum;
	use sha2::{Digest, Sha256};

	#[test]
	fn test_sign_verify() {
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let x448_kp = x448::KeyPair::generate();
		let s_kp = ed25519::KeyPair::generate();
		let pack = KeyPackage::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);

		// verifies, when constructed properly
		assert!(pack.verify());

		// and fails when it's not
		let mut forged_pack = pack;
		forged_pack.sig = Signature::new([1u8; Signature::SIZE]);

		assert!(!forged_pack.verify());
	}

	#[test]
	fn test_ensure_whole_content_is_hashed() {
		// this test ensures not only ilum is used for hashing KeyPackage
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let x448_kp = x448::KeyPair::generate();
		let s_kp = ed25519::KeyPair::generate();
		let pack = KeyPackage::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);
		let hash = pack.hash().to_vec();
		let target_hash: Hash = Sha256::digest(
			[
				pack.ilum_ek.as_slice(),
				pack.x448_ek.as_bytes(),
				pack.svk.as_bytes(),
				pack.sig.as_bytes(),
			]
			.concat(),
		)
		.into();

		assert_eq!(hash, target_hash);
	}
}

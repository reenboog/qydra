use sha2::{Digest, Sha256};

use crate::{
	ed25519::{self, Signature},
	hash::{self, Hashable},
	id::{Id, Identifiable},
	x448,
};

// no life time is specified; by default, such keys are non expiring
// no key scheme is specifid; a predefined set of keys is used instead

// a public key package signed with an ecc-svk; used by the protocol internally
#[derive(Clone, PartialEq, Debug)]
pub struct PublicKey {
	pub ilum: ilum::PublicKey,
	pub x448: x448::PublicKey,
	pub svk: ed25519::PublicKey,
	pub sig: ed25519::Signature,
}

#[derive(Clone, PartialEq, Debug)]
pub struct PrivateKey {
	pub ilum: ilum::SecretKey,
	pub x448: x448::PrivateKey,
	pub ssk: ed25519::PrivateKey,
}

impl PublicKey {
	pub fn new(
		ilum_ek: &ilum::PublicKey,
		x448_ek: &x448::PublicKey,
		svk: &ed25519::PublicKey,
		ssk: &ed25519::PrivateKey,
	) -> Self {
		Self {
			ilum: ilum_ek.clone(),
			x448: x448_ek.clone(),
			svk: svk.clone(),
			sig: sign(ilum_ek, x448_ek, svk, ssk),
		}
	}
}

impl PublicKey {
	pub fn verify(&self) -> bool {
		verify(&self.ilum, &self.x448, &self.svk, &self.sig)
	}
}

pub fn sign(
	ilum_ek: &ilum::PublicKey,
	x448_ek: &x448::PublicKey,
	svk: &ed25519::PublicKey,
	ssk: &ed25519::PrivateKey,
) -> Signature {
	let bytes = hpack(ilum_ek, x448_ek, svk);

	ssk.sign(&bytes)
}

#[derive(Clone, PartialEq, Debug)]
pub struct KeyPair {
	pub private: PrivateKey,
	pub public: PublicKey,
}

impl KeyPair {
	pub fn generate(ilum_seed: &ilum::Seed) -> Self {
		let ilum = ilum::gen_keypair(ilum_seed);
		let x448 = x448::KeyPair::generate();
		let ed25519 = ed25519::KeyPair::generate();
		let public = PublicKey::new(&ilum.pk, &x448.public, &ed25519.public, &ed25519.private);

		Self {
			private: PrivateKey {
				ilum: ilum.sk,
				x448: x448.private,
				ssk: ed25519.private,
			},
			public,
		}
	}
}

pub fn verify(
	ilum_ek: &ilum::PublicKey,
	x448_ek: &x448::PublicKey,
	svk: &ed25519::PublicKey,
	sig: &Signature,
) -> bool {
	let bytes = hpack(ilum_ek, x448_ek, svk);

	svk.verify(&bytes, sig)
}

// pack and hash
fn hpack(
	ilum_ek: &ilum::PublicKey,
	x448_ek: &x448::PublicKey,
	svk: &ed25519::PublicKey,
) -> Vec<u8> {
	Sha256::digest([ilum_ek.as_slice(), x448_ek.as_bytes(), svk.as_bytes()].concat()).to_vec()
}

impl Hashable for KeyPair {
	fn hash(&self) -> hash::Hash {
		self.public.hash()
	}
}

impl Hashable for PublicKey {
	fn hash(&self) -> hash::Hash {
		Sha256::digest(
			[
				self.ilum.as_slice(),
				self.x448.as_bytes(),
				self.svk.as_bytes(),
				self.sig.as_bytes(),
			]
			.concat(),
		)
		.into()
	}
}

impl Identifiable for KeyPair {
	fn id(&self) -> Id {
		self.public.id()
	}
}

impl Identifiable for PublicKey {
	fn id(&self) -> Id {
		Id(self.hash())
	}
}

#[cfg(test)]
mod tests {
	use super::PublicKey;
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
		let pack = PublicKey::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);

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
		let pack = PublicKey::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);
		let hash = pack.hash().to_vec();
		let target_hash: Hash = Sha256::digest(
			[
				pack.ilum.as_slice(),
				pack.x448.as_bytes(),
				pack.svk.as_bytes(),
				pack.sig.as_bytes(),
			]
			.concat(),
		)
		.into();

		assert_eq!(hash, target_hash);
	}
}

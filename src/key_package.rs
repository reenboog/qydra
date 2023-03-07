use sha2::{Digest, Sha256};

use crate::{
	dilithium::{self, Signature},
	hash::Hashable,
	member::Id,
};

#[derive(Clone)]
pub struct KeyPackage {
	// TODO: do I need to pack this with id as well?
	pub ek: ilum::PublicKey,
	pub svk: dilithium::PublicKey,
	pub signature: dilithium::Signature,
}

impl KeyPackage {
	pub fn new(
		ek: &ilum::PublicKey,
		svk: &dilithium::PublicKey,
		ssk: &dilithium::PrivateKey,
	) -> Self {
		Self {
			ek: ek.clone(),
			svk: svk.clone(),
			signature: sign(ek, svk, ssk),
		}
	}
}

impl KeyPackage {
	pub fn verify(&self) -> bool {
		verify(&self.ek, &self.svk, &self.signature)
	}
}

// TODO: add id as well
pub fn sign(
	ek: &ilum::PublicKey,
	svk: &dilithium::PublicKey,
	ssk: &dilithium::PrivateKey,
) -> Signature {
	// sign not the whole package, but its hash instead
	let bytes = Sha256::digest(pack(ek, svk));

	ssk.sign(&bytes)
}

// TODO: add id as well
pub fn verify(ek: &ilum::PublicKey, svk: &dilithium::PublicKey, sig: &Signature) -> bool {
	let bytes = Sha256::digest(pack(ek, svk));

	svk.verify(&bytes, sig)
}

// TODO: respect ecc keys as well, when introduced
fn pack(ek: &ilum::PublicKey, svk: &dilithium::PublicKey) -> Vec<u8> {
	[ek.as_slice(), svk.as_bytes()].concat()
}

impl Hashable for KeyPackage {
	fn hash(&self) -> crate::hash::Hash {
		// TODO: do I need user_id here?
		// TODO: respect ecc keys as well, when introduced
		Sha256::digest(
			[
				self.ek.as_slice(),
				self.svk.as_bytes(),
				self.signature.as_bytes(),
			]
			.concat(),
		)
		.into()
	}
}

impl KeyPackage {
	pub fn id(&self) -> Id {
		Id(self.hash())
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_hash() {
		//
	}

	#[test]
	fn test_sign_verify() {
		//
	}
}

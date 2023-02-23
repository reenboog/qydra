use crate::{dilithium, hash::Hashable};

#[derive(Clone)]
pub struct KeyPackage {
	pub ek: ilum::PublicKey,
	pub svk: dilithium::PublicKey,
	pub signature: dilithium::Signature,
}

impl Hashable for KeyPackage {
	fn hash(&self) -> crate::hash::Hash {
		use sha2::{Digest, Sha256};

		// TODO: do I need user_id here?
		Sha256::digest([&self.ek[..], self.svk.as_bytes(), self.signature.as_bytes()].concat())
			.into()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_hash() {
		//
	}
}

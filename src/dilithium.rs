use std::hash::Hash;

use pqcrypto_dilithium::ffi::{
	PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_BYTES, PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_PUBLICKEYBYTES,
};

// pub const PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 4864;

#[derive(Clone)]
pub struct PrivateKey {
	// TODO: either implement multilayering or import from bxolotl
}

#[derive(Clone)]
pub struct PublicKey {
	// TODO: implement
	bytes: [u8; Self::SIZE]
}

impl PublicKey {
	pub const SIZE: usize = PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_PUBLICKEYBYTES;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self {
			bytes,
		}
	}
}

impl PublicKey {
	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

pub struct KeyPair {
	private: PrivateKey,
	public: PublicKey,
}

impl KeyPair {
	pub fn generate() -> KeyPair {
		// TODO: inmplement
		todo!()
	}
}

#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
	bytes: [u8; Self::SIZE],
}

impl Signature {
	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

impl Signature {
	const SIZE: usize = PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_BYTES;

	// TODO: implement
	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self {
			bytes,
		}
	}
}

#[cfg(test)]
mod tests {
	use pqcrypto_dilithium::dilithium5aes::{detached_sign, keypair, verify_detached_signature};

	#[test]
	fn test_sign() {
		let key = keypair();

		let msg = b"hi there";
		let sig = detached_sign(msg, &key.1);

		assert!(verify_detached_signature(&sig, msg, &key.0).is_ok());
	}
}

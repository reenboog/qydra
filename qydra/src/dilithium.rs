use pqcrypto_dilithium::ffi::{
	PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_BYTES,
	PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_PUBLICKEYBYTES as PK_BYTES,
	PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_SECRETKEYBYTES as SK_BYTES,
};
use pqcrypto_traits::sign::DetachedSignature;

use crate::{private_key, public_key};

#[derive(Debug, PartialEq)]
pub struct KeyTypeDilithium;
pub type PrivateKey = private_key::PrivateKey<KeyTypeDilithium, SK_BYTES>;
pub type PublicKey = public_key::PublicKey<KeyTypeDilithium, PK_BYTES>;

impl PrivateKey {
	pub fn sign(&self, msg: &[u8]) -> Signature {
		use pqcrypto_dilithium::dilithium5aes::{self, detached_sign};
		use pqcrypto_traits::sign::SecretKey;

		let ssk = dilithium5aes::SecretKey::from_bytes(self.as_bytes()).unwrap();
		let sig = detached_sign(msg, &ssk);

		Signature::new(sig.as_bytes().to_owned().try_into().unwrap())
	}
}

impl PublicKey {
	pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
		use pqcrypto_dilithium::dilithium5aes::{self, verify_detached_signature};
		use pqcrypto_traits::sign::PublicKey;

		let psk = dilithium5aes::PublicKey::from_bytes(self.as_bytes()).unwrap();

		verify_detached_signature(
			&DetachedSignature::from_bytes(sig.as_bytes()).unwrap(),
			msg,
			&psk,
		)
		.is_ok()
	}
}

pub struct KeyPair {
	pub private: PrivateKey,
	pub public: PublicKey,
}

impl KeyPair {
	pub fn generate() -> KeyPair {
		use pqcrypto_dilithium::dilithium5aes::keypair;
		use pqcrypto_traits::sign::{PublicKey, SecretKey};

		let (pk, sk) = keypair();

		KeyPair {
			private: PrivateKey::new(sk.as_bytes().try_into().unwrap()),
			public: self::PublicKey::new(pk.as_bytes().try_into().unwrap()),
		}
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
	pub const SIZE: usize = PQCLEAN_DILITHIUM5AES_CLEAN_CRYPTO_BYTES;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self { bytes }
	}
}

#[cfg(test)]
mod tests {
	use crate::dilithium::KeyPair;

	#[test]
	fn test_sign_verify() {
		let msg = b"hi there";
		let kp = KeyPair::generate();

		let sig = kp.private.sign(msg);

		assert!(kp.public.verify(msg, &sig));
	}

	#[test]
	fn test_verification_fails_with_wrong_key() {
		let msg = b"hi there";
		let kp = KeyPair::generate();

		let sig = kp.private.sign(msg);

		assert!(!KeyPair::generate().public.verify(msg, &sig));
	}

	#[test]
	fn test_verification_fails_for_wrong_message() {
		let msg = b"hi there";
		let kp = KeyPair::generate();

		let sig = kp.private.sign(msg);

		assert!(!kp.public.verify(b"wrong message", &sig));
	}
}

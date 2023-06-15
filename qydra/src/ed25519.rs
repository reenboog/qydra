use crate::{private_key, public_key};

#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
	bytes: [u8; Self::SIZE],
}

impl Signature {
	pub const SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

impl TryFrom<Vec<u8>> for Signature {
	type Error = std::array::TryFromSliceError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		Ok(Self::new(value.as_slice().try_into()?))
	}
}

#[derive(Debug, PartialEq)]
pub struct KeyTypeEd25519;
pub type PrivateKey = private_key::PrivateKey<KeyTypeEd25519, { KeyPair::PRIV }>;
pub type PublicKey = public_key::PublicKey<KeyTypeEd25519, { KeyPair::PUB }>;

#[derive(Debug, PartialEq)]
pub struct KeyPair {
	pub private: PrivateKey,
	pub public: PublicKey,
}

impl KeyPair {
	pub const PRIV: usize = ed25519_dalek::SECRET_KEY_LENGTH;
	pub const PUB: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

	pub fn generate() -> Self {
		let private = PrivateKey::generate();
		let public = PublicKey::from_private(&private);

		Self { private, public }
	}
}

impl PrivateKey {
	pub fn generate() -> Self {
		let mut csprng = rand_07::thread_rng();
		let private = ed25519_dalek::SecretKey::generate(&mut csprng);

		private.as_bytes().into()
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		use ed25519_dalek::Signer;

		let secret = ed25519_dalek::SecretKey::from_bytes(self.as_bytes()).unwrap();
		let public = ed25519_dalek::PublicKey::from(&secret);
		let keypair = ed25519_dalek::Keypair { secret, public };
		let signature = keypair.sign(&msg);

		Signature::new(signature.into())
	}
}

impl From<&PrivateKey> for ed25519_dalek::SecretKey {
	fn from(key: &PrivateKey) -> Self {
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

impl PublicKey {
	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		use ed25519_dalek::Verifier;

		if let Ok(public) = ed25519_dalek::PublicKey::from_bytes(self.as_bytes()) {
			public
				.verify(
					msg,
					&ed25519_dalek::Signature::from_bytes(signature.as_bytes()).unwrap(),
				)
				.is_ok()
		} else {
			false
		}
	}

	pub fn from_private(key: &PrivateKey) -> Self {
		let private = ed25519_dalek::SecretKey::from(key);
		let public = ed25519_dalek::PublicKey::from(&private);

		Self::new(public.as_bytes().clone())
	}
}

#[cfg(test)]
mod tests {
	use super::{KeyPair, PrivateKey, PublicKey, Signature};

	#[test]
	fn test_from_private() {
		let pk = KeyPair::generate();
		let public = PublicKey::from_private(&pk.private);

		assert_eq!(pk.public, public);
	}

	#[test]
	fn test_rfc8032_vectors() {
		let public = b"\xfc\x51\xcd\x8e\x62\x18\xa1\xa3\x8d\xa4\x7e\xd0\x02\x30\xf0\x58\x08\x16\xed\x13\xba\x33\x03\xac\x5d\xeb\x91\x15\x48\x90\x80\x25";
		let msg = b"\xaf\x82";
		let signature = b"\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a";

		assert!(
			PublicKey::new(public.to_owned()).verify(msg, &Signature::new(signature.to_owned()))
		);
	}

	#[test]
	fn test_signature_as_bytes() {
		let private = b"\xc5\xaa\x8d\xf4\x3f\x9f\x83\x7b\xed\xb7\x44\x2f\x31\xdc\xb7\xb1\x66\xd3\x85\x35\x07\x6f\x09\x4b\x85\xce\x3a\x2e\x0b\x44\x58\xf7";
		let msg = b"\xaf\x82";
		let signature = b"\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a";

		assert_eq!(
			PrivateKey::new(private.to_owned()).sign(msg).as_bytes(),
			signature
		);
	}

	#[test]
	fn test_sign_verify() {
		let kp = KeyPair::generate();
		let msg = [22u8; 248];
		let sig = kp.private.sign(&msg);

		assert!(kp.public.verify(&msg, &sig));
	}

	#[test]
	fn test_verification_fails_with_wrong_key() {
		let kp1 = KeyPair::generate();
		let kp2 = KeyPair::generate();
		let msg = b"123456";
		let sig1 = kp1.private.sign(msg);
		let sig2 = kp2.private.sign(msg);

		assert!(kp1.public.verify(msg, &sig1));
		assert!(kp2.public.verify(msg, &sig2));
		assert!(!kp1.public.verify(msg, &sig2));
		assert!(!kp2.public.verify(msg, &sig1));
	}
}

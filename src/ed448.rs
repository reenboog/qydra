use crate::{private_key, public_key};

#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
	bytes: [u8; Self::SIZE],
}

impl Signature {
	const SIZE: usize = 114;

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
pub struct KeyTypeEd448;
pub type PrivateKey = private_key::PrivateKey<KeyTypeEd448, { KeyPair::PRIV }>;
pub type PublicKey = public_key::PublicKey<KeyTypeEd448, { KeyPair::PUB }>;

#[derive(Debug, PartialEq)]
pub struct KeyPair {
	pub private: PrivateKey,
	pub public: PublicKey,
}

impl KeyPair {
	pub const PRIV: usize = 57;
	pub const PUB: usize = 57;

	pub fn generate() -> Self {
		let private = PrivateKey::generate();
		let public = PublicKey::from_private(&private);

		Self { private, public }
	}
}

impl PrivateKey {
	pub fn generate() -> Self {
		use ed448_rust::PrivateKey;

		let mut csprng = rand::thread_rng();
		let private = PrivateKey::new(&mut csprng);

		private.as_bytes().into()
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		use ed448_rust::PrivateKey;

		let private = PrivateKey::from(self);
		let signature = private.sign(msg, None).unwrap();

		Signature::new(signature)
	}
}

impl From<&PrivateKey> for ed448_rust::PrivateKey {
	fn from(key: &PrivateKey) -> Self {
		Self::from(key.as_bytes())
	}
}

impl TryFrom<&PublicKey> for ed448_rust::PublicKey {
	type Error = ed448_rust::Ed448Error;

	fn try_from(key: &PublicKey) -> Result<ed448_rust::PublicKey, Self::Error> {
		Self::try_from(key.as_bytes())
	}
}

impl PublicKey {
	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		use ed448_rust::PublicKey;

		if let Ok(public) = PublicKey::try_from(self) {
			public.verify(msg, signature.as_bytes(), None).is_ok()
		} else {
			false
		}
	}

	pub fn from_private(key: &PrivateKey) -> Self {
		use ed448_rust::{PrivateKey, PublicKey};

		let private = PrivateKey::from(key);
		let public = PublicKey::from(&private);

		(&public.as_bytes()).into()
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
		let public = b"\xdc\xea\x9e\x78\xf3\x5a\x1b\xf3\x49\x9a\x83\x1b\x10\xb8\x6c\x90\xaa\xc0\x1c\xd8\x4b\x67\xa0\x10\x9b\x55\xa3\x6e\x93\x28\xb1\xe3\x65\xfc\xe1\x61\xd7\x1c\xe7\x13\x1a\x54\x3e\xa4\xcb\x5f\x7e\x9f\x1d\x8b\x00\x69\x64\x47\x00\x14\x00";
		let msg = b"\x0c\x3e\x54\x40\x74\xec\x63\xb0\x26\x5e\x0c";
		let signature = b"\x1f\x0a\x88\x88\xce\x25\xe8\xd4\x58\xa2\x11\x30\x87\x9b\x84\x0a\x90\x89\xd9\x99\xaa\xba\x03\x9e\xaf\x3e\x3a\xfa\x09\x0a\x09\xd3\x89\xdb\xa8\x2c\x4f\xf2\xae\x8a\xc5\xcd\xfb\x7c\x55\xe9\x4d\x5d\x96\x1a\x29\xfe\x01\x09\x94\x1e\x00\xb8\xdb\xde\xea\x6d\x3b\x05\x10\x68\xdf\x72\x54\xc0\xcd\xc1\x29\xcb\xe6\x2d\xb2\xdc\x95\x7d\xbb\x47\xb5\x1f\xd3\xf2\x13\xfb\x86\x98\xf0\x64\x77\x42\x50\xa5\x02\x89\x61\xc9\xbf\x8f\xfd\x97\x3f\xe5\xd5\xc2\x06\x49\x2b\x14\x0e\x00";

		assert!(
			PublicKey::new(public.to_owned()).verify(msg, &Signature::new(signature.to_owned()))
		);
	}

	#[test]
	fn test_signature_as_bytes() {
		let private = b"\xcd\x23\xd2\x4f\x71\x42\x74\xe7\x44\x34\x32\x37\xb9\x32\x90\xf5\x11\xf6\x42\x5f\x98\xe6\x44\x59\xff\x20\x3e\x89\x85\x08\x3f\xfd\xf6\x05\x00\x55\x3a\xbc\x0e\x05\xcd\x02\x18\x4b\xdb\x89\xc4\xcc\xd6\x7e\x18\x79\x51\x26\x7e\xb3\x28";
		let msg = b"\x0c\x3e\x54\x40\x74\xec\x63\xb0\x26\x5e\x0c";
		let signature = b"\x1f\x0a\x88\x88\xce\x25\xe8\xd4\x58\xa2\x11\x30\x87\x9b\x84\x0a\x90\x89\xd9\x99\xaa\xba\x03\x9e\xaf\x3e\x3a\xfa\x09\x0a\x09\xd3\x89\xdb\xa8\x2c\x4f\xf2\xae\x8a\xc5\xcd\xfb\x7c\x55\xe9\x4d\x5d\x96\x1a\x29\xfe\x01\x09\x94\x1e\x00\xb8\xdb\xde\xea\x6d\x3b\x05\x10\x68\xdf\x72\x54\xc0\xcd\xc1\x29\xcb\xe6\x2d\xb2\xdc\x95\x7d\xbb\x47\xb5\x1f\xd3\xf2\x13\xfb\x86\x98\xf0\x64\x77\x42\x50\xa5\x02\x89\x61\xc9\xbf\x8f\xfd\x97\x3f\xe5\xd5\xc2\x06\x49\x2b\x14\x0e\x00";

		assert_eq!(
			PrivateKey::new(private.to_owned()).sign(msg).as_bytes(),
			signature
		);
	}

	#[test]
	fn test_sign_verify() {
		let kp = KeyPair::generate();
		let msg = b"123456";
		let sig = kp.private.sign(msg);

		assert!(kp.public.verify(msg, &sig));
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

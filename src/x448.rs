use crate::{private_key, public_key};

#[derive(Debug, PartialEq)]
pub struct KeyTypeX448;

pub type PrivateKey = private_key::PrivateKey<KeyTypeX448, { KeyPair::PRIV }>;
pub type PublicKey = public_key::PublicKey<KeyTypeX448, { KeyPair::PUB }>;
pub type SharedKey = private_key::SharedKey<KeyTypeX448, { KeyPair::SHARED }>;

#[derive(Debug, PartialEq)]
pub struct KeyPair {
	pub private: PrivateKey,
	pub public: PublicKey,
}

impl PrivateKey {
	pub fn generate() -> Self {
		use x448::Secret;

		let mut csprng = rand_07::thread_rng();
		let secret = Secret::new(&mut csprng);

		secret.as_bytes().into()
	}
}

impl PublicKey {
	pub fn from_private(key: &PrivateKey) -> Self {
		use x448::{PublicKey, Secret};

		let secret = Secret::from(key);
		let public = PublicKey::from(&secret);

		public.as_bytes().into()
	}
}

// internal use only
impl From<&PrivateKey> for x448::Secret {
	fn from(key: &PrivateKey) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

// internal use only
impl From<&PublicKey> for x448::PublicKey {
	fn from(key: &PublicKey) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

impl KeyPair {
	pub const PRIV: usize = 56;
	pub const PUB: usize = 56;
	pub const SHARED: usize = 56;

	pub fn generate() -> Self {
		let private = PrivateKey::generate();
		let public = PublicKey::from_private(&private);

		Self { private, public }
	}
}

pub fn dh_exchange(private: &PrivateKey, public: &PublicKey) -> SharedKey {
	use x448::{PublicKey, Secret};

	let private = Secret::from(private);
	let public = PublicKey::from(public);
	let shared = private.as_diffie_hellman(&public).unwrap();

	SharedKey::new(*shared.as_bytes())
}

//
#[cfg(test)]
mod tests {
	use super::{dh_exchange, KeyPair, PrivateKey, PublicKey};

	#[test]
	fn test_dh_rfc7748_vectors() {
		let alice = b"\x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\x9a\xc2\xd8\xc0\xa5\x98\x72\x6b";
		let bob = b"\x3e\xb7\xa8\x29\xb0\xcd\x20\xf5\xbc\xfc\x0b\x59\x9b\x6f\xec\xcf\x6d\xa4\x62\x71\x07\xbd\xb0\xd4\xf3\x45\xb4\x30\x27\xd8\xb9\x72\xfc\x3e\x34\xfb\x42\x32\xa1\x3c\xa7\x06\xdc\xb5\x7a\xec\x3d\xae\x07\xbd\xc1\xc6\x7b\xf3\x36\x09";
		let shared_ref = b"\x07\xff\xf4\x18\x1a\xc6\xcc\x95\xec\x1c\x16\xa9\x4a\x0f\x74\xd1\x2d\xa2\x32\xce\x40\xa7\x75\x52\x28\x1d\x28\x2b\xb6\x0c\x0b\x56\xfd\x24\x64\xc3\x35\x54\x39\x36\x52\x1c\x24\x40\x30\x85\xd5\x9a\x44\x9a\x50\x37\x51\x4a\x87\x9d";

		let alice = PrivateKey::new(alice.to_owned());
		let bob = PublicKey::new(bob.to_owned());
		let shared = dh_exchange(&alice, &bob);

		assert_eq!(shared.as_bytes(), shared_ref);
	}

	#[test]
	fn test_public_from_private_rfc7748_vec() {
		let private = PrivateKey::new(b"\x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\x9a\xc2\xd8\xc0\xa5\x98\x72\x6b".to_owned());
		let public = PublicKey::from_private(&private);

		assert_eq!(public.as_bytes().to_owned(), b"\x9b\x08\xf7\xcc\x31\xb7\xe3\xe6\x7d\x22\xd5\xae\xa1\x21\x07\x4a\x27\x3b\xd2\xb8\x3d\xe0\x9c\x63\xfa\xa7\x3d\x2c\x22\xc5\xd9\xbb\xc8\x36\x64\x72\x41\xd9\x53\xd4\x0c\x5b\x12\xda\x88\x12\x0d\x53\x17\x7f\x80\xe5\x32\xc4\x1f\xa0".to_owned());
	}

	#[test]
	fn test_gen_private_not_zeroes() {
		let key = PrivateKey::generate();

		assert_ne!(key.as_bytes().to_owned(), [0u8; KeyPair::PRIV])
	}

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPair::generate();

		assert_ne!(kp.private.as_bytes().to_owned(), [0u8; KeyPair::PRIV]);
		assert_ne!(kp.public.as_bytes().to_owned(), [0u8; KeyPair::PUB]);
	}

	#[test]
	fn test_dh_exchange() {
		let alice_kp = KeyPair::generate();
		let bob_kp = KeyPair::generate();
		let dh_ab = dh_exchange(&alice_kp.private, &bob_kp.public);
		let dh_ba = dh_exchange(&bob_kp.private, &alice_kp.public);

		assert_ne!(dh_ab.as_bytes().to_owned(), [0u8; KeyPair::SHARED]);
		assert_eq!(dh_ab, dh_ba);
	}
}

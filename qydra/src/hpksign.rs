use crate::{dilithium, ed25519};
use sha2::{Digest, Sha256};

// represents a compound signing key: ecc + pq
#[derive(Clone, PartialEq, Debug)]
pub struct PublicKey {
	pub(crate) ed25519: ed25519::PublicKey,
	pub(crate) dilithium: dilithium::PublicKey,
}

#[derive(Clone, PartialEq, Debug)]
pub struct PrivateKey {
	pub(crate) ed25519: ed25519::PrivateKey,
	pub(crate) dilithium: dilithium::PrivateKey,
}

#[derive(Clone, PartialEq, Debug)]
pub struct KeyPair {
	pub(crate) private: PrivateKey,
	pub(crate) public: PublicKey,
}

impl KeyPair {
	pub fn generate() -> Self {
		let ed25519::KeyPair {
			private: ed_priv,
			public: ed_pub,
		} = ed25519::KeyPair::generate();
		let dilithium::KeyPair {
			private: dlth_priv,
			public: dlth_pub,
		} = dilithium::KeyPair::generate();

		Self {
			private: PrivateKey {
				ed25519: ed_priv,
				dilithium: dlth_priv,
			},
			public: PublicKey {
				ed25519: ed_pub,
				dilithium: dlth_pub,
			},
		}
	}
}

// a compound signature
#[derive(Clone, PartialEq, Debug)]
pub struct Signature {
	// 1 sign(msg) with ecc -> ecc_sig
	// 2 sign(msg + ecc_sig) with dilithium -> (ecc_sig, dilithium_sig)
	pub dilithium: dilithium::Signature,
	pub ed25519: ed25519::Signature,
}

impl PrivateKey {
	pub fn sign(&self, msg: &[u8]) -> Signature {
		let ed25519 = self.ed25519.sign(msg);
		let dilithium = self.dilithium.sign(&hpack(&ed25519, msg));

		Signature { dilithium, ed25519 }
	}
}

fn hpack(sig: &ed25519::Signature, msg: &[u8]) -> Vec<u8> {
	Sha256::digest([sig.as_bytes(), msg].concat()).to_vec()
}

impl PublicKey {
	pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
		self.ed25519.verify(msg, &sig.ed25519)
			&& self
				.dilithium
				.verify(&hpack(&sig.ed25519, msg), &sig.dilithium)
	}
}

#[cfg(test)]
mod tests {
	use super::KeyPair;

	#[test]
	fn test_sign_verify() {
		let kp = KeyPair::generate();
		let msg = b"So, how`s the party, Boris?";
		let sig = kp.private.sign(msg);

		assert!(kp.public.verify(msg, &sig));
	}
}

use crate::{
	hash::Hashable,
	hpksign,
	id::{self, Identifiable},
	key_package,
};

// basically a KeyPackage signed with user's static identity
#[derive(Clone, PartialEq, Debug)]
pub struct KeyPair {
	pub kp: key_package::KeyPair,
	pub sig: hpksign::Signature,
}

pub fn generate(ilum_seed: &ilum::Seed, identity: &hpksign::PrivateKey, num: u8) -> Vec<KeyPair> {
	(0..num)
		.map(|_| KeyPair::generate(ilum_seed, identity))
		.collect()
}

impl KeyPair {
	// init keys are signed with an identity (never changes) dilithium key
	pub fn generate(ilum_seed: &ilum::Seed, identity: &hpksign::PrivateKey) -> Self {
		let kp = key_package::KeyPair::generate(ilum_seed);
		let kp_hash = kp.hash();

		Self {
			kp,
			sig: identity.sign(&kp_hash),
		}
	}
}

impl Identifiable for KeyPair {
	fn id(&self) -> id::Id {
		self.kp.id()
	}
}

// fetched from the backend, double-signed with IdentityKeys – with both, ed25519 and dilithium
// TODO: distinguish FetchedPublicKey { kp, identity, sig } & PublicKeyToUpload { kp, sig }
#[derive(Clone, PartialEq, Debug)]
pub struct PublicKey {
	// the key package itself
	pub kp: key_package::PublicKey,
	// svk to verify kp
	pub identity: hpksign::PublicKey,
	pub sig: hpksign::Signature,
}

pub struct PrivateKey {
	pub kp: key_package::PrivateKey,
}

impl PublicKey {
	pub fn verify(&self) -> bool {
		self.identity.verify(&self.kp.hash(), &self.sig) && self.kp.verify()
	}
}

impl Identifiable for PublicKey {
	fn id(&self) -> id::Id {
		self.kp.id()
	}
}

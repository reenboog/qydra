use crate::{aes_gcm, hash::Hashable, key_package::KeyPackage, member::Id};

#[derive(Clone)]
pub struct PendingCommit {
	// TODO: implement
}

pub struct Commit {
	// committer new key package
	pub kp: KeyPackage,
	// key-independent encapsulation
	pub cti: ilum::Cti,
	// aes iv
	pub iv: aes_gcm::Iv,
	// aes ciphertext, raw bytes
	pub sym_ct: Vec<u8>,
	// proposal ids
	pub prop_ids: Vec<Id>,
}

impl Hashable for Commit {
	fn hash(&self) -> crate::hash::Hash {
		todo!()
	}
}

// I already have types for Cti & Ctd, but sym enc is now required (Cti)
pub struct FramedCommit {
	//
}

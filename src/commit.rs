use crate::{
	aes_gcm, group::Group, hash::Hashable, key_package::KeyPackage, member::Id,
	proposal::FramedProposal,
};

#[derive(Clone)]
pub struct PendingCommit {
	// the new state
	pub state: Group,
	// ids of framed proposals to ensure no proposals have been received since the commit was sent to the backend
	pub proposals: Vec<Id>,
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
	// 1 : return (G.groupid, G.epoch, G.id, ‘commit’,𝐶0, sig, confTag)
}

impl FramedCommit {
	pub fn id(&self) -> Id {
		todo!()
		// return string(hashPack(
		// 	pad,
		// 	FramedCommitKeyHashId,
		// 	fc.GroupId,
		// 	packUint(fc.Epoch),
		// 	fc.InterimTransHash,
		// 	[]byte(fc.Id),
		// 	fc.C0.Pack(pad),
		// 	fc.Sig,
		// 	fc.ConfTag,
		// ))
	}	
}

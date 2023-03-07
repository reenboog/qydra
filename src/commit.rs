use crate::{group::Group, hash::Hashable, hpkencrypt, key_package::KeyPackage, member::Id};
use sha2::{Digest, Sha256};

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
	// key-independent, compound (multi-layered) encapsulation
	pub cti: hpkencrypt::CmpdCti,
	// proposal ids; order is important, so should be pre-sorted/validated
	pub prop_ids: Vec<Id>,
}

impl Hashable for Commit {
	fn hash(&self) -> crate::hash::Hash {
		Sha256::digest(
			[
				self.kp.hash().as_slice(),
				&self.cti.hash(),
				&self
					.prop_ids
					.iter()
					.map(|id| id.0)
					.collect::<Vec<[u8; Id::SIZE]>>()
					.concat(),
			]
			.concat(),
		)
		.into()
	}
}

// I already have types for Cti & Ctd, but sym enc is now required (Cti)
pub struct FramedCommit {
	//
	// 1 : return (G.groupid, G.epoch, G.id, ‘commit’,𝐶0, sig, confTag)
}

impl FramedCommit {
	pub fn id(&self) -> Id {
		// simply hash myself?
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

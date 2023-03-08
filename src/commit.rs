use crate::{
	dilithium::Signature,
	group::Group,
	hash::{Hash, Hashable},
	hmac, hpkencrypt,
	key_package::KeyPackage,
	member::Id,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct PendingCommit {
	// the new state
	pub state: Group,
	// ids of framed proposals to ensure no proposals have been received since the commit was sent to the backend
	pub proposals: Vec<Id>,
}

#[derive(Clone)]
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
	pub guid: Hash,
	pub epoch: u64,
	pub sender: Id,
	pub commit: Commit,
	pub sig: Signature,
	pub conf_tag: hmac::Digest,
}

impl FramedCommit {
	pub fn new(
		guid: Hash,
		epoch: u64,
		sender: Id,
		commit: Commit,
		sig: Signature,
		conf_tag: hmac::Digest,
	) -> Self {
		Self {
			guid,
			epoch,
			sender,
			commit,
			sig,
			conf_tag,
		}
	}

	pub fn id(&self) -> Id {
		Id(Sha256::digest(
			[
				self.guid.as_slice(),
				&self.epoch.to_be_bytes(),
				self.sender.as_bytes(),
				&self.commit.hash(),
				self.sig.as_bytes(),
				self.conf_tag.as_bytes(),
			]
			.concat(),
		)
		.into())
	}
}

use crate::{
	dilithium::Signature,
	group::Group,
	hash::Hashable,
	hmac, hpkencrypt,
	id::{Id, Identifiable},
	key_package::KeyPackage,
	nid::Nid,
};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Debug)]
pub struct PendingCommit {
	// the new state
	pub state: Group,
	// ids of framed proposals to ensure no proposals have been received since the commit was sent to the backend
	pub proposals: Vec<Id>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Commit {
	// committer new key package
	pub kp: KeyPackage,
	// key-independent, compound (multi-layered) encapsulation
	pub cti: hpkencrypt::CmpdCti,
	// proposal ids; order is important, so should be pre-sorted/validated
	pub prop_ids: Vec<Id>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommitCtd {
	pub user_id: Nid,
	// ctd can be nil in case user_id is removed
	pub ctd: Option<hpkencrypt::CmpdCtd>,
}

impl CommitCtd {
	pub fn new(user_id: Nid, ctd: Option<hpkencrypt::CmpdCtd>) -> Self {
		Self { user_id, ctd }
	}
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
#[derive(Debug, PartialEq, Clone)]
pub struct FramedCommit {
	pub guid: Id,
	pub epoch: u64,
	pub sender: Nid,
	pub commit: Commit,
	pub sig: Signature, // do I need this? I could verify the encrypted content instead
	// TODO: how about mac?
	pub conf_tag: hmac::Digest,
}

impl FramedCommit {
	pub fn new(
		guid: Id,
		epoch: u64,
		sender: Nid,
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
}

impl Identifiable for FramedCommit {
	fn id(&self) -> Id {
		Id(Sha256::digest(
			[
				self.guid.as_bytes().as_slice(),
				&self.epoch.to_be_bytes(),
				self.sender.as_bytes().as_slice(),
				&self.commit.hash(),
				self.sig.as_bytes(),
				self.conf_tag.as_bytes(),
			]
			.concat(),
		)
		.into())
	}
}

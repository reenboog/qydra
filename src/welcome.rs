use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac, hpkencrypt,
	id::Id,
	key_schedule::JoinerSecret,
	nid::Nid,
	roster::Roster,
};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Debug)]
pub struct WlcmCti {
	pub cti: hpkencrypt::CmpdCti,
	pub sig: Signature,
}

impl WlcmCti {
	pub fn new(cti: hpkencrypt::CmpdCti, sig: Signature) -> Self {
		Self { cti, sig }
	}
}

#[derive(Clone, PartialEq, Debug)]
pub struct WlcmCtd {
	pub user_id: Nid,
	pub key_id: Id,
	pub ctd: hpkencrypt::CmpdCtd,
}

impl WlcmCtd {
	pub fn new(user_id: Nid, key_id: Id, ctd: hpkencrypt::CmpdCtd) -> Self {
		Self {
			user_id,
			key_id,
			ctd,
		}
	}
}

// sent to each invitee hpke-encrypted
#[derive(Clone)]
pub struct Info {
	pub guid: Id,
	pub epoch: u64,
	pub roster: Roster,
	pub conf_trans_hash: Hash,
	pub conf_tag: hmac::Digest,
	pub inviter: Nid,
	pub joiner: JoinerSecret,
}

impl Info {
	pub fn new(
		guid: Id,
		epoch: u64,
		roster: Roster,
		conf_trans_hash: Hash,
		conf_tag: hmac::Digest,
		inviter: Nid,
		joiner: JoinerSecret,
	) -> Self {
		Self {
			guid,
			epoch,
			roster,
			conf_trans_hash,
			conf_tag,
			inviter,
			joiner,
		}
	}
}

impl Hashable for Info {
	fn hash(&self) -> Hash {
		Sha256::digest(
			[
				self.guid.as_bytes().as_slice(),
				&self.epoch.to_be_bytes(),
				&self.roster.hash(),
				&self.conf_trans_hash,
				self.conf_tag.as_bytes(),
				self.inviter.as_bytes().as_slice(),
				&self.joiner,
			]
			.concat(),
		)
		.into()
	}
}

use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac, hpkencrypt,
	id::Id,
	key_schedule::JoinerSecret,
	roster::Roster,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct WlcmCti {
	pub cti: hpkencrypt::CmpdCti,
	pub sig: Signature,
}

impl WlcmCti {
	pub fn new(cti: hpkencrypt::CmpdCti, sig: Signature) -> Self {
		Self { cti, sig }
	}
}

#[derive(Clone)]
pub struct WlcmCtd {
	pub user_id: Id,
	pub key_id: Id,
	pub ctd: hpkencrypt::CmpdCtd,
}

impl WlcmCtd {
	pub fn new(user_id: Id, key_id: Id, ctd: hpkencrypt::CmpdCtd) -> Self {
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
	pub guid: Hash,
	pub epoch: u64,
	pub roster: Roster,
	pub conf_trans_hash: Hash,
	pub conf_tag: hmac::Digest,
	pub inviter: Id,
	pub joiner: JoinerSecret,
}

impl Info {
	pub fn new(
		guid: Hash,
		epoch: u64,
		roster: Roster,
		conf_trans_hash: Hash,
		conf_tag: hmac::Digest,
		inviter: Id,
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
				self.guid.as_slice(),
				&self.epoch.to_be_bytes(),
				&self.roster.hash(),
				&self.conf_trans_hash,
				self.conf_tag.as_bytes(),
				self.inviter.as_bytes(),
				&self.joiner,
			]
			.concat(),
		)
		.into()
	}
}

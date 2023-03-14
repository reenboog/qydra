use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac, hpkencrypt,
	id::Id,
	roster::Roster,
};
use ilum::Ctd;
use sha2::{Digest, Sha256};

pub struct WlcmCti {
	pub info: Info,
	pub cti: hpkencrypt::CmpdCti,
	pub sig: Signature,
}

impl WlcmCti {
	pub fn new(info: Info, cti: hpkencrypt::CmpdCti, sig: Signature) -> Self {
		Self { info, cti, sig }
	}
}

pub struct WlcmCtd {
	pub user_id: Id,
	pub key_id: Id,
	pub ctd: Ctd,
}

impl WlcmCtd {
	pub fn new(user_id: Id, key_id: Id, ctd: Ctd) -> Self {
		Self {
			user_id,
			key_id,
			ctd,
		}
	}
}

pub struct Info {
	pub guid: Hash,
	pub epoch: u64,
	pub roster: Roster,
	pub conf_trans_hash: Hash,
	pub conf_tag: hmac::Digest,
	pub inviter: Id,
}

impl Info {
	pub fn new(
		guid: Hash,
		epoch: u64,
		roster: Roster,
		conf_trans_hash: Hash,
		conf_tag: hmac::Digest,
		inviter: Id,
	) -> Self {
		Self {
			guid,
			epoch,
			roster,
			conf_trans_hash,
			conf_tag,
			inviter,
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
			]
			.concat(),
		)
		.into()
	}
}

// should be encrypted with the recipient's public key at least
// type WelcomeMessageI struct {
// 	GroupInfo *GroupInfo
// 	T         []byte
// 	Sig       []byte
// }

// type WelcomeMessageD struct {
// 	KpHash []byte
// 	Ctd    []byte
// }

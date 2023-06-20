use crate::{
	ed25519,
	hash::{Hash, Hashable},
	hmac, hpkencrypt, hpksign,
	id::{Id, Identifiable},
	key_schedule::JoinerSecret,
	nid::Nid,
	roster::Roster,
};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Debug)]
pub struct WlcmCti {
	pub cti: hpkencrypt::CmpdCti,
	// Info.hash() signed with the inviter's current ed25519 ssk
	pub roster_sig: ed25519::Signature,
	// hash(Info.hash() + ed25519_sig) signed with the inviter's identity keys
	pub identity_sig: hpksign::Signature,
}

impl WlcmCti {
	pub fn new(
		cti: hpkencrypt::CmpdCti,
		roster_sig: ed25519::Signature,
		identity_sig: hpksign::Signature,
	) -> Self {
		Self {
			cti,
			roster_sig,
			identity_sig,
		}
	}
}

impl Identifiable for WlcmCti {
	fn id(&self) -> Id {
		// unique content + unique ssk = unique ids
		Id(Sha256::digest(self.roster_sig.as_bytes()).into())
	}
}

#[derive(Clone, PartialEq, Debug)]
pub struct WlcmCtd {
	pub user_id: Nid,
	pub kp_id: Id,
	pub ctd: hpkencrypt::CmpdCtd,
}

impl WlcmCtd {
	pub fn new(user_id: Nid, kp_id: Id, ctd: hpkencrypt::CmpdCtd) -> Self {
		Self {
			user_id,
			kp_id,
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
	pub description: Vec<u8>,
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
		description: Vec<u8>,
	) -> Self {
		Self {
			guid,
			epoch,
			roster,
			conf_trans_hash,
			conf_tag,
			inviter,
			joiner,
			description,
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
				&self.description,
			]
			.concat(),
		)
		.into()
	}
}

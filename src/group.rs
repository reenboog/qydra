use std::collections::HashMap;

use ilum::*;
use rand::Rng;

use crate::commit::PendingCommit;
use crate::{dilithium, key_schedule};
use crate::hash::{self, Hash, Hashable};
use crate::hmac::Digest;
use crate::key_package::KeyPackage;
use crate::key_schedule::EpochSecrets;
use crate::member::{Id, Member};
use crate::roster::Roster;
use crate::update::PendingUpdate;

// group state
struct Group {
	uid: [u8; 32], // TODO: introduce a type?
	epoch: u64,

	// WARNING: seed should be public and shared among all participating keys; mPKE won't work otherwise
	seed: ilum::Seed,

	conf_trans_hash: Hash,
	conf_trans_hash_without_committer: Hash,
	interim_trans_hash: Hash,

	// roster: HashMap<Id, Member>,
	// roster_hash: Hash,
	roster: Roster,

	// TODO: HashMap<Id, vert_svks>?
	pending_updates: HashMap<Id, PendingUpdate>,
	pending_commits: HashMap<Id, PendingCommit>,

	// FIXME: introduce a struct similar to Owner
	// my id
	user_id: Id,
	// my decryption key
	dk: ilum::SecretKey,
	// my signature verificatin key
	ssk: dilithium::PrivateKey,

	// FIXME: replace with a type?
	init_secret: Hash,   // TODO: should it be of fixed size? Should it be Digest?
	app_secret: Hash,    // TODO: should it be of fixed size? Should it be Digest?
	member_secret: Hash, // TODO: should it be of fixed size? Should it be Digest?
}

// a similar structure should be used for `me` in `Group`
#[derive(Clone)]
pub struct Owner {
	id: Id,
	kp: KeyPackage,
	dk: ilum::SecretKey,
	ssk: dilithium::PrivateKey,
}

impl Group {
	// generates a group owned by owner; recipients should use a different initializer! NOTE:
	pub fn create(seed: Seed, owner: Owner) -> Self {
		let roster = Roster::from(Member::new(owner.id, owner.kp));
		let uid = rand::thread_rng().gen();
		let epoch = 0;
		let joiner_secret = rand::thread_rng().gen();

		let group = Self {
			uid,
			epoch,
			seed,

			conf_trans_hash: hash::empty(),
			conf_trans_hash_without_committer: hash::empty(),
			interim_trans_hash: hash::empty(),

			roster,
			// roster_hash: hash::empty(),
			pending_updates: HashMap::new(),
			pending_commits: HashMap::new(),

			user_id: owner.id,

			dk: owner.dk,
			ssk: owner.ssk,

			init_secret: rand::thread_rng().gen(), // todo: can it be a random digest?
			app_secret: rand::thread_rng().gen(),  // todo: can it be a random digest?
			member_secret: rand::thread_rng().gen(),
		};

		// ctx = hash(uid, epoch=0, roster=[me].hash())
		let secrets = key_schedule::derive_epoch_secrets(group.ctx(), joiner_secret);
		// let conf_tag = hmac(conf_trans_hash=[0u8; 32], conf_key);
		// interim_trans_hash = hash(conf_trans_hash=[0u8; 32], conf_tag);

		group
	}

	// group/epoch_header?
	fn ctx(&self) -> Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest(
			[
				&self.uid[..],
				&self.epoch.to_be_bytes(),
				&self.roster.hash(),
			]
			.concat(),
		)
		.into()
	}

	fn ctx_w_interim(&self) -> Hash {
		use sha2::{Digest, Sha256};

		Sha256::digest(
			[
				&self.uid[..],
				&self.epoch.to_be_bytes(),
				&self.roster.hash(),
				&self.interim_trans_hash,
			]
			.concat(),
		)
		.into()
	}
}

// func (gs *GroupState) GroupCont() []byte {
// }

// func (gs *GroupState) GroupContWInterim() []byte {
// 	// DRYing of GroupCont?
// 	return pack(
// 		gs.GroupId,
// 		packUint(gs.Epoch),
// 		gs.MemberHash,
// 		gs.ConfTransHash,
// 		// this field is the only added
// 		gs.InterimTransHash,
// 	)
// }

// TODO: this should replace rooster and rooster_hash
// struct Roster {
// 	members: BTreeMap<Id, Member>,
// 	hash: Hash
// }

#[cfg(test)]
mod tests {
	#[test]
	fn test_create_group() {
		// TODO: create a group and check its initial fields
	}
}

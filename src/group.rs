use std::collections::HashMap;

use ilum::*;
use rand::Rng;

use crate::commit::PendingCommit;
use crate::hash::{self, Hash, Hashable};
use crate::key_package::{self, KeyPackage};
use crate::key_schedule::EpochSecrets;
use crate::member::{Id, Member};
use crate::proposal::{FramedProposal, Proposal};
use crate::roster::Roster;
use crate::update::PendingUpdate;
use crate::{dilithium, hmac, key_schedule};
use sha2::{Digest, Sha256};

// group state
pub struct Group {
	uid: Hash, // TODO: introduce a type?
	epoch: u64,

	// WARNING: seed should be public and shared among all participating keys; mPKE won't work otherwise
	seed: ilum::Seed,

	conf_trans_hash: Hash,
	conf_trans_hash_without_committer: Hash,
	interim_trans_hash: Hash,

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

	secrets: EpochSecrets,
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
	// generates a group owned by owner; recipients should use a different initializer!
	pub fn create(seed: Seed, owner: Owner) -> Self {
		let roster = Roster::from(Member::new(owner.id, owner.kp));
		let uid = rand::thread_rng().gen::<Hash>();
		let epoch = 0;
		let joiner_secret = rand::thread_rng().gen();
		let conf_trans_hash = hash::empty();
		let ctx = Self::derive_ctx(&uid, epoch, &roster, &conf_trans_hash, &[]);
		let (secrets, conf_key) = key_schedule::derive_epoch_secrets(ctx, joiner_secret);
		let conf_tag = hmac::digest(&hmac::Key::from(&conf_key), &conf_trans_hash);
		let interim_trans_hash = Self::interim_trans_hash(&conf_trans_hash, conf_tag.as_bytes());

		Self {
			uid,
			epoch,
			seed,

			// ledger?
			conf_trans_hash,
			conf_trans_hash_without_committer: conf_trans_hash.clone(),
			interim_trans_hash,

			roster,

			pending_updates: HashMap::new(),
			pending_commits: HashMap::new(),

			user_id: owner.id,

			dk: owner.dk, // TODO: introduce ecc keys as well
			ssk: owner.ssk,

			secrets,
		}
	}

	// group/epoch_header?
	fn ctx(&self) -> Hash {
		Self::derive_ctx(
			&self.uid,
			self.epoch,
			&self.roster,
			&self.conf_trans_hash,
			&[],
		)
	}

	// TODO: this KeyPackage should be verified by a higher layer while here, we're making a TOFU assumption
	pub fn propose_add(&self, id: Id, kp: KeyPackage) -> FramedProposal {
		// FIXME: use a result instead
		assert!(!self.roster.contains(&id));

		self.frame_proposal(Proposal::Add { id, kp })
	}

	// TODO: use Result instead
	pub fn propose_remove(&self, id: &Id) -> FramedProposal {
		// FIXME: use a result instead
		assert!(self.roster.contains(id));

		self.frame_proposal(Proposal::Remove { id: id.clone() })
	}

	pub fn propose_update(&mut self) -> FramedProposal {
		let (kp, sk) = self.gen_kp();
		let fp = self.frame_proposal(Proposal::Update { kp });
		let pu = PendingUpdate::new(sk, self.ssk.clone()); // TODO: make update ssk as well

		self.pending_updates.insert(fp.id(), pu);

		fp
	}

	fn frame_proposal(&self, proposal: Proposal) -> FramedProposal {
		// sig = sign(proposal)
		// tag = mac(proposal + sig)
		todo!()
		// TODO: apply current epoch and other state
	}

	fn gen_kp(&self) -> (KeyPackage, ilum::SecretKey) {
		// TODO: update signing key as well

		let kp = ilum::gen_keypair(&self.seed);
		let package = KeyPackage::new(
			&kp.pk,
			&self.roster.get(&self.user_id).unwrap().kp.svk, // TODO: do not hard unwrap
			&self.ssk,
		);

		(package, kp.sk)
	}

	// used for signing commits and proposals when packing only; do I need it at all?
	// fn ctx_w_interim(&self) -> Hash {
	// 	Self::derive_ctx(
	// 		&self.uid,
	// 		self.epoch,
	// 		&self.roster,
	// 		&self.conf_trans_hash,
	// 		&self.interim_trans_hash,
	// 	)
	// }

	fn verify_kp(id: &Id, kp: &KeyPackage) {
		// id == pk.id
		// if I don't have kp in my certs
		// send a VERIFY req to the backend: // almost TOFU
		// 	 if ok, add this pk to my certs
		// verify signature
	}
}

impl Group {
	// TODO: move somewhere else; introduce dedicated types for hashes
	fn interim_trans_hash(conf_trans_hash: &Hash, conf_tag: &Hash) -> Hash {
		Sha256::digest([conf_trans_hash.as_slice(), conf_tag].concat()).into()
	}

	fn derive_ctx(
		uid: &[u8],
		epoch: u64,
		roster: &Roster,
		conf_trans_hash: &[u8],
		interim_trans_hash: &[u8],
	) -> Hash {
		Sha256::digest(
			[
				uid,
				epoch.to_be_bytes().as_slice(),
				&roster.hash(),
				conf_trans_hash,
				interim_trans_hash,
			]
			.concat(),
		)
		.into()
	}
}

#[cfg(test)]
mod tests {

	#[test]
	fn test_create_group() {
		// TODO: implement
	}
}

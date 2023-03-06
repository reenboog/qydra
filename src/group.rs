use std::collections::HashMap;

use ilum::*;
use rand::Rng;

use crate::commit::{Commit, FramedCommit, PendingCommit};
use crate::dilithium::Signature;
use crate::hash::{self, Hash, Hashable};
use crate::key_package::KeyPackage;
use crate::key_schedule::{CommitSecret, ConfirmationSecret, EpochSecrets, JoinerSecret, MacSecret};
use crate::member::{Id, Member};
use crate::proposal::{self, FramedProposal, Proposal};
use crate::roster::Roster;
use crate::update::PendingUpdate;
use crate::welcome::{WelcomeD, WelcomeI};
use crate::{dilithium, hmac, hpkencrypt, key_schedule};
use sha2::{Digest, Sha256};

pub enum Error {
	WrongGroup,
	WrongEpoch,
	UnknownSender,
	InvalidSignature,
	InvalidMac,
}

// group state
#[derive(Clone)]
pub struct Group {
	uid: Hash, // TODO: introduce a type?
	epoch: u64,

	// WARNING: seed should be public and shared among all participating keys; mPKE won't work otherwise
	seed: ilum::Seed,

	conf_trans_hash: Hash,
	interim_trans_hash: Hash, // trans_tag could be stored instead to derive interim_hash on the fly

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
		let ctx = Self::derive_ctx(&uid, epoch, &roster, &conf_trans_hash);
		let (secrets, conf_key) = key_schedule::derive_epoch_secrets(ctx, &joiner_secret);
		let conf_tag = Self::conf_tag(&conf_key, &conf_trans_hash);
		let interim_trans_hash = Self::interim_trans_hash(&conf_trans_hash, conf_tag.as_bytes());

		Self {
			uid,
			epoch,
			seed,

			// ledger?
			conf_trans_hash,
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

	fn next(&self) -> Group {
		let mut new_group = self.clone();

		new_group.epoch += 1;
		new_group.pending_updates = HashMap::new();
		new_group.pending_commits = HashMap::new();

		new_group
	}

	fn ctx(&self) -> Hash {
		Self::derive_ctx(&self.uid, self.epoch, &self.roster, &self.conf_trans_hash)
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

	// means: "This proposal is signed by *ME* from the *GROUP* that has *STATE*"
	fn frame_proposal(&self, proposal: Proposal) -> FramedProposal {
		let to_sign = Sha256::digest(
			[
				self.ctx().as_slice(),
				self.user_id.as_bytes(),
				&proposal.hash(),
			]
			.concat(),
		);

		let sig = self.ssk.sign(&to_sign);
		let to_mac = Sha256::digest([to_sign.as_slice(), sig.as_bytes()].concat());
		let mac_nonce = proposal::Nonce(rand::thread_rng().gen());
		let mac_key = Self::mac_key(&self.secrets.mac, &self.user_id, &mac_nonce);
		let mac = hmac::digest(&mac_key, &to_mac);

		FramedProposal::new(self.uid, self.epoch, self.user_id, proposal, sig, mac, mac_nonce)
	}

	// returns (user_id, Proposal)
	fn unframe_proposal(&self, fp: &FramedProposal) -> Result<(Id, Proposal), Error> {
		if fp.guid != self.uid {
			return Err(Error::WrongGroup);
		}

		if fp.epoch != self.epoch {
			return Err(Error::WrongEpoch);
		}

		if let Some(sender) = self.roster.get(&fp.sender) {
			let to_sign = Sha256::digest(
				[
					self.ctx().as_slice(),
					fp.sender.as_bytes(),
					&fp.prop.hash(),
				]
				.concat(),
			);

			if !sender.kp.svk.verify(&to_sign, &fp.sig) {
				return Err(Error::InvalidSignature);
			}

			let to_mac = Sha256::digest([to_sign.as_slice(), fp.sig.as_bytes()].concat());
			let mac_key = Self::mac_key(&self.secrets.mac, &fp.sender, &fp.nonce);

			if !hmac::verify(&to_mac, &mac_key, &fp.mac) {
				return Err(Error::InvalidMac);
			}

			return Ok((fp.sender, fp.prop.clone()))
		} else {
			return Err(Error::UnknownSender);
		}
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

	// TODO: return a new group state instead of using mut?
	// apply proposals: get the new state + diffs + filter bad proposals
	// these should be filtered/validated and ordered by an outer layer
	pub fn commit(&self, fps: &[FramedProposal]) {
		// apply previously stored-filtered-validated proposals and get (new_group, diff { updated, removed, added })
		let (mut new, diff) = self.aply_proposals(fps);

		// by the spec, I am to check these:
		// 1 assert(!changes.removes.contains(self.user_id))
		// 2 assert(!changes.updates.contans(self.user_id))
		// but I should actually check it all at a higher level
		// plus, it's fine committing my own update actually

		// these will get Welcome
		let to_welcome = diff.added;
		// these will get Commit
		// TODO: move to Roster and test
		let to_notify = new
			.roster
			.ids()
			.into_iter()
			.filter(|id| !to_welcome.contains(id))
			.map(|id| new.roster.get(&id).unwrap().clone())
			.collect::<Vec<Member>>();

		let (com_secret, com_kp, encryption) = new.rekey(&to_notify);

		// member_hash is automatically derived at this point
		// a shared commit part that is to be signed; will be sent to ids_to_notify
		let commit = Commit {
			kp: com_kp,
			cti: encryption.cti,
			iv: encryption.iv,
			sym_ct: encryption.sym_ct,
			// this commit will include all the given proposal ids
			prop_ids: fps.iter().map(|fp| fp.id()).collect(),
		};

		// sign commit
		let sig = self.sign_commit(&commit);
		new.conf_trans_hash = self.derive_conf_trans_hash(&self.user_id, &commit, &sig);

		let (joiner, epoch_secrets, conf_key) = new.derive_secrets(&self, &com_secret);
		new.secrets = epoch_secrets;

		let conf_tag = Self::conf_tag(&conf_key, &new.conf_trans_hash);
		new.interim_trans_hash =
			Self::interim_trans_hash(&new.conf_trans_hash, conf_tag.as_bytes());

		// TODO: if I allow updating my own keys, will I be able to unframe/verify? – rather yes, since the new state is not applied (see PendingCommit)
		let framed_commit = self.frame_commit(&commit, &sig, &conf_tag);
		let ctds = self
			.roster
			.ids()
			.iter()
			.map(|id| {
				// to_notify can either be the same as self.roster or 'shorter', eg
				// r: [a, b, c, d, e]
				// n: [a, c, e]
				// in either case, keys never change, plus, to_notify is as ordered as encryption.ctds
				// TODO: make such bond stronger
				if let Some(idx) = to_notify.iter().position(|m| m.id == *id) {
					Some((id.clone(), encryption.ctds[idx]))
				} else {
					None
				}
			})
			.collect::<Vec<Option<(Id, Ctd)>>>();

		// add welcomes
		// assing pend_com
		// return (framed_commit, (node_id, ctd), wi, (node_id, wd))
	}

	fn welcome(
		&self,
		invited: &[Member],
		joiner_secret: &JoinerSecret,
		conf_tag: &hmac::Digest,
	) -> (WelcomeI, Vec<WelcomeD>) {
		todo!()
	}

	fn derive_secrets(
		&self,
		prev_state: &Group,
		commit_secret: &CommitSecret,
	) -> (JoinerSecret, EpochSecrets, ConfirmationSecret) {
		let joiner = key_schedule::derive_joiner(&prev_state.secrets.init, &commit_secret);
		let (epoch_secrets, conf_key) = key_schedule::derive_epoch_secrets(self.ctx(), &joiner);

		(joiner, epoch_secrets, conf_key)
	}

	// should return 2 hashes: wo_cmtr & w_cmtr or one is enough?
	fn derive_conf_trans_hash(&self, committer: &Id, commit: &Commit, sig: &Signature) -> Hash {
		// OLD guid, OLD, epoch, OLD interim!
		// comCont ← (G.groupid, G.epoch, ‘commit’, 𝐶0, sig)
		// G′.confTransHash-w.o-‘idc’ ← H(G.interimTransHash, comCont)
		// G′.confTransHash ← H(G′.confTransHash-w.o-‘idc’, id𝑐 )
		// return G'

		// gs.ConfTransHash = hashPack(
		// 	pad,
		// 	ConfTransHashId,
		// 	old.InterimTransHash, // what's its initial value? all zeros? already contains epoch from derive_epoch_keys
		// 	old.GroupId,
		// 	packUint(old.Epoch),
		// 	[]byte(idC),
		// 	[]byte("commit"),
		// 	C0.Pack(pad),
		// 	sig,
		// )

		todo!()
	}

	// means: "This commit is signed by *ME* from the *GROUP* that has *STATE*"
	// hence, groupCont() should contain all shared (non derivable) state (its hash)
	fn sign_commit(&self, commit: &Commit) -> Signature {
		// 1: comCont ← (G.groupCont(), G.id, ‘commit’,𝐶0)
		// 2: sig ← SIG.Sign(ppSIG, G.ssk, comCont)
		// 3: return sig

		// groupContWInterim := gs.GroupContWInterim() // does this authenticate anything?

		// packedC := c.Pack(pad) // TODO: use hash_pack instead
		// comCont := hashPack(
		// 	pad,
		// 	CommitSignId,
		// 	groupContWInterim,
		// 	[]byte(gs.Id), // sender
		// 	[]byte("commit"),
		// 	packedC,
		// )
		// sig, err := gs.Ssk.Sign(
		// 	nil,
		// 	comCont,
		// 	crypto.Hash(0),
		// )
		// if err != nil {
		// 	panic(err)
		// }
		// return sig
		todo!()
	}

	fn frame_commit(
		&self,
		commit: &Commit,
		sig: &Signature,
		conf_tag: &hmac::Digest,
	) -> FramedCommit {
		todo!()
	}

	// TODO: return (com, kp, enc) and apply instead of state change?
	fn rekey(
		&mut self,
		receivers: &[Member],
	) -> (CommitSecret, KeyPackage, hpkencrypt::Encryption) {
		let com_secret = rand::thread_rng().gen::<CommitSecret>();
		let (kp, sk) = self.gen_kp();

		// TODO: update ssk/svk as well; should I return this instead? if yes, com_secret won't by encrypted for my new com_key, but I ignore it anyway
		_ = self.roster.set(&self.user_id, &kp);
		self.dk = sk;

		let keys = receivers
			.iter()
			.map(|m| m.kp.ek.clone())
			.collect::<Vec<ilum::PublicKey>>();
		// encrypt com_secret for all recipients including myself (though I'll ignore it when processing)
		let encryption = hpkencrypt::encrypt(&com_secret, &self.seed, &keys);

		(com_secret, kp, encryption)
	}

	// generates a new state { epoch + 1, roster, roster_hash }, returns diff
	// TODO: introduce a dedicated type instead of [FramedProposal]
	fn aply_proposals(&self, fps: &[FramedProposal]) -> (Group, Diff) {
		let mut new = self.next();
		// updates, removes, adds
		// FIXME: add these checks?
		// in the spec:

		// TODO: rather apply props and don't do anything – they should be already validated
		fps.into_iter().for_each(|fp| {
			// TODO: implement
			match fp.prop {
				Proposal::Add { id, ref kp } => todo!(),
				Proposal::Remove { id } => todo!(),
				Proposal::Update { ref kp } => todo!(),
			};
		});

		// (new, diff)
		todo!()
	}

	fn verify_kp(id: &Id, kp: &KeyPackage) {
		// id == pk.id
		// if I don't have kp in my certs
		// send a VERIFY req to the backend: // almost TOFU
		// 	 if ok, add this pk to my certs
		// verify signature
	}
}

// struct Delta {
// 	// it is possible to process someone else's proposals, so sender is required
// 	sender: Id,
// 	proposal: Proposal,
// }

// A properly ordered, validated set of proposals
struct Diff {
	updated: Vec<Id>,
	removed: Vec<Id>,
	added: Vec<Id>, // a sender can propose any number of Deltas
	                // a receiver can have one Delta
}

impl Group {
	// TODO: move somewhere else; introduce dedicated types for hashes
	fn interim_trans_hash(conf_trans_hash: &Hash, conf_tag: &Hash) -> Hash {
		Sha256::digest([conf_trans_hash.as_slice(), conf_tag].concat()).into()
	}

	fn conf_tag(conf_key: &Hash, conf_trans_hash: &Hash) -> hmac::Digest {
		hmac::digest(&hmac::Key::from(conf_key), conf_trans_hash)
	}

	fn mac_key(seed: &MacSecret, user_id: &Id, nonce: &proposal::Nonce) -> hmac::Key {
		hmac::Key::new(Sha256::digest(
			[
				seed.as_slice(),
				user_id.as_bytes(),
				&nonce.0,
			]
			.concat(),
		)
		.into())
	}

	fn derive_ctx(uid: &[u8], epoch: u64, roster: &Roster, conf_trans_hash: &[u8]) -> Hash {
		Sha256::digest(
			[
				uid,
				epoch.to_be_bytes().as_slice(),
				&roster.hash(),
				conf_trans_hash,
			]
			.concat(),
		)
		.into()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_next() {
		// pend_upd = []
		// pend_com = [
		// epoch = epoch + 1
	}

	#[test]
	fn test_frame_unframe_proposal() {

	}

	#[test]
	fn test_apply_proposals() {
		// test good proposals
		// test bad proposals
	}

	#[test]
	fn test_create_group() {
		// TODO: implement
	}

	#[test]
	fn test_rekey() {
		// TODO: implement
	}

	#[test]
	fn test_derive_conf_trans_hash() {
		// TODO: implement
	}
}

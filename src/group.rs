use std::collections::HashMap;

use ilum::*;
use rand::Rng;

use crate::commit::{Commit, FramedCommit, PendingCommit};
use crate::dilithium::Signature;
use crate::hash::{self, Hash, Hashable};
use crate::key_package::KeyPackage;
use crate::key_schedule::{
	CommitSecret, ConfirmationSecret, EpochSecrets, JoinerSecret, MacSecret,
};
use crate::member::{Id, Member};
use crate::proposal::{self, FramedProposal, Proposal};
use crate::roster::Roster;
use crate::update::PendingUpdate;
use crate::welcome::{self, WlcmCtd, WlcmCti};
use crate::{aes_gcm, dilithium, hmac, hpkencrypt, key_schedule};
use sha2::{Digest, Sha256};

pub enum Error {
	WrongGroup,
	WrongEpoch,
	UnknownSender,
	InvalidSignature,
	InvalidMac,
	// basically impossible: we're processing our own commit that we don't have; impersonation could take place; abort
	UnknownPendingCommit,
	// a commit referring to unknown proposals is being processed; retry policy could be applied
	PropsMismatch,
	// we're trying to commit while being removed in one of its proposals; abort, someone else should commit instead
	SelfRemoveNotAllowed,
	// corresponds to either KeyPairMismatch or BadAesMaterial; in general, should never happen
	HpkeDecryptFailed,
	// the supplied key pair failed to verify: pk-sk was either not signed with ssk or something else
	InvalidCommitKeyPair,
	// whatever was encapsulated by the committer is of unexpected form
	WrongComSecretSize,
	// failed to converge to a shared state
	InvalidConfTag,
	// this invite was not meant for me
	NotMyWelcome,
	// invitee is not in the group, but trying to invite you to it
	UnauthorizedInviter,
	// invitation is improperly signed or forged
	InvalidWelcomeSignature,
	// some of the roster's key pairs failed to verify
	ForgedRoster,
	// I received a welcome, but I'm not in its roster
	InvitedButNotInRoster,
	// key advertised in the welcome message does not match with what's used for the roster
	InitKeyMismatch,
	// whatever was encapsulated by the inviter is of unexpected form
	WrongJoinerSecretSize,
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
	// TODO: move to a higher level entity
	pending_updates: HashMap<Id, PendingUpdate>,
	pending_commits: HashMap<Id, PendingCommit>, // keyed by FramedCommit.id

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

		FramedProposal::new(
			self.uid,
			self.epoch,
			self.user_id,
			proposal,
			sig,
			mac,
			mac_nonce,
		)
	}

	/// verifies commit's guid, epoch & signature
	fn unframe_commit(
		&self,
		fc: &FramedCommit,
	) -> Result<(Id, Commit, Signature, hmac::Digest), Error> {
		if fc.guid != self.uid {
			return Err(Error::WrongGroup);
		}

		if fc.epoch != self.epoch {
			return Err(Error::WrongEpoch);
		}

		if let Some(sender) = self.roster.get(&fc.sender) {
			// TODO: introduce a helper pack function
			let to_sign = Sha256::digest(
				[
					self.ctx().as_slice(),
					fc.sender.as_bytes(),
					&fc.commit.hash(),
				]
				.concat(),
			);

			if !sender.kp.svk.verify(&to_sign, &fc.sig) {
				return Err(Error::InvalidSignature);
			}

			return Ok((fc.sender, fc.commit.clone(), fc.sig.clone(), fc.conf_tag));
		} else {
			return Err(Error::UnknownSender);
		}
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
				[self.ctx().as_slice(), fp.sender.as_bytes(), &fp.prop.hash()].concat(), // TODO: move to a helper pack function?
			);

			if !sender.kp.svk.verify(&to_sign, &fp.sig) {
				return Err(Error::InvalidSignature);
			}

			let to_mac = Sha256::digest([to_sign.as_slice(), fp.sig.as_bytes()].concat()); // TODO: move to a helper pack function?
			let mac_key = Self::mac_key(&self.secrets.mac, &fp.sender, &fp.nonce);

			if !hmac::verify(&to_mac, &mac_key, &fp.mac) {
				return Err(Error::InvalidMac);
			}

			return Ok((fp.sender, fp.prop.clone()));
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
	pub fn commit(
		&mut self,
		fps: &[FramedProposal],
	) -> Result<
		(
			FramedCommit,
			Vec<(Id, Option<Ctd>)>,
			Option<(WlcmCti, Vec<WlcmCtd>)>,
		),
		Error,
	> {
		// apply previously stored-filtered-validated proposals and get (new_group, diff { updated, removed, added })
		let (mut new, diff) = self.aply_proposals(fps);

		// REVIEW: this should be checked by a higher level in the first place
		// self-removing commits make not sence for it is the committer who generates new entropy:
		// if you're evicted, you can't have access to the group's new state, hence you can't be the source of that state

		// in general, self-remove can be achieved by merely sending a proposal and clearing all local state:
		// recipients, will later commit such a proposal while the sender would not care anymore
		// though what if such a proposal is lost, eg A proposes while B commits? Should A keep sending?
		// should there a dedicated message be introduced for simplicity/consistency?

		// in a multi-device setting, it is also sufficient to check whether the proposal is sent from "me",
		// which should be done by a higher leve as well
		if diff.removed.contains(&self.user_id) {
			return Err(Error::SelfRemoveNotAllowed);
		}
		// suggested by design, but self-updates should actually be fine
		// assert(!changes.updates.contans(self.user_id))

		// these will get Welcome
		let to_welcome = diff.added;
		// these will get Commit; there will always be at least one recipient – me
		// TODO: move to Roster and test
		let to_notify = new
			.roster
			.ids()
			.into_iter()
			.filter(|id| !to_welcome.iter().find(|m| m.id == *id).is_some())
			.map(|id| new.roster.get(&id).unwrap().clone())
			.collect::<Vec<Member>>();

		let (com_secret, com_kp, encryption) = new.rekey(&to_notify);

		let commit = Commit {
			kp: com_kp,
			cti: encryption.cti,
			// this commit will include all the given proposal ids
			prop_ids: fps.iter().map(|fp| fp.id()).collect(),
		};

		// sign commit
		let sig = self.sign_commit(&commit);
		new.conf_trans_hash = self.derive_conf_trans_hash(&self.user_id, &commit, &sig); // TODO: move to Transcript/Ledger?

		let (joiner_secret, epoch_secrets, conf_key) = new.derive_secrets(&self, &com_secret);
		new.secrets = epoch_secrets;

		let conf_tag = Self::conf_tag(&conf_key, &new.conf_trans_hash);
		new.interim_trans_hash =
			Self::interim_trans_hash(&new.conf_trans_hash, conf_tag.as_bytes());

		let framed_commit = self.frame_commit(&commit, &sig, &conf_tag);
		// empty ctd-s will be sent to the removed users, while non-empty ones – to to_notify
		// the removed ones will too have access to this new epoch, but won't be able to decrypt it for no corresponding ctd would exist
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
				(
					id.clone(),
					if let Some(idx) = to_notify.iter().position(|m| m.id == *id) {
						Some(encryption.ctds[idx])
					} else {
						None
					},
				)
			})
			.collect::<Vec<(Id, Option<Ctd>)>>();

		let welcomes = new.welcome(&to_welcome, &joiner_secret, &conf_tag);

		self.pending_commits.insert(
			framed_commit.id(),
			PendingCommit {
				state: new,
				proposals: fps.iter().map(|p| p.id()).collect(),
			},
		);

		Ok((framed_commit, ctds, welcomes))
	}

	// TODO: wrap { FramedCommit, Ctd }?
	pub fn process(
		&self,
		fc: &FramedCommit,
		ctd: &ilum::Ctd,
		fps: &[FramedProposal],
	) -> Result<Option<Group>, Error> {
		// verify group, epoch, membership and the signature first
		let (sender, commit, sig, conf_tag) = self.unframe_commit(fc)?;

		if sender == self.user_id {
			// this is one of my own commits, so just return its state and apply it
			if let Some(pc) = self.pending_commits.get(&fc.id()) {
				// REVIEW: do I need to ensure fc.prop_ids ⊆ fps at this particular point?
				// by now, I already have a precomputed state, plus, the commit is verified, so we should be ok

				return Ok(Some(pc.state.clone()));
			} else {
				// the proposed (by me) framed commit passed all validations, but was not found locally; should not ever be possible
				return Err(Error::UnknownPendingCommit);
			}
		} else {
			// this is someone else's commit, so update your state by applying its proposals

			// late proposals could be received after/while the commit's sent, so fps ⊇ fc.prop_ids is possible, but
			// it is crucial to *ensure* fc.prop_ids ⊆ fps, otherwise the new state won't converge
			// alternatively, we could ignore all this and rely on conf_tag solely (if it fails, it fails),
			// but this check gives a bit more of context
			let fps = fps
				.into_iter()
				.filter(|&fp| commit.prop_ids.contains(&fp.id()))
				.cloned()
				.collect::<Vec<FramedProposal>>();

			if fps.len() != commit.prop_ids.len() {
				return Err(Error::PropsMismatch);
			}

			let (mut new, diff) = self.aply_proposals(&fps);

			if diff.removed.contains(&sender) {
				// committers can't remove themselves
				return Err(Error::SelfRemoveNotAllowed);
			}

			// TODO: my ctd should be nil, if I get here;
			if diff.removed.contains(&self.user_id) {
				// I was removed; clear my state and leave
				return Ok(None);
			}

			new.conf_trans_hash = self.derive_conf_trans_hash(&sender, &commit, &sig);

			let ek = self.roster.get(&self.user_id).unwrap().kp.ek;
			let com_secret = CommitSecret::try_from(
				hpkencrypt::decrypt(
					&commit.cti.sym_ct,
					&commit.cti.cti,
					ctd,
					&self.seed,
					&ek,
					&self.dk,
					&commit.cti.iv,
				)
				.or(Err(Error::HpkeDecryptFailed))?,
			)
			.or(Err(Error::WrongComSecretSize))?;

			// REVIEW: this verifies the new ilum keypair, but assumes signing keys are static for now;
			// otherwise, committers would need to sign their new signing keys with their current epoch's signing keys
			if !commit.kp.verify() {
				return Err(Error::InvalidCommitKeyPair);
			}

			new.roster.set(&sender, &commit.kp);

			let (_, epoch_secrets, conf_key) = new.derive_secrets(&self, &com_secret);

			if !Self::verify_conf_tag(&conf_key, &new.conf_trans_hash, &conf_tag) {
				return Err(Error::InvalidConfTag);
			}

			new.secrets = epoch_secrets;
			new.interim_trans_hash =
				Self::interim_trans_hash(&new.conf_trans_hash, conf_tag.as_bytes());

			return Ok(Some(new));
		}
	}

	fn welcome(
		&self,
		invited: &[Member],
		joiner_secret: &JoinerSecret,
		conf_tag: &hmac::Digest,
	) -> Option<(WlcmCti, Vec<WlcmCtd>)> {
		if invited.is_empty() {
			None
		} else {
			let info = welcome::Info::new(
				self.uid,
				self.epoch,
				self.roster.clone(),
				self.conf_trans_hash,
				conf_tag.clone(),
				self.user_id,
			);
			let keys = invited
				.iter()
				.map(|m| m.kp.ek)
				.collect::<Vec<ilum::PublicKey>>();

			// FIXME: it's better to encrypt the whole welcome::Info object + joiner, but joiner only is ok for now as well
			let encryption = hpkencrypt::encrypt(joiner_secret, &self.seed, &keys);
			let to_sign = Sha256::digest([info.hash().as_slice(), &encryption.cti.hash()].concat());
			let sig = self.ssk.sign(&to_sign);
			let cti = WlcmCti::new(info, encryption.cti, sig);
			let ctds = invited
				.iter()
				.enumerate()
				.map(|(idx, m)| WlcmCtd::new(m.id, m.kp.id(), encryption.ctds[idx]))
				.collect();

			Some((cti, ctds))
		}
	}

	// include the used keys as well?
	// kp, dk & ssk should be fetched from a local storage by wd.key_id
	pub fn join(
		id: &Id,
		kp: &KeyPackage,
		dk: &ilum::SecretKey,
		ssk: &dilithium::PrivateKey,
		seed: &Seed,
		wi: &WlcmCti,
		wd: &WlcmCtd,
	) -> Result<Self, Error> {
		let inviter = wi
			.info
			.roster
			.get(&wi.info.inviter)
			.map_or(Err(Error::UnauthorizedInviter), |m| Ok(m))?;

		if *id != wd.user_id {
			return Err(Error::NotMyWelcome);
		}

		let invitee = wi
			.info
			.roster
			.get(id)
			.map_or(Err(Error::InvitedButNotInRoster), |m| Ok(m))?;

		if kp.id() != invitee.kp.id() {
			return Err(Error::InitKeyMismatch);
		}

		let to_sign = Sha256::digest([wi.info.hash().as_slice(), &wi.cti.hash()].concat());

		if !inviter.kp.svk.verify(&to_sign, &wi.sig) {
			return Err(Error::InvalidWelcomeSignature);
		}

		if !wi.info.roster.verify_keys() {
			return Err(Error::ForgedRoster);
		}

		// let conf_tag = Self::conf_tag(&conf_key, &conf_trans_hash);
		let ctx = Self::derive_ctx(
			&wi.info.guid,
			wi.info.epoch,
			&wi.info.roster,
			&wi.info.conf_trans_hash,
		);
		let joiner = JoinerSecret::try_from(
			hpkencrypt::decrypt(
				&wi.cti.sym_ct,
				&wi.cti.cti,
				&wd.ctd,
				seed,
				&invitee.kp.ek,
				&dk,
				&wi.cti.iv,
			)
			.or(Err(Error::HpkeDecryptFailed))?,
		)
		.or(Err(Error::WrongJoinerSecretSize))?;
		let (secrets, conf_key) = key_schedule::derive_epoch_secrets(ctx, &joiner);

		if !Self::verify_conf_tag(&conf_key, &wi.info.conf_trans_hash, &wi.info.conf_tag) {
			return Err(Error::InvalidConfTag);
		}

		let interim_trans_hash =
			Self::interim_trans_hash(&wi.info.conf_trans_hash, wi.info.conf_tag.as_bytes());

		let group = Group {
			uid: wi.info.guid,
			epoch: wi.info.epoch,
			seed: seed.clone(),
			conf_trans_hash: wi.info.conf_trans_hash,
			interim_trans_hash,
			roster: wi.info.roster.clone(),
			pending_updates: HashMap::new(),
			pending_commits: HashMap::new(),
			user_id: id.clone(),
			dk: dk.clone(),
			ssk: ssk.clone(),
			secrets,
		};

		return Ok(group);
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

	fn derive_conf_trans_hash(&self, committer: &Id, commit: &Commit, sig: &Signature) -> Hash {
		Sha256::digest(
			[
				// TODO: use ctx() instead of { uid, epoch }?
				self.uid.as_slice(),
				&self.epoch.to_be_bytes(),
				&commit.hash(),
				sig.as_bytes(),
				&self.interim_trans_hash,
				committer.as_bytes(),
			]
			.concat(),
		)
		.into()
	}

	// means: "This commit is signed by *ME* from the *GROUP* that has *STATE*"
	// hence, groupCont() should contain all shared (non derivable) state (its hash)
	fn sign_commit(&self, commit: &Commit) -> Signature {
		// TODO: move to a helper pack function?
		let to_sign = Sha256::digest(
			[
				self.ctx().as_slice(),
				self.user_id.as_bytes(),
				&commit.hash(),
			]
			.concat(),
		);

		self.ssk.sign(&to_sign)
	}

	fn frame_commit(
		&self,
		commit: &Commit,
		sig: &Signature,
		conf_tag: &hmac::Digest,
	) -> FramedCommit {
		FramedCommit::new(
			self.uid,
			self.epoch,
			self.user_id,
			commit.clone(),
			sig.clone(),
			conf_tag.clone(),
		)
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

		// verifies sig and mac

		// TODO: rather apply props and don't do anything – they should be already validated
		fps.into_iter().for_each(|fp| {
			// TODO: implement
			match fp.prop {
				Proposal::Add { id, ref kp } => todo!(), // TODO: verify the new svk
				Proposal::Remove { id } => todo!(),
				Proposal::Update { ref kp } => todo!(), // TODO: verify the new svk
			};
		});

		// (new, diff)
		todo!()
	}
}

// A properly ordered, validated set of proposals
struct Diff {
	updated: Vec<Id>,
	removed: Vec<Id>,
	added: Vec<Member>, // a sender can propose any number of Deltas
	                    // a receiver can have one Delta
}

impl Group {
	// TODO: move somewhere else; introduce dedicated types for hashes
	fn interim_trans_hash(conf_trans_hash: &Hash, conf_tag: &Hash) -> Hash {
		Sha256::digest([conf_trans_hash.as_slice(), conf_tag].concat()).into()
	}

	fn conf_tag(key: &Hash, conf_trans_hash: &Hash) -> hmac::Digest {
		hmac::digest(&hmac::Key::from(key), conf_trans_hash)
	}

	fn verify_conf_tag(key: &Hash, conf_trans_hash: &Hash, tag: &hmac::Digest) -> bool {
		hmac::verify(conf_trans_hash, &hmac::Key::from(key), tag)
	}

	fn mac_key(seed: &MacSecret, user_id: &Id, nonce: &proposal::Nonce) -> hmac::Key {
		hmac::Key::new(
			Sha256::digest([seed.as_slice(), user_id.as_bytes(), &nonce.0].concat()).into(),
		)
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
	fn test_frame_unframe_proposal() {}

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

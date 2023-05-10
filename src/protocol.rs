/*

	The backend is to ensure the same order for all received messages for all group members, eg if the backend
	*receives* m1, m2, m3 (*regardless* of what was sent earlier), everyone in the group is to receive m1, then m2 and finally m3:

										|		a		b		c		d		..	z
	b ----m2----->		|		m1	m1 	m1	m1	..	m1
	c ----m3---->			|		m2	m2 	m2	m2	..	m2
	d ----m1------>		|		m3	m3 	m3	m3	..	m3

	Updates with version lower than the most recent are to be ignored when received except for my own
	commits containing either adds or removes – if that's a case, resend by a higher level (for an updated epoch)

	Bth, there is no reason for the backend to refuse any commits anymore: the only thing it needs to do is
	to queue whatever comes in and whether a commit/proposal is still valid each recipient is to decide themselves.

	Adds and removes are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From thr sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message could look like this:

 // encrypt?
	struct Stage {
		proposals: Option<[FramedProposal]>,
		commit: Option<FramedCommid>,
	}

	A party should not issue a commit if there's an unacked proposal of its own: say, Alice proposes [upd_a] and commits immediately
	which for some reason makes the proposal to be either lost or received by the BE after the commit. When processing, recipients would not
	find the attached proposal which leads to an error by design.

	How to implement self-removes? One can't create a self-removing commit for he should not know the new com_secret.
	A Remove(id = self) proposal might be ignore by a concurrent commit. Sending a dedicated Leave message might not be sufficient as well,
	unless some one else commits immediately, but who?

	When a device/account is deleted, the backend could respond to users' messages by attaching a nack(user_deleted=[ids]), so that
	one could send a proposal-commit pair in order to fix the roster

*/

/*
	An update strategy could be to send an update every 10 messages and commit after 5 messagesafter that.
	Hence, encrypt should return an optional Update/Commit.

	Also, a context is required to be added to Welcome. It may include group_name, description, hidden, roles, etc.
*/

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
	ciphertext::Ciphertext,
	commit::{CommitCtd, FramedCommit},
	dilithium::{self, Signature},
	group::{self, Group, Owner},
	hash::Hash,
	hpkencrypt::CmpdCtd,
	id::Id,
	key_package::KeyPackage,
	nid::Nid,
	proposal::FramedProposal,
	serializable::Serializable,
	welcome::{WlcmCtd, WlcmCti},
	x448,
};

// a randomly generated public seed that is to be used for all instances of this protocol in order for mPKE to work
pub const ILUM_SEED: &[u8; 16] =
	b"\x96\x48\xb8\x08\x8b\x16\x1c\xf1\x22\xee\xb4\x5a\x29\x69\x02\x43";

#[derive(Debug)]
pub enum Error {
	FailedToCreate,
	DbLocked,
	KeyPackageNotFound(Id),
	GroupAlreadyExists(Id),
	NoGroupFound(Id),
	GroupCantBeEmpty,
}

impl From<group::Error> for Error {
	fn from(val: group::Error) -> Self {
		match val {
			// FIXME: implement!
			_ => Error::FailedToCreate,
		}
	}
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendCommit {
	pub cti: Ciphertext,
	pub ctds: Vec<CommitCtd>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendAdd {
	pub props: Vec<Ciphertext>,
	pub commit: SendCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendInvite {
	pub wcti: WlcmCti,
	pub wctds: Vec<WlcmCtd>,
	pub add: Option<SendAdd>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendRemove {
	pub props: Vec<Ciphertext>,
	pub commit: SendCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendProposal {
	pub props: Vec<Ciphertext>,
	pub recipients: Vec<Nid>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendMsg {
	pub payload: Ciphertext,
	pub recipients: Vec<Nid>,
}

#[derive(Debug, PartialEq)]
pub enum Send {
	Invite(SendInvite),
	Remove(SendRemove),
	Props(SendProposal),
	Commit(SendCommit),
	Msg(SendMsg),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedWelcome {
	pub cti: WlcmCti,
	pub ctd: CmpdCtd,
	pub kp_id: Id,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedCommit {
	pub cti: Ciphertext,
	pub ctd: CmpdCtd,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedProposal {
	pub props: Vec<Ciphertext>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedAdd {
	pub props: ReceivedProposal,
	pub commit: ReceivedCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedRemove {
	pub props: ReceivedProposal,
	pub cti: Ciphertext,
	pub ctd: Option<CmpdCtd>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Received {
	Welcome(ReceivedWelcome),
	Add(ReceivedAdd),
	Remove(ReceivedRemove),
	Props(ReceivedProposal),
	Commit(ReceivedCommit),
	Msg(Ciphertext),
}

// private keys + public KeyPackage
pub struct KeyBundle {
	pub ilum_dk: ilum::SecretKey,
	pub ilum_ek: ilum::PublicKey,
	pub x448_dk: x448::PrivateKey,
	pub x448_ek: x448::PublicKey,
	pub ssk: dilithium::PrivateKey,
	pub svk: dilithium::PublicKey,
	pub sig: Signature,
}

#[async_trait]
pub trait Storage {
	// TODO: could it be sufficient to represent user identity as a signing key?
	async fn save_group(&self, group: &[u8], uid: &[u8], epoch: u64, roster: Vec<&[u8]>);
	// someone used my public keys to invite me
	async fn get_my_prekey_bundle_by_id(&self, id: Id) -> Result<KeyBundle, Error>;
	async fn delete_my_prekey_bundle_by_id(&self, id: Id) -> Result<(), Error>;
	// my static qydra identity used to create all groups
	// TODO: introduce an ephemeral package signed witha static identity?
	// TODO: should it accept my Nid?
	async fn get_my_identity_key_bundle(&self) -> Result<KeyBundle, Error>;
	async fn get_latest_by_guid(&self, guid: Id) -> Result<Group, Error>;
}

#[async_trait]
pub trait Api {
	async fn fetch_key_packages(&self, nid: &[Nid]) -> Vec<KeyPackage>;
}

pub struct Protocol<S, A> {
	storage: Arc<S>,
	api: Arc<A>,
}

impl<S, A> Protocol<S, A>
where
	S: Storage,
	A: Api,
{
	async fn handle_welcome(&self, wlcm: ReceivedWelcome, receiver: Nid) -> Result<(), Error> {
		let KeyBundle {
			ilum_dk,
			ilum_ek,
			x448_dk,
			x448_ek,
			ssk,
			svk,
			sig,
		} = self.storage.get_my_prekey_bundle_by_id(wlcm.kp_id).await?;

		let group = Group::join(
			&receiver,
			&KeyPackage {
				ilum_ek,
				x448_ek,
				svk,
				sig,
			},
			&ilum_dk,
			&x448_dk,
			&ssk,
			ILUM_SEED,
			&wlcm.cti,
			&wlcm.ctd,
		)?;

		// no such group should exist yet
		if let Err(Error::NoGroupFound(_)) =
			self.storage.get_latest_by_guid(group.uid()).await
		{
			// TODO: check if the sender can invite me
			self.save_group(&group).await;

			Ok(())
		} else {
			Err(Error::GroupAlreadyExists(group.uid()))
		}
	}

	async fn handle_add(&self, add: ReceivedAdd, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_remove(&self, remove: ReceivedRemove, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_props(&self, props: ReceivedProposal, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_commit(&self, commit: ReceivedCommit, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_msg(&self, msg: Ciphertext, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	// TODO: should this return anything?
	pub async fn handle_received(&self, rcvd: Received, receiver: Nid) -> Result<(), Error> {
		use Received::*;

		match rcvd {
			Welcome(w) => self.handle_welcome(w, receiver).await,
			Add(a) => self.handle_add(a, receiver).await,
			Remove(r) => self.handle_remove(r, receiver).await,
			Props(p) => self.handle_props(p, receiver).await,
			Commit(c) => self.handle_commit(c, receiver).await,
			Msg(m) => self.handle_msg(m, receiver).await,
		}
	}

	// invitees should NOT contain the group owner, or the process will fail upon proposing
	pub async fn create_group(&self, owner_id: Nid, invitees: &[Nid]) -> Result<(Id, SendInvite), Error> {
		if invitees.is_empty() {
			Err(Error::GroupCantBeEmpty)
		} else {
			// fetch prekeys for each invitee
			let kps = self.api.fetch_key_packages(invitees).await;
			// get my identity key bundle
			// TODO: use just a static signing key instead of a bundle and sign an empeheral key package instead?
			let KeyBundle {
				ilum_dk,
				ilum_ek,
				x448_dk,
				x448_ek,
				ssk,
				svk,
				sig,
			} = self.storage.get_my_identity_key_bundle().await?;
			let owner = Owner {
				id: owner_id,
				kp: KeyPackage {
					ilum_ek,
					x448_ek,
					svk,
					sig,
				},
				ilum_dk,
				x448_dk,
				ssk,
			};
			// create a group of size 1 containing just me
			let mut group = Group::create(ILUM_SEED.to_owned(), owner);
			// propose to add everyone
			let fps = invitees
				.into_iter()
				.zip(kps.into_iter())
				.map(|(nid, kp)| {
					group
						.propose_add(*nid, kp)
						.map(|(fp, _)| fp)
						.map_err(|e| e.into())
				})
				.collect::<Result<Vec<FramedProposal>, Error>>()?;

			// commit the proposal
			let (fc, _, ctds, wlcms) = group.commit(&fps)?;
			// this processed group will now have everyone in it
			let group = group
				.process(&fc, ctds.first().unwrap().ctd.as_ref(), &fps)?
				.unwrap();

			// TODO: add an optional SendInvite in case everything fails?
			self.save_group(&group).await;

			let (wcti, wctds) = wlcms.unwrap();
			let invite = SendInvite {
				wcti,
				wctds,
				// the group has just been created, so there's nobody to to process this commit but me
				add: None,
			};

			// send SendWelcome to everyone
			Ok((group.uid(), invite))
		}
	}

	async fn encrypt_msg(&self, msg: &[u8], guid: Id) -> Result<(), Error> {
		// get the latest group
		// encrypt
		// save
		// return
		todo!()
	}

	// keep in mind, each nid is simply a concatenation of CID & device_number, eg ABCDEFGH42, so no `:` is used
	// TODO: do I need to additionally save group meta context, eg name, description, roles, etc?
	async fn save_group(&self, group: &Group) {
		let roster: Vec<Vec<u8>> = group.roster().ids().iter().map(|n| n.as_bytes()).collect();
		self.storage
			.save_group(
				&group.serialize(),
				group.uid().as_bytes(),
				group.epoch(),
				roster.iter().map(|n| n.as_slice()).collect(),
			)
			.await;
	}
}

// enum Message {
// 	App(Vec<u8>),
// 	Propose(FramedProposal),
// 	Commit(FramedCommit, ilum::Ctd),
// 	Welcome(WlcmCti, WlcmCtd),
// }

// fn decrypt(msg: Encrypted) -> Message {
// 1 get state for (guid, epoch)
// 2 get a chain tree for the given message type
// 3 get a detached key for the given tree & gen
// 4 derive mac_key and enc_key from the given detached key
// 5 verify mac of the payload
// 6 if msg.type == commit
//	6.1 if sender == me
//		6.1.1 if not_outdated apply_by_id
//		6.1.2 else resend_if_required_or_ignore
// 	6.2 else
//		6.2.1 if not_outdated decrypt_and_apply(cm, enc_key)
//		6.2.1 ignore
// 7 else if msg.type == proposal decrypt_and_store_if_not_outdated(p, enc_key)
// 8 else decrypt_and_store

// todo!()
// }

#[cfg(test)]
mod tests {
	#[test]
	fn test_create_group() {
		//
	}
}

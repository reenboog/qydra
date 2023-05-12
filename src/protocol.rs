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
	to queue whatever comes in and whether a commit/proposal is still valid each recipient is to decide himself.

	Adds and removes are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From the sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message is implemented in Schema.proto as SendInvite/SendAdd.

	A node should not issue a commit if there's an unacked proposal of its own: say, Alice proposes [upd_a] and commits immediately
	which for some reason makes the proposal to be either lost or received by the BE after the commit. When processing, recipients would not
	find the attached proposal which leads to an error by design. –Actually we shouldn't worry as long as messages are sent in order.

	How to implement self-removes? One can't create a self-evicting commit for he should not know the new com_secret.
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

/*

	When one deletes himself/removes a device/leaves a group, the following steps could apply
	1 fetch a challenge from the backend (signed by the backend): ts of when the user quits
	2 sign the challenge
	3 send Send::Msg { payload = LEAVE { sign(challenge, my_key) }.encode, recipients = all }
		or
	4 the backend sends DEACTIVATED and signs it. But how would it know the roster?

	a recipient would then:
	1 find an epoch to process LEAVE and process it
	2 issue a SendRemove { ref = LEAVE } and send it via the most recent epoch (FIXME: then everyone would send such a message – BAD)
		or add this Remove to the next Update proposal? – PREFERRED
		or MAYBE someone should add this Remove to his next Update proposal? (defined by nid)

	or
	1 send a Leave proposal
	2 recipients would always check if it's a Leave proposal and mark the sender as PENDING_REMOVE
	2.1 if it's my device, quit immediately and do nothing
	3 during on of the subsequent update commits, remove this user entirely: propose an update + remove and then commit
	4 given the commit from 3 will be added to the end of the queue, handle future-agnostic removes in case, the user is re-added before the commit:
		if this node has ever been added afterwards, mark it as non PENDING_LEAVE, so that the check will fail

	TODO: indeed, use Group context for name, creator, description, roles, etc
*/

/*
	To implement admins, owners and alike a GroupContext (to be used when deriving group.ctx() as well) could be introduced (contains a signed list of all roles) +
	a new UpdateContext proposal to grant/revoke access

*/

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
	ciphertext::{Ciphertext, ContentType},
	commit::CommitCtd,
	dilithium::{self},
	group::{self, Group, Owner},
	hash::{self, Hashable},
	hpkencrypt::CmpdCtd,
	id::{Id, Identifiable},
	key_package::KeyPackage,
	msg::Msg,
	nid::Nid,
	proposal::FramedProposal,
	serializable::{Deserializable, Serializable},
	transport,
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

pub struct Encrypted {
	// actual payload to send
	pub send: transport::Send,
	// every N encryptions, users update and every M – commit that update
	pub update: Option<transport::Send>,
}

pub struct Decrypted {
	pub pt: Vec<u8>,
	// if LEAVE is implemented this could be used to remove that peer: sign(sign("leave", server_ssk), user_ssk)
	// pub pending_leave: Option<SendRemove>,
}

// returned by handle_msg
pub enum Incoming {}

#[async_trait]
pub trait Storage {
	// a log of message ids should be stored locally to ensure no duplicate is processed twice
	async fn should_process_rcvd(&self, id: Id) -> bool;
	// TODO: could it be sufficient to represent user identity as a signing key?
	async fn save_group(&self, group: &[u8], uid: &[u8], epoch: u64, roster: Vec<&[u8]>);
	async fn save_proposal(&self, guid: Id, prop: &[u8]);
	async fn get_group(&self, uid: &[u8], epoch: u64) -> Result<Group, Error>;
	async fn get_latest_epoch(&self, guid: Id) -> Result<Group, Error>;
	// someone used my public keys to invite me
	async fn get_my_prekey_bundle_by_id(&self, id: Id) -> Result<transport::KeyBundle, Error>;
	async fn delete_my_prekey_bundle_by_id(&self, id: Id) -> Result<(), Error>;
	// my static qydra identity used to create all groups
	// TODO: introduce an ephemeral package signed witha static identity?
	// TODO: should it accept my Nid?
	async fn get_my_identity_key_bundle(&self) -> Result<transport::KeyBundle, Error>;
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
	async fn handle_welcome(
		&self,
		wlcm: transport::ReceivedWelcome,
		receiver: Nid,
	) -> Result<(), Error> {
		let transport::KeyBundle {
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
		if let Err(Error::NoGroupFound(_)) = self.storage.get_latest_epoch(group.uid()).await {
			// TODO: check if the sender can invite me
			self.save_group(&group).await;

			Ok(())
		} else {
			Err(Error::GroupAlreadyExists(group.uid()))
		}
	}

	async fn handle_add(&self, add: transport::ReceivedAdd, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_remove(
		&self,
		remove: transport::ReceivedRemove,
		receiver: Nid,
	) -> Result<(), Error> {
		todo!()
	}

	async fn handle_edit(&self, edit: transport::ReceivedEdit, receiver: Nid) -> Result<(), Error> {
		todo!()
	}

	async fn handle_props(
		&self,
		props: transport::ReceivedProposal,
		receiver: Nid,
	) -> Result<(), Error> {
		todo!()
	}

	async fn handle_commit(
		&self,
		commit: transport::ReceivedCommit,
		receiver: Nid,
	) -> Result<(), Error> {
		// if someone is trying to remove someone who's already removed, ignore
		// if I'm trying to remove (processing my own commit) someone who's already removed, ignore
		// if I'm adding someone who's added, ignore
		todo!()
	}

	// if LEAVE { sig: signed_by_evictee } is introduced, it can be processed here; hence, this should return Option<SendRemove> (for the latest epoch)
	async fn handle_msg(&self, ct: Ciphertext, receiver: Nid) -> Result<(), Error> {
		match self
			.storage
			.get_group(&ct.guid.as_bytes().to_vec(), ct.epoch)
			.await
		{
			Ok(mut group) => {
				let pt = group.decrypt::<Msg>(ct, ContentType::Msg)?;

				self.save_group(&group).await;

				// TODO: return pt.0
			}
			Err(err) => {
				// if not found, get the most recent on and compare epoch
				// if recent.epoch < ct.epoch -> state corrupted
				// else too old epoch
			}
		}

		// TODO: how about admins?

		// Ok(pt.0)
		Ok(())
	}

	// TODO: should this return anything?
	// TODO: introduce a type
	pub async fn handle_received(
		&self,
		rcvd: transport::Received,
		receiver: Nid,
	) -> Result<(), Error> {
		use transport::Received::*;

		match rcvd {
			Welcome(w) => self.handle_welcome(w, receiver).await,
			Add(a) => self.handle_add(a, receiver).await,
			Remove(r) => self.handle_remove(r, receiver).await,
			Edit(e) => self.handle_edit(e, receiver).await,
			Props(p) => self.handle_props(p, receiver).await,
			Commit(c) => self.handle_commit(c, receiver).await,
			Msg(m) => self.handle_msg(m, receiver).await,
		}
	}

	// invitees should NOT contain the group owner, or the process will fail upon proposing
	pub async fn create_group(
		&self,
		owner_id: Nid,
		invitees: &[Nid],
	) -> Result<(Id, transport::SendInvite), Error> {
		if invitees.is_empty() {
			Err(Error::GroupCantBeEmpty)
		} else {
			// fetch prekeys for each invitee
			let kps = self.api.fetch_key_packages(invitees).await;
			// get my identity key bundle
			// TODO: use just a static signing key instead of a bundle and sign an empeheral key package instead?
			let transport::KeyBundle {
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
			let invite = transport::SendInvite {
				wcti,
				wctds,
				// the group has just been created, so there's nobody to to process this commit but me
				add: None,
			};

			// send SendWelcome to everyone
			Ok((group.uid(), invite))
		}
	}

	pub async fn encrypt_msg(&self, pt: &[u8], guid: Id) -> Result<Encrypted, Error> {
		let mut group = self.storage.get_latest_epoch(guid).await?;
		let msg = Msg(pt.to_vec());
		let ct = group.encrypt(&msg, ContentType::Msg);
		// TODO: do I need to send this to myself?
		let send = transport::Send::Msg(transport::SendMsg {
			payload: ct,
			recipients: group.roster().ids(),
		});

		// TODO: propose update, if time has come? eg: if seq > ENCS_TO_UPD && !group.has_pending_updates
		let encrypted = Encrypted {
			send,
			update: None, // FIXME: apply props and update-commit, if required
		};

		self.save_group(&group).await;
		// FIXME: increment counters!
		Ok(encrypted)
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

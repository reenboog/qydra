/*

	The backend is to ensure the same order for all received messages for all group members, eg if the backend
	*receives* m1, m2, m3 (*regardless* of what was *sent* earlier), everyone in the group is to receive m1, then m2 and finally m3:

										|		a		b		c		d		..	z
	b ----m2----->		|		m1	m1 	m1	m1	..	m1
	c ----m3---->			|		m2	m2 	m2	m2	..	m2
	d ----m1------>		|		m3	m3 	m3	m3	..	m3

	Add and remove proposals are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From the sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message is implemented in Schema.proto as SendInvite/SendAdd.

	When a device/account is deleted, the backend could respond to users' messages by attaching a nack(user_deleted=[ids]), so that
	one could send a proposal-commit pair in order to fix the roster. –Actually, an external event should trigger remove(nids), eg an http call, etc

	An update strategy could be to send an update every 10 messages and commit after 5 messages after that.
	Hence, send_msg should return an optional Update/Commit.
*/

/*
	To implement admins, owners and alike a GroupContext (to be used when deriving group.ctx() as well) could be introduced (contains a signed list of all roles) +
	a new Edit proposal to grant/revoke access

*/

use std::{sync::Arc};

use async_trait::async_trait;

use crate::{
	ciphertext::{Ciphertext, ContentType},
	commit::{FramedCommit},
	group::{self, Group, Owner},
	id::{Id},
	key_package::KeyPackage,
	msg::Msg,
	nid::Nid,
	proposal::{FramedProposal, Proposal},
	transport::{self, SendLeave, SendMsg},
};

// a randomly generated public seed that is to be used for all instances of this protocol in order for mPKE to work
pub const ILUM_SEED: &[u8; 16] =
	b"\x96\x48\xb8\x08\x8b\x16\x1c\xf1\x22\xee\xb4\x5a\x29\x69\x02\x43";

#[derive(Debug)]
pub enum Error {
	FailedToCreate,
	// the app is locked, retry later
	DbLocked,
	KeyPackageNotFound(Id),
	GroupAlreadyExists(Id),
	NoGroupFound(Id),
	GroupCantBeEmpty,
	// there's no way to process and recover from this; REINIT
	TooNewEpoch {
		epoch: u64,
		current: u64,
	},
	// decryption failure
	FailedToDecrypt {
		id: Id,
		content_type: ContentType,
		sender: Nid,
		guid: Id,
		epoch: u64,
		ctx: String,
	},
	// should never happend
	FailedToProcessOwnCommit {
		ctx: String,
	},
	NoUserInGroup {
		nid: Nid,
		guid: Id,
	},
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
	// every N encryptions, users update and every M – commit that update or issue a SendRemove, in case of any pending_remove
	pub update: Option<transport::Send>,
}

pub struct Decrypted {
	pub pt: Vec<u8>,
	// if LEAVE is implemented this could be used to remove that peer: sign(sign("leave", server_ssk), user_ssk)
	// pub pending_leave: Option<SendRemove>,
}

#[async_trait]
pub trait Storage {
	// TODO: all save_ functions should check for duplicates
	// a log of message ids should be stored locally to ensure no duplicate is processed twice
	async fn should_process_rcvd(&self, id: Id) -> bool;
	async fn mark_rcvd_as_processed(&self, id: Id);

	// TODO: could it be sufficient to represent user identity as a signing key?
	async fn save_group(&self, group: &Group, uid: &Id, epoch: u64, roster: Vec<&Nid>) -> Result<(), Error>;
	// delete all epochs for this group, all framed commits, all pending_remove-s
	async fn delete_group(&self, guid: &Id);

	// gets all nids for the specified nid; useful in case a device is added/remove between the tasks
	async fn get_nids_for_nid(&self, nid: &Nid) -> Result<Vec<Nid>, Error>;

	async fn save_prop(&self, prop: &FramedProposal, id: Id, epoch: u64, guid: Id);
	async fn get_prop(&self, id: Id, epoch: u64, guid: Id) -> Result<FramedProposal, Error>;

	async fn save_commit(&self, commit: &FramedCommit, id: Id);
	async fn get_commit(&self, id: Id) -> Result<FramedCommit, Error>;

	// async fn save_proposal(&self, guid: Id, prop: &[u8]);
	// mark nid for removal during one of the next update cycles
	async fn mark_as_pending_remove(&self, guid: Id, pending: bool, nid: Nid) -> Result<(), Error>;
	// should return all nids for a given nid stored in the database
	async fn get_pending_removes(&self, guid: Id) -> Result<Vec<Nid>, Error>;

	// mark this group as pending leave for myself; once my own LEAVE message arrives, delete it completely
	async fn mark_as_pending_leave(&self, guid: Id, pending: bool, req_id: Id);
	async fn is_pending_leave(&self, guid: Id, req_id: Id) -> Result<bool, Error>;

	async fn get_group(&self, uid: &Id, epoch: u64) -> Result<Group, Error>;
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
		sender: Nid,
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
			self.save_group(&group).await?;

			Ok(())
		} else {
			Err(Error::GroupAlreadyExists(group.uid()))
		}
	}

	// returns Send { SendAdd { .. } }, if this ADD was triggered by me, but someone else's comit came first
	async fn handle_add(
		&self,
		add: transport::ReceivedAdd,
		sender: Nid,
		receiver: Nid,
	) -> Result<Option<transport::Send>, Error> {
		use std::cmp::Ordering::*;

		let epoch = add.commit.cti.epoch;
		let guid = add.commit.cti.guid;
		let mut group = self.storage.get_latest_epoch(guid).await?;

		match epoch.cmp(&group.epoch()) {
			Less => {
				// if my outdated add, reframe and resend, if not empty
				// get all devices for this nid when adding
				Ok(None)
			}
			Equal => {
				// TODO: uncheck pending_remove for this nid, if any, which is actually weird to do (REMOVE should unmark it)
				// self.storage.mark_as_pending_leave(nid, false);
				// IMPORTANT: I must add my own devices, not somebody else!
				// if my commit, fetch props and commit from the db
				Ok(None)
			}
			Greater => {
				// the only explanation is the server lost part of its state and I missed a few commits before this one
				// nothing can be done here except to reinitialize
				Err(Error::TooNewEpoch {
					epoch,
					current: group.epoch(),
				})
			}
		}
	}

	// returns Option<Send { SendRemove { .. } }>, if this REMOVE was triggered by me, but someone else's commit came first
	// if nids are already removed by now, Option is used to do nothing
	async fn handle_remove(
		&self,
		sender: Nid,
		remove: transport::ReceivedRemove,
		receiver: Nid,
	) -> Result<Option<transport::Send>, Error> {
		use futures::future;
		use std::cmp::Ordering::*;

		let epoch = remove.cti.epoch;
		let guid = remove.cti.guid;
		let mut group = self.storage.get_latest_epoch(guid).await?;
		let pending_removes = self.storage.get_pending_removes(guid).await?;

		match epoch.cmp(&group.epoch()) {
			// an outdated epoch
			Less => {
				if sender == receiver {
					// replacing the sender by a malicious backend won't cause any harm: someone else's removal won't be found locally in my database,
					// and others won't be able to decrypt it since the sender is signed and hashed along with the entire payload

					// only resend manually triggered removals and ignnore pending_removes
					// if one of the proposals is not found, the backend is trying to mess up with me – ignore
					// if one of the evictees leaves while this removal is being resent, he'll be handled later as pending_remove
					let nids = future::try_join_all(
						remove
							.props
							.props
							.into_iter()
							.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
					)
					.await?
					.into_iter()
					.filter_map(|fp| match fp.prop {
						Proposal::Remove { id } if !pending_removes.contains(&id) => Some(id),
						_ => None,
					})
					.collect::<Vec<Nid>>();

					if nids.is_empty() {
						Ok(None)
					} else {
						// while sender is the same as receiver here, I'm emphasizing it is *I* who's removing now
						// FIXME: should I get all nids for each nid and filter already removed ones to pass them to remove?
						Ok(self.remove(&nids, receiver, guid).await)
					}
				} else {
					// it's someone else's outdated remove – they'll resend it later, if need be
					Ok(None)
				}
			}
			Equal => {
				let fps = if sender != receiver {
					// it's someone else's REMOVE, so I need to decrypt both, the props and the commit, then process
					let fps = remove
						.props
						.props
						.into_iter()
						.map(|p| {
							group
								.decrypt(p.clone(), ContentType::Propose, &sender)
								.or(Err(Error::FailedToDecrypt {
									id: p.content_id,
									content_type: ContentType::Propose,
									sender,
									guid,
									epoch,
									ctx: "handle_remove: prop".to_string(),
								}))
						})
						.collect::<Result<Vec<FramedProposal>, Error>>()?;
					let fc = group
						.decrypt::<FramedCommit>(remove.cti.clone(), ContentType::Commit, &sender)
						.or(Err(Error::FailedToDecrypt {
							id: remove.cti.content_id,
							content_type: ContentType::Commit,
							sender,
							guid,
							epoch,
							ctx: "handle_remove: commit".to_string(),
						}))?;

					// ensure the sender has access to commit all the announced proposals
					let fps = fps.into_iter().filter_map(|fp| match fp.prop {
						Proposal::Remove { id }
						// TODO: check access rules
						// TODO: distinguish remove type with an enum: Delegated, DetachDevice, Evict
						if pending_removes.contains(&id) || sender.is_same_id(&id) /* || can_nid_remove_nid(sender, nid, group) */ =>
						{
							Some(fp)
						}
						_ => None,
					})
					.collect::<Vec<FramedProposal>>();

					// should I distinguish "Alice left" vs "Alice was removed by Bob"?
					// Also, if just a device is remove (not the whole account), no need to display anything
					if let Some(new_group) = group.process(&fc, remove.ctd.as_ref(), &fps)? {
						// decryption changes the inner chains, so always save to achieve FS
						self.save_group(&group).await?;
						// we have a new epoch, so save this new group as well
						self.save_group(&new_group).await?;
					} else {
						// I was removed, so delete the group and all its state
						self.delete_group(&guid).await?;
					}

					Ok(fps)
				} else {
					let fps = future::try_join_all(
						remove
							.props
							.props
							.into_iter()
							.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
					)
					.await?;
					let fc = self.storage.get_commit(remove.cti.content_id).await?;

					// TODO: respect remove type (delegated, detached, evicted) here as well

					// is it required to check my own access rules? If I fake this remove, others won't accept it anyway
					// no need to save the old group here, since it hasn't changed (nothing was decrypted & processing is immutable)
					if let Some(new_group) = group.process(&fc, remove.ctd.as_ref(), &fps)? {
						self.save_group(&new_group).await?;

						Ok(fps)
					} else {
						Err(Error::FailedToProcessOwnCommit {
							ctx: format!(
								"REMOVE on guid: {:#?}, epoch: {}, sender: {:#?}",
								guid, epoch, sender
							),
						})
					}
				}?;

				// mark the removed nids as not pending remove, had they ever been marked
				future::try_join_all(
					fps.into_iter()
						.filter_map(|fp| match fp.prop {
							Proposal::Remove { id } => Some(id),
							_ => None,
						})
						.map(|id| self.storage.mark_as_pending_remove(guid, false, id)),
				)
				.await?;

				Ok(None)
			}
			Greater => {
				// the only explanation is the server lost part of its state and I missed a few commits before this one
				// nothing can be done here except to reinitialize
				Err(Error::TooNewEpoch {
					epoch,
					current: group.epoch(),
				})
			}
		}
	}

	async fn handle_edit(
		&self,
		edit: transport::ReceivedEdit,
		sender: Nid,
		receiver: Nid,
	) -> Result<(), Error> {
		todo!()
		// if mine & outdated, reframe and resend, if required
	}

	async fn handle_props(
		&self,
		props: transport::ReceivedProposal,
		sender: Nid,
		receiver: Nid,
	) -> Result<(), Error> {
		todo!()
	}

	// currently, only updates are processed here; adds & removes are handled separately
	async fn handle_commit(
		&self,
		commit: transport::ReceivedCommit,
		sender: Nid,
		receiver: Nid,
	) -> Result<(), Error> {
		// if someone is trying to remove someone who's already removed, ignore
		// if I'm trying to remove (processing my own commit) someone who's already removed, ignore
		// if I'm adding someone who's added, ignore

		// get most recent epoch first

		// get all fps for this epoch
		// if sender == receiver
		//	my own commit, so	check commit.cti.content_id to get a local copy of FramedCommit
		//	process(fc, commit.ctd)

		todo!()
	}

	// just a regular message
	async fn handle_msg(&self, ct: Ciphertext, sender: Nid, receiver: Nid) -> Result<(), Error> {
		// match self
		// 	.storage
		// 	.get_group(&ct.guid.as_bytes().to_vec(), ct.epoch)
		// 	.await
		// {
		// 	Ok(mut group) => {
		// 		let pt = group.decrypt::<Msg>(ct, ContentType::Msg)?;

		// 		self.save_group(&group).await;

		// 		// TODO: return pt.0
		// 	}
		// 	Err(err) => {
		// 		// if not found, get the most recent on and compare epoch
		// 		// if recent.epoch < ct.epoch -> state corrupted
		// 		// else too old epoch
		// 	}
		// }

		// TODO: how about admins?

		// Ok(pt.0)
		Ok(())
	}

	async fn handle_leave(
		&self,
		ct: Ciphertext,
		sender: Nid,
		receiver: Nid,
	) -> Result<Option<Msg>, Error> {
		// if it takes too long for q to deliver, nid might be already removed, and even re-added,
		// so that this remove would make no sense anymore:
		// *---------------->---->
		// q, m, u, u, m, r, a, m
		// to fight that, Member::joinead_at_epoch is used below

		let guid = ct.guid;
		let epoch = ct.epoch;
		let latest_epoch = self.storage.get_latest_epoch(guid).await?;
		let user = latest_epoch
			.roster()
			.get(&sender)
			.ok_or(Error::NoUserInGroup { nid: sender, guid })?;

		if epoch < user.joined_at_epoch {
			// this user has been re-added since this leave was sent; no action required
			Ok(None)
		} else {
			// is this my leave request?
			if sender == receiver {
				// if content_id doesn't match, someone is trying to fake me leaving
				if self.storage.is_pending_leave(guid, ct.content_id).await? {
					// it's my own leave, so just quit
					self.delete_group(&guid).await?;
				}

				Ok(None)
			} else {
				let mut group = self.storage.get_group(&guid, epoch).await?;

				// ensure it's actually a leave message
				if let Ok(msg) = group.decrypt::<Msg>(ct.clone(), ContentType::Msg, &sender) {
					if receiver.is_same_id(&sender) {
						// I left on one of my other devices – remove this group immediately
						self.delete_group(&ct.guid).await?;

						Ok(None)
					} else {
						// an encryption key has been consumed, so save the group to keep FS
						self.save_group(&group).await?;
						// someone else is leaving, so mark him as pending_remove and maybe remove during one of the consequent updates
						self.storage
							.mark_as_pending_remove(guid, true, sender)
							.await?;

						// msg can be used to display the sender's farewell in the chat, if specified
						Ok(Some(msg))
					}
				} else {
					// someone sent this leave, but I failed to decrypt it; should not happen
					Err(Error::FailedToDecrypt {
						id: ct.content_id,
						content_type: ContentType::Msg,
						sender,
						guid,
						epoch,
						ctx: "handle_leave".to_string(),
					})
				}
			}
		}
	}

	// TODO: also, return an optional Send for either Update, Commit or SendRemove
	pub fn send_msg(&self, sender: Nid, guid: Id, pt: &[u8]) -> Result<transport::Send, Error> {
		// get most recent group
		// encrypt the message
		// build Send { SendMsg { Msg { .. }, recipients = .. } }
		// FIXME: when it is time to update, check if there are pending_remove nids
		// if yes, get all nids for each nid and issue a SendRemove instead of SendUpdate
		// return SendSmg and Option<SendCommit>
		todo!()
	}

	// this shouldn't be public, by the way; instead, use from send_msg()
	fn update(&self, sender: Nid) {
		// 1 get the most recent epoch
		// 2 if pending_remove(guid) is not empty
		//		send SendRemove(pending_remove-s)
		//	 else
		//		send SendCommit
	}

	pub async fn edit(&self, desc: &[u8], sender: Nid, guid: Id) -> Result<(), Error> {
		// keep sending if fails
		todo!()
	}

	pub async fn add(&self, invitees: &[Nid], sender: Nid, guid: Id) -> Result<(), Error> {
		// 1 fetch all nids for this contact
		// if this commit fails, check whether some nids are already added by someone else
		todo!()
	}

	pub async fn leave(
		&self,
		sender: Nid,
		guid: Id,
		farewell: &[u8],
	) -> Result<transport::Send, Error> {
		let mut group = self.storage.get_latest_epoch(guid).await?;
		let ct = group.encrypt(&Msg(farewell.to_vec()), ContentType::Msg);
		let req_id = ct.content_id;
		let farewell = SendMsg {
			payload: ct,
			recipients: group.roster().ids(),
		};
		self.save_group(&group).await?;
		self.storage.mark_as_pending_leave(guid, true, req_id).await;

		Ok(transport::Send::Leave(SendLeave { farewell }))
	}

	// NOTE: this should be the only interface to remove nids from groups; if a nid is deactivated or something,
	// NOTE: when unlocking, it is required to check for all deactivated accounts first and only then connect to the socket API for consistency! – otherwise
	// one coiuld receive a remove for a pending_remove account (deactivated), which is not yet marked as pending_remove
	// an external event should trigger this call
	// it is possible nids are already remove, hence Option
	// if one is deactivated, mark him as pending_delete
	// if one manually removes one of his devices, he should manually send a SendRemove message
	pub async fn remove(&self, nids: &[Nid], sender: Nid, guid: Id) -> Option<transport::Send> {
		// I can delete one of my devices
		// others can't delete just one device – they should use nids_for_nid

		// when one disables one of his devices, he should manually remove it by sending SendRemove; hence, do not use nids_for_nids!
		// should I use nids_for_nids here at all? if I miss a device, my commit will be rejected
		// 1 reframe the proposals to resign/recrypt and filter unnecessary ones
		// let reframed = group.reframe_proposals(&props);
		// 2 get missing nids in case of missing devies
		// ^ should all this be done in handle_remove instead?
		// 3 return

		// also, get all nids for this nid again and propose for them as well

		// let group = self.storage.get_latest_epoch(guid).await?;

		// 1 get all nids for this user
		// 2 make FramedProposals and store them
		// 3 make FrameCommit and store it
		// it is possible some peers are already removed; check and filter

		// let nids = self.storage.get_nids_for_nid(&id).await?;
		// nids.into_iter().for_each(|nid| {
		// 	if props.get(&nid.as_bytes()).is_none() {
		// 		if let Ok((fp, ct)) = group.propose_remove(&nid) {
		// 			props.insert(nid.as_bytes(), nid);
		// 		}
		// 	}
		// });

		todo!()
	}

	// handling Rcvd might required resending. Hence Option<transport::Send>
	pub async fn handle_received(
		&self,
		rcvd: transport::Received,
		sender: Nid,
		receiver: Nid,
	) -> Result<Option<transport::Send>, Error> {
		use transport::Received::*;

		// FIXME: mark Received as processed at some point
		// TODO: if sender is pending_remove, ignore or throw?
		// TODO: if pending_leave(guid) ignore except for ReceivedLeave & Remove or should I really care?

		match rcvd {
			Welcome(w) => {
				self.handle_welcome(w, sender, receiver).await?;

				Ok(None)
			}
			Add(a) => {
				self.handle_add(a, sender, receiver).await?;

				Ok(None)
			}
			Remove(r) => Ok(self.handle_remove(sender, r, receiver).await?),
			Edit(e) => {
				self.handle_edit(e, sender, receiver).await?;

				Ok(None)
			}
			Props(p) => {
				self.handle_props(p, sender, receiver).await?;

				Ok(None)
			}
			Commit(c) => {
				self.handle_commit(c, sender, receiver).await?;

				Ok(None)
			}
			Leave(l) => {
				self.handle_leave(l, sender, receiver).await?;

				Ok(None)
			}
			Msg(m) => {
				self.handle_msg(m, sender, receiver).await?;

				Ok(None)
			}
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
			self.save_group(&group).await?;

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

		self.save_group(&group).await?;
		// FIXME: increment counters!
		Ok(encrypted)
	}

	// db may be locked, hence Result
	async fn delete_group(&self, guid: &Id) -> Result<(), Error> {
		self.storage.delete_group(guid).await;
		// delete pending_remove
		// delete framed proposals
		// delete framed commits
		// delete description and other info?
		// delete pending_leave
		Ok(())
	}

	// keep in mind, each nid is simply a concatenation of CID & device_number, eg ABCDEFGH42, so no `:` is used
	// TODO: do I need to additionally save group meta context, eg name, description, roles, etc?
	// db may be locked, hence Result
	async fn save_group(&self, group: &Group) -> Result<(), Error> {
		// TODO: add a flag to clear all previous epochs and remove commits and proposals?
		let roster: Vec<Nid> = group.roster().ids();
		self.storage
			.save_group(
				&group,
				&group.uid(),
				group.epoch(),
				roster.iter().map(|n| n).collect(),
			)
			.await
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

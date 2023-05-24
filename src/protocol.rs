/*

	The backend is to ensure the same order for all received messages for all group members, eg if the backend
	*receives* m1, m2, m3 (*regardless* of what was *sent* earlier), everyone in the group is to receive m1, then m2 and finally m3:

										|		a		b		c		d		..	z
	b ----m2----->		|		m1	m1 	m1	m1	..	m1
	c ----m3---->			|		m2	m2 	m2	m2	..	m2
	d ----m1------>		|		m3	m3 	m3	m3	..	m3

	It is possible for a SendInvite to be outdated, but the invitees wouldn't know: the current roster always receives ReceivedAdd while the invites – ReceivedWelcome.
	To address that, the invites are to mark the group as pending_admit and prevent sending (and/or hide it from the UI), but to always process all incoming messages.
	The inviter, on the other hand, is to send such SendAdmit to the invitees once his SendInvite (its ReceivedAdd variant) is proccessed

	Add and remove proposals are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From the sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message is implemented in Schema.proto as SendInvite/SendAdd.

	When a device/account is deleted, the backend could respond to users' messages by attaching a nack(user_deleted=[ids]), so that
	one could send a proposal-commit pair in order to fix the roster. –Actually, an external event should trigger remove(nids), eg an http call, etc. For that

	An update strategy could be to send an update every 10 messages and commit after 5 messages after that.
	Hence, send_msg should return an optional Update/Commit.

	It is important to include pending_remove-s, if any, when inviting new members, since that state is not shared.
*/

/*
	To implement admins, owners and alike a GroupContext (to be used when deriving group.ctx() as well) could be introduced (contains a signed list of all roles) +
	a new Edit proposal to grant/revoke access
*/

use std::sync::Arc;

use async_trait::async_trait;
use futures::future;

use crate::{
	ciphertext::{Ciphertext, ContentType},
	commit::FramedCommit,
	group::{Group, Owner},
	id::Id,
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
	// the app is locked, retry later
	DbLocked,
	KeyPackageNotFound(Id),
	FailedToJoin,
	GroupAlreadyExists {
		guid: Id,
		epoch: u64,
		invited_to_epoch: u64,
	},
	NoGroupFound(Id),
	// some props or commits (or else) not found
	BrokenState {
		guid: Id,
		epoch: u64,
		ctx: String,
	},
	UnknownProp(Id),
	UnknownCommit(Id),
	NoEmptyGroupsAllowed,
	CantCreate {
		ctx: String,
	},
	// there's no way to process and recover from this; REINIT
	TooNewEpoch {
		epoch: u64,
		current: u64,
		guid: Id,
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
	FailedToProcessCommit {
		ctx: String,
	},
	NoSuchUserInGroup {
		nid: Nid,
		guid: Id,
	},
	// we're invited, but can't do anything until Admit is received
	PendingAdmit {
		guid: Id,
	},
	// admission message decrypted, but cross check failed
	UnknownAdmit {
		guid: Id,
		greeting: Vec<u8>,
	},
	// resend whatever is supplied
	NeedsResend(transport::Send),

	// nids might already be added/removed
	NoChangeRequired {
		guid: Id,
		ctx: String,
	},
	// someone else's outdated commit, should be ignored
	OutdatedCommit {
		guid: Id,
		sender: Nid,
		epoch: u64,
		ctx: String,
	},
}

// should contain Vec<transport::Send>
pub struct Encrypted {
	// actual payload to send
	pub send: transport::Send,
	// every N encryptions, users update and every M – commit that update or issue a SendRemove, in case of any pending_remove
	pub update: Option<transport::Send>,
}

pub enum Processed {
	Welcome,
	Admit,
	Add(OnAdd),
	Remove(OnRemove),
	// if farewell is Some, someone left; otherwise – me
	Leave { farewell: Option<Msg> },
}

pub struct OnAdd {
	// the new members
	pub joined: Vec<Nid>,
	// lefties from a previous epoch
	pub left: Vec<Nid>,
	// I should not only add, but also admit; None, if not my add
	pub admit: Option<transport::Send>,
}

pub struct OnRemove {
	// explicitly removed nids; if contains(my_nid), I'm removed
	pub evicted: Vec<Nid>,
	// lefties from a previous epoch
	pub left: Vec<Nid>,
	// detached devices; if contains(my_nid), I'm detached (= removed)
	pub detached: Vec<Nid>,
}

pub struct OnEdit {
	pub left: Vec<Nid>,
	pub desc: Vec<u8>,
}

pub struct OnHandle {
	sender: Nid,
	guid: Id,
	outcome: Processed,
}

#[async_trait]
pub trait Storage {
	// TODO: all save_ functions should check for duplicates
	// a log of message ids should be stored locally to ensure no duplicate is processed twice
	async fn should_process_rcvd(&self, id: Id) -> bool;
	async fn mark_rcvd_as_processed(&self, id: Id);

	// TODO: could it be sufficient to represent user identity as a signing key?
	async fn save_group(
		&self,
		group: &Group,
		uid: &Id,
		epoch: u64,
		roster: Vec<&Nid>,
	) -> Result<(), Error>;
	// delete all epochs for this group, all framed commits, all pending_remove-s
	async fn delete_group(&self, guid: Id) -> Result<(), Error>;

	// gets all nids for the specified nid; useful in case a device is added/remove between the tasks
	async fn get_nids_for_nid(&self, nid: Nid) -> Result<Vec<Nid>, Error>;

	async fn save_prop(
		&self,
		prop: &FramedProposal,
		id: Id,
		epoch: u64,
		guid: Id,
	) -> Result<(), Error>;
	// Ok(Prop) | Err(UnknownProp)
	async fn get_prop(&self, id: Id, epoch: u64, guid: Id) -> Result<FramedProposal, Error>;
	async fn delete_props(&self, guid: Id, epoch: u64) -> Result<(), Error>;

	async fn save_commit(&self, commit: &FramedCommit, id: Id, guid: Id) -> Result<(), Error>;
	// Ok(Commit) | Err(UnknownCommit)
	async fn get_commit(&self, id: Id, epoch: u64, guid: Id) -> Result<FramedCommit, Error>;
	async fn delete_commits(&self, guid: Id, epoch: u64) -> Result<FramedCommit, Error>;

	// mark nid for removal during one of the next update cycles
	async fn mark_as_pending_remove(&self, guid: Id, pending: bool, nid: Nid) -> Result<(), Error>;
	// should return all nids for a given nid stored in the database
	async fn get_pending_removes(&self, guid: Id) -> Result<Vec<Nid>, Error>;

	// mark this group as pending leave for MYSELF; once my own LEAVE message arrives, delete it
	async fn mark_as_pending_leave(&self, guid: Id, pending: bool, req_id: Id)
		-> Result<(), Error>;
	async fn is_pending_leave(&self, guid: Id, req_id: Id) -> Result<bool, Error>;

	// ensure admit refers to both, the sender and the guid when implementing the ffi layer
	async fn mark_as_pending_admit(
		&self,
		guid: Id,
		sender: Nid,
		pending: bool,
	) -> Result<(), Error>;
	async fn is_pending_admit(&self, guid: Id) -> Result<bool, Error>;

	async fn get_group(&self, uid: &Id, epoch: u64) -> Result<Group, Error>;
	async fn get_latest_epoch(&self, guid: Id) -> Result<Group, Error>;
	// someone used my public keys to invite me
	async fn get_my_prekey_bundle(&self, id: Id) -> Result<transport::KeyBundle, Error>;
	async fn delete_my_prekey_bundle(&self, id: Id) -> Result<(), Error>;
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
		} = self.storage.get_my_prekey_bundle(wlcm.kp_id).await?;

		// TODO: verify the inviter (sender) first (introduce a parameter)
		// TODO: check whether the sender can invite me?
		// wcti should be ecc-signed (implemented) & sign(ecc_sig + wlcm.hash) with dilithium

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
		)
		.or(Err(Error::FailedToJoin))?;
		let guid = group.uid();

		match self.storage.get_latest_epoch(guid).await {
			// it's ok to receive a welcome to an existing group as long as we're not yet admitted
			// AND the new group's epoch is larger than what's stored locally – just delete it, if any
			Ok(existing_group) => {
				if self.storage.is_pending_admit(guid).await?
					&& group.epoch() > existing_group.epoch()
				{
					self.storage.delete_group(guid).await
				} else {
					Err(Error::GroupAlreadyExists {
						guid,
						epoch: existing_group.epoch(),
						invited_to_epoch: group.epoch(),
					})
				}
			}
			Err(Error::NoGroupFound(..)) => Ok(()),
			Err(err) => Err(err),
		}?;

		self.save_group(&group).await?;
		self.storage.mark_as_pending_admit(guid, sender, true).await
	}

	async fn handle_admit(
		&self,
		admit: Ciphertext,
		sender: Nid,
		receiver: Nid,
	) -> Result<(), Error> {
		let guid = admit.guid;
		let epoch = admit.epoch;
		let id = admit.content_id;
		let mut group = self.storage.get_group(&guid, epoch).await?;

		// I won't be able to decrypt my own admission anyway
		if sender != receiver {
			let Msg(greeting) = group
				.decrypt::<Msg>(admit, ContentType::Msg, &sender)
				.or(Err(Error::FailedToDecrypt {
					id,
					content_type: ContentType::Msg,
					sender,
					guid,
					epoch,
					ctx: "admit".to_string(),
				}))?;

			self.save_group(&group).await?;

			// admssion should refer to the grop its admitting to
			if greeting == guid.as_bytes() {
				self.storage
					.mark_as_pending_admit(guid, sender, false)
					.await?;
			} else {
				return Err(Error::UnknownAdmit { guid, greeting });
			}
		}

		Ok(())
	}

	// Some(OnAdd) for processed adds, None for someone else's outdated commits,
	// Error::NeedsResend for my outdated commit; if OnAdd::admit is Some, send it
	// may contain Remove proposals, in case pending_removes are present
	async fn handle_add(
		&self,
		add: transport::ReceivedAdd,
		sender: Nid,
		receiver: Nid,
	) -> Result<OnAdd, Error> {
		use std::cmp::Ordering::*;

		let epoch = add.commit.cti.epoch;
		let guid = add.commit.cti.guid;
		let mut latest_epoch = self.storage.get_latest_epoch(guid).await?;

		// this add might arrive after nid is added AND removed (almost impossible), but we're ok with that
		// *-------------------------------->
		// a, u, m, m, q, u, u, r, a, m, u, m
		match epoch.cmp(&latest_epoch.epoch()) {
			Less => {
				if sender == receiver {
					Err(Error::NeedsResend(
						self.add(
							&future::try_join_all(
								add.props
									.props
									.into_iter()
									.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
							)
							.await?
							.into_iter()
							.filter_map(|fp| match fp.prop {
								Proposal::Add { id, kp } => Some((id, Some(kp))),
								_ => None,
							})
							.collect::<Vec<(Nid, Option<KeyPackage>)>>(),
							sender,
							guid,
						)
						.await?,
					))
				} else {
					Err(Error::OutdatedCommit {
						guid,
						sender,
						epoch,
						ctx: "ADD".to_string(),
					})
				}
			}
			Equal => {
				// ensure the sender has access to commit all the announced proposals; otherwise, processing will fail
				// also collect some meta info for the UI layer, eg: nid-a added nid-b, nid-c left, etc

				struct Diff {
					props: Vec<FramedProposal>,
					joined: Vec<Nid>,
					left: Vec<Nid>,
				}

				let pending_removes = self.storage.get_pending_removes(guid).await?;
				let filter_map_props = |fps: Vec<FramedProposal>| -> Diff {
					let mut joined = Vec::new();
					let mut left = Vec::new();
					let props = fps
						.into_iter()
						.filter_map(|fp| match fp.prop {
						Proposal::Remove { id }
						// pending removes are ok when adding someone
						if pending_removes.contains(&id) =>
						{
							left.push(id);

							Some(fp)
						},
						// TODO: should I check if sender is trying to add only one device of someone else to enforce the "only I can add my stuff" policy?
						Proposal::Add { id, .. } if true /* FIXME: implement can_nid_add_nid(sender, id) */ => {
							joined.push(id);

							Some(fp)
						}
						_ => None,
					})
						.collect();

					Diff {
						props,
						joined,
						left,
					}
				};

				// (Option<transport::Send { Admit { .. } }>, fps)
				let fps = if sender != receiver {
					// it's someone else's ADD, so I need to decrypt both, the props and the commit, then process
					let fps = filter_map_props(
						add.props
							.props
							.into_iter()
							.map(|p| {
								latest_epoch
									.decrypt(p.clone(), ContentType::Propose, &sender)
									.or(Err(Error::FailedToDecrypt {
										id: p.content_id,
										content_type: ContentType::Propose,
										sender,
										guid,
										epoch,
										ctx: "handle_add: prop".to_string(),
									}))
							})
							.collect::<Result<Vec<FramedProposal>, Error>>()?,
					);
					let fc = latest_epoch
						.decrypt::<FramedCommit>(
							add.commit.cti.clone(),
							ContentType::Commit,
							&sender,
						)
						.or(Err(Error::FailedToDecrypt {
							id: add.commit.cti.content_id,
							content_type: ContentType::Commit,
							sender,
							guid,
							epoch,
							ctx: "handle_add: commit".to_string(),
						}))?;

					// decryption changes the inner chains, so always save to achieve FS
					self.save_group(&latest_epoch).await?;

					if let Ok(Some(new_group)) =
						latest_epoch.process(&fc, Some(add.commit.ctd).as_ref(), &fps.props)
					{
						// we have a new epoch, so save this new group as well
						self.save_group(&new_group).await?;

						// I processed someone else's Add, so there's nothing else left to do
						Ok((None, fps))
					} else {
						// those who left, won't receive this, explicit removes are not allowed here,
						// so None when processing means error here
						Err(Error::FailedToProcessCommit {
							ctx: format!(
								"ADD on guid: {:#?}, epoch: {}, sender: {:#?}",
								guid, epoch, sender
							),
						})
					}
				} else {
					let fps = filter_map_props(
						future::try_join_all(
							add.props
								.props
								.into_iter()
								.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
						)
						.await?,
					);
					let fc = self
						.storage
						.get_commit(add.commit.cti.content_id, epoch, guid)
						.await?;

					// no need to save the old group here, since it hasn't changed (nothing was decrypted & processing is immutable)
					if let Ok(Some(mut new_group)) =
						latest_epoch.process(&fc, Some(add.commit.ctd).as_ref(), &fps.props)
					{
						// admit the newcomers; can be sent to the invitees only, but it's ok as is
						let admit = transport::Send::Admit(transport::SendAdmit {
							greeting: transport::SendMsg {
								// guid is used as a greeting for the purpose of a cross check
								payload: new_group
									.encrypt(&Msg(guid.as_bytes().to_vec()), ContentType::Msg),
								recipients: new_group.roster().ids(),
							},
						});

						self.save_group(&new_group).await?;

						Ok((Some(admit), fps))
					} else {
						Err(Error::FailedToProcessCommit {
							ctx: format!(
								"own ADD on guid: {:#?}, epoch: {}, sender: {:#?}",
								guid, epoch, sender
							),
						})
					}
				}?;

				// mark the removed nids as not pending remove, had they ever been marked
				future::try_join_all(
					fps.1
						.left
						.iter()
						.map(|nid| self.storage.mark_as_pending_remove(guid, false, *nid)),
				)
				.await?;

				Ok(OnAdd {
					joined: fps.1.joined,
					left: fps.1.left,
					admit: fps.0,
				})
			}
			Greater => {
				// the only explanation is the server lost part of its state and I missed a few commits before this one
				// nothing can be done here except to reinitialize
				Err(Error::TooNewEpoch {
					epoch,
					current: latest_epoch.epoch(),
					guid,
				})
			}
		}
	}

	// Some(OnRemove) for processed removes, None for someone else's outdated commits
	async fn handle_remove(
		&self,
		sender: Nid,
		remove: transport::ReceivedRemove,
		receiver: Nid,
	) -> Result<OnRemove, Error> {
		use std::cmp::Ordering::*;

		let epoch = remove.cti.epoch;
		let guid = remove.cti.guid;
		let mut latest_epoch = self.storage.get_latest_epoch(guid).await?;

		match epoch.cmp(&latest_epoch.epoch()) {
			// an outdated epoch
			Less => {
				// nid may be removed and re-added before this remove arrives – it should be processed anyway with a next commit
				// *----------------->
				// r, m, q, r, u, a, m
				if sender == receiver {
					// replacing the sender by a malicious backend won't cause any harm: someone else's removal won't be found locally in my database,
					// and others won't be able to decrypt it since the sender is signed and hashed along with the entire payload

					// if one of the proposals is not found, the backend is trying to mess up with me – ignore
					Err(Error::NeedsResend(
						self.remove(
							&future::try_join_all(
								remove
									.props
									.props
									.into_iter()
									.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
							)
							.await?
							.into_iter()
							.filter_map(|fp| match fp.prop {
								Proposal::Remove { id } => Some(id),
								_ => None,
							})
							.collect::<Vec<Nid>>(),
							receiver,
							guid,
						)
						.await?,
					))
				} else {
					// it's someone else's outdated remove – they'll resend it later, if need be
					Err(Error::OutdatedCommit {
						guid,
						sender,
						epoch,
						ctx: "REMOVE".to_string(),
					})
				}
			}
			Equal => {
				// ensure the sender has access to commit all the announced proposals; otherwise, processing will fail
				// also collect some meta info for the UI layer, eg: nid-a removed nid-b, nid-c left, etc
				struct Diff {
					props: Vec<FramedProposal>,
					left: Vec<Nid>,
					detached: Vec<Nid>,
					evicted: Vec<Nid>,
				}

				let pending_removes = self.storage.get_pending_removes(guid).await?;
				let filter_map_props = |fps: Vec<FramedProposal>| -> Diff {
					let mut left = Vec::new();
					let mut detached = Vec::new();
					let mut evicted = Vec::new();
					let props = fps
						.into_iter()
						.filter_map(|fp| {
							if let Proposal::Remove { id } = fp.prop {
								let is_pending_remove = pending_removes.contains(&id);
								let is_same_sender_id = sender.is_same_id(&id);
								let can_remove = true; // FIXME: implement can_nid_remove_nid(sender, nid, group)
					   // TODO: should I check if sender is trying to remove only one device of someone else
					   // to enforce the "only I can remove my stuff" policy?

								if is_pending_remove {
									left.push(id);
								} else if is_same_sender_id {
									detached.push(id);
								} else {
									evicted.push(id);
								}

								if is_pending_remove || is_same_sender_id || can_remove {
									Some(fp)
								} else {
									None
								}
							} else {
								None
							}
						})
						.collect();

					Diff {
						props,
						left,
						detached,
						evicted,
					}
				};

				let (fps, fc) = if sender != receiver {
					// it's someone else's REMOVE, so I need to decrypt both, the props and the commit, then process
					let fps = remove
						.props
						.props
						.into_iter()
						.map(|p| {
							latest_epoch
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
					let fc = latest_epoch
						.decrypt::<FramedCommit>(remove.cti.clone(), ContentType::Commit, &sender)
						.or(Err(Error::FailedToDecrypt {
							id: remove.cti.content_id,
							content_type: ContentType::Commit,
							sender,
							guid,
							epoch,
							ctx: "handle_remove: commit".to_string(),
						}))?;

					// decryption changes the inner chains, so always save to preserve FS
					self.save_group(&latest_epoch).await?;

					Ok((fps, fc))
				} else {
					let fps = future::try_join_all(
						remove
							.props
							.props
							.into_iter()
							.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
					)
					.await?;
					let fc = self
						.storage
						.get_commit(remove.cti.content_id, epoch, guid)
						.await?;

					Ok((fps, fc))
				}?;

				let diff = filter_map_props(fps);

				match latest_epoch.process(&fc, remove.ctd.as_ref(), &diff.props) {
					Ok(Some(new_group)) => {
						// we have a new epoch, so save this new group as well
						self.save_group(&new_group).await?;
					}
					Ok(None) => {
						// I was removed, so delete the group and all its state
						self.delete_group(&guid).await?;
					}
					Err(_) => {
						// something weird has just happened; not much to do, but log
						return Err(Error::FailedToProcessCommit {
							ctx: format!(
								"own ADD on guid: {:#?}, epoch: {}, sender: {:#?}",
								guid, epoch, sender
							),
						});
					}
				}

				// mark the removed nids as not pending remove, had they ever been marked
				future::try_join_all(
					diff.left
						.iter()
						.map(|nid| self.storage.mark_as_pending_remove(guid, false, *nid)),
				)
				.await?;

				Ok(OnRemove {
					evicted: diff.evicted,
					left: diff.left,
					detached: diff.detached,
				})
			}
			Greater => {
				// the only explanation is the server lost part of its state and I missed a few commits before this one
				// nothing can be done here except to reinitialize
				Err(Error::TooNewEpoch {
					epoch,
					current: latest_epoch.epoch(),
					guid,
				})
			}
		}
	}

	// Ok(OnEdit) | Resend(Send)
	async fn handle_edit(
		&self,
		edit: transport::ReceivedEdit,
		sender: Nid,
		receiver: Nid,
	) -> Result<OnEdit, Error> {
		// it is worth nothing, cases similar to "delayed remove/add" are possible when changing access rules:
		// eg, a delayed revoke for an already revoked/re-granted token should be ok as long as access level still allows that
		use std::cmp::Ordering::*;

		let epoch = edit.commit.cti.epoch;
		let guid = edit.commit.cti.guid;
		let mut latest_epoch = self.storage.get_latest_epoch(guid).await?;

		match epoch.cmp(&latest_epoch.epoch()) {
			Less => {
				if sender == receiver {
					// it's my edit, so try resending it
					Err(Error::NeedsResend(
						self.edit(
							&future::try_join_all(
								edit.props
									.props
									.into_iter()
									.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
							)
							.await?
							.into_iter()
							.find_map(|fp| match fp.prop {
								Proposal::Edit { description } => Some(description),
								_ => None,
							})
							.ok_or(Error::BrokenState {
								guid,
								epoch,
								ctx: "handle_edit: no edit prop found".to_string(),
							})?,
							receiver,
							guid,
						)
						.await?,
					))
				} else {
					Err(Error::OutdatedCommit {
						guid,
						sender,
						epoch,
						ctx: "EDIT".to_string(),
					})
				}
			}
			Equal => {
				struct Diff {
					props: Vec<FramedProposal>,
					left: Vec<Nid>,
					desc: Vec<u8>,
				}

				let pending_removes = self.storage.get_pending_removes(guid).await?;
				let filter_map_props = |fps: Vec<FramedProposal>| -> Diff {
					let mut left = Vec::new();
					let mut desc = Vec::new();
					let props = fps
						.into_iter()
						.filter_map(|fp| match fp.prop {
						// pending removes are ok when editing
						Proposal::Remove { id }
						if pending_removes.contains(&id) => {
							left.push(id);

							Some(fp)
						},
						// apply only one edit, in case someone is abusing the protocol
						Proposal::Edit { ref description } if desc.is_empty() && true /* FIXME: implement can_edit */ => {
							desc = description.clone();

							Some(fp)
						}
						_ => None,
					})
						.collect();

					Diff { props, left, desc }
				};

				let (fps, fc) = if sender != receiver {
					// it's someone else's REMOVE, so I need to decrypt both, the props and the commit, then process
					let fps = edit
						.props
						.props
						.into_iter()
						.map(|p| {
							latest_epoch
								.decrypt(p.clone(), ContentType::Propose, &sender)
								.or(Err(Error::FailedToDecrypt {
									id: p.content_id,
									content_type: ContentType::Propose,
									sender,
									guid,
									epoch,
									ctx: "handle_edit: prop".to_string(),
								}))
						})
						.collect::<Result<Vec<FramedProposal>, Error>>()?;
					let fc = latest_epoch
						.decrypt::<FramedCommit>(
							edit.commit.cti.clone(),
							ContentType::Commit,
							&sender,
						)
						.or(Err(Error::FailedToDecrypt {
							id: edit.commit.cti.content_id,
							content_type: ContentType::Commit,
							sender,
							guid,
							epoch,
							ctx: "handle_edit: commit".to_string(),
						}))?;

					// decryption changes the inner chains, so always save to preserve FS
					self.save_group(&latest_epoch).await?;

					Ok((fps, fc))
				} else {
					let fps = future::try_join_all(
						edit.props
							.props
							.into_iter()
							.map(|ct| self.storage.get_prop(ct.content_id, epoch, guid)),
					)
					.await?;
					let fc = self
						.storage
						.get_commit(edit.commit.cti.content_id, epoch, guid)
						.await?;

					Ok((fps, fc))
				}?;

				// apply access rules
				let diff = filter_map_props(fps);

				if let Ok(Some(new_group)) =
					latest_epoch.process(&fc, Some(&edit.commit.ctd), &diff.props)
				{
					self.save_group(&new_group).await?;
				} else {
					// something weird has just happened; not much to do, but log
					return Err(Error::FailedToProcessCommit {
						ctx: format!(
							"EDIT on guid: {:#?}, epoch: {}, sender: {:#?}",
							guid, epoch, sender
						),
					});
				}

				// mark the removed nids as not pending remove, had they ever been marked
				future::try_join_all(
					diff.left
						.iter()
						.map(|nid| self.storage.mark_as_pending_remove(guid, false, *nid)),
				)
				.await?;

				Ok(OnEdit {
					left: diff.left,
					desc: diff.desc,
				})
			}
			Greater =>
			// the only explanation is the server lost part of its state and I missed a few commits before this one
			// nothing can be done here except to reinitialize
			{
				Err(Error::TooNewEpoch {
					epoch,
					current: latest_epoch.epoch(),
					guid,
				})
			}
		}
	}

	// ()
	async fn handle_props(
		&self,
		props: transport::ReceivedProposal,
		sender: Nid,
		receiver: Nid,
	) -> Result<(), Error> {
		todo!()
		// mark as non pending?
	}

	// ()
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
		// mark as non pending?

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
		// mark as non pending?

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
			.ok_or(Error::NoSuchUserInGroup { nid: sender, guid })?;

		// mark as non pending?

		if epoch < user.joined_at_epoch {
			// this user has been re-added since this leave was sent (an almost impossible case); no action required
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
	pub async fn send_msg(&self, guid: Id, pt: &[u8]) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			// get most recent group
			// encrypt the message
			// build Send { SendMsg { Msg { .. }, recipients = .. } }
			// FIXME: when it is time to update, check if there are pending_remove nids
			// if yes, get all nids for each nid and issue a SendRemove instead of SendUpdate
			// return SendSmg and Option<SendCommit>
			todo!()
		}
	}

	// this shouldn't be public, by the way; instead, use from send_msg()
	pub async fn update(&self, guid: Id) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			// 1 get the most recent epoch
			// 2 if pending_remove(guid) is not empty
			//		send SendRemove(pending_remove-s)
			//	 else
			//		send SendCommit

			todo!()
		}
	}

	pub async fn edit(&self, desc: &[u8], sender: Nid, guid: Id) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			// keep sending if fails

			todo!()
		}
	}

	async fn add(
		&self,
		invitees: &[(Nid, Option<KeyPackage>)],
		sender: Nid,
		guid: Id,
	) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			// 1 fetch all nids for this contact unless it's my device
			// 2 fetch prekeys for each nid
			// 3 if has pending_removes propose to remove them as well
			// TODO: respect access rules

			// err if already added – NoChangeRequried { .. }

			// if this commit fails, check whether some nids are already added by someone else

			// FIXME: ignore pending_removal if !pending_removes.contains(&id)
			// 1 fetch all nids for this contact
			// 2 fetch prekeys for each nid and verify them (use dilithium identities, when implemented)
			// 3 store proposals - remove old ones first?
			// 4 store commit
			// if this commit fails, check whether some nids are already added by someone else
			todo!()
		}
	}

	pub async fn leave(&self, guid: Id, farewell: &[u8]) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			let mut latest_epoch = self.storage.get_latest_epoch(guid).await?;
			let ct = latest_epoch.encrypt(&Msg(farewell.to_vec()), ContentType::Msg);
			let req_id = ct.content_id;
			let farewell = SendMsg {
				payload: ct,
				recipients: latest_epoch.roster().ids(),
			};

			self.save_group(&latest_epoch).await?;
			self.storage
				.mark_as_pending_leave(guid, true, req_id)
				.await?;

			Ok(transport::Send::Leave(SendLeave { farewell }))
		}
	}

	// NOTE: this should be the only interface to remove nids from groups; if a nid is deactivated or something,
	// NOTE: when unlocking, it is required to check for all deactivated accounts first and only then connect to the socket API for consistency! – otherwise
	// one could receive a remove for a pending_remove account (deactivated), which is not yet marked as pending_remove
	// an external event should trigger this call
	// it is possible nids are already remove, hence Error::NoChangeRequired
	// if one is deactivated, mark him as pending_delete
	// if one manually removes one of his devices, he should manually send a SendRemove message
	pub async fn remove(
		&self,
		nids: &[Nid],
		sender: Nid,
		guid: Id,
	) -> Result<transport::Send, Error> {
		if self.storage.is_pending_admit(guid).await? {
			Err(Error::PendingAdmit { guid })
		} else {
			// I can delete one of my devices
			// others can't delete just one device – they should use nids_for_nid

			// also remove pending_remove, if any?
			// TODO: respect access rules
			// if the [nids] is empty, do nothing

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
		// ignore already processed messages
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
			Admit(a) => {
				self.handle_admit(a, sender, receiver).await?;

				Ok(None)
			}
			Remove(r) => {
				self.handle_remove(sender, r, receiver).await?;

				Ok(None)
			}
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

		// mark as processed
	}

	// invitees should NOT contain the group owner, or the process will fail upon proposing
	pub async fn create_group(
		&self,
		owner_id: Nid,
		invitees: &[Nid],
	) -> Result<(Id, transport::SendInvite), Error> {
		if invitees.is_empty() {
			Err(Error::NoEmptyGroupsAllowed)
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
						.map_err(|e| Error::CantCreate {
							ctx: format!("{:#?}", e),
						})
				})
				.collect::<Result<Vec<FramedProposal>, Error>>()?;

			// commit the proposal
			let (fc, _, ctds, wlcms) = group.commit(&fps).map_err(|e| Error::CantCreate {
				ctx: format!("{:#?}", e),
			})?;
			// this processed group will now have everyone in it
			let group = group
				.process(&fc, ctds.first().unwrap().ctd.as_ref(), &fps)
				.unwrap()
				.unwrap();

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
		// TODO: check if pending admit?
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
		self.storage.delete_group(*guid).await?;
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

#[cfg(test)]
mod tests {
	#[test]
	fn test_create_group() {
		//
	}
}

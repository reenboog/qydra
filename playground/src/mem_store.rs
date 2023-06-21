use std::{
	collections::{BTreeMap, HashMap},
	sync::Arc,
};

use async_trait::async_trait;
use qydra::{
	commit::FramedCommit,
	group::Group,
	hpksign,
	id::{Id, Identifiable},
	nid::Nid,
	prekey,
	proposal::FramedProposal,
	protocol::{self, Error},
};
use tokio::sync::Mutex;

// a basic storage to keep stuf in memory
pub struct MemStore {
	groups: Arc<Mutex<HashMap<Id, BTreeMap<u64, Group>>>>,
	nids: Arc<Mutex<Vec<Nid>>>,
	// (prop, parent_commit)
	props: Arc<Mutex<HashMap<Id, (FramedProposal, Option<Id>)>>>,
	commits: Arc<Mutex<HashMap<Id, FramedCommit>>>,
	processed: Arc<Mutex<Vec<Id>>>,
	pending_removes: Arc<Mutex<HashMap<Id, Vec<Nid>>>>,
	pending_leaves: Arc<Mutex<HashMap<Id, Id>>>,
	// { (group, epoch), ctr }
	messages_sent_ctr: Arc<Mutex<HashMap<Id, HashMap<u64, u8>>>>,
	pending_admits: Arc<Mutex<HashMap<Id, Nid>>>,
	prekeys: Arc<Mutex<HashMap<Id, prekey::KeyPair>>>,
	identities: Arc<Mutex<HashMap<Nid, hpksign::PublicKey>>>,

	my_identity: hpksign::KeyPair,

	locked: bool,
}

impl MemStore {
	pub fn new(prekeys: HashMap<Id, prekey::KeyPair>, identity: hpksign::KeyPair) -> Self {
		Self {
			groups: Arc::new(Mutex::new(HashMap::new())),
			nids: Arc::new(Mutex::new(Vec::new())),
			props: Arc::new(Mutex::new(HashMap::new())),
			commits: Arc::new(Mutex::new(HashMap::new())),
			processed: Arc::new(Mutex::new(Vec::new())),
			pending_removes: Arc::new(Mutex::new(HashMap::new())),
			pending_leaves: Arc::new(Mutex::new(HashMap::new())),
			messages_sent_ctr: Arc::new(Mutex::new(HashMap::new())),
			pending_admits: Arc::new(Mutex::new(HashMap::new())),
			prekeys: Arc::new(Mutex::new(prekeys)),
			identities: Arc::new(Mutex::new(HashMap::new())),

			my_identity: identity,

			locked: false,
		}
	}
}

impl MemStore {
	pub fn lock(&mut self, locked: bool) {
		self.locked = locked;
	}
}

#[async_trait]
impl protocol::Storage for MemStore {
	async fn should_process_rcvd(&self, id: Id) -> Result<bool, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(!self.processed.lock().await.contains(&id))
		}
	}

	async fn mark_rcvd_as_processed(&self, id: Id) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut processed = self.processed.lock().await;

			if !processed.contains(&id) {
				processed.push(id)
			}

			Ok(())
		}
	}

	// gets all nids for the specified nid (including mine);
	// useful in case a device is added/removed between the tasks
	async fn get_nids_for_nid(&self, nid: Nid) -> Result<Vec<Nid>, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.nids
				.lock()
				.await
				.iter()
				.filter(|n| n.is_same_id(&nid))
				.cloned()
				.collect())
		}
	}

	// add nids to the existing list of whatever is stored for nid
	async fn save_nids(&self, new: &[Nid]) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut all_nids = self.nids.lock().await;
			let to_add = new
				.iter()
				.filter(|e| !all_nids.contains(e))
				.collect::<Vec<_>>();

			all_nids.extend(to_add);

			Ok(())
		}
	}

	// detaches nids from nid
	async fn remove_nids(&self, remove: &[Nid]) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.nids.lock().await.retain(|n| !remove.contains(n));

			Ok(())
		}
	}

	// parent_commit = None for update props or content_id for add/remove/edit commits otherwise
	async fn save_props(
		&self,
		props: &[FramedProposal],
		_epoch: u64,
		_guid: Id,
		parent_commit: Option<Id>,
	) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut locked = self.props.lock().await;

			props.into_iter().for_each(|fp| {
				locked.insert(fp.id(), (fp.clone(), parent_commit));
			});

			Ok(())
		}
	}

	// Ok(Prop) | Err(UnknownProp)
	// IMPORTANT: respect parent_commit when fetching from the db
	async fn get_props_for_epoch(
		&self,
		guid: Id,
		epoch: u64,
		parent_commit: Option<Id>,
	) -> Result<Vec<FramedProposal>, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.props
				.lock()
				.await
				.iter()
				.filter(|(_, v)| v.0.guid == guid && v.0.epoch == epoch && v.1 == parent_commit)
				.map(|(_, v)| v.0.clone())
				.collect::<Vec<_>>())
		}
	}

	async fn get_prop_by_id(&self, id: Id) -> Result<FramedProposal, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.props
				.lock()
				.await
				.get(&id)
				.map(|(fp, _)| fp.clone())
				.ok_or(Error::UnknownProp(id))?)
		}
	}

	async fn delete_props(&self, guid: Id, epoch: u64) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.props
				.lock()
				.await
				.retain(|_, v| !(v.0.guid == guid && v.0.epoch == epoch));

			Ok(())
		}
	}

	async fn save_commit(&self, commit: &FramedCommit, id: Id, _guid: Id) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.commits.lock().await.insert(id, commit.clone());

			Ok(())
		}
	}

	// Ok(Commit) | Err(UnknownCommit)
	async fn get_commit(&self, id: Id) -> Result<FramedCommit, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.commits
				.lock()
				.await
				.get(&id)
				.cloned()
				.ok_or(Error::UnknownCommit(id))?)
		}
	}

	// there should actually be just one commit per epoch, so it might change
	async fn delete_commits(&self, guid: Id, epoch: u64) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.commits
				.lock()
				.await
				.retain(|_, v| !(v.guid == guid && v.epoch == epoch));

			Ok(())
		}
	}

	// mark nid who previously sent LEAVE to remove during one of the next update cycles; do nothing if none found
	async fn mark_as_pending_remove(&self, guid: Id, pending: bool, nid: Nid) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut prs = self.pending_removes.lock().await;
			let entry = prs.entry(guid).or_insert(Vec::new());

			if pending {
				if !entry.contains(&nid) {
					entry.push(nid);
				}
			} else {
				entry.retain(|n| *n != nid)
			}

			Ok(())
		}
	}
	async fn get_pending_removes(&self, guid: Id) -> Result<Vec<Nid>, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.pending_removes
				.lock()
				.await
				.get(&guid)
				.cloned()
				.unwrap_or(vec![]))
		}
	}

	// mark this group as pending leave for MYSELF; once my own LEAVE message arrives, delete it
	async fn mark_as_pending_leave(
		&self,
		guid: Id,
		pending: bool,
		req_id: Id,
	) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut pls = self.pending_leaves.lock().await;

			if pending {
				pls.insert(guid, req_id);
			} else {
				pls.retain(|k, v| !(*k == guid && *v == req_id));
			}

			Ok(())
		}
	}
	async fn is_pending_leave(&self, guid: Id, req_id: Id) -> Result<bool, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.pending_leaves
				.lock()
				.await
				.get(&guid)
				.map_or(false, |r| *r == req_id))
		}
	}

	// increments "messages sent" counter for this epoch and returns the current value
	async fn inc_sent_msg_count(&self, guid: Id, epoch: u64) -> Result<u8, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut msgs_ctr = self.messages_sent_ctr.lock().await;
			let ctr = msgs_ctr
				.entry(guid)
				.or_insert(HashMap::new())
				.entry(epoch)
				.and_modify(|e| *e += 1)
				.or_insert(0);

			Ok(*ctr)
		}
	}

	// ensure admit refers to both, the sender and the guid when implementing the ffi layer
	async fn mark_as_pending_admit(
		&self,
		guid: Id,
		sender: Nid,
		pending: bool,
	) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			let mut admits = self.pending_admits.lock().await;

			if pending {
				admits.insert(guid, sender);
			} else {
				admits.retain(|k, v| !(*k == guid && *v == sender));
			}

			Ok(())
		}
	}
	async fn is_pending_admit(&self, guid: Id) -> Result<bool, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self.pending_admits.lock().await.get(&guid).is_some())
		}
	}

	async fn save_group(
		&self,
		group: &Group,
		uid: &Id,
		epoch: u64,
		_roster: Vec<Nid>,
	) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.groups
				.lock()
				.await
				.entry(uid.clone())
				.or_insert(BTreeMap::new())
				.insert(epoch, group.clone());

			Ok(())
		}
	}

	// delete all epochs for this group
	async fn delete_group(&self, guid: Id) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.groups.lock().await.remove(&guid);

			Ok(())
		}
	}

	async fn get_group(&self, uid: &Id, epoch: u64) -> Result<Group, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.groups
				.lock()
				.await
				.get(uid)
				.and_then(|epochs| epochs.get(&epoch))
				.ok_or(Error::NoGroupFound(*uid))?
				.clone())
		}
	}

	async fn get_latest_epoch_for_group(&self, guid: Id) -> Result<Group, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.groups
				.lock()
				.await
				.get(&guid)
				.and_then(|epochs| epochs.values().last())
				.ok_or(Error::NoGroupFound(guid))?
				.clone())
		}
	}
	// someone used my public keys to invite me
	async fn get_my_prekey(&self, id: Id) -> Result<prekey::KeyPair, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.prekeys
				.lock()
				.await
				.get(&id)
				.ok_or(Error::KeyPackageNotFound(id))?
				.clone())
		}
	}
	async fn delete_my_prekey(&self, id: Id) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.prekeys.lock().await.remove(&id);

			Ok(())
		}
	}
	// my static qydra identity used to create all groups
	async fn get_my_identity_key(&self) -> Result<hpksign::PrivateKey, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self.my_identity.private.clone())
		}
	}

	async fn get_identity_key(&self, nid: &Nid) -> Result<hpksign::PublicKey, Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			Ok(self
				.identities
				.lock()
				.await
				.get(&nid)
				.ok_or(Error::IdentityNotFound(*nid))?
				.clone())
		}
	}

	async fn save_identity_key(&self, nid: &Nid, key: &hpksign::PublicKey) -> Result<(), Error> {
		if self.locked {
			Err(Error::DbLocked)
		} else {
			self.identities.lock().await.insert(*nid, key.clone());

			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::MemStore;
	use qydra::{
		ed25519,
		group::{Group, Owner},
		hpksign,
		id::{Id, Identifiable},
		key_package,
		nid::Nid,
		prekey,
		proposal::{FramedProposal, Proposal},
		protocol::{Error, Storage},
	};
	use std::collections::HashMap;

	#[tokio::test]
	async fn test_lock_unlock() -> Result<(), Error> {
		let mut store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());

		store.lock(true);
		// this one should fail, since store is locked
		assert_eq!(
			store
				.save_nids(&vec![Nid::new(b"abcdefgh", 0), Nid::new(b"abcdefgh", 1)])
				.await,
			Err(Error::DbLocked)
		);

		store.lock(false);
		// from now on, store is unlocked, so all is good
		store
			.save_nids(&vec![Nid::new(b"abcdefgh", 0), Nid::new(b"abcdefgh", 1)])
			.await?;
		Ok(())
	}

	#[tokio::test]
	async fn test_get_set_remove_nids_for_nid() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());

		store
			.save_nids(&vec![Nid::new(b"abcdefgh", 0), Nid::new(b"abcdefgh", 1)])
			.await?;
		// this should not save anything
		store
			.save_nids(&vec![Nid::new(b"abcdefgh", 0), Nid::new(b"abcdefgh", 1)])
			.await?;
		// while this should
		store
			.save_nids(&vec![Nid::new(b"abcdefgh", 2), Nid::new(b"abcdefgh", 55)])
			.await?;

		assert_eq!(
			vec![
				Nid::new(b"abcdefgh", 0),
				Nid::new(b"abcdefgh", 1),
				Nid::new(b"abcdefgh", 2),
				Nid::new(b"abcdefgh", 55)
			],
			store.get_nids_for_nid(Nid::new(b"abcdefgh", 0)).await?
		);
		// device number is ignored as it should be
		assert_eq!(
			vec![
				Nid::new(b"abcdefgh", 0),
				Nid::new(b"abcdefgh", 1),
				Nid::new(b"abcdefgh", 2),
				Nid::new(b"abcdefgh", 55)
			],
			store.get_nids_for_nid(Nid::new(b"abcdefgh", 4)).await?
		);

		store.remove_nids(&vec![Nid::new(b"abcdefgh", 55)]).await?;

		assert_eq!(
			vec![
				Nid::new(b"abcdefgh", 0),
				Nid::new(b"abcdefgh", 1),
				Nid::new(b"abcdefgh", 2),
			],
			store.get_nids_for_nid(Nid::new(b"abcdefgh", 4)).await?
		);

		Ok(())
	}

	#[tokio::test]
	async fn test_should_process_rcvd() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());
		let id = Id([1u8; 32]);

		assert_eq!(store.should_process_rcvd(id).await, Ok(true));

		store.mark_rcvd_as_processed(id).await?;

		assert_eq!(store.should_process_rcvd(id).await, Ok(false));

		Ok(())
	}

	#[tokio::test]
	async fn test_save_get_delete_props() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());

		let group_a = Id([1u8; 32]);
		let group_b = Id([2u8; 32]);

		let p0 = FramedProposal::new(
			group_a,
			1,
			Nid::new(b"abcdefgh", 1),
			Proposal::Remove {
				id: Nid::new(b"aaaaaaaa", 0),
			},
			ed25519::Signature::new([33u8; 64]),
			qydra::hmac::Digest([44u8; 32]),
			qydra::proposal::Nonce([55u8; 4]),
		);
		let p1 = FramedProposal::new(
			group_a,
			1,
			Nid::new(b"abcdefgh", 1),
			Proposal::Remove {
				id: Nid::new(b"bbbbbbbb", 0),
			},
			ed25519::Signature::new([34u8; 64]),
			qydra::hmac::Digest([45u8; 32]),
			qydra::proposal::Nonce([55u8; 4]),
		);
		let p2 = FramedProposal::new(
			group_b,
			2,
			Nid::new(b"abcdefgh", 1),
			Proposal::Remove {
				id: Nid::new(b"cccccccc", 0),
			},
			ed25519::Signature::new([34u8; 64]),
			qydra::hmac::Digest([45u8; 32]),
			qydra::proposal::Nonce([55u8; 4]),
		);

		store
			.save_props(&vec![p0.clone()], 1, group_a, None)
			.await?;
		store
			.save_props(&vec![p1.clone()], 1, group_a, None)
			.await?;

		assert_eq!(store.get_prop_by_id(p0.id()).await, Ok(p0.clone()));

		assert!(store
			.get_props_for_epoch(group_a, 1, None)
			.await?
			.iter()
			.all(|p| vec![p0.clone(), p1.clone()].contains(p)));

		store
			.save_props(&vec![p2.clone()], 2, group_b, Some(Id([33u8; 32])))
			.await?;

		// wrong epoch
		assert_eq!(
			store.get_props_for_epoch(group_b, 1, None).await,
			Ok(vec![])
		);
		// wrong parent commit
		assert_eq!(
			store.get_props_for_epoch(group_b, 2, None).await,
			Ok(vec![])
		);
		// both ok
		assert_eq!(
			store
				.get_props_for_epoch(group_b, 2, Some(Id([33u8; 32])))
				.await,
			Ok(vec![p2])
		);

		store.delete_props(group_a, 1).await?;
		store.delete_props(group_b, 2).await?;

		assert_eq!(
			store.get_props_for_epoch(group_b, 1, None).await,
			Ok(vec![])
		);
		assert_eq!(
			store.get_props_for_epoch(group_b, 2, None).await,
			Ok(vec![])
		);
		assert_eq!(
			store
				.get_props_for_epoch(group_b, 2, Some(Id([33u8; 32])))
				.await,
			Ok(vec![])
		);

		Ok(())
	}

	#[tokio::test]
	async fn test_inc_sent_msg_count() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());
		let guid = Id([12u8; 32]);

		assert_eq!(store.inc_sent_msg_count(guid, 0).await, Ok(0));
		assert_eq!(store.inc_sent_msg_count(guid, 0).await, Ok(1));
		// ensure different groups don't collide
		assert_eq!(store.inc_sent_msg_count(Id([88u8; 32]), 0).await, Ok(0));
		// ensure different epochs don't collide either
		assert_eq!(store.inc_sent_msg_count(guid, 1).await, Ok(0));
		assert_eq!(store.inc_sent_msg_count(guid, 1).await, Ok(1));
		assert_eq!(store.inc_sent_msg_count(guid, 0).await, Ok(2));

		Ok(())
	}

	#[tokio::test]
	async fn test_pending_admit() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());

		let group_a = Id([11u8; 32]);
		let group_b = Id([21u8; 32]);
		let alice = Nid::new(b"aliceaal", 0);
		let bob = Nid::new(b"bobbobbo", 0);

		// so, by default, nothing is pending admit
		assert!(!store.is_pending_admit(group_a).await?);

		// alice marks group_a as pending admit
		store.mark_as_pending_admit(group_a, alice, true).await?;
		// which makes group_a pending admit, but keeps group_b intact
		assert!(store.is_pending_admit(group_a).await?);
		assert!(!store.is_pending_admit(group_b).await?);

		// pretend bob trying to admit what he should not
		store.mark_as_pending_admit(group_a, bob, false).await?;
		// so, nothing changes
		assert!(store.is_pending_admit(group_a).await?);
		assert!(!store.is_pending_admit(group_b).await?);

		// but if alice admits, it all goes as expected
		store.mark_as_pending_admit(group_a, alice, false).await?;
		assert!(!store.is_pending_admit(group_a).await?);

		// same for bob
		store.mark_as_pending_admit(group_b, bob, true).await?;
		assert!(store.is_pending_admit(group_b).await?);
		store.mark_as_pending_admit(group_b, bob, false).await?;
		assert!(!store.is_pending_admit(group_b).await?);

		Ok(())
	}

	#[tokio::test]
	async fn test_get_save_delete_group() -> Result<(), Error> {
		let store = MemStore::new(HashMap::new(), hpksign::KeyPair::generate());
		let seed = [12u8; 16];
		let alice_identity = hpksign::KeyPair::generate();
		let alice_kp = key_package::KeyPair::generate(&seed);
		let alice_id = Nid::new(b"aliceali", 0);
		let alice = Owner {
			id: alice_id.clone(),
			kp: alice_kp,
			identity: alice_identity.private,
		};

		// create a group and store it
		let mut group = Group::create(seed, alice);

		store
			.save_group(
				&group,
				&group.uid(),
				group.epoch(),
				group.roster().ids().clone(),
			)
			.await?;

		assert_eq!(
			store.get_group(&group.uid(), group.epoch()).await,
			Ok(group.clone())
		);

		let bob_id = Nid::new(b"bobbobbo", 0);
		let bob_identity = hpksign::KeyPair::generate();
		let bob_prekey = prekey::KeyPair::generate(&seed, &bob_identity.private);
		let bob_pk = prekey::PublicKey {
			kp: bob_prekey.kp.public.clone(),
			identity: bob_identity.public.clone(),
			sig: bob_prekey.sig.clone(),
		};
		let (add_bob_prop, _) = group.propose_add(bob_id, bob_pk).unwrap();
		let (update_alice_prop, _) = group.propose_update();
		let (edit_prop, _) = group.propose_edit(b"v1").unwrap();
		// alice invites using her initial group
		let (fc, _, ctds, _) = group
			.commit(&[
				add_bob_prop.clone(),
				update_alice_prop.clone(),
				edit_prop.clone(),
			])
			.unwrap();

		// add bob and store it
		let updated_group = group
			.process(
				&fc,
				ctds.first().unwrap().ctd.as_ref(),
				&[add_bob_prop, edit_prop, update_alice_prop],
			)
			.unwrap()
			.unwrap();

		// proposals and commits modify the source group, so here we have to manually save it (the protocol does it automatically)
		store
			.save_group(
				&group,
				&group.uid(),
				group.epoch(),
				group.roster().ids().clone(),
			)
			.await?;

		store
			.save_group(
				&updated_group,
				&updated_group.uid(),
				updated_group.epoch(),
				updated_group.roster().ids().clone(),
			)
			.await?;

		// updated group does not override the source group
		assert_eq!(
			store.get_group(&group.uid(), group.epoch()).await,
			Ok(group.clone())
		);
		assert_eq!(
			store
				.get_group(&updated_group.uid(), updated_group.epoch())
				.await,
			Ok(updated_group.clone())
		);

		// now, delete the group
		store.delete_group(group.uid()).await?;
		// which removes all epochs for the given group
		assert_eq!(
			store.get_group(&group.uid(), group.epoch()).await,
			Err(Error::NoGroupFound(group.uid()))
		);
		assert_eq!(
			store
				.get_group(&updated_group.uid(), updated_group.epoch())
				.await,
			Err(Error::NoGroupFound(updated_group.uid()))
		);

		Ok(())
	}
}

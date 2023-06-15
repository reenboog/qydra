use std::{
	collections::{BTreeMap, HashMap},
	sync::Arc,
};

use async_trait::async_trait;
use qydra::{
	commit::FramedCommit,
	group::Group,
	id::{Id, Identifiable},
	key_package,
	nid::Nid,
	proposal::FramedProposal,
	protocol::{self, Error},
};
use tokio::sync::Mutex;

pub struct Store {
	groups: Arc<Mutex<HashMap<Id, BTreeMap<u64, Group>>>>,
	nids: Arc<Mutex<Vec<Nid>>>,
	// (prop, parent_commit)
	props: Arc<Mutex<HashMap<Id, (FramedProposal, Option<Id>)>>>,
	commits: Arc<Mutex<HashMap<Id, FramedCommit>>>,
	processed: Arc<Mutex<Vec<Id>>>,
	pending_removes: Arc<Mutex<HashMap<Id, Vec<Nid>>>>,
	pending_leaves: Arc<Mutex<HashMap<Id, Id>>>,
	messages_sent_ctr: Arc<Mutex<HashMap<Id, HashMap<u64, u8>>>>,
	pending_admits: Arc<Mutex<HashMap<Id, Nid>>>,
}

impl Store {
	pub fn new() -> Self {
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
		}
	}
}

#[async_trait]
impl protocol::Storage for Store {
	async fn should_process_rcvd(&self, id: Id) -> bool {
		!self.processed.lock().await.contains(&id)
	}

	async fn mark_rcvd_as_processed(&self, id: Id) {
		let mut processed = self.processed.lock().await;

		if !processed.contains(&id) {
			processed.push(id)
		}
	}

	async fn save_group(
		&self,
		group: &Group,
		uid: &Id,
		epoch: u64,
		_roster: Vec<&Nid>,
	) -> Result<(), Error> {
		self.groups
			.lock()
			.await
			.entry(uid.clone())
			.or_insert(BTreeMap::new())
			.insert(epoch, group.clone());

		Ok(())
	}
	// delete all epochs for this group, all framed commits, all pending_remove-s
	async fn delete_group(&self, guid: Id) -> Result<(), Error> {
		self.groups.lock().await.remove(&guid);

		Ok(())
	}

	// gets all nids for the specified nid (including mine);
	// useful in case a device is added/removed between the tasks
	async fn get_nids_for_nid(&self, nid: Nid) -> Result<Vec<Nid>, Error> {
		Ok(self
			.nids
			.lock()
			.await
			.iter()
			.filter(|n| n.is_same_id(&nid))
			.cloned()
			.collect())
	}
	// add nids to the existing list of whatever is stored for nid
	async fn save_nids(&self, new: &[Nid]) -> Result<(), Error> {
		let mut all_nids = self.nids.lock().await;
		let to_add = new
			.iter()
			.filter(|e| !all_nids.contains(e))
			.collect::<Vec<_>>();

		all_nids.extend(to_add);

		Ok(())
	}
	// detaches nids from nid
	async fn remove_nids(&self, remove: &[Nid]) -> Result<(), Error> {
		self.nids.lock().await.retain(|n| !remove.contains(n));

		Ok(())
	}

	// parent_commit = None for update props or content_id for add/remove/edit commits otherwise
	async fn save_props(
		&self,
		props: &[FramedProposal],
		_epoch: u64,
		_guid: Id,
		parent_commit: Option<Id>,
	) -> Result<(), Error> {
		let mut locked = self.props.lock().await;

		props.into_iter().for_each(|fp| {
			locked.insert(fp.id(), (fp.clone(), parent_commit));
		});

		Ok(())
	}
	// Ok(Prop) | Err(UnknownProp)
	// IMPORTANT: respect parent_commit when fetching from the db
	async fn get_props_for_epoch(
		&self,
		guid: Id,
		epoch: u64,
		parent_commit: Option<Id>,
	) -> Result<Vec<FramedProposal>, Error> {
		Ok(self
			.props
			.lock()
			.await
			.iter()
			.filter(|(_, v)| v.0.guid == guid && v.0.epoch == epoch && v.1 == parent_commit)
			.map(|(_, v)| v.0.clone())
			.collect::<Vec<_>>())
	}
	async fn get_prop_by_id(&self, id: Id) -> Result<FramedProposal, Error> {
		Ok(self
			.props
			.lock()
			.await
			.get(&id)
			.map(|(fp, _)| fp.clone())
			.ok_or(Error::UnknownProp(id))?)
	}
	async fn delete_props(&self, guid: Id, epoch: u64) -> Result<(), Error> {
		self.props
			.lock()
			.await
			.retain(|_, v| !(v.0.guid == guid && v.0.epoch == epoch));

		Ok(())
	}

	async fn save_commit(&self, commit: &FramedCommit, id: Id, _guid: Id) -> Result<(), Error> {
		self.commits.lock().await.insert(id, commit.clone());

		Ok(())
	}
	// Ok(Commit) | Err(UnknownCommit)
	async fn get_commit(&self, id: Id) -> Result<FramedCommit, Error> {
		Ok(self
			.commits
			.lock()
			.await
			.get(&id)
			.cloned()
			.ok_or(Error::UnknownCommit(id))?)
	}
	// there should actually be just one commit per epoch, so it might change
	async fn delete_commits(&self, guid: Id, epoch: u64) -> Result<(), Error> {
		self.commits
			.lock()
			.await
			.retain(|_, v| !(v.guid == guid && v.epoch == epoch));

		Ok(())
	}

	// mark nid who previously sent LEAVE to remove during one of the next update cycles; do nothing if none found
	async fn mark_as_pending_remove(&self, guid: Id, pending: bool, nid: Nid) -> Result<(), Error> {
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
	async fn get_pending_removes(&self, guid: Id) -> Result<Vec<Nid>, Error> {
		Ok(self
			.pending_removes
			.lock()
			.await
			.get(&guid)
			.cloned()
			.unwrap_or(vec![]))
	}

	// mark this group as pending leave for MYSELF; once my own LEAVE message arrives, delete it
	async fn mark_as_pending_leave(
		&self,
		guid: Id,
		pending: bool,
		req_id: Id,
	) -> Result<(), Error> {
		let mut pls = self.pending_leaves.lock().await;

		if pending {
			pls.insert(guid, req_id);
		} else {
			pls.retain(|k, v| !(*k == guid && *v == req_id));
		}

		Ok(())
	}
	async fn is_pending_leave(&self, guid: Id, req_id: Id) -> Result<bool, Error> {
		Ok(self
			.pending_leaves
			.lock()
			.await
			.get(&guid)
			.map_or(false, |r| *r == req_id))
	}

	// increments "messages sent" counter for this epoch and returns the current value
	async fn inc_sent_msg_count(&self, guid: Id, epoch: u64) -> Result<u8, Error> {
		let mut msgs_ctr = self.messages_sent_ctr.lock().await;
		let ctr = msgs_ctr
			.entry(guid)
			.or_insert(HashMap::new())
			.entry(epoch)
			.and_modify(|e| *e += 1)
			.or_insert(0);

		Ok(*ctr)
	}

	// ensure admit refers to both, the sender and the guid when implementing the ffi layer
	async fn mark_as_pending_admit(
		&self,
		guid: Id,
		sender: Nid,
		pending: bool,
	) -> Result<(), Error> {
		let mut admits = self.pending_admits.lock().await;

		if pending {
			admits.insert(guid, sender);
		} else {
			admits.retain(|k, v| !(*k == guid && *v == sender));
		}

		Ok(())
	}
	async fn is_pending_admit(&self, guid: Id) -> Result<bool, Error> {
		Ok(self.pending_admits.lock().await.get(&guid).is_some())
	}

	async fn get_group(&self, uid: &Id, epoch: u64) -> Result<Group, Error> {
		Ok(self
			.groups
			.lock()
			.await
			.get(uid)
			.and_then(|epochs| epochs.get(&epoch))
			.ok_or(Error::NoGroupFound(*uid))?
			.clone())
	}
	async fn get_latest_epoch(&self, guid: Id) -> Result<Group, Error> {
		Ok(self
			.groups
			.lock()
			.await
			.get(&guid)
			.and_then(|epochs| epochs.values().last())
			.ok_or(Error::NoGroupFound(guid))?
			.clone())
	}
	// someone used my public keys to invite me
	async fn get_my_prekey_bundle(&self, id: Id) -> Result<key_package::KeyBundle, Error> {
		todo!()
	}
	async fn delete_my_prekey_bundle(&self, id: Id) -> Result<(), Error> {
		todo!()
	}
	// my static qydra identity used to create all groups
	// TODO: introduce an ephemeral package signed witha static identity?
	// TODO: should it accept my Nid?
	async fn get_my_identity_key_bundle(&self) -> Result<key_package::KeyBundle, Error> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	use super::Store;
	use qydra::{
		nid::Nid,
		protocol::{self, Storage},
	};

	#[tokio::test]
	async fn test_get_set_nids_for_nid() -> Result<(), protocol::Error> {
		let store = Store::new();

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

		Ok(())
	}
}

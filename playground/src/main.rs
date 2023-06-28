pub mod mem_api;
pub mod mem_store;

use futures::future;
use mem_api::MemApi;
use mem_store::MemStore;
use qydra::{
	hpksign, nid, prekey,
	protocol::{self, Storage},
	transport::ReceivedWelcome,
	transport::{
		self, ReceivedAdd, ReceivedAdmit, ReceivedCommit, ReceivedEdit, ReceivedLeave,
		ReceivedProposal, ReceivedRemove,
	},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

pub const PREKEYS_PER_USER: u8 = 10;
fn main() {}

pub struct Node {
	// stores: HashMap<nid::Nid, MemStore>,
	nid: nid::Nid,
	protocol: protocol::Protocol<MemStore, MemApi>,
	// keep it for external events
	store: Arc<MemStore>,
}

impl Node {
	pub async fn new(api: Arc<MemApi>, nid: nid::Nid) -> Self {
		let identity = hpksign::KeyPair::generate();
		let prekeys = protocol::gen_prekeys(&identity.private, PREKEYS_PER_USER);
		let store = Arc::new(MemStore::new(prekeys.clone(), identity.clone()));

		let identity = identity.public;
		let prekeys = prekeys
			.iter()
			.map(|pk| prekey::PublicKey {
				kp: pk.kp.public.clone(),
				identity: identity.clone(),
				sig: pk.sig.clone(),
			})
			.collect();

		let protocol = protocol::Protocol::new(store.clone(), api.clone(), 3, 5);

		api.register(nid, identity, prekeys).await;

		Self {
			nid,
			protocol,
			store,
		}
	}

	async fn add_to_address_book(&self, nids: &[nid::Nid]) {
		_ = self.store.save_nids(nids).await;
	}

	async fn remove_from_address_book(&self, nids: &[nid::Nid]) {
		_ = self.store.remove_nids(nids).await;
	}
}

pub async fn gen_nodes(id: nid::Cid, num_devices: u8, api: Arc<MemApi>) -> Vec<Node> {
	let nodes = future::join_all(
		(0..num_devices).map(|device| Node::new(api.clone(), nid::Nid::new(&id, device))),
	)
	.await;
	let nids = nodes
		.iter()
		.map(|node| node.nid.clone())
		.collect::<Vec<_>>();

	// link nodes to each other
	future::join_all(nodes.iter().map(|node| node.add_to_address_book(&nids))).await;

	nodes
}

#[cfg(test)]
mod tests {
	use crate::{gen_nodes, mem_api::MemApi, MemDelivery, Node};
	use futures::future;
	use qydra::{
		id::Id,
		nid,
		protocol::{Error, OnAdd, OnHandle, Processed, Storage},
		transport::{self, Received},
	};
	use rand::Rng;
	use std::{collections::HashMap, sync::Arc};

	// makes everyone send an arbitrary message to everyone else in the group
	// does not send updates or commits
	async fn ensure_encrypt_decrypt_works_from_everyone_to_everyone(
		nodes: &[&Node],
		guid: Id,
		messages_per_sender: usize,
		delivery: &MemDelivery,
	) -> Result<(), Error> {
		// messages should be unique, so add some randomly generated id to it
		let uid: [u8; 32] = rand::thread_rng().gen();
		let fmt = |idx: usize, nid: &nid::Nid| format!("hi N {} from {:?} {:?}", idx, nid, uid);

		for sender in nodes {
			for i in 0..messages_per_sender {
				let msg = fmt(i, &sender.nid);
				let snd = sender.protocol.encrypt_msg(msg.as_bytes(), guid).await?;

				delivery.send(snd.send).await;
			}

			for receiver in nodes {
				let rcvd = delivery.drain(receiver.nid).await;

				assert_eq!(rcvd.len(), messages_per_sender);

				for i in 0..messages_per_sender {
					let handled = receiver
						.protocol
						.handle_received(rcvd[i].clone(), sender.nid, receiver.nid)
						.await;

					if sender.nid == receiver.nid {
						// my own messages are always ignored
						assert!(matches!(
							handled,
							Err(Error::NoChangeRequired { guid: _, ctx: _ })
						))
					} else {
						if let Ok(OnHandle {
							sender,
							guid: _,
							outcome: Processed::Msg(m),
						}) = handled
						{
							assert_eq!(m, fmt(i, &sender).as_bytes());
						}
					}
				}
			}
		}

		Ok(())
	}

	#[tokio::test]
	async fn test_normal_flow() -> Result<(), Error> {
		let api = Arc::new(MemApi::new(HashMap::new(), HashMap::new()));
		let delivery = Arc::new(MemDelivery::new());

		let aaa = gen_nodes(b"aaaaaaaa".to_owned(), 3, api.clone()).await;
		let bbb = gen_nodes(b"bbbbbbbb".to_owned(), 2, api.clone()).await;
		let mut ccc = gen_nodes(b"cccccccc".to_owned(), 4, api.clone()).await;
		let ddd = gen_nodes(b"dddddddd".to_owned(), 2, api.clone()).await;
		let eee = gen_nodes(b"eeeeeeee".to_owned(), 2, api.clone()).await;

		let owner = &aaa[0];

		// make all aaas add all bbbs (but not bbb add all aaas)
		let bbb_to_add = vec![bbb[0].nid, bbb[1].nid];

		future::join_all(aaa.iter().map(|node| node.add_to_address_book(&bbb_to_add))).await;

		// it's sufficient to pass just one nid for each Node – the protocol will fetch the rest
		let (guid, snd) = owner
			.protocol
			// here I'm adding just one device of bbb, but the protocol will catch up the rest as long as I have them in my db
			.create_group(owner.nid, &vec![bbb[0].nid])
			.await?;

		// a1, a2, b0, b1
		if let transport::Send::Invite(ref invited) = snd {
			let invited = invited
				.wctds
				.iter()
				.map(|w| w.user_id)
				.collect::<Vec<nid::Nid>>();

			// the protocol adds my own devices and all the bbb's devices I'm aware of
			assert!(invited
				.iter()
				.all(|n| vec![aaa[1].nid, aaa[2].nid, bbb[0].nid, bbb[1].nid].contains(n)));
		} else {
			panic!("create_group failed: Send::Invite expected, got something else.");
		}

		// "send" this message to the backend
		delivery.send(snd).await;

		let rcvd = delivery.drain(owner.nid).await.clone();
		// there should be just one message for the owner (and for everyone actually)
		assert_eq!(rcvd.len(), 1);
		let rcvd = rcvd[0].clone();

		// the inviter also issues an admit message for everyone after processing this message
		let admit = if let Processed::Add(OnAdd {
			attached,
			detached,
			joined,
			left,
			admit,
		}) = owner
			.protocol
			.handle_received(rcvd, owner.nid, owner.nid)
			.await?
			.outcome
		{
			assert!(attached.contains(&nid::Nid::new(b"aaaaaaaa", 1)));
			assert!(attached.contains(&nid::Nid::new(b"aaaaaaaa", 2)));

			assert!(joined.contains(&nid::Nid::new(b"bbbbbbbb", 0)));
			assert!(joined.contains(&nid::Nid::new(b"bbbbbbbb", 1)));

			assert!(left.is_empty());
			assert!(detached.is_empty());

			admit.unwrap()
		} else {
			panic!("handle_received failed: expected a commit, got something else.")
		};

		// now, the owner amdits everyone
		delivery.send(admit).await;
		// and processes the admit (ignored on his end)
		assert!(matches!(
			owner
				.protocol
				.handle_received(
					delivery.drain(owner.nid).await[0].clone(),
					owner.nid,
					owner.nid
				)
				.await,
			Err(Error::NoChangeRequired { guid: _, ctx: _ })
		));

		// now aaa[1], aaa[2], bbbp[0] & bbb[1] process their messages
		for node in aaa.iter().skip(1).chain(bbb.iter()) {
			let rcvd = delivery.drain(node.nid).await;
			// there should be two messages: welcome and admit
			assert_eq!(rcvd.len(), 2);
			let wlcm = rcvd[0].clone();

			assert!(matches!(
				node.protocol
					.handle_received(wlcm, owner.nid, node.nid)
					.await?
					.outcome,
				Processed::Welcome
			));

			// ensure everyone has the same state
			let group = node.store.get_latest_epoch_for_group(guid).await?;
			let owner_group = owner.store.get_latest_epoch_for_group(guid).await?;

			// everyone should be waiting for an admission
			assert!(node.store.is_pending_admit(guid).await?);

			assert_eq!(group.epoch(), 1);
			assert_eq!(group.roster(), owner_group.roster());
			assert_eq!(group.conf_trans_hash(), owner_group.conf_trans_hash());
			assert_eq!(group.intr_trans_hash(), owner_group.intr_trans_hash());

			let admit = rcvd[1].clone();

			assert!(matches!(
				node.protocol
					.handle_received(admit, owner.nid, node.nid)
					.await?
					.outcome,
				Processed::Admit
			));

			// and the group is not pending admit anymore
			assert!(!node.store.is_pending_admit(guid).await?);
		}

		// and test if encryption works by making everyone send a few messages to everyone
		ensure_encrypt_decrypt_works_from_everyone_to_everyone(
			&[&aaa[0], &aaa[1], &aaa[2], &bbb[0], &bbb[1]],
			guid,
			2,
			&delivery,
		)
		.await?;

		// invite bbb[0] again and get an error, since he's invited
		assert!(matches!(
			owner
				.protocol
				.add(&vec![bbb[0].nid, bbb[1].nid], owner.nid, guid)
				.await,
			Err(Error::NoChangeRequired { guid: _, ctx: _ })
		));

		// now, add ccc to the group
		// but it will fail, since aaa doesn't have cccs in his address book, so internally nids_for_nids will be empty
		assert!(matches!(
			owner.protocol.add(&vec![ccc[0].nid], owner.nid, guid).await,
			Err(Error::NoChangeRequired { guid: _, ctx: _ })
		));

		// so, make aaa and bbb add just one real ccc and an `outdated` one - it'll make ccc add
		// his other devices when joining and remove the unused one
		let ccc_to_add = vec![ccc[0].nid, ccc[1].nid];
		future::join_all(aaa.iter().map(|node| node.add_to_address_book(&ccc_to_add))).await;
		// pretend ccc[1] is `deactivated` at the same time cccs are invited by aaa[0], by making the other cccs forget it
		ccc[0].remove_from_address_book(&[ccc[1].nid]).await;
		ccc[2].remove_from_address_book(&[ccc[1].nid]).await;
		ccc[3].remove_from_address_book(&[ccc[1].nid]).await;

		let snd = owner.protocol.add(&ccc_to_add, owner.nid, guid).await?;

		// send it to the server: this Send is sent to aaas, bbbs, ccc[0] and ccc[1] as well
		delivery.send(snd).await;

		let rcvd = delivery.drain(owner.nid).await.clone();
		// there should be just one message for the owner (and for everyone actually)
		assert_eq!(rcvd.len(), 1);
		let rcvd = rcvd[0].clone();

		let admit = if let Processed::Add(OnAdd {
			attached,
			detached,
			joined,
			left,
			admit,
		}) = owner
			.protocol
			.handle_received(rcvd, owner.nid, owner.nid)
			.await?
			.outcome
		{
			// so, aaa[0] is adding ccc[0] & ccc[1], but ccc[1] will be later removed by ccc[0] since it's `deactivated`
			assert_eq!(joined.len(), 2);
			assert!(joined.contains(&nid::Nid::new(b"cccccccc", 0)));
			assert!(joined.contains(&nid::Nid::new(b"cccccccc", 1)));

			assert!(left.is_empty());
			assert!(attached.is_empty());
			assert!(detached.is_empty());

			admit.unwrap()
		} else {
			panic!("handle_received failed: expected a commit, got something else.")
		};

		// now, the owner amdits ccc to everyone
		delivery.send(admit).await;
		// and processes the admit it's just sent (ignored on his end)
		assert!(matches!(
			owner
				.protocol
				.handle_received(
					delivery.drain(owner.nid).await[0].clone(),
					owner.nid,
					owner.nid,
				)
				.await,
			Err(Error::NoChangeRequired { guid: _, ctx: _ })
		));

		// now all remaining aaas and all bbbs will process aaa[0]'s add and admit
		for node in aaa.iter().skip(1).chain(bbb.iter()) {
			let rcvd = delivery.drain(node.nid).await;

			assert_eq!(rcvd.len(), 2);

			for rcv in rcvd {
				// first add then admit
				_ = node
					.protocol
					.handle_received(rcv, owner.nid, node.nid)
					.await;
			}

			// ensure everyone has the same state
			let group = node.store.get_latest_epoch_for_group(guid).await?;
			let owner_group = owner.store.get_latest_epoch_for_group(guid).await?;

			assert_eq!(owner_group.epoch(), 2);
			assert_eq!(group.epoch(), 2);
			assert_eq!(group.roster(), owner_group.roster());
			assert_eq!(group.conf_trans_hash(), owner_group.conf_trans_hash());
			assert_eq!(group.intr_trans_hash(), owner_group.intr_trans_hash());
		}

		let rcvd = delivery.drain(ccc[0].nid).await;
		assert_eq!(rcvd.len(), 2);

		// now ccc[0] handles aaa[0]'a welcome and nothing happens for now
		ccc[0]
			.protocol
			.handle_received(rcvd[0].clone(), owner.nid, ccc[0].nid)
			.await?;

		// and then an admit: now, since some devices are missing and some are deactivated, it's an error – NeedsAction
		if let Err(Error::NeedsAction(snd)) = ccc[0]
			.protocol
			.handle_received(rcvd[1].clone(), owner.nid, ccc[0].nid)
			.await
		{
			// this Send welcomes ccc's missing devices and removes the unused ones
			delivery.send(snd).await;
		} else {
			panic!("expected a send from ccc[0], fot something else");
		}

		// since ccc[1] is no more, ccc[0] did not include it in its previous Send, so remove it from the cccs list
		let removed = ccc.remove(1);

		// so, everyone but ccc[0] processes his welcome of ccc[2-3]
		for node in aaa.iter().chain(bbb.iter()).chain(ccc.iter().skip(1)) {
			let rcvd = delivery.drain(node.nid).await;
			assert_eq!(rcvd.len(), 1);

			let handled = node
				.protocol
				.handle_received(rcvd[0].clone(), ccc[0].nid, node.nid)
				.await?;

			if node.nid.is_same_id(&ccc[0].nid) {
				// welcome
				assert!(matches!(handled.outcome, Processed::Welcome));
			} else {
				// add
				if let Processed::Add(OnAdd {
					attached,
					detached,
					joined,
					left,
					admit,
				}) = handled.outcome
				{
					assert_eq!(attached.len(), 2);
					assert!(attached.contains(&nid::Nid::new(b"cccccccc", 2)));
					assert!(attached.contains(&nid::Nid::new(b"cccccccc", 3)));

					assert_eq!(detached.len(), 1);
					assert_eq!(detached[0], nid::Nid::new(b"cccccccc", 1));

					assert!(joined.is_empty());
					assert!(left.is_empty());
					assert!(admit.is_none());
				} else {
					panic!("expected add from ccc[0], but got something else");
				}
			}
		}

		let rcvd = delivery.drain(ccc[0].nid).await;
		assert_eq!(rcvd.len(), 1);

		// ccc[0] processes his own welcome and issues an admit for ccc[2-3]
		if let Processed::Add(OnAdd {
			attached: _,
			detached: _,
			joined: _,
			left: _,
			admit,
		}) = ccc[0]
			.protocol
			.handle_received(rcvd[0].clone(), ccc[0].nid, ccc[0].nid)
			.await?
			.outcome
		{
			delivery.send(admit.unwrap()).await;
		} else {
			panic!("expected an add from ccc[0], got something else");
		}

		// and now everyone processes this final admit
		for node in aaa.iter().chain(bbb.iter()).chain(ccc.iter()) {
			let rcvd = delivery.drain(node.nid).await;
			assert_eq!(rcvd.len(), 1);

			let handled = node
				.protocol
				.handle_received(rcvd[0].clone(), ccc[0].nid, node.nid)
				.await;

			// ccc[1-3] should be pending admit while others should not care
			if node.nid.is_same_id(&ccc[0].nid) && node.nid != ccc[0].nid {
				assert!(matches!(handled?.outcome, Processed::Admit));
			} else {
				assert!(matches!(
					handled,
					Err(Error::NoChangeRequired { guid: _, ctx: _ })
				));
			}
		}

		ensure_encrypt_decrypt_works_from_everyone_to_everyone(
			&[
				&aaa[0], &aaa[1], &aaa[2], &bbb[0], &bbb[1], &ccc[0], &ccc[1], &ccc[2],
			],
			guid,
			2,
			&delivery,
		)
		.await?;

		// and the removed ccc should have three messages to process, though it won't since it's
		// `deactivated`: aaa[0]'s initial welcome-admit and ccc[0]'s remove
		let rcvd = delivery.drain(removed.nid).await;
		assert_eq!(rcvd.len(), 3);

		matches!(rcvd[0], Received::Welcome(..));
		matches!(rcvd[1], Received::Admit(..));
		matches!(rcvd[2], Received::Remove(..));

		Ok(())
	}

	// test_a_device_is_attached_while_nid_is_being_added
	// test_a_device_is_detached_while_nid_is_being_added
	// test_a1-a2_are_added_but_a2_is_to_detach_and_a3_is_to_add
	// tes_a1-a2_are_added_a1_detaches_a2_and_adds_a3_on_post_admit_but_a3_is_added_sooner_so_add_returns_a2_to_detach
}

struct MemDelivery {
	//
	queue: Arc<Mutex<HashMap<nid::Nid, Vec<transport::Received>>>>,
}

impl MemDelivery {
	pub fn new() -> Self {
		Self {
			queue: Arc::new(Mutex::new(HashMap::new())),
		}
	}
	pub async fn send(&self, snd: transport::Send) {
		let mut queue = self.queue.lock().await;

		use transport::Received;
		use transport::Send;

		// FIXME: all case should handle pending remove (check Send::Invite)
		match snd {
			Send::Invite(i) => {
				// handle all welcomes
				i.wctds.iter().for_each(|w| {
					queue
						.entry(w.user_id)
						.or_insert(Vec::new())
						.push(Received::Welcome(ReceivedWelcome {
							cti: i.wcti.clone(),
							ctd: w.ctd.clone(),
							kp_id: w.kp_id,
						}))
				});
				// handle all invites (to commit)
				if let Some(invites) = i.add {
					invites.commit.ctds.iter().for_each(|ctd| {
						queue.entry(ctd.user_id).or_insert(Vec::new()).push({
							let props = ReceivedProposal {
								props: invites.props.clone(),
							};

							if let Some(ref ctd) = ctd.ctd {
								Received::Add(ReceivedAdd {
									props,
									commit: ReceivedCommit {
										cti: invites.commit.cti.clone(),
										ctd: ctd.clone(),
									},
								})
							} else {
								Received::Remove(ReceivedRemove {
									props,
									cti: invites.commit.cti.clone(),
									ctd: None,
								})
							}
						})
					});
				}
			}
			Send::Admit(a) => {
				a.greeting.recipients.iter().for_each(|nid| {
					queue
						.entry(*nid)
						.or_insert(Vec::new())
						.push(Received::Admit(ReceivedAdmit {
							id: a.id,
							welcome: a.greeting.payload.clone(),
						}))
				});
			}
			Send::Remove(r) => {
				r.commit.ctds.iter().for_each(|ctd| {
					queue
						.entry(ctd.user_id)
						.or_insert(Vec::new())
						.push(Received::Remove(ReceivedRemove {
							props: ReceivedProposal {
								props: r.props.clone(),
							},
							cti: r.commit.cti.clone(),
							ctd: ctd.ctd.clone(),
						}))
				});
			}
			Send::Edit(e) => {
				e.commit.ctds.iter().for_each(|ctd| {
					queue
						.entry(ctd.user_id)
						.or_insert(Vec::new())
						.push(Received::Edit(ReceivedEdit {
							props: ReceivedProposal {
								props: e.props.clone(),
							},
							commit: ReceivedCommit {
								cti: e.commit.cti.clone(),
								ctd: ctd.ctd.clone().unwrap(),
							},
						}))
				});
			}
			Send::Props(p) => {
				p.recipients.iter().for_each(|nid| {
					queue
						.entry(*nid)
						.or_insert(Vec::new())
						.push(Received::Props(ReceivedProposal {
							props: p.props.clone(),
						}))
				});
			}
			Send::Commit(c) => {
				c.ctds.iter().for_each(|ctd| {
					queue
						.entry(ctd.user_id)
						.or_insert(Vec::new())
						.push(Received::Commit(ReceivedCommit {
							cti: c.cti.clone(),
							ctd: ctd.ctd.clone().unwrap(),
						}))
				});
			}
			Send::Leave(l) => {
				l.farewell.recipients.iter().for_each(|nid| {
					queue
						.entry(*nid)
						.or_insert(Vec::new())
						.push(Received::Leave(ReceivedLeave {
							id: l.id,
							farewell: l.farewell.payload.clone(),
						}))
				});
			}
			Send::Msg(m) => {
				m.recipients.iter().for_each(|nid| {
					queue
						.entry(*nid)
						.or_insert(Vec::new())
						.push(Received::Msg(m.payload.clone()))
				});
			}
		}
	}

	pub async fn drain(&self, nid: nid::Nid) -> Vec<transport::Received> {
		self.queue.lock().await.remove(&nid).unwrap_or(Vec::new())
	}
}

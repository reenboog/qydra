use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use qydra::{
	hpksign,
	nid::Nid,
	prekey,
	protocol::{self, Error},
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MemApi {
	prekeys: Arc<Mutex<HashMap<Nid, Vec<prekey::PublicKey>>>>,
	identities: Arc<Mutex<HashMap<Nid, hpksign::PublicKey>>>,
}

impl MemApi {
	pub fn new(
		prekeys: HashMap<Nid, Vec<prekey::PublicKey>>,
		identities: HashMap<Nid, hpksign::PublicKey>,
	) -> Self {
		Self {
			prekeys: Arc::new(Mutex::new(prekeys)),
			identities: Arc::new(Mutex::new(identities)),
		}
	}

	// upload all prekeys
	pub async fn register(
		&self,
		nid: Nid,
		identity: hpksign::PublicKey,
		prekeys: Vec<prekey::PublicKey>,
	) {
		self.identities.lock().await.insert(nid, identity);
		self.prekeys
			.lock()
			.await
			.extend(vec![(nid, prekeys)].into_iter().collect::<HashMap<_, _>>());
	}
}

#[async_trait]
impl protocol::Api for MemApi {
	// returns init key packages for the specified nids; empty, if nids are empty
	async fn fetch_prekeys(&self, nids: &[Nid]) -> Result<Vec<prekey::PublicKey>, Error> {
		// in reality, at least one prekey should always be kept
		let mut keys = self.prekeys.lock().await;
		let mut res = Vec::new();

		for nid in nids {
			let entry = keys.get_mut(&nid).ok_or(Error::IdentityNotFound(*nid))?;
			let key = entry.pop().ok_or(Error::IdentityNotFound(*nid))?;

			res.push(key.clone());

			if entry.is_empty() {
				entry.push(key);
			}
		}

		Ok(res)
	}

	// invitees can use it to verify welcome messages; may be stored locally to speed things up and for TOFU purposes
	async fn fetch_identity_key(&self, nid: &Nid) -> Result<hpksign::PublicKey, Error> {
		self.identities
			.lock()
			.await
			.get(nid)
			.cloned()
			.ok_or(Error::IdentityNotFound(*nid))
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use qydra::{
		hpksign,
		nid::Nid,
		prekey,
		protocol::{self, Api, Error},
	};

	use crate::mem_api::MemApi;

	#[tokio::test]
	async fn test_api_fetch_prekey() -> Result<(), Error> {
		let alice = hpksign::KeyPair::generate();
		let alice_id = Nid::new(b"aaaaaaaa", 0);
		let alice_prekeys = protocol::gen_prekeys(&alice.private, 2);
		let bob_id = Nid::new(b"bbbbbbbb", 0);
		let bob = hpksign::KeyPair::generate();
		let bob_prekeys = protocol::gen_prekeys(&bob.private, 2);
		let prekeys: HashMap<Nid, Vec<prekey::PublicKey>> = vec![
			(
				alice_id,
				alice_prekeys
					.into_iter()
					.map(|pk| prekey::PublicKey {
						kp: pk.kp.public,
						identity: alice.public.clone(),
						sig: pk.sig,
					})
					.collect(),
			),
			(
				bob_id,
				bob_prekeys
					.into_iter()
					.map(|pk| prekey::PublicKey {
						kp: pk.kp.public,
						identity: bob.public.clone(),
						sig: pk.sig,
					})
					.collect(),
			),
		]
		.into_iter()
		.collect();
		let identities: HashMap<Nid, hpksign::PublicKey> =
			vec![(alice_id, alice.public), (bob_id, bob.public)]
				.into_iter()
				.collect();
		let api = MemApi::new(prekeys, identities);

		let keys_0 = api.fetch_prekeys(&vec![alice_id, bob_id]).await?;
		let keys_1 = api.fetch_prekeys(&vec![alice_id, bob_id]).await?;
		// I have only 2 sets of keys, so 2-3 will be using last resort keys basically
		let keys_2 = api.fetch_prekeys(&vec![alice_id, bob_id]).await?;
		let keys_3 = api.fetch_prekeys(&vec![alice_id, bob_id]).await?;

		assert_ne!(keys_0, keys_1);
		assert_eq!(keys_1, keys_2);
		assert_eq!(keys_2, keys_3);

		Ok(())
	}
}

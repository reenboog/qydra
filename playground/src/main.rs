pub mod mem_store;
use std::sync::Arc;

use mem_store::MemStore;
use qydra::{hpksign, protocol};

fn main() {
	// let prekeys_per_user = 10;
	// let alice = hpksign::KeyPair::generate();
	// let alice_prekeys = protocol::gen_prekeys(&alice.private, prekeys_per_user);
	// let bob = hpksign::KeyPair::generate();
	// let alice_store = MemStore::new(alice_prekeys, alice);
	// let protocol = protocol::Protocol::new(Arc::new(alice_store), api, 3, 5);
}

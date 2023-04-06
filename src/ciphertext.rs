use crate::{aes_gcm, dilithium, hash::Hash, hmac, id::Id};

#[derive(Clone, Copy)]
pub enum MsgType {
	Propose,
	Commit,
	App,
}

// TODO: add padding
pub struct Ciphertext {
	pub msg_type: MsgType,
	pub msg_id: Id,
	pub sender: Id,
	pub guid: Hash,
	pub epoch: u64,
	pub gen: u32,
	pub payload: Vec<u8>,
	pub iv: aes_gcm::Iv,
	pub tag: hmac::Digest,
	pub sig: dilithium::Signature,
}

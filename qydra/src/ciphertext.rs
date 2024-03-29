use crate::{aes_gcm, ed25519, hmac, id::Id, reuse_guard};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContentType {
	Msg,
	Propose,
	Commit,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ciphertext {
	pub content_id: Id,
	pub payload: Vec<u8>,
	pub guid: Id,
	pub epoch: u64,
	pub gen: u32,
	pub iv: aes_gcm::Iv,
	pub sig: ed25519::Signature,
	pub mac: hmac::Digest,
	pub reuse_grd: reuse_guard::ReuseGuard,
}

use crate::{aes_gcm, dilithium, hmac, id::Id, nid::Nid, reuse_guard};

#[derive(Debug, PartialEq)]
pub enum Error {
	UnknownContentType,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContentType {
	Msg,
	Propose,
	Commit,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ciphertext {
	pub content_type: ContentType,
	pub content_id: Id,
	pub payload: Vec<u8>,
	pub guid: Id,
	pub epoch: u64,
	pub gen: u32,
	pub sender: Nid,
	pub iv: aes_gcm::Iv,
	pub sig: dilithium::Signature,
	pub mac: hmac::Digest,
	pub reuse_grd: reuse_guard::ReuseGuard,
}

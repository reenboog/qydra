use crate::{aes_gcm, dilithium, hash::Hash, hmac, id::Id};

#[derive(Debug, PartialEq)]
pub enum Error {
	UnknownContentType,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContentType {
	App,
	Propose,
	Commit,
}

#[derive(Debug, PartialEq)]
pub struct Ciphertext {
	pub content_type: ContentType,
	pub content_id: Id,
	pub payload: Vec<u8>,
	pub guid: Hash,
	pub epoch: u64,
	pub gen: u32,
	pub sender: Id,
	pub iv: aes_gcm::Iv,
	pub sig: dilithium::Signature,
	pub mac: hmac::Digest,
}

use crate::{
	hash::{self, Hashable},
	id::{Id, Identifiable},
	serializable::{Deserializable, Serializable},
};
use sha2::Digest;
use sha2::Sha256;
use std::convert::Infallible;

#[derive(PartialEq, Debug, Clone)]
// wraps an arbitray message for use in group::encrypt/decrypt
pub struct Msg(pub Vec<u8>);

impl Hashable for Msg {
	fn hash(&self) -> hash::Hash {
		Sha256::digest(&self.0).into()
	}
}

impl Identifiable for Msg {
	fn id(&self) -> Id {
		Id(self.hash())
	}
}

impl Serializable for Msg {
	fn serialize(&self) -> Vec<u8> {
		self.0.clone()
	}
}

impl Deserializable for Msg {
	type Error = Infallible;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Ok(Msg(buf.to_vec()))
	}
}

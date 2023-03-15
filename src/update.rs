use crate::dilithium;

#[derive(Clone)]
pub struct PendingUpdate {
	pub dk: ilum::SecretKey,
	pub ssk: dilithium::PrivateKey,
}

impl PendingUpdate {
	pub fn new(dk: ilum::SecretKey, ssk: dilithium::PrivateKey) -> Self {
		Self { dk, ssk }
	}
}

use crate::dilithium;

#[derive(Clone)]
pub struct PendingUpdate {
	dk: ilum::SecretKey,
	ssk: dilithium::PrivateKey,
}

impl PendingUpdate {
	pub fn new(dk: ilum::SecretKey, ssk: dilithium::PrivateKey) -> Self {
		Self { dk, ssk }
	}
}

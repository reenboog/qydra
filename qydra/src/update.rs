use crate::{dilithium, x448};

#[derive(Clone, PartialEq, Debug)]
pub struct PendingUpdate {
	pub ilum_dk: ilum::SecretKey,
	pub x448_dk: x448::PrivateKey,
	pub ssk: dilithium::PrivateKey,
}

impl PendingUpdate {
	pub fn new(
		ilum_dk: ilum::SecretKey,
		x448_dk: x448::PrivateKey,
		ssk: dilithium::PrivateKey,
	) -> Self {
		Self {
			ilum_dk,
			x448_dk,
			ssk,
		}
	}
}

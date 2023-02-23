use sha2::Digest;
use sha2::Sha256;

use crate::hash;
use crate::hkdf;

// FIXME: wrap with structs to prevent type coersion

// these are ephemeral and used on the fly
pub type JoinerSecret = [u8; hash::SIZE];
pub type ConfirmationSecret = [u8; hash::SIZE];

// these should be persisted per epoch
pub type InitSecret = [u8; hash::SIZE];
pub type AppSecret = [u8; hash::SIZE];
pub type MacSecret = [u8; hash::SIZE];

pub struct EpochSecrets {
	init: InitSecret,
	app: AppSecret,
	mac: MacSecret,
}

// TODO: introduce a type for tcx?
pub fn derive_epoch_secrets(
	ctx: hash::Hash,
	joiner_secret: JoinerSecret,
) -> (EpochSecrets, ConfirmationSecret) {
	let digest = Sha256::digest([ctx, joiner_secret].concat());

	// TODO: introduce SIZE for each subkey?
	let init = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"init_secret");
	let app = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"app_secret");
	let mac = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"mac_secret");
	let conf = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"conf_secret");

	(EpochSecrets { init, app, mac }, conf)
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_derive_epoch_secrets() {
		// TODO: implement
	}
}

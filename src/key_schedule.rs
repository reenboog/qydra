use sha2::Digest;
use sha2::Sha256;

use crate::chain_tree::ChainTree;
use crate::ciphertext::ContentType;
use crate::hash;
use crate::hkdf;

// FIXME: wrap with structs to prevent type coersion

// these are ephemeral and used on the fly
pub type JoinerSecret = [u8; hash::SIZE]; // fed into the key schedule; everything is derived from it
pub type ConfirmationSecret = [u8; hash::SIZE];
pub type CommitSecret = [u8; hash::SIZE]; // sent to existing users; later applied to old.init to derive new.joiner

// these should be persisted per epoch
pub type InitSecret = [u8; hash::SIZE];
pub type MacSecret = [u8; hash::SIZE];
// TODO: introduce ResumptionSecret for session reinitialization?

const MAX_KEYS_TO_SKIP: u32 = 1000;

#[derive(Clone, PartialEq, Debug)]
pub struct EpochSecrets {
	pub init: InitSecret,
	pub mac: MacSecret, // TODO: get rid of me

	pub hs: ChainTree,
	pub app: ChainTree,
}

impl EpochSecrets {
	pub fn chain_tree_for_message_type(&mut self, msg_type: ContentType) -> &mut ChainTree {
		match msg_type {
			ContentType::Propose => &mut self.hs,
			ContentType::Commit => &mut self.hs,
			ContentType::App => &mut self.app,
		}
	}
}

// TODO: introduce a type for ctx?
pub fn derive_epoch_secrets(
	ctx: hash::Hash,
	joiner_secret: &JoinerSecret,
	group_size: u32,
) -> (EpochSecrets, ConfirmationSecret) {
	// TODO: introduce psk into the scheme?
	let digest = Sha256::digest([ctx.as_slice(), joiner_secret].concat());

	// TODO: introduce SIZE for each subkey?
	let init = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"init_secret");
	let app = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"app_secret");
	let mac = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"mac_secret");
	let conf = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"conf_secret");
	let hs = hkdf::Hkdf::from_ikm(&digest).expand::<{ hash::SIZE }>(b"hs_secret");

	(
		EpochSecrets {
			init,
			mac,
			app: ChainTree::try_new(group_size, app, MAX_KEYS_TO_SKIP).unwrap(),
			hs: ChainTree::try_new(group_size, hs, MAX_KEYS_TO_SKIP).unwrap(),
		},
		conf,
	)
}

pub fn derive_joiner(init_secret: &InitSecret, commit_secret: &CommitSecret) -> JoinerSecret {
	let digest = Sha256::digest([init_secret.as_slice(), commit_secret].concat());

	hkdf::Hkdf::from_ikm(&digest)
		.expand::<{ hash::SIZE }>(b"joiner_secret")
		.into()
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_derive_epoch_secrets() {
		// TODO: implement
	}
}

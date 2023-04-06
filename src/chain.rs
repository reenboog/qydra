use crate::{hash, hkdf::Hkdf, hmac};
use std::collections::HashMap;

/*
		 ...
			|
	chain_key[n-1] -> detached_key[n-1] -> { message_key[n-1], nonce[n-1] }
			|
	chain_key[n] -> detached_key[n] -> { message_key[n], nonce[n] }
			|
	chain_key[n+1] -> detached_key[n+1] -> { message_key[n+1], nonce[n+1] }
			|
		 ...
*/

#[derive(Debug, PartialEq)]
pub enum Error {
	KeyHasBeenUsed(u32), // generation key
	TooManyKeysSkipped,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct DetachedKey(pub hash::Hash);

impl DetachedKey {
	pub const SIZE: usize = 32;
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainKey(hash::Hash);

const HKDF_SALT: &[u8; hmac::Key::SIZE] = b"ChainChainChainChainChainChainCh";

impl ChainKey {
	pub fn detached(&self) -> DetachedKey {
		DetachedKey(Hkdf::from_ikm_salted(&self.0, HKDF_SALT).expand::<{ hash::SIZE }>(b"detached"))
	}

	pub fn next(&self) -> Self {
		Self(Hkdf::from_ikm_salted(&self.0, HKDF_SALT).expand::<{ hash::SIZE }>(b"next"))
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct Chain {
	// to preserve FS, we should only store intermediate *detached keys*, not chain keys and
	// and keep only the last chain key required to derive future message keys; from the detached keys
	// any subsequent keys and nonces can be derived
	pub skipped_keys: HashMap<u32, DetachedKey>,
	pub next_key: ChainKey,
	pub next_idx: u32,
	pub max_keys_to_skip: u32,
}

impl Chain {
	pub fn new(head: hash::Hash, max_keys_to_skip: u32) -> Self {
		Self {
			skipped_keys: HashMap::new(),
			next_key: ChainKey(head),
			next_idx: 0,
			max_keys_to_skip,
		}
	}

	// if FS is preserved, it would be impossible to send to myself given the key is consumed immediately;
	// hence a duplicate of this chain is to be used or the keys themselves should be stored (not required in most real cases)
	pub fn get(&mut self, idx: u32) -> Result<DetachedKey, Error> {
		if idx < self.next_idx {
			Ok(self
				.skipped_keys
				.remove(&idx)
				.ok_or(Error::KeyHasBeenUsed(idx))?)
		} else {
			let keys_to_skip = idx - self.next_idx;

			if keys_to_skip + self.skipped_keys.len() as u32 > self.max_keys_to_skip {
				Err(Error::TooManyKeysSkipped)
			} else {
				while self.next_idx <= idx {
					self.advance();
				}

				Ok(self.skipped_keys.remove(&idx).unwrap())
			}
		}
	}

	pub fn get_next(&mut self) -> Result<(DetachedKey, u32), Error> {
		let idx = self.next_idx;

		Ok((self.get(idx)?, idx))
	}

	fn advance(&mut self) {
		self.skipped_keys
			.insert(self.next_idx, self.next_key.detached());
		self.next_key = self.next_key.next();
		self.next_idx += 1;
	}
}

#[cfg(test)]
mod tests {
	use super::{Chain, Error};

	#[test]
	fn test_advance() {
		let mut ch = Chain::new([1u8; 32], 3);
		ch.advance();

		// ensure the first detached key is not equal to the first chain key
		assert_ne!(ch.next_key.0, ch.skipped_keys.get(&0).unwrap().0);

		ch.advance();
		ch.advance();
		ch.advance();

		// ensure subsequent keys are different as well
		assert_ne!(ch.skipped_keys.get(&0), ch.skipped_keys.get(&1));
		assert_ne!(ch.skipped_keys.get(&1), ch.skipped_keys.get(&2));
		assert_ne!(ch.skipped_keys.get(&3), ch.skipped_keys.get(&2));

		assert_eq!(ch.skipped_keys.len(), 4);
		assert_eq!(ch.next_idx, 4);
	}

	#[test]
	fn test_get() {
		let mut ch = Chain::new([1u8; 32], 3);

		assert_eq!(ch.skipped_keys.len(), 0);

		assert!(ch.get(3).is_ok());
		assert_eq!(ch.skipped_keys.len(), 3);
		assert_eq!(ch.next_idx, 4);
		assert!(ch.get(0).is_ok());
		assert_eq!(ch.skipped_keys.len(), 2);
		assert_eq!(ch.next_idx, 4);
		assert!(ch.get(2).is_ok());
		assert_eq!(ch.skipped_keys.len(), 1);
		assert_eq!(ch.next_idx, 4);
		assert!(ch.get(1).is_ok());
		assert_eq!(ch.skipped_keys.len(), 0);
		assert_eq!(ch.next_idx, 4);
	}

	#[test]
	fn test_get_next() {
		let mut ch0 = Chain::new([1u8; 32], 3);
		let mut ch1 = Chain::new([1u8; 32], 3);

		let k2 = ch0.get(2).unwrap();
		let k0 = ch0.get(0).unwrap();
		let k1 = ch0.get(1).unwrap();

		assert_eq!(ch1.get_next().unwrap().0, k0);
		assert_eq!(ch1.get_next().unwrap().0, k1);
		assert_eq!(ch1.get_next().unwrap().0, k2);
	}

	#[test]
	fn test_err_on_key_reuse() {
		let mut ch = Chain::new([1u8; 32], 3);

		assert!(ch.get(3).is_ok());
		assert!(ch.get(3).is_err());

		assert!(ch.get(1).is_ok());
		assert!(ch.get(1).is_err());
	}

	#[test]
	fn test_no_key_skip_allowed() {
		let mut ch = Chain::new([1u8; 32], 0);

		// one by one (no skipping) is just fine
		assert!(ch.get(0).is_ok());
		assert!(ch.get(1).is_ok());
		assert!(ch.get(2).is_ok());

		// while skipping is not
		assert!(ch.get(4).is_err());
		assert!(ch.get(5).is_err());

		// and back to normal order
		assert!(ch.get(3).is_ok());
	}

	#[test]
	fn test_skip_too_many_keys() {
		let mut ch = Chain::new([1u8; 32], 3);

		assert_eq!(ch.get(4).err(), Some(Error::TooManyKeysSkipped));
		assert!(ch.get(2).is_ok());

		assert_eq!(ch.get(10).err(), Some(Error::TooManyKeysSkipped));
		// previous state is preserved and no additional advancement takes place
		assert_eq!(ch.skipped_keys.len(), 2);
		assert_eq!(ch.next_idx, 3);
	}
}

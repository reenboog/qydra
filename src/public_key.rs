use crate::{id::Id, key::key};
use sha2::{Digest, Sha256};

key!(PublicKey);

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	pub fn id(&self) -> Id {
		Id(Sha256::digest(self.as_bytes()).into())
	}
}

#[cfg(test)]
mod tests {
	use crate::id::Id;
	use super::PublicKey;

	struct TestKeyType;
	type TestPublicKey = PublicKey<TestKeyType, 10>;

	#[test]
	fn test_id() {
		let key = TestPublicKey::new(b"0123456789".to_owned());
		let id = key.id();
		let target_id = b"\x84\xd8\x98\x77\xf0\xd4\x04\x1e\xfb\x6b\xf9\x1a\x16\xf0\x24\x8f\x2f\xd5\x73\xe6\xaf\x05\xc1\x9f\x96\xbe\xdb\x9f\x88\x2f\x78\x82".to_owned();

		assert_eq!(Id(target_id), id);
	}
}

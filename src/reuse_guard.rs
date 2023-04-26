use rand::Rng;

// a small mix-in applied to a slice (deterministic keys, ivs, etc) to avoid reuse attacks
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReuseGuard([u8; Self::SIZE]);

impl ReuseGuard {
	const SIZE: usize = 4;

	pub fn new() -> Self {
		Self(rand::thread_rng().gen())
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}

	pub fn apply_to(&self, slice: &[u8]) -> Vec<u8> {
		slice
			.iter()
			.enumerate()
			.map(|(i, &a)| a ^ self.0.get(i).unwrap_or(&0))
			.collect()
	}
}

impl TryFrom<Vec<u8>> for ReuseGuard {
	type Error = std::array::TryFromSliceError;

	fn try_from(val: Vec<u8>) -> Result<Self, Self::Error> {
		Ok(Self(val.as_slice().try_into()?))
	}
}

impl From<[u8; Self::SIZE]> for ReuseGuard {
	fn from(val: [u8; Self::SIZE]) -> Self {
		Self(val)
	}
}

#[cfg(test)]
mod tests {
	use crate::reuse_guard::ReuseGuard;
	use rand::Rng;

	#[test]
	fn test_unmask_on_reuse() {
		let grd = ReuseGuard::new();
		let slice: [u8; 10] = rand::thread_rng().gen();

		assert_ne!(slice, grd.apply_to(&slice).as_slice());
		assert_eq!(slice, grd.apply_to(&grd.apply_to(&slice)).as_slice());
	}

	#[test]
	fn test_try_from() {
		assert!(ReuseGuard::try_from(vec![1, 2, 3, 4]).is_ok());
		assert!(ReuseGuard::try_from(vec![1, 2,]).is_err());
		assert!(ReuseGuard::try_from(vec![]).is_err());
	}

	#[test]
	fn test_apply_to_an_equal_slice() {
		let grd = ReuseGuard::from([1, 2, 3, 4]);
		let slice = vec![5, 6, 7, 8];

		assert_eq!(grd.apply_to(&slice), vec![4, 4, 4, 12]);
	}

	#[test]
	fn test_apply_to_a_larger_slice() {
		let grd = ReuseGuard::from([5, 6, 7, 8]);
		let slice = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

		assert_eq!(
			grd.apply_to(&slice),
			vec![4, 4, 4, 12, 5, 6, 7, 8, 9, 10, 11, 12]
		);
	}

	#[test]
	fn test_apply_to_a_smaller_slice() {
		let slice = vec![1, 2];
		let grd = ReuseGuard::from([5, 6, 7, 8]);

		assert_eq!(grd.apply_to(&slice), vec![4, 4]);
	}
}

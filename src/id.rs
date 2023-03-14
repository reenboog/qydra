#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Id(pub [u8; Self::SIZE]);

impl Id {
	pub const SIZE: usize = 32;
}

impl Id {
	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

pub type Hash = [u8; SIZE];

pub const SIZE: usize = 32;

pub fn empty() -> Hash {
	[0u8; SIZE]
}

pub trait Hashable {
	fn hash(&self) -> Hash;
}

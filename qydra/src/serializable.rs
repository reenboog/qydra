pub trait Serializable {
	fn serialize(&self) -> Vec<u8>;
}

pub trait Deserializable {
	type Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized;
}

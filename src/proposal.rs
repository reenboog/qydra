use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac::Digest,
	key_package::KeyPackage,
	member::Id,
};

// TODO: serialize in order to be framed
pub enum Proposal {
	Add { id: Id, kp: KeyPackage },
	Remove { id: Id },
	Update { kp: KeyPackage }, // id as well? TODO: introduce `proactive` updates to consume other people's prekeys
}

impl Hashable for Proposal {
	fn hash(&self) -> Hash {
		use sha2::{Digest, Sha256};

		let bytes = match self {
			Proposal::Add { id, kp } => [id.as_bytes().as_slice(), &kp.hash()].concat(),
			Proposal::Remove { id } => id.as_bytes().to_vec(),
			Proposal::Update { kp } => kp.hash().to_vec(),
		};

		Sha256::digest(bytes).into()
	}
}

pub struct FramedProposal {
	pub guid: Hash,
	pub epoch: u64,
	pub interim_trans_hash: Hash, // why do I need this here? do I validate it somewhere?
	pub sender: Id,
	pub prop: Proposal,
	pub sig: Signature, // signed with ssk (not updated upon rekey currently)
	pub mac: Digest,
}

impl FramedProposal {
	pub fn new(
		guid: Hash,
		epoch: u64,
		interim_trans_hash: Hash,
		sender: Id,
		prop: Proposal,
		sig: Signature,
		mac: Digest,
	) -> Self {
		Self {
			guid,
			epoch,
			interim_trans_hash,
			sender,
			prop,
			sig,
			mac,
		}
	}

	pub fn id(&self) -> Id {
		use sha2::{Digest, Sha256};

		Id(Sha256::digest(
			[
				&self.guid,
				self.epoch.to_be_bytes().as_slice(),
				&self.interim_trans_hash,
				self.sender.as_bytes(),
				&self.prop.hash(),
				self.sig.as_bytes(),
				self.mac.as_bytes(),
			]
			.concat(),
		)
		.into())
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn tedst_id() {
		// TODO: implement
	}

	#[test]
	fn test_hash_proposal() {
		// TODO: implement
		// compare same and different cases
	}
}

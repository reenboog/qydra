use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac::Digest,
	key_package::KeyPackage,
	member::Id,
};

// TODO: serialize in order to be framed
#[derive(Clone)]
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

pub struct Nonce(pub [u8; 4]);

pub struct FramedProposal {
	pub guid: Hash,
	pub epoch: u64,
	pub sender: Id,
	pub prop: Proposal,
	pub sig: Signature, // signed with ssk (not updated upon rekey currently)
	pub mac: Digest,
	pub nonce: Nonce, // mixed with the mac_key to prevent key reuse
}

// groupCount is what I have now; it is not sent – it's just signed!
// P is delta to apply

// 0: groupCont ← (G.groupid, G.epoch, G.memberHash, G.confTransHash)
// 1: propCont ← (G.groupCont(), G.id, ‘proposal’, P) // This is macked and signed
// 2: sig ← SIG.Sign(ppSIG, G.ssk, propCont)
// 3: membTag ← MAC.TagGen(G.membKey, (propCont, sig))
// 4: return (G.groupid, G.epoch, G.id, ‘proposal’, P, sig, membTag)

impl FramedProposal {
	pub fn new(
		guid: Hash,
		epoch: u64,
		sender: Id,
		prop: Proposal,
		sig: Signature,
		mac: Digest,
		nonce: Nonce,
	) -> Self {
		Self {
			guid,
			epoch,
			sender,
			prop,
			sig,
			mac,
			nonce,
		}
	}

	pub fn id(&self) -> Id {
		use sha2::{Digest, Sha256};

		Id(Sha256::digest(
			[
				&self.guid,
				self.epoch.to_be_bytes().as_slice(),
				self.sender.as_bytes(),
				&self.prop.hash(),
				self.sig.as_bytes(),
				self.mac.as_bytes(),
				&self.nonce.0,
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

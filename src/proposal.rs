use crate::{dilithium::Signature, hash::Hash, hmac::Digest, key_package::KeyPackage, member::Id};

// TODO: serialize in order to be framed
pub enum Proposal {
	Add { id: Id, kp: KeyPackage },
	Remove { id: Id },
	Update { kp: KeyPackage }, // id as well? TODO: introduce `proactive` updates to consume other people's prekeys
}

pub struct FramedProposal {
	pub guid: Hash,
	pub epoch: u64,
	pub interim_trans_hash: Hash,
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
		// return hashPack(
		// 	pad,
		// 	PropIdHashId,
		// 	fp.GroupId,
		// 	packUint(fp.Epoch),
		// 	fp.InterimTransHash,
		// 	[]byte(fp.Id),
		// 	fp.P.Pack(pad),
		// 	fp.Sig,
		// 	fp.MembTag,
		// )

		todo!()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn tedst_id() {
		// TODO: implement
	}
}

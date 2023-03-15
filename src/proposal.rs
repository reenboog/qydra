use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac::Digest,
	id::Id,
	key_package::KeyPackage,
};

// TODO: serialize in order to be framed
#[derive(Clone)]
pub enum Proposal {
	Update { kp: KeyPackage }, // id as well? TODO: introduce `proactive` updates to consume other people's prekeys
	Remove { id: Id },
	Add { id: Id, kp: KeyPackage },
}

// Recovery: No need for a proposal, because the assumption is that group members no longer share the same state.
// Any party that wants to recover the group can create a new group and indicate that they want to include a PSK derived from the recovery_secret of some last known good epoch.

// REVIEW: updates can be lazy and potentially lost while add/remove proposals are to be sent in a commit itself

/*

It contains multiple Update and/or Remove proposals that apply to
	the same leaf. If the committer has received multiple such
	proposals they SHOULD prefer any Remove received, or the most
	recent Update if there are no Removes.

It contains multiple Add proposals that contain KeyPackages that
	represent the same client according to the application (for
	example, identical signature keys)


A group member that has observed one or more valid proposals within
	an epoch MUST send a Commit message before sending application data.
	This ensures, for example, that any members whose removal was
	proposed during the epoch are actually removed before any
	application data is transmitted.


Due to the asynchronous nature of proposals, receivers of a Commit
	SHOULD NOT enforce that all valid proposals sent within the current
	epoch are referenced by the next Commit. In the event that a valid
	proposal is omitted from the next Commit, and that proposal is still
	valid in the current epoch, the sender of the proposal MAY resend it
	after updating it to reflect the current epoch.

*/

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

#[derive(Clone)]
pub struct Nonce(pub [u8; 4]);

#[derive(Clone)]
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

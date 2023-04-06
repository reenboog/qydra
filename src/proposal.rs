use crate::{
	dilithium::Signature,
	hash::{Hash, Hashable},
	hmac::Digest,
	id::{Id, Identifiable},
	key_package::KeyPackage,
};

#[derive(Clone, PartialEq, Debug)]
pub enum Proposal {
	Remove { id: Id },
	Update { kp: KeyPackage },
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

#[derive(Clone, PartialEq, Debug)]
pub struct Nonce(pub [u8; 4]);

#[derive(Clone, PartialEq, Debug)]
// almost the whole structure can be encrypted with the current hs chain
// non encrypted FC should be stored alongside with its encrypted counterpart in order to call `commit`
// otherwise, its corresponding chain_tree entry will be consumed immediately when encrypting and decrypting my
// own proposal wouldn't be possible (unless a copy of my hs encryption chain is employed)
pub struct FramedProposal {
	pub guid: Hash,
	pub epoch: u64,
	pub sender: Id,
	pub prop: Proposal,
	// FIXME: should I use ECC inside instead, so that PQ would be applied to the outer layer while
	// ECC will be used in the internal layer for efficiency?
	pub sig: Signature, // signed with ssk (not updated upon rekey currently); do I need this as well? I could verify the encrypted content instead
	pub mac: Digest,    // do I need this? I'll be encrypting this prop anyway
	pub nonce: Nonce, // mixed with the mac_key to prevent key reuse; but should it be mac-ed with a hs chain actually?
}

// a validated by a group proposal
pub struct UnframedProposal {
	pub id: Id,
	pub sender: Id,
	pub prop: Proposal,
}

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
}

impl Identifiable for FramedProposal {
	fn id(&self) -> Id {
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

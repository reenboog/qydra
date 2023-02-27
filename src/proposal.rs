use crate::{key_package::KeyPackage, member::Id};

// TODO: serialize in order to be framed
pub enum Proposal {
	Add { id: Id, kp: KeyPackage },
	Remove { id: Id },
	Update { kp: KeyPackage }, // id as well?
}

pub struct FramedProposal {
	// GroupId          []byte
	// Epoch            uint
	// InterimTransHash []byte // do I need to check it in unframe_commit actually? sig & tag are checled anyway; maybe include conf_trans_hash instead and check if it's derived properly?
	// Id               string // sender id
	// P                Proposal
	// Sig              []byte
	// MembTag          []byte
}

impl FramedProposal {
	pub fn new(p: Proposal) -> Self {
		// TODO: implement
		Self {}
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

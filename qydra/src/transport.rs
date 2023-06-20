use crate::{
	ciphertext::Ciphertext,
	commit::CommitCtd,
	hash,
	hpkencrypt::CmpdCtd,
	id::{Id, Identifiable},
	nid::Nid,
	welcome::WlcmCtd,
	welcome::WlcmCti,
};

#[derive(PartialEq, Debug, Clone)]
pub struct SendCommit {
	pub cti: Ciphertext,
	pub ctds: Vec<CommitCtd>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendAdd {
	pub props: Vec<Ciphertext>,
	pub commit: SendCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendInvite {
	pub wcti: WlcmCti,
	pub wctds: Vec<WlcmCtd>,
	pub add: Option<SendAdd>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendRemove {
	pub props: Vec<Ciphertext>,
	pub commit: SendCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendEdit {
	pub props: Vec<Ciphertext>,
	pub commit: SendCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendProposal {
	pub props: Vec<Ciphertext>,
	pub recipients: Vec<Nid>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendMsg {
	pub payload: Ciphertext,
	pub recipients: Vec<Nid>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendLeave {
	pub farewell: SendMsg,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendAdmit {
	pub greeting: SendMsg,
}

#[derive(Debug, PartialEq)]
pub enum Send {
	Invite(SendInvite),
	Admit(SendAdmit),
	Remove(SendRemove),
	Edit(SendEdit),
	Props(SendProposal),
	Commit(SendCommit),
	Leave(SendLeave),
	Msg(SendMsg),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedWelcome {
	pub cti: WlcmCti,
	pub ctd: CmpdCtd,
	pub kp_id: Id,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedCommit {
	pub cti: Ciphertext,
	pub ctd: CmpdCtd,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedProposal {
	pub props: Vec<Ciphertext>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedAdd {
	pub props: ReceivedProposal,
	pub commit: ReceivedCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedRemove {
	pub props: ReceivedProposal,
	pub cti: Ciphertext,
	pub ctd: Option<CmpdCtd>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedEdit {
	pub props: ReceivedProposal,
	pub commit: ReceivedCommit,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Received {
	Welcome(ReceivedWelcome),
	Add(ReceivedAdd),
	Admit(Ciphertext),
	Remove(ReceivedRemove),
	Edit(ReceivedEdit),
	Props(ReceivedProposal),
	Commit(ReceivedCommit),
	Leave(Ciphertext),
	Msg(Ciphertext),
}

impl Identifiable for Received {
	fn id(&self) -> Id {
		match self {
			Received::Welcome(wlcm) => wlcm.cti.id(),
			Received::Add(add) => add.commit.cti.content_id,
			Received::Admit(admt) => admt.content_id,
			Received::Remove(rmv) => rmv.cti.content_id,
			Received::Edit(edit) => edit.commit.cti.content_id,
			Received::Props(props) => props
				.props
				.first()
				.map_or(Id(hash::empty()), |p| p.content_id),
			Received::Commit(cmt) => cmt.cti.content_id,
			Received::Leave(leave) => leave.content_id,
			Received::Msg(msg) => msg.content_id,
		}
	}
}

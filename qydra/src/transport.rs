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
use rand::Rng;

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
	pub id: Id,
}

impl SendLeave {
	pub fn new(farewell: SendMsg) -> Self {
		Self {
			farewell,
			id: Id(rand::thread_rng().gen()),
		}
	}
}

#[derive(PartialEq, Debug, Clone)]
pub struct SendAdmit {
	pub greeting: SendMsg,
	pub id: Id,
}

impl SendAdmit {
	pub fn new(greeting: SendMsg) -> Self {
		Self {
			greeting,
			id: Id(rand::thread_rng().gen()),
		}
	}
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
pub struct ReceivedAdmit {
	pub id: Id,
	pub welcome: Ciphertext,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReceivedLeave {
	pub id: Id,
	pub farewell: Ciphertext,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Received {
	Welcome(ReceivedWelcome),
	Add(ReceivedAdd),
	Admit(ReceivedAdmit),
	Remove(ReceivedRemove),
	Edit(ReceivedEdit),
	Props(ReceivedProposal),
	Commit(ReceivedCommit),
	Leave(ReceivedLeave),
	Msg(Ciphertext),
}

impl Identifiable for Received {
	fn id(&self) -> Id {
		match self {
			Received::Welcome(wlcm) => wlcm.cti.id(),
			Received::Add(add) => add.commit.cti.content_id,
			Received::Admit(admt) => admt.id,
			Received::Remove(rmv) => rmv.cti.content_id,
			Received::Edit(edit) => edit.commit.cti.content_id,
			Received::Props(props) => props
				.props
				.first()
				// FIXME: implement somehow different?
				.map_or(Id(hash::empty()), |p| p.content_id),
			Received::Commit(cmt) => cmt.cti.content_id,
			Received::Leave(leave) => leave.id,
			Received::Msg(msg) => msg.content_id,
		}
	}
}

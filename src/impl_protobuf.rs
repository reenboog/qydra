include!(concat!(env!("OUT_DIR"), "/main.rs"));

use std::collections::{BTreeMap, HashMap};

use crate::{
	aes_gcm, chain, chain_tree, ciphertext, commit, dilithium, group, hash, hpkencrypt, id,
	key_package, key_schedule, member, nid, proposal, roster, secret_tree,
	serializable::{Deserializable, Serializable},
	transport, treemath, update, welcome,
};
use prost::Message;

#[derive(Debug, PartialEq)]
pub enum Error {
	BadFormat,
	WrongIlumKeySize,
	WrongX448KeySize,
	WrongDilithiumKeySize,
	WrongDilithiumSigSize,
	WrongIdSize,
	WrongNidSize,
	BadKeyPackageFormat,
	BadMemberFormat,
	BadRosterFormat,
	WrongGuidSize,
	WrongConfTransHashSize,
	WrongInterimTransHashSize,
	WrongConfTagSize,
	WrongJoinerSize,
	BadGroupInfoFormat,
	BadProposalFormat,
	WrongMacSize,
	WrongNonceSize,
	WrongReuseGuardSize,
	BadFramedProposalFormat,
	WrongCtiSize,
	WrongCtdSize,
	WrongIvSize,
	BadCtiFormat,
	BadCtdFormat,
	BadWlcmCtiFormat,
	BadWlcmCtdFormat,
	BadCommitFormat,
	BadFramedCommitFormat,
	BadCommitCtdFormat,
	BadCiphertextFormat,
	WrongKeyPackageIdSize,
	BadSendCommitFormat,
	BadSendLeaveFormat,
	BadSendAddFormat,
	BadSendInviteFormat,
	BadSendRemoveFormat,
	BadSendEditFormat,
	BadSendProposalFormat,
	BadSendMsgFormat,
	BadSendFormat,
	BadReceivedWelcomeFormat,
	BadReceivedCommitFormat,
	BadReceivedLeaveFormat,
	BadReceivedProposalFormat,
	BadReceivedAddFormat,
	BadReceivedRemoveFormat,
	BadReceivedEditFormat,
	BadReceivedFormat,
	WrongDetachedKeySize,
	BadChainFormat,
	BadSecretTreeFormat,
	WrongSecretSize,
	WrongChainTree,
	BadChainTreeFormat,
	BadEpochSecretsFormat,
	WrongInitKeySize,
	WrongMacKeySize,
	BadPendingUpdateFormat,
	BadPendingCommitFormat,
	BadGroupFormat,
	WrongSeedSize,
}

// Chain
impl From<&chain::Chain> for Chain {
	fn from(val: &chain::Chain) -> Self {
		Self {
			skipped_keys: val
				.skipped_keys
				.iter()
				.map(|(k, v)| (*k, v.0.to_vec()))
				.collect(),
			next_key: val.next_key.as_bytes().to_vec(),
			next_idx: val.next_idx,
			max_keys_to_skip: val.max_keys_to_skip,
		}
	}
}

impl Serializable for chain::Chain {
	fn serialize(&self) -> Vec<u8> {
		Chain::from(self).encode_to_vec()
	}
}

impl TryFrom<Chain> for chain::Chain {
	type Error = Error;

	fn try_from(val: Chain) -> Result<Self, Self::Error> {
		Ok(Self {
			skipped_keys: val
				.skipped_keys
				.into_iter()
				.map(|(k, v)| {
					Ok((
						k,
						chain::DetachedKey(v.try_into().or(Err(Error::WrongDetachedKeySize))?),
					))
				})
				.collect::<Result<HashMap<u32, chain::DetachedKey>, Error>>()?,
			next_key: chain::ChainKey(
				val.next_key
					.try_into()
					.or(Err(Error::WrongDetachedKeySize))?,
			),
			next_idx: val.next_idx,
			max_keys_to_skip: val.max_keys_to_skip,
		})
	}
}

impl Deserializable for chain::Chain {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Chain::decode(buf).or(Err(Error::BadChainFormat))?)
	}
}

// SecretTree
impl From<&secret_tree::HkdfTree> for SecretTree {
	fn from(val: &secret_tree::HkdfTree) -> Self {
		Self {
			group_size: val.group_size.0,
			root: val.root.0,
			secrets: val.secrets.iter().map(|(k, v)| (k.0, v.to_vec())).collect(),
		}
	}
}

impl Serializable for secret_tree::HkdfTree {
	fn serialize(&self) -> Vec<u8> {
		SecretTree::from(self).encode_to_vec()
	}
}

impl TryFrom<SecretTree> for secret_tree::HkdfTree {
	type Error = Error;

	fn try_from(val: SecretTree) -> Result<Self, Self::Error> {
		Ok(Self {
			group_size: treemath::LeafCount(val.group_size),
			root: treemath::NodeIndex(val.root),
			secrets: val
				.secrets
				.iter()
				.map(|(k, v)| {
					Ok((
						treemath::NodeIndex(*k),
						v.clone().try_into().or(Err(Error::WrongSecretSize))?,
					))
				})
				.collect::<Result<BTreeMap<treemath::NodeIndex, hash::Hash>, Error>>()?,
			kdf: secret_tree::hkdf,
		})
	}
}

impl Deserializable for secret_tree::HkdfTree {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SecretTree::decode(buf).or(Err(Error::BadSecretTreeFormat))?)
	}
}

// ChainTree
impl From<&chain_tree::ChainTree> for ChainTree {
	fn from(val: &chain_tree::ChainTree) -> Self {
		Self {
			chains: val.chains.iter().map(|(k, v)| (k.0, v.into())).collect(),
			secret_tree: (&val.secret_tree).into(),
			max_keys_to_skip: val.max_keys_to_skip,
		}
	}
}

impl Serializable for chain_tree::ChainTree {
	fn serialize(&self) -> Vec<u8> {
		ChainTree::from(self).encode_to_vec()
	}
}

impl TryFrom<ChainTree> for chain_tree::ChainTree {
	type Error = Error;

	fn try_from(val: ChainTree) -> Result<Self, Self::Error> {
		Ok(Self {
			chains: val
				.chains
				.iter()
				.map(|(k, v)| {
					Ok((
						treemath::LeafIndex(*k),
						v.clone().try_into().or(Err(Error::BadChainFormat))?,
					))
				})
				.collect::<Result<BTreeMap<treemath::LeafIndex, chain::Chain>, Error>>()?,
			secret_tree: val
				.secret_tree
				.try_into()
				.or(Err(Error::BadSecretTreeFormat))?,
			max_keys_to_skip: val.max_keys_to_skip,
		})
	}
}

impl Deserializable for chain_tree::ChainTree {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ChainTree::decode(buf).or(Err(Error::BadChainTreeFormat))?)
	}
}

// EpochSecrets
impl From<&key_schedule::EpochSecrets> for EpochSecrets {
	fn from(val: &key_schedule::EpochSecrets) -> Self {
		Self {
			init: val.init.to_vec(),
			mac: val.mac.to_vec(),
			hs: (&val.hs).into(),
			app: (&val.app).into(),
		}
	}
}

impl Serializable for key_schedule::EpochSecrets {
	fn serialize(&self) -> Vec<u8> {
		EpochSecrets::from(self).encode_to_vec()
	}
}

impl TryFrom<EpochSecrets> for key_schedule::EpochSecrets {
	type Error = Error;

	fn try_from(val: EpochSecrets) -> Result<Self, Self::Error> {
		Ok(Self {
			init: val.init.try_into().or(Err(Error::WrongInitKeySize))?,
			mac: val.mac.try_into().or(Err(Error::WrongMacKeySize))?,
			hs: val.hs.try_into().or(Err(Error::BadChainTreeFormat))?,
			app: val.app.try_into().or(Err(Error::BadChainTreeFormat))?,
		})
	}
}

impl Deserializable for key_schedule::EpochSecrets {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(EpochSecrets::decode(buf).or(Err(Error::BadEpochSecretsFormat))?)
	}
}

// PendingUpdate
impl From<&update::PendingUpdate> for PendingUpdate {
	fn from(val: &update::PendingUpdate) -> Self {
		Self {
			ilum_dk: val.ilum_dk.to_vec(),
			x448_dk: val.x448_dk.as_bytes().to_vec(),
			ssk: val.ssk.as_bytes().to_vec(),
		}
	}
}

impl Serializable for update::PendingUpdate {
	fn serialize(&self) -> Vec<u8> {
		PendingUpdate::from(self).encode_to_vec()
	}
}

impl TryFrom<PendingUpdate> for update::PendingUpdate {
	type Error = Error;

	fn try_from(val: PendingUpdate) -> Result<Self, Self::Error> {
		Ok(Self {
			ilum_dk: val.ilum_dk.try_into().or(Err(Error::WrongIlumKeySize))?,
			x448_dk: val.x448_dk.try_into().or(Err(Error::WrongX448KeySize))?,
			ssk: val.ssk.try_into().or(Err(Error::WrongDilithiumKeySize))?,
		})
	}
}

impl Deserializable for update::PendingUpdate {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(PendingUpdate::decode(buf).or(Err(Error::BadPendingUpdateFormat))?)
	}
}

// Group
impl From<&group::Group> for Group {
	fn from(val: &group::Group) -> Self {
		Self {
			uid: val.uid().as_bytes().to_vec(),
			epoch: val.epoch(),
			seed: val.seed().to_vec(),
			conf_trans_hash: val.conf_trans_hash().to_vec(),
			interim_trans_hash: val.intr_trans_hash().to_vec(),
			roster: val.roster().into(),
			pending_updates: val
				.pending_updates()
				.iter()
				.map(|(k, v)| PendingUpdateEntry {
					id: k.0.to_vec(),
					upd: v.into(),
				})
				.collect(),
			pending_commits: val
				.pending_commits()
				.iter()
				.map(|(k, v)| PendingCommitEntry {
					id: k.0.to_vec(),
					commit: v.into(),
				})
				.collect(),
			user_id: val.user_id().as_bytes().to_vec(),
			ilum_dk: val.ilum_dk().to_vec(),
			x448_dk: val.x448_dk().as_bytes().to_vec(),
			ssk: val.ssk().as_bytes().to_vec(),
			secrets: val.secrets().into(),
			description: val.description().to_vec(),
		}
	}
}

impl Serializable for group::Group {
	fn serialize(&self) -> Vec<u8> {
		Group::from(self).encode_to_vec()
	}
}

impl TryFrom<Group> for group::Group {
	type Error = Error;

	fn try_from(val: Group) -> Result<Self, Self::Error> {
		Ok(Self::new(
			id::Id(val.uid.try_into().or(Err(Error::WrongGuidSize))?),
			val.epoch,
			val.seed.try_into().or(Err(Error::WrongSeedSize))?,
			val.conf_trans_hash
				.try_into()
				.or(Err(Error::WrongConfTransHashSize))?,
			val.interim_trans_hash
				.try_into()
				.or(Err(Error::WrongInterimTransHashSize))?,
			val.roster.try_into().or(Err(Error::BadRosterFormat))?,
			val.pending_updates
				.iter()
				.map(|pu| {
					Ok((
						id::Id(pu.id.clone().try_into().or(Err(Error::WrongIdSize))?),
						pu.upd
							.clone()
							.try_into()
							.or(Err(Error::BadPendingUpdateFormat))?,
					))
				})
				.collect::<Result<HashMap<id::Id, update::PendingUpdate>, Error>>()?,
			val.pending_commits
				.iter()
				.map(|pc| {
					Ok((
						id::Id(pc.id.clone().try_into().or(Err(Error::WrongIdSize))?),
						pc.commit
							.clone()
							.try_into()
							.or(Err(Error::BadPendingCommitFormat))?,
					))
				})
				.collect::<Result<HashMap<id::Id, commit::PendingCommit>, Error>>()?,
			val.user_id.try_into().or(Err(Error::WrongNidSize))?,
			val.ilum_dk.try_into().or(Err(Error::WrongIlumKeySize))?,
			val.x448_dk.try_into().or(Err(Error::WrongX448KeySize))?,
			val.ssk.try_into().or(Err(Error::WrongDilithiumKeySize))?,
			val.secrets
				.try_into()
				.or(Err(Error::BadEpochSecretsFormat))?,
			val.description,
		))
	}
}

impl Deserializable for group::Group {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Group::decode(buf).or(Err(Error::BadGroupFormat))?)
	}
}

// PendingCommit
impl From<&commit::PendingCommit> for PendingCommit {
	fn from(val: &commit::PendingCommit) -> Self {
		Self {
			state: (&val.state).into(),
			proposals: val
				.proposals
				.iter()
				.map(|p| p.as_bytes().to_vec())
				.collect(),
		}
	}
}

impl Serializable for commit::PendingCommit {
	fn serialize(&self) -> Vec<u8> {
		PendingCommit::from(self).encode_to_vec()
	}
}

impl TryFrom<PendingCommit> for commit::PendingCommit {
	type Error = Error;

	fn try_from(val: PendingCommit) -> Result<Self, Self::Error> {
		Ok(Self {
			state: val.state.try_into().or(Err(Error::BadGroupFormat))?,
			proposals: val
				.proposals
				.into_iter()
				.map(|p| Ok(id::Id(p.try_into().or(Err(Error::WrongIdSize))?)))
				.collect::<Result<Vec<id::Id>, Error>>()?,
		})
	}
}

impl Deserializable for commit::PendingCommit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(PendingCommit::decode(buf).or(Err(Error::BadPendingCommitFormat))?)
	}
}

// KeyPackage
impl From<&key_package::KeyPackage> for KeyPackage {
	fn from(val: &key_package::KeyPackage) -> Self {
		Self {
			ilum_ek: val.ilum_ek.to_vec(),
			x448_ek: val.x448_ek.as_bytes().to_vec(),
			svk: val.svk.as_bytes().to_vec(),
			sig: val.sig.as_bytes().to_vec(),
		}
	}
}

impl Serializable for key_package::KeyPackage {
	fn serialize(&self) -> Vec<u8> {
		KeyPackage::from(self).encode_to_vec()
	}
}

impl TryFrom<KeyPackage> for key_package::KeyPackage {
	type Error = Error;

	fn try_from(val: KeyPackage) -> Result<Self, Self::Error> {
		Ok(Self {
			ilum_ek: val.ilum_ek.try_into().or(Err(Error::WrongIlumKeySize))?,
			x448_ek: val.x448_ek.try_into().or(Err(Error::WrongX448KeySize))?,
			svk: dilithium::PublicKey::try_from(val.svk).or(Err(Error::WrongDilithiumKeySize))?,
			sig: dilithium::Signature::new(
				val.sig.try_into().or(Err(Error::WrongDilithiumSigSize))?,
			),
		})
	}
}

impl Deserializable for key_package::KeyPackage {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(KeyPackage::decode(buf).or(Err(Error::BadKeyPackageFormat))?)
	}
}

// Member
impl From<&member::Member> for Member {
	fn from(val: &member::Member) -> Self {
		Self {
			id: val.id.as_bytes().to_vec(),
			kp: (&val.kp).into(),
		}
	}
}

impl Serializable for member::Member {
	fn serialize(&self) -> Vec<u8> {
		Member::from(self).encode_to_vec()
	}
}

impl TryFrom<Member> for member::Member {
	type Error = Error;

	fn try_from(val: Member) -> Result<Self, Self::Error> {
		Ok(Self::new(
			nid::Nid::try_from(val.id).or(Err(Error::WrongNidSize))?,
			val.kp.try_into().or(Err(Error::BadKeyPackageFormat))?,
		))
	}
}

impl Deserializable for member::Member {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Member::decode(buf).or(Err(Error::BadMemberFormat))?)
	}
}

// Roster
impl From<&roster::Roster> for Roster {
	fn from(val: &roster::Roster) -> Self {
		Self {
			members: val.members.values().map(|m| m.into()).collect(),
		}
	}
}

impl Serializable for roster::Roster {
	fn serialize(&self) -> Vec<u8> {
		Roster::from(self).encode_to_vec()
	}
}

impl TryFrom<Roster> for roster::Roster {
	type Error = Error;

	fn try_from(val: Roster) -> Result<Self, Self::Error> {
		let mut res = roster::Roster::new();

		for m in val.members {
			if let Ok(member) = member::Member::try_from(m) {
				_ = res.add(member);
			}
		}

		Ok(res)
	}
}

impl Deserializable for roster::Roster {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Roster::decode(buf).or(Err(Error::BadRosterFormat))?)
	}
}

// Info
impl From<&welcome::Info> for GroupInfo {
	fn from(val: &welcome::Info) -> Self {
		Self {
			guid: val.guid.as_bytes().to_vec(),
			epoch: val.epoch,
			roster: (&val.roster).into(),
			conf_trans_hash: val.conf_trans_hash.to_vec(),
			conf_tag: val.conf_tag.as_bytes().to_vec(),
			inviter: val.inviter.as_bytes().to_vec(),
			joiner: val.joiner.to_vec(),
			description: val.description.clone(),
		}
	}
}

impl Serializable for welcome::Info {
	fn serialize(&self) -> Vec<u8> {
		GroupInfo::from(self).encode_to_vec()
	}
}

impl TryFrom<GroupInfo> for welcome::Info {
	type Error = Error;

	fn try_from(val: GroupInfo) -> Result<Self, Self::Error> {
		Ok(Self::new(
			id::Id(val.guid.try_into().or(Err(Error::WrongGuidSize))?),
			val.epoch,
			val.roster.try_into().or(Err(Error::BadRosterFormat))?,
			val.conf_trans_hash
				.try_into()
				.or(Err(Error::WrongConfTransHashSize))?,
			val.conf_tag.try_into().or(Err(Error::WrongConfTagSize))?,
			nid::Nid::try_from(val.inviter).or(Err(Error::WrongNidSize))?,
			val.joiner.try_into().or(Err(Error::WrongJoinerSize))?,
			val.description,
		))
	}
}

impl Deserializable for welcome::Info {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(GroupInfo::decode(buf).or(Err(Error::BadGroupInfoFormat))?)
	}
}

// WlcmCti
impl From<&welcome::WlcmCti> for WlcmCti {
	fn from(val: &welcome::WlcmCti) -> Self {
		Self {
			cti: (&val.cti).into(),
			sig: val.sig.as_bytes().to_vec(),
		}
	}
}

impl Serializable for welcome::WlcmCti {
	fn serialize(&self) -> Vec<u8> {
		WlcmCti::from(self).encode_to_vec()
	}
}

impl TryFrom<WlcmCti> for welcome::WlcmCti {
	type Error = Error;

	fn try_from(val: WlcmCti) -> Result<Self, Self::Error> {
		Ok(Self {
			cti: val.cti.try_into().or(Err(Error::BadCtiFormat))?,
			sig: dilithium::Signature::new(
				val.sig.try_into().or(Err(Error::WrongDilithiumSigSize))?,
			),
		})
	}
}

impl Deserializable for welcome::WlcmCti {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(WlcmCti::decode(buf).or(Err(Error::BadWlcmCtiFormat))?)
	}
}

// WlcmCtd
impl From<&welcome::WlcmCtd> for WlcmCtd {
	fn from(val: &welcome::WlcmCtd) -> Self {
		Self {
			user_id: val.user_id.as_bytes().to_vec(),
			kp_id: val.kp_id.as_bytes().to_vec(),
			ctd: (&val.ctd).into(),
		}
	}
}

impl Serializable for welcome::WlcmCtd {
	fn serialize(&self) -> Vec<u8> {
		WlcmCtd::from(self).encode_to_vec()
	}
}

impl TryFrom<WlcmCtd> for welcome::WlcmCtd {
	type Error = Error;

	fn try_from(val: WlcmCtd) -> Result<Self, Self::Error> {
		Ok(Self {
			user_id: nid::Nid::try_from(val.user_id).or(Err(Error::WrongNidSize))?,
			kp_id: id::Id(val.kp_id.try_into().or(Err(Error::WrongKeyPackageIdSize))?),
			ctd: hpkencrypt::CmpdCtd::try_from(val.ctd).or(Err(Error::BadCtdFormat))?,
		})
	}
}

impl Deserializable for welcome::WlcmCtd {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(WlcmCtd::decode(buf).or(Err(Error::BadWlcmCtdFormat))?)
	}
}

// Proposal
impl From<&proposal::Proposal> for Prop {
	fn from(val: &proposal::Proposal) -> Self {
		use prop::Variant;
		use proposal::Proposal::*;

		Self {
			variant: Some(match val {
				Remove { id } => Variant::Remove(prop::Remove {
					id: id.as_bytes().to_vec(),
				}),
				Update { kp } => Variant::Update(prop::Update { kp: kp.into() }),
				Add { id, kp } => Variant::Add(prop::Add {
					id: id.as_bytes().to_vec(),
					kp: kp.into(),
				}),
				Edit { description } => Variant::Edit(prop::Edit {
					description: description.clone(),
				}),
			}),
		}
	}
}

impl Serializable for proposal::Proposal {
	fn serialize(&self) -> Vec<u8> {
		Prop::from(self).encode_to_vec()
	}
}

impl TryFrom<Prop> for proposal::Proposal {
	type Error = Error;

	fn try_from(val: Prop) -> Result<Self, Self::Error> {
		use prop::Variant;
		use proposal::Proposal::*;

		Ok(match val.variant.ok_or(Error::BadProposalFormat)? {
			Variant::Remove(r) => Remove {
				id: nid::Nid::try_from(r.id).or(Err(Error::WrongIdSize))?,
			},
			Variant::Update(u) => Update {
				kp: u.kp.try_into().or(Err(Error::BadKeyPackageFormat))?,
			},
			Variant::Add(a) => Add {
				id: nid::Nid::try_from(a.id).or(Err(Error::WrongIdSize))?,
				kp: a.kp.try_into().or(Err(Error::BadKeyPackageFormat))?,
			},
			Variant::Edit(e) => Edit {
				description: e.description,
			},
		})
	}
}

impl Deserializable for proposal::Proposal {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Prop::decode(buf).or(Err(Error::BadProposalFormat))?)
	}
}

// FramedProposal
impl From<&proposal::FramedProposal> for FramedProposal {
	fn from(val: &proposal::FramedProposal) -> Self {
		Self {
			guid: val.guid.as_bytes().to_vec(),
			epoch: val.epoch,
			sender: val.sender.as_bytes().to_vec(),
			prop: (&val.prop).into(),
			sig: val.sig.as_bytes().to_vec(),
			mac: val.mac.as_bytes().to_vec(),
			nonce: val.nonce.0.to_vec(),
		}
	}
}
impl Serializable for proposal::FramedProposal {
	fn serialize(&self) -> Vec<u8> {
		FramedProposal::from(self).encode_to_vec()
	}
}

impl TryFrom<FramedProposal> for proposal::FramedProposal {
	type Error = Error;

	fn try_from(val: FramedProposal) -> Result<Self, Self::Error> {
		Ok(Self::new(
			id::Id(val.guid.try_into().or(Err(Error::WrongGuidSize))?),
			val.epoch,
			nid::Nid::try_from(val.sender).or(Err(Error::WrongIdSize))?,
			val.prop.try_into().or(Err(Error::BadProposalFormat))?,
			dilithium::Signature::new(val.sig.try_into().or(Err(Error::WrongDilithiumSigSize))?),
			val.mac.try_into().or(Err(Error::WrongMacSize))?,
			proposal::Nonce(val.nonce.try_into().or(Err(Error::WrongNonceSize))?),
		))
	}
}

impl Deserializable for proposal::FramedProposal {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(FramedProposal::decode(buf).or(Err(Error::BadFramedProposalFormat))?)
	}
}

// CmpdCti
impl From<&hpkencrypt::CmpdCti> for CmpdCti {
	fn from(val: &hpkencrypt::CmpdCti) -> Self {
		Self {
			ct: val.ct.clone(),
			encrypted_eph_key: val.encrypted_eph_key.clone(),
			iv: val.iv.as_bytes().to_vec(),
			ilum_cti: val.ilum_cti.to_vec(),
		}
	}
}

impl Serializable for hpkencrypt::CmpdCti {
	fn serialize(&self) -> Vec<u8> {
		CmpdCti::from(self).encode_to_vec()
	}
}

impl TryFrom<CmpdCti> for hpkencrypt::CmpdCti {
	type Error = Error;

	fn try_from(val: CmpdCti) -> Result<Self, Self::Error> {
		Ok(Self::new(
			val.ct,
			val.encrypted_eph_key,
			aes_gcm::Iv(val.iv.try_into().or(Err(Error::WrongIvSize))?),
			val.ilum_cti.try_into().or(Err(Error::WrongCtiSize))?,
		))
	}
}

impl Deserializable for hpkencrypt::CmpdCti {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(CmpdCti::decode(buf).or(Err(Error::BadCtiFormat))?)
	}
}

// CmpdCtd
impl From<&hpkencrypt::CmpdCtd> for CmpdCtd {
	fn from(val: &hpkencrypt::CmpdCtd) -> Self {
		Self {
			ilum_ctd: val.ilum_ctd.to_vec(),
			ecc_ctd: val.ecc_ctd.clone(),
		}
	}
}

impl Serializable for hpkencrypt::CmpdCtd {
	fn serialize(&self) -> Vec<u8> {
		CmpdCtd::from(self).encode_to_vec()
	}
}

impl TryFrom<CmpdCtd> for hpkencrypt::CmpdCtd {
	type Error = Error;

	fn try_from(val: CmpdCtd) -> Result<Self, Self::Error> {
		Ok(Self::new(
			val.ilum_ctd.try_into().or(Err(Error::WrongCtdSize))?,
			val.ecc_ctd,
		))
	}
}

impl Deserializable for hpkencrypt::CmpdCtd {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(CmpdCtd::decode(buf).or(Err(Error::BadCtdFormat))?)
	}
}

// Commit
impl From<&commit::Commit> for Commit {
	fn from(val: &commit::Commit) -> Self {
		Self {
			kp: (&val.kp).into(),
			cti: (&val.cti).into(),
			prop_ids: val
				.prop_ids
				.iter()
				.map(|pid| pid.as_bytes().to_vec())
				.collect(),
		}
	}
}

impl Serializable for commit::Commit {
	fn serialize(&self) -> Vec<u8> {
		Commit::from(self).encode_to_vec()
	}
}

impl TryFrom<Commit> for commit::Commit {
	type Error = Error;

	fn try_from(val: Commit) -> Result<Self, Self::Error> {
		Ok(Self {
			kp: val.kp.try_into().or(Err(Error::BadKeyPackageFormat))?,
			cti: val.cti.try_into().or(Err(Error::BadCtiFormat))?,
			prop_ids: val
				.prop_ids
				.into_iter()
				.map(|pid| Ok(id::Id(pid.try_into().or(Err(Error::WrongIdSize))?)))
				.collect::<Result<Vec<id::Id>, Error>>()?,
		})
	}
}

impl Deserializable for commit::Commit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Commit::decode(buf).or(Err(Error::BadCommitFormat))?)
	}
}

// FramedCommit
impl From<&commit::FramedCommit> for FramedCommit {
	fn from(val: &commit::FramedCommit) -> Self {
		Self {
			guid: val.guid.as_bytes().to_vec(),
			epoch: val.epoch,
			sender: val.sender.as_bytes().to_vec(),
			commit: (&val.commit).into(),
			sig: val.sig.as_bytes().to_vec(),
			conf_tag: val.conf_tag.as_bytes().to_vec(),
		}
	}
}

impl Serializable for commit::FramedCommit {
	fn serialize(&self) -> Vec<u8> {
		FramedCommit::from(self).encode_to_vec()
	}
}

impl TryFrom<FramedCommit> for commit::FramedCommit {
	type Error = Error;

	fn try_from(val: FramedCommit) -> Result<Self, Self::Error> {
		Ok(Self::new(
			id::Id(val.guid.try_into().or(Err(Error::WrongGuidSize))?),
			val.epoch,
			nid::Nid::try_from(val.sender).or(Err(Error::WrongIdSize))?,
			val.commit.try_into().or(Err(Error::BadCommitFormat))?,
			dilithium::Signature::new(val.sig.try_into().or(Err(Error::WrongDilithiumSigSize))?),
			val.conf_tag.try_into().or(Err(Error::WrongMacSize))?,
		))
	}
}

impl Deserializable for commit::FramedCommit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(FramedCommit::decode(buf).or(Err(Error::BadFramedCommitFormat))?)
	}
}

// CommitCtd
impl From<&commit::CommitCtd> for CommitCtd {
	fn from(val: &commit::CommitCtd) -> Self {
		Self {
			user_id: val.user_id.as_bytes().to_vec(),
			ctd: val.ctd.as_ref().map(|ctd| ctd.into()),
		}
	}
}

impl Serializable for commit::CommitCtd {
	fn serialize(&self) -> Vec<u8> {
		CommitCtd::from(self).encode_to_vec()
	}
}

impl TryFrom<CommitCtd> for commit::CommitCtd {
	type Error = Error;

	fn try_from(val: CommitCtd) -> Result<Self, Self::Error> {
		Ok(Self::new(
			nid::Nid::try_from(val.user_id).or(Err(Error::WrongNidSize))?,
			val.ctd
				.map(|ctd| hpkencrypt::CmpdCtd::try_from(ctd))
				.transpose()?,
		))
	}
}

impl Deserializable for commit::CommitCtd {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(CommitCtd::decode(buf).or(Err(Error::BadCommitCtdFormat))?)
	}
}

// SendCommit
impl From<&transport::SendCommit> for SendCommit {
	fn from(val: &transport::SendCommit) -> Self {
		Self {
			cti: (&val.cti).into(),
			ctds: val.ctds.iter().map(|ctd| ctd.into()).collect(),
		}
	}
}

impl Serializable for transport::SendCommit {
	fn serialize(&self) -> Vec<u8> {
		SendCommit::from(self).encode_to_vec()
	}
}

impl TryFrom<SendCommit> for transport::SendCommit {
	type Error = Error;

	fn try_from(val: SendCommit) -> Result<Self, Self::Error> {
		Ok(Self {
			cti: val.cti.try_into().or(Err(Error::BadCiphertextFormat))?,
			ctds: val
				.ctds
				.iter()
				.map(|ctd| {
					Ok(commit::CommitCtd::try_from(ctd.clone())
						.or(Err(Error::BadCommitCtdFormat))?)
				})
				.collect::<Result<Vec<commit::CommitCtd>, Error>>()?,
		})
	}
}

impl Deserializable for transport::SendCommit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendCommit::decode(buf).or(Err(Error::BadSendCommitFormat))?)
	}
}

// SendLeave
impl From<&transport::SendLeave> for SendLeave {
	fn from(val: &transport::SendLeave) -> Self {
		Self {
			farewell: (&val.farewell).into(),
		}
	}
}

impl Serializable for transport::SendLeave {
	fn serialize(&self) -> Vec<u8> {
		SendLeave::from(self).encode_to_vec()
	}
}

impl TryFrom<SendLeave> for transport::SendLeave {
	type Error = Error;

	fn try_from(val: SendLeave) -> Result<Self, Self::Error> {
		Ok(Self {
			farewell: val
				.farewell
				.try_into()
				.or(Err(Error::BadCiphertextFormat))?,
		})
	}
}

impl Deserializable for transport::SendLeave {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendLeave::decode(buf).or(Err(Error::BadSendLeaveFormat))?)
	}
}

// SendAdd
impl From<&transport::SendAdd> for SendAdd {
	fn from(val: &transport::SendAdd) -> Self {
		Self {
			props: val.props.iter().map(|p| p.into()).collect(),
			commit: (&val.commit).into(),
		}
	}
}

impl Serializable for transport::SendAdd {
	fn serialize(&self) -> Vec<u8> {
		SendAdd::from(self).encode_to_vec()
	}
}

impl TryFrom<SendAdd> for transport::SendAdd {
	type Error = Error;

	fn try_from(val: SendAdd) -> Result<Self, Self::Error> {
		Ok(Self {
			props: val
				.props
				.iter()
				.map(|p| {
					Ok(ciphertext::Ciphertext::try_from(p.clone())
						.or(Err(Error::BadCiphertextFormat))?)
				})
				.collect::<Result<Vec<ciphertext::Ciphertext>, Error>>()?,
			commit: transport::SendCommit::try_from(val.commit)
				.or(Err(Error::BadSendCommitFormat))?,
		})
	}
}

impl Deserializable for transport::SendAdd {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendAdd::decode(buf).or(Err(Error::BadSendAddFormat))?)
	}
}

// SendInvite
impl From<&transport::SendInvite> for SendInvite {
	fn from(val: &transport::SendInvite) -> Self {
		Self {
			wcti: (&val.wcti).into(),
			wctds: val.wctds.iter().map(|w| w.into()).collect(),
			add: val.add.as_ref().map(|a| a.into()),
		}
	}
}

impl Serializable for transport::SendInvite {
	fn serialize(&self) -> Vec<u8> {
		SendInvite::from(self).encode_to_vec()
	}
}

impl TryFrom<SendInvite> for transport::SendInvite {
	type Error = Error;

	fn try_from(val: SendInvite) -> Result<Self, Self::Error> {
		Ok(Self {
			wcti: val.wcti.try_into().or(Err(Error::BadWlcmCtiFormat))?,
			wctds: val
				.wctds
				.iter()
				.map(|ctd| {
					Ok(welcome::WlcmCtd::try_from(ctd.clone()).or(Err(Error::BadWlcmCtdFormat))?)
				})
				.collect::<Result<Vec<welcome::WlcmCtd>, Error>>()?,
			add: val
				.add
				.map(|a| transport::SendAdd::try_from(a))
				.transpose()?,
		})
	}
}

impl Deserializable for transport::SendInvite {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendInvite::decode(buf).or(Err(Error::BadSendInviteFormat))?)
	}
}

// SendRemove
impl From<&transport::SendRemove> for SendRemove {
	fn from(val: &transport::SendRemove) -> Self {
		Self {
			props: val.props.iter().map(|p| p.into()).collect(),
			commit: (&val.commit).into(),
			delegated: val.delegated,
		}
	}
}

impl Serializable for transport::SendRemove {
	fn serialize(&self) -> Vec<u8> {
		SendRemove::from(self).encode_to_vec()
	}
}

impl TryFrom<SendRemove> for transport::SendRemove {
	type Error = Error;

	fn try_from(val: SendRemove) -> Result<Self, Self::Error> {
		Ok(Self {
			props: val
				.props
				.iter()
				.map(|p| {
					Ok(ciphertext::Ciphertext::try_from(p.clone())
						.or(Err(Error::BadCiphertextFormat))?)
				})
				.collect::<Result<Vec<ciphertext::Ciphertext>, Error>>()?,
			commit: transport::SendCommit::try_from(val.commit)
				.or(Err(Error::BadSendCommitFormat))?,
			delegated: val.delegated,
		})
	}
}

impl Deserializable for transport::SendRemove {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendRemove::decode(buf).or(Err(Error::BadSendRemoveFormat))?)
	}
}

// SendEdit
impl From<&transport::SendEdit> for SendEdit {
	fn from(val: &transport::SendEdit) -> Self {
		Self {
			prop: (&val.prop).into(),
			commit: (&val.commit).into(),
		}
	}
}

impl Serializable for transport::SendEdit {
	fn serialize(&self) -> Vec<u8> {
		SendEdit::from(self).encode_to_vec()
	}
}

impl TryFrom<SendEdit> for transport::SendEdit {
	type Error = Error;

	fn try_from(val: SendEdit) -> Result<Self, Self::Error> {
		Ok(Self {
			prop: val.prop.try_into().or(Err(Error::BadCiphertextFormat))?,
			commit: transport::SendCommit::try_from(val.commit)
				.or(Err(Error::BadSendCommitFormat))?,
		})
	}
}

impl Deserializable for transport::SendEdit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendEdit::decode(buf).or(Err(Error::BadSendRemoveFormat))?)
	}
}

// SendProposal
impl From<&transport::SendProposal> for SendProposal {
	fn from(val: &transport::SendProposal) -> Self {
		Self {
			props: val.props.iter().map(|p| p.into()).collect(),
			recipients: val
				.recipients
				.iter()
				.map(|nid| nid.as_bytes().to_vec())
				.collect(),
		}
	}
}

impl Serializable for transport::SendProposal {
	fn serialize(&self) -> Vec<u8> {
		SendProposal::from(self).encode_to_vec()
	}
}

impl TryFrom<SendProposal> for transport::SendProposal {
	type Error = Error;

	fn try_from(val: SendProposal) -> Result<Self, Self::Error> {
		// FIXME: should I just filter failed instead?
		Ok(Self {
			props: val
				.props
				.iter()
				.map(|p| {
					Ok(ciphertext::Ciphertext::try_from(p.clone())
						.or(Err(Error::BadCiphertextFormat))?)
				})
				.collect::<Result<Vec<ciphertext::Ciphertext>, Error>>()?,
			recipients: val
				.recipients
				.iter()
				.map(|nid| Ok(nid::Nid::try_from(nid.clone()).or(Err(Error::WrongIdSize))?))
				.collect::<Result<Vec<nid::Nid>, Error>>()?,
		})
	}
}

impl Deserializable for transport::SendProposal {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendProposal::decode(buf).or(Err(Error::BadSendProposalFormat))?)
	}
}

// SendMsg
impl From<&transport::SendMsg> for SendMsg {
	fn from(val: &transport::SendMsg) -> Self {
		Self {
			payload: (&val.payload).into(),
			recipients: val
				.recipients
				.iter()
				.map(|nid| nid.as_bytes().to_vec())
				.collect(),
		}
	}
}

impl Serializable for transport::SendMsg {
	fn serialize(&self) -> Vec<u8> {
		SendMsg::from(self).encode_to_vec()
	}
}

impl TryFrom<SendMsg> for transport::SendMsg {
	type Error = Error;

	fn try_from(val: SendMsg) -> Result<Self, Self::Error> {
		Ok(Self {
			payload: ciphertext::Ciphertext::try_from(val.payload)
				.or(Err(Error::BadCiphertextFormat))?,
			recipients: val
				.recipients
				.iter()
				.map(|nid| Ok(nid::Nid::try_from(nid.clone()).or(Err(Error::WrongIdSize))?))
				.collect::<Result<Vec<nid::Nid>, Error>>()?,
		})
	}
}

impl Deserializable for transport::SendMsg {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendMsg::decode(buf).or(Err(Error::BadSendMsgFormat))?)
	}
}

// Send
impl From<&transport::Send> for Send {
	fn from(val: &transport::Send) -> Self {
		use send::Variant;

		Self {
			variant: Some(match val {
				transport::Send::Invite(i) => Variant::Invite(SendInvite::from(i)),
				transport::Send::Remove(r) => Variant::Remove(SendRemove::from(r)),
				transport::Send::Edit(e) => Variant::Edit(SendEdit::from(e)),
				transport::Send::Props(p) => Variant::Props(SendProposal::from(p)),
				transport::Send::Commit(c) => Variant::Commit(SendCommit::from(c)),
				transport::Send::Leave(l) => Variant::Leave(SendLeave::from(l)),
				transport::Send::Msg(m) => Variant::Msg(SendMsg::from(m)),
			}),
		}
	}
}

impl Serializable for transport::Send {
	fn serialize(&self) -> Vec<u8> {
		Send::from(self).encode_to_vec()
	}
}

impl TryFrom<Send> for transport::Send {
	type Error = Error;

	fn try_from(val: Send) -> Result<Self, Self::Error> {
		use send::Variant;
		use transport::Send::*;

		Ok(match val.variant.ok_or(Error::BadSendFormat)? {
			Variant::Invite(i) => Invite(i.try_into()?),
			Variant::Remove(r) => Remove(r.try_into()?),
			Variant::Edit(e) => Edit(e.try_into()?),
			Variant::Props(p) => Props(p.try_into()?),
			Variant::Commit(c) => Commit(c.try_into()?),
			Variant::Leave(l) => Leave(l.try_into()?),
			Variant::Msg(m) => Msg(m.try_into()?),
		})
	}
}

impl Deserializable for transport::Send {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Send::decode(buf).or(Err(Error::BadSendFormat))?)
	}
}

// Ciphertext
impl From<&ciphertext::Ciphertext> for Ciphertext {
	fn from(val: &ciphertext::Ciphertext) -> Self {
		Self {
			content_id: val.content_id.as_bytes().to_vec(),
			payload: val.payload.clone(),
			guid: val.guid.as_bytes().to_vec(),
			epoch: val.epoch,
			gen: val.gen,
			sender: val.sender.as_bytes().to_vec(),
			iv: val.iv.as_bytes().to_vec(),
			sig: val.sig.as_bytes().to_vec(),
			mac: val.mac.as_bytes().to_vec(),
			reuse_grd: val.reuse_grd.as_bytes().to_vec(),
		}
	}
}

impl Serializable for ciphertext::Ciphertext {
	fn serialize(&self) -> Vec<u8> {
		Ciphertext::from(self).encode_to_vec()
	}
}

impl TryFrom<Ciphertext> for ciphertext::Ciphertext {
	type Error = Error;

	fn try_from(val: Ciphertext) -> Result<Self, Self::Error> {
		Ok(Self {
			content_id: id::Id(val.content_id.try_into().or(Err(Error::WrongIdSize))?),
			payload: val.payload,
			guid: id::Id(val.guid.try_into().or(Err(Error::WrongGuidSize))?),
			epoch: val.epoch,
			gen: val.gen,
			sender: nid::Nid::try_from(val.sender).or(Err(Error::WrongIdSize))?,
			iv: aes_gcm::Iv(val.iv.try_into().or(Err(Error::WrongIvSize))?),
			sig: dilithium::Signature::new(
				val.sig.try_into().or(Err(Error::WrongDilithiumSigSize))?,
			),
			mac: val.mac.try_into().or(Err(Error::WrongMacSize))?,
			reuse_grd: val
				.reuse_grd
				.try_into()
				.or(Err(Error::WrongReuseGuardSize))?,
		})
	}
}

impl Deserializable for ciphertext::Ciphertext {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Ciphertext::decode(buf).or(Err(Error::BadCiphertextFormat))?)
	}
}

// ReceivedWelcome
impl From<&transport::ReceivedWelcome> for ReceivedWelcome {
	fn from(val: &transport::ReceivedWelcome) -> Self {
		Self {
			cti: (&val.cti).into(),
			ctd: (&val.ctd).into(),
			kp_id: val.kp_id.as_bytes().to_vec(),
		}
	}
}

impl Serializable for transport::ReceivedWelcome {
	fn serialize(&self) -> Vec<u8> {
		ReceivedWelcome::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedWelcome> for transport::ReceivedWelcome {
	type Error = Error;

	fn try_from(val: ReceivedWelcome) -> Result<Self, Self::Error> {
		Ok(Self {
			cti: val.cti.try_into().or(Err(Error::BadWlcmCtiFormat))?,
			ctd: val.ctd.try_into().or(Err(Error::BadCtdFormat))?,
			kp_id: id::Id(val.kp_id.try_into().or(Err(Error::WrongKeyPackageIdSize))?),
		})
	}
}

impl Deserializable for transport::ReceivedWelcome {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedWelcome::decode(buf).or(Err(Error::BadReceivedWelcomeFormat))?)
	}
}

// ReceivedCommit
impl From<&transport::ReceivedCommit> for ReceivedCommit {
	fn from(val: &transport::ReceivedCommit) -> Self {
		Self {
			cti: (&val.cti).into(),
			ctd: (&val.ctd).into(),
		}
	}
}

impl Serializable for transport::ReceivedCommit {
	fn serialize(&self) -> Vec<u8> {
		ReceivedCommit::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedCommit> for transport::ReceivedCommit {
	type Error = Error;

	fn try_from(val: ReceivedCommit) -> Result<Self, Self::Error> {
		Ok(Self {
			cti: val.cti.try_into().or(Err(Error::BadCtiFormat))?,
			ctd: val.ctd.try_into().or(Err(Error::BadCtdFormat))?,
		})
	}
}

impl Deserializable for transport::ReceivedCommit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedCommit::decode(buf).or(Err(Error::BadReceivedCommitFormat))?)
	}
}

// ReceivedProposal
impl From<&transport::ReceivedProposal> for ReceivedProposal {
	fn from(val: &transport::ReceivedProposal) -> Self {
		Self {
			props: val.props.iter().map(|p| p.into()).collect(),
		}
	}
}

impl Serializable for transport::ReceivedProposal {
	fn serialize(&self) -> Vec<u8> {
		ReceivedProposal::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedProposal> for transport::ReceivedProposal {
	type Error = Error;

	fn try_from(val: ReceivedProposal) -> Result<Self, Self::Error> {
		Ok(Self {
			props: val
				.props
				.iter()
				.map(|p| {
					Ok(ciphertext::Ciphertext::try_from(p.clone())
						.or(Err(Error::BadCiphertextFormat))?)
				})
				.collect::<Result<Vec<ciphertext::Ciphertext>, Error>>()?,
		})
	}
}

impl Deserializable for transport::ReceivedProposal {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedProposal::decode(buf).or(Err(Error::BadReceivedProposalFormat))?)
	}
}

// ReceivedAdd
impl From<&transport::ReceivedAdd> for ReceivedAdd {
	fn from(val: &transport::ReceivedAdd) -> Self {
		Self {
			props: (&val.props).into(),
			commit: (&val.commit).into(),
		}
	}
}

impl Serializable for transport::ReceivedAdd {
	fn serialize(&self) -> Vec<u8> {
		ReceivedAdd::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedAdd> for transport::ReceivedAdd {
	type Error = Error;

	fn try_from(val: ReceivedAdd) -> Result<Self, Self::Error> {
		Ok(Self {
			props: val
				.props
				.try_into()
				.or(Err(Error::BadReceivedProposalFormat))?,
			commit: val
				.commit
				.try_into()
				.or(Err(Error::BadReceivedCommitFormat))?,
		})
	}
}

impl Deserializable for transport::ReceivedAdd {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedAdd::decode(buf).or(Err(Error::BadReceivedAddFormat))?)
	}
}

// ReceivedRemove
impl From<&transport::ReceivedRemove> for ReceivedRemove {
	fn from(val: &transport::ReceivedRemove) -> Self {
		Self {
			props: (&val.props).into(),
			cti: (&val.cti).into(),
			ctd: val.ctd.as_ref().map(|ctd| ctd.into()),
			delegated: val.delegated,
		}
	}
}

impl Serializable for transport::ReceivedRemove {
	fn serialize(&self) -> Vec<u8> {
		ReceivedRemove::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedRemove> for transport::ReceivedRemove {
	type Error = Error;

	fn try_from(val: ReceivedRemove) -> Result<Self, Self::Error> {
		Ok(Self {
			props: val
				.props
				.try_into()
				.or(Err(Error::BadReceivedProposalFormat))?,
			cti: val.cti.try_into().or(Err(Error::BadCiphertextFormat))?,
			ctd: val.ctd.map(|ctd| ctd.try_into()).transpose()?,
			delegated: val.delegated,
		})
	}
}

impl Deserializable for transport::ReceivedRemove {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedRemove::decode(buf).or(Err(Error::BadReceivedRemoveFormat))?)
	}
}

// ReceivedEdit
impl From<&transport::ReceivedEdit> for ReceivedEdit {
	fn from(val: &transport::ReceivedEdit) -> Self {
		Self {
			prop: (&val.prop).into(),
			cti: (&val.cti).into(),
			ctd: (&val.ctd).into(),
		}
	}
}

impl Serializable for transport::ReceivedEdit {
	fn serialize(&self) -> Vec<u8> {
		ReceivedEdit::from(self).encode_to_vec()
	}
}

impl TryFrom<ReceivedEdit> for transport::ReceivedEdit {
	type Error = Error;

	fn try_from(val: ReceivedEdit) -> Result<Self, Self::Error> {
		Ok(Self {
			prop: val
				.prop
				.try_into()
				.or(Err(Error::BadReceivedProposalFormat))?,
			cti: val.cti.try_into().or(Err(Error::BadCiphertextFormat))?,
			ctd: val.ctd.try_into().or(Err(Error::BadCtdFormat))?,
		})
	}
}

impl Deserializable for transport::ReceivedEdit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(ReceivedEdit::decode(buf).or(Err(Error::BadReceivedEditFormat))?)
	}
}

// Received
impl From<&transport::Received> for Received {
	fn from(val: &transport::Received) -> Self {
		use received::Variant;

		Self {
			variant: Some(match val {
				transport::Received::Welcome(w) => Variant::Wlcm(w.into()),
				transport::Received::Add(a) => Variant::Add(a.into()),
				transport::Received::Remove(r) => Variant::Remove(r.into()),
				transport::Received::Edit(e) => Variant::Edit(e.into()),
				transport::Received::Props(p) => Variant::Props(p.into()),
				transport::Received::Commit(c) => Variant::Commit(c.into()),
				transport::Received::Leave(l) => Variant::Leave(l.into()),
				transport::Received::Msg(m) => Variant::Msg(m.into()),
			}),
		}
	}
}

impl Serializable for transport::Received {
	fn serialize(&self) -> Vec<u8> {
		Received::from(self).encode_to_vec()
	}
}

impl TryFrom<Received> for transport::Received {
	type Error = Error;

	fn try_from(val: Received) -> Result<Self, Self::Error> {
		use received::Variant;
		use transport::Received::*;

		Ok(match val.variant.ok_or(Error::BadReceivedFormat)? {
			Variant::Wlcm(w) => Welcome(w.try_into()?),
			Variant::Add(a) => Add(a.try_into()?),
			Variant::Remove(r) => Remove(r.try_into()?),
			Variant::Edit(e) => Edit(e.try_into()?),
			Variant::Props(p) => Props(p.try_into()?),
			Variant::Commit(c) => Commit(c.try_into()?),
			Variant::Leave(l) => Leave(l.try_into()?),
			Variant::Msg(m) => Msg(m.try_into()?),
		})
	}
}

impl Deserializable for transport::Received {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(Received::decode(buf).or(Err(Error::BadReceivedFormat))?)
	}
}

#[cfg(test)]
mod tests {
	use crate::{
		aes_gcm, chain, chain_tree, ciphertext, commit, dilithium, group, hmac, hpkencrypt, id,
		key_package, key_schedule, member, nid, proposal, reuse_guard, roster, secret_tree,
		serializable::{Deserializable, Serializable},
		transport, treemath, update, welcome, x448,
	};

	#[test]
	fn test_secret_tree() {
		let mut st = secret_tree::HkdfTree::try_new_for_root_secret(18, [42u8; 32]).unwrap();
		// consume a few secrets to fill up the tree
		_ = st.get(treemath::LeafIndex(3));
		_ = st.get(treemath::LeafIndex(11));
		_ = st.get(treemath::LeafIndex(7));
		let serialized = st.serialize();
		let deserialized = secret_tree::HkdfTree::deserialize(&serialized);

		assert_eq!(Ok(st), deserialized);
	}

	#[test]
	fn test_chain() {
		let c = chain::Chain {
			skipped_keys: vec![(2, chain::DetachedKey([12u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([78u8; 32]),
			next_idx: 99,
			max_keys_to_skip: 567,
		};
		let serialized = c.serialize();
		let deserialized = chain::Chain::deserialize(&serialized);

		assert_eq!(Ok(c), deserialized);
	}

	#[test]
	fn test_chain_tree() {
		let mut st = secret_tree::HkdfTree::try_new_for_root_secret(18, [42u8; 32]).unwrap();
		// consume a few secrets to fill up the tree
		_ = st.get(treemath::LeafIndex(3));
		_ = st.get(treemath::LeafIndex(11));
		_ = st.get(treemath::LeafIndex(7));

		let c0 = chain::Chain {
			skipped_keys: vec![(2, chain::DetachedKey([12u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([78u8; 32]),
			next_idx: 99,
			max_keys_to_skip: 57,
		};
		let c1 = chain::Chain {
			skipped_keys: vec![(1, chain::DetachedKey([33u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([66u8; 32]),
			next_idx: 12,
			max_keys_to_skip: 57,
		};
		let ct = chain_tree::ChainTree {
			chains: vec![(treemath::LeafIndex(0), c0), (treemath::LeafIndex(1), c1)]
				.into_iter()
				.collect(),
			secret_tree: st,
			max_keys_to_skip: 57,
		};
		let serialized = ct.serialize();
		let deserialized = chain_tree::ChainTree::deserialize(&serialized);

		assert_eq!(Ok(ct), deserialized);
	}

	#[test]
	fn test_epoch_secrets() {
		let mut st = secret_tree::HkdfTree::try_new_for_root_secret(18, [42u8; 32]).unwrap();
		// consume a few secrets to fill up the tree
		_ = st.get(treemath::LeafIndex(3));
		_ = st.get(treemath::LeafIndex(7));

		let c0 = chain::Chain {
			skipped_keys: vec![(2, chain::DetachedKey([12u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([78u8; 32]),
			next_idx: 99,
			max_keys_to_skip: 57,
		};
		let c1 = chain::Chain {
			skipped_keys: vec![(1, chain::DetachedKey([33u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([66u8; 32]),
			next_idx: 12,
			max_keys_to_skip: 57,
		};
		let hs = chain_tree::ChainTree {
			chains: vec![(treemath::LeafIndex(0), c0), (treemath::LeafIndex(1), c1)]
				.into_iter()
				.collect(),
			secret_tree: st,
			max_keys_to_skip: 57,
		};
		let mut st = secret_tree::HkdfTree::try_new_for_root_secret(18, [22u8; 32]).unwrap();
		// consume a few secrets to fill up the tree
		_ = st.get(treemath::LeafIndex(10));
		_ = st.get(treemath::LeafIndex(1));
		_ = st.get(treemath::LeafIndex(7));

		let c0 = chain::Chain {
			skipped_keys: vec![(2, chain::DetachedKey([77u8; 32]))]
				.into_iter()
				.collect(),
			next_key: chain::ChainKey([28u8; 32]),
			next_idx: 39,
			max_keys_to_skip: 57,
		};
		let app = chain_tree::ChainTree {
			chains: vec![(treemath::LeafIndex(0), c0)].into_iter().collect(),
			secret_tree: st,
			max_keys_to_skip: 57,
		};
		let es = key_schedule::EpochSecrets {
			init: [11u8; 32],
			mac: [33u8; 32],
			hs,
			app,
		};
		let serialized = es.serialize();
		let deserialized = key_schedule::EpochSecrets::deserialize(&serialized);

		assert_eq!(Ok(es), deserialized);
	}

	#[test]
	fn test_pending_update() {
		let seed = b"1234567890abcdef";
		let ilum = ilum::gen_keypair(seed);
		let pu = update::PendingUpdate {
			ilum_dk: ilum.sk,
			x448_dk: x448::KeyPair::generate().private,
			ssk: dilithium::KeyPair::generate().private,
		};
		let serialized = pu.serialize();
		let deserialized = update::PendingUpdate::deserialize(&serialized);

		assert_eq!(Ok(pu), deserialized);
	}

	#[test]
	fn test_group() {
		let seed = [12u8; 16];
		let alice_ekp = ilum::gen_keypair(&seed);
		let alice_x448_kp = x448::KeyPair::generate();
		let alice_skp = dilithium::KeyPair::generate();
		let alice_id = nid::Nid::new(b"aliceali", 0);
		let alice = group::Owner {
			id: alice_id.clone(),
			kp: key_package::KeyPackage::new(
				&alice_ekp.pk,
				&alice_x448_kp.public,
				&alice_skp.public,
				&alice_skp.private,
			),
			ilum_dk: alice_ekp.sk,
			x448_dk: alice_x448_kp.private,
			ssk: alice_skp.private,
		};

		let mut alice_group = group::Group::create(seed, alice);

		let bob_user_id = nid::Nid::new(b"bobbobbo", 0);
		let bob_user_ekp = ilum::gen_keypair(&seed);
		let bob_x448_kp = x448::KeyPair::generate();
		let bob_user_skp = dilithium::KeyPair::generate();
		let bob_user_kp = key_package::KeyPackage::new(
			&bob_user_ekp.pk,
			&bob_x448_kp.public,
			&bob_user_skp.public,
			&bob_user_skp.private,
		);
		let (add_bob_prop, _) = alice_group
			.propose_add(bob_user_id, bob_user_kp.clone())
			.unwrap();
		let (update_alice_prop, _) = alice_group.propose_update();
		// alice invites using her initial group
		let (fc, _, ctds, _) = alice_group
			.commit(&[add_bob_prop.clone(), update_alice_prop.clone()])
			.unwrap();

		// and get alice_group
		let mut alice_group = alice_group
			.process(
				&fc,
				ctds.first().unwrap().ctd.as_ref(),
				&[add_bob_prop, update_alice_prop],
			)
			.unwrap()
			.unwrap();

		let charlie_user_id = nid::Nid::new(b"charliec", 0);
		let charlie_user_ekp = ilum::gen_keypair(&seed);
		let charlie_x448_kp = x448::KeyPair::generate();
		let charlie_user_skp = dilithium::KeyPair::generate();
		let charlie_user_kp = key_package::KeyPackage::new(
			&charlie_user_ekp.pk,
			&charlie_x448_kp.public,
			&charlie_user_skp.public,
			&charlie_user_skp.private,
		);
		// now alice proposes to add charlie
		let (add_charlie_prop, _) = alice_group
			.propose_add(charlie_user_id, charlie_user_kp.clone())
			.unwrap();
		let (update_alice_prop, _) = alice_group.propose_update();
		// commits using her alic_group
		let _ = alice_group
			.commit(&[add_charlie_prop.clone(), update_alice_prop.clone()])
			.unwrap();

		let serialized = alice_group.serialize();
		let deserialized = group::Group::deserialize(&serialized);

		assert_eq!(Ok(alice_group), deserialized);
	}

	#[test]
	fn test_key_package() {
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let x448_kp = x448::KeyPair::generate();
		let s_kp = dilithium::KeyPair::generate();
		let pack =
			key_package::KeyPackage::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);
		let serialized = pack.serialize();
		let deserialized = key_package::KeyPackage::deserialize(&serialized);

		assert_eq!(Ok(pack), deserialized);
	}

	#[test]
	fn test_member() {
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let x448_kp = x448::KeyPair::generate();
		let s_kp = dilithium::KeyPair::generate();
		let pack =
			key_package::KeyPackage::new(&e_kp.pk, &x448_kp.public, &s_kp.public, &s_kp.private);
		let member = member::Member::new(nid::Nid::new(b"abcdefgh", 0), pack);
		let serialized = member.serialize();
		let deserialized = member::Member::deserialize(&serialized);

		assert_eq!(Ok(member), deserialized);
	}

	#[test]
	fn test_roster() {
		let mut r = roster::Roster::new();

		_ = r.add(member::Member::new(
			nid::Nid::new(b"abcdefgh", 0),
			key_package::KeyPackage {
				ilum_ek: [34u8; 768],
				x448_ek: x448::KeyPair::generate().public,
				svk: dilithium::PublicKey::new([56u8; 2592]),
				sig: dilithium::Signature::new([78u8; 4595]),
			},
		));

		_ = r.add(member::Member::new(
			nid::Nid::new(b"ijklmnop", 0),
			key_package::KeyPackage {
				ilum_ek: [56u8; 768],
				x448_ek: x448::KeyPair::generate().public,
				svk: dilithium::PublicKey::new([78u8; 2592]),
				sig: dilithium::Signature::new([90u8; 4595]),
			},
		));

		_ = r.add(member::Member::new(
			nid::Nid::new(b"qrstuvwx", 0),
			key_package::KeyPackage {
				ilum_ek: [78u8; 768],
				x448_ek: x448::KeyPair::generate().public,
				svk: dilithium::PublicKey::new([90u8; 2592]),
				sig: dilithium::Signature::new([12u8; 4595]),
			},
		));

		let serialized = r.serialize();
		let deserialized = roster::Roster::deserialize(&serialized);

		assert_eq!(Ok(r), deserialized);
	}

	#[test]
	fn test_proposal() {
		use proposal::Proposal;

		let kp = key_package::KeyPackage {
			ilum_ek: [56u8; 768],
			x448_ek: x448::KeyPair::generate().public,
			svk: dilithium::PublicKey::new([78u8; 2592]),
			sig: dilithium::Signature::new([90u8; 4595]),
		};

		let prop = Proposal::Remove {
			id: nid::Nid::new(b"abcdefgh", 0),
		};
		let serialized = prop.serialize();
		let deserialized = Proposal::deserialize(&serialized);

		assert_eq!(Ok(prop), deserialized);

		let prop = Proposal::Update { kp: kp.clone() };
		let serialized = prop.serialize();
		let deserialized = Proposal::deserialize(&serialized);

		assert_eq!(Ok(prop), deserialized);

		let prop = Proposal::Add {
			id: nid::Nid::new(b"ijklmnop", 0),
			kp: kp,
		};
		let serialized = prop.serialize();
		let deserialized = Proposal::deserialize(&serialized);

		assert_eq!(Ok(prop), deserialized);
	}

	#[test]
	fn test_framed_proposal() {
		use proposal::Proposal;

		let kp = key_package::KeyPackage {
			ilum_ek: [56u8; 768],
			x448_ek: x448::KeyPair::generate().public,
			svk: dilithium::PublicKey::new([78u8; 2592]),
			sig: dilithium::Signature::new([90u8; 4595]),
		};
		let prop = Proposal::Add {
			id: nid::Nid::new(b"abcdefgh", 0),
			kp,
		};
		let fc = proposal::FramedProposal::new(
			id::Id([123u8; 32]),
			17u64,
			nid::Nid::new(b"ijklmnop", 0),
			prop,
			dilithium::Signature::new([42u8; 4595]),
			hmac::Digest([33u8; 32]),
			proposal::Nonce([33u8; 4]),
		);

		let serialized = fc.serialize();
		let deserialized = proposal::FramedProposal::deserialize(&serialized);

		assert_eq!(Ok(fc), deserialized);
	}

	#[test]
	fn test_cmpd_cti() {
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let serialized = cti.serialize();
		let deserialized = hpkencrypt::CmpdCti::deserialize(&serialized);

		assert_eq!(Ok(cti), deserialized);
	}

	#[test]
	fn test_cmpd_ctd() {
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let serialized = ctd.serialize();
		let deserialized = hpkencrypt::CmpdCtd::deserialize(&serialized);

		assert_eq!(Ok(ctd), deserialized);
	}

	#[test]
	fn test_wlcm_cti() {
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let wcti = welcome::WlcmCti::new(cti, dilithium::Signature::new([57u8; 4595]));
		let serialized = wcti.serialize();
		let deserialized = welcome::WlcmCti::deserialize(&serialized);

		assert_eq!(Ok(wcti), deserialized);
	}

	#[test]
	fn test_wlcm_ctd() {
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let wctd = welcome::WlcmCtd::new(nid::Nid::new(b"abcdefgh", 1), id::Id([22u8; 32]), ctd);
		let serialized = wctd.serialize();
		let deserialized = welcome::WlcmCtd::deserialize(&serialized);

		assert_eq!(Ok(wctd), deserialized);
	}

	#[test]
	fn test_send_add() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti,
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sa = transport::SendAdd {
			props: vec![prop],
			commit: sc,
		};
		let serialized = sa.serialize();
		let deserialized = transport::SendAdd::deserialize(&serialized);

		assert_eq!(Ok(sa), deserialized);
	}

	#[test]
	fn test_send_remove() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti,
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sr = transport::SendRemove {
			props: vec![prop],
			commit: sc,
			delegated: true,
		};
		let serialized = sr.serialize();
		let deserialized = transport::SendRemove::deserialize(&serialized);

		assert_eq!(Ok(sr), deserialized);
	}

	#[test]
	fn test_send_invite() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti,
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sa = transport::SendAdd {
			props: vec![prop],
			commit: sc,
		};
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let wcti = welcome::WlcmCti::new(cti, dilithium::Signature::new([57u8; 4595]));
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let wctd = welcome::WlcmCtd::new(nid::Nid::new(b"abcdefgh", 1), id::Id([22u8; 32]), ctd);
		let si = transport::SendInvite {
			wcti,
			wctds: vec![wctd],
			add: Some(sa),
		};
		let serialized = si.serialize();
		let deserialized = transport::SendInvite::deserialize(&serialized);

		assert_eq!(Ok(si), deserialized);
	}

	#[test]
	fn test_send_proposal() {
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sp = transport::SendProposal {
			props: vec![prop],
			recipients: vec![nid::Nid::new(b"abcdefgh", 0), nid::Nid::new(b"abcdefgt", 2)],
		};
		let serialized = sp.serialize();
		let deserialized = transport::SendProposal::deserialize(&serialized);

		assert_eq!(Ok(sp), deserialized);
	}

	#[test]
	fn test_send_edit() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti: cti.clone(),
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let se = transport::SendEdit {
			prop: ct,
			commit: sc,
		};
		let serialized = se.serialize();
		let deserialized = transport::SendEdit::deserialize(&serialized);

		assert_eq!(Ok(se), deserialized);
	}

	#[test]
	fn test_send_leave() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sm = transport::SendMsg {
			payload: ct,
			recipients: vec![nid::Nid::new(b"abcdefgh", 0), nid::Nid::new(b"abcdefgt", 2)],
		};
		let sl = transport::SendLeave { farewell: sm };
		let serialized = sl.serialize();
		let deserialized = transport::SendLeave::deserialize(&serialized);

		assert_eq!(Ok(sl), deserialized);
	}

	#[test]
	fn test_send_msg() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sm = transport::SendMsg {
			payload: ct,
			recipients: vec![nid::Nid::new(b"abcdefgh", 0), nid::Nid::new(b"abcdefgt", 2)],
		};
		let serialized = sm.serialize();
		let deserialized = transport::SendMsg::deserialize(&serialized);

		assert_eq!(Ok(sm), deserialized);
	}

	#[test]
	fn test_send() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti: cti.clone(),
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sa = transport::SendAdd {
			props: vec![prop.clone()],
			commit: sc.clone(),
		};
		let cmpd_cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let wcti = welcome::WlcmCti::new(cmpd_cti, dilithium::Signature::new([57u8; 4595]));
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let wctd = welcome::WlcmCtd::new(nid::Nid::new(b"abcdefgh", 1), id::Id([22u8; 32]), ctd);
		let si = transport::SendInvite {
			wcti,
			wctds: vec![wctd],
			add: Some(sa),
		};
		let send = transport::Send::Invite(si);
		let serialied = send.serialize();
		let deserialized = transport::Send::deserialize(&serialied);

		assert_eq!(Ok(send), deserialized);

		let sr = transport::SendRemove {
			props: vec![prop.clone()],
			commit: sc,
			delegated: false,
		};

		let send = transport::Send::Remove(sr);
		let serialied = send.serialize();
		let deserialized = transport::Send::deserialize(&serialied);

		assert_eq!(Ok(send), deserialized);

		let sp = transport::SendProposal {
			props: vec![prop],
			recipients: vec![nid::Nid::new(b"abcdefgh", 0), nid::Nid::new(b"abcdefgt", 2)],
		};

		let send = transport::Send::Props(sp);
		let serialied = send.serialize();
		let deserialized = transport::Send::deserialize(&serialied);

		assert_eq!(Ok(send), deserialized);

		let sc = transport::SendCommit {
			cti: cti.clone(),
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};

		let send = transport::Send::Commit(sc);
		let serialied = send.serialize();
		let deserialized = transport::Send::deserialize(&serialied);

		assert_eq!(Ok(send), deserialized);

		let sm = transport::SendMsg {
			payload: cti,
			recipients: vec![nid::Nid::new(b"abcdefgh", 0), nid::Nid::new(b"abcdefgt", 2)],
		};

		let send = transport::Send::Msg(sm);
		let serialied = send.serialize();
		let deserialized = transport::Send::deserialize(&serialied);

		assert_eq!(Ok(send), deserialized);
	}

	#[test]
	fn test_commit() {
		let kp = key_package::KeyPackage {
			ilum_ek: [56u8; 768],
			x448_ek: x448::KeyPair::generate().public,
			svk: dilithium::PublicKey::new([78u8; 2592]),
			sig: dilithium::Signature::new([90u8; 4595]),
		};
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let commit = commit::Commit {
			kp,
			cti,
			prop_ids: vec![id::Id([12u8; 32]), id::Id([34u8; 32])],
		};
		let serialized = commit.serialize();
		let deserialized = commit::Commit::deserialize(&serialized);

		assert_eq!(Ok(commit), deserialized);
	}

	#[test]
	fn test_framed_commit() {
		let kp = key_package::KeyPackage {
			ilum_ek: [56u8; 768],
			x448_ek: x448::KeyPair::generate().public,
			svk: dilithium::PublicKey::new([78u8; 2592]),
			sig: dilithium::Signature::new([90u8; 4595]),
		};
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let commit = commit::Commit {
			kp,
			cti,
			prop_ids: vec![id::Id([12u8; 32]), id::Id([34u8; 32])],
		};

		let fc = commit::FramedCommit::new(
			id::Id([88u8; 32]),
			42,
			nid::Nid::new(b"abcdefgh", 0),
			commit,
			dilithium::Signature::new([77u8; 4595]),
			hmac::Digest([22u8; 32]),
		);
		let serialized = fc.serialize();
		let deserialized = commit::FramedCommit::deserialize(&serialized);

		assert_eq!(Ok(fc), deserialized);
	}

	#[test]
	fn test_commit_ctd() {
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let commit_ctd = commit::CommitCtd::new(nid::Nid::new(b"abcdefgh", 0), Some(ctd));
		let serialized = commit_ctd.serialize();
		let deserialized = commit::CommitCtd::deserialize(&serialized);

		assert_eq!(Ok(commit_ctd), deserialized);

		let commit_ctd = commit::CommitCtd::new(nid::Nid::new(b"ijklmnop", 0), None);
		let serialized = commit_ctd.serialize();
		let deserialized = commit::CommitCtd::deserialize(&serialized);

		assert_eq!(Ok(commit_ctd), deserialized);
	}

	#[test]
	fn test_send_commit() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let sc = transport::SendCommit {
			cti,
			ctds: vec![
				commit::CommitCtd::new(
					nid::Nid::new(b"abcdefgh", 0),
					Some(hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3])),
				),
				commit::CommitCtd::new(nid::Nid::new(b"ssfdsss2", 0), None),
			],
		};
		let serialized = sc.serialize();
		let deserialized = transport::SendCommit::deserialize(&serialized);

		assert_eq!(Ok(sc), deserialized);
	}

	#[test]
	fn test_received_wlcm() {
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let cti = welcome::WlcmCti::new(cti, dilithium::Signature::new([57u8; 4595]));
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let wlcm = transport::ReceivedWelcome {
			cti,
			ctd,
			kp_id: id::Id([88u8; 32]),
		};
		let serialized = wlcm.serialize();
		let deserialized = transport::ReceivedWelcome::deserialize(&serialized);

		assert_eq!(Ok(wlcm), deserialized);
	}

	#[test]
	fn test_received_commit() {
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rc = transport::ReceivedCommit { cti, ctd };
		let serialized = rc.serialize();
		let deserialized = transport::ReceivedCommit::deserialize(&serialized);

		assert_eq!(Ok(rc), deserialized);
	}

	#[test]
	fn test_received_prop() {
		let ct0 = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ct1 = ciphertext::Ciphertext {
			content_id: id::Id([23u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 6, 7, 8, 9, 0],
			guid: id::Id([78u8; 32]),
			epoch: 102,
			gen: 2023,
			sender: nid::Nid::new(b"abcdef00", 9),
			iv: aes_gcm::Iv([98u8; 12]),
			sig: dilithium::Signature::new([30u8; 4595]),
			mac: hmac::Digest([71u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let rp = transport::ReceivedProposal {
			props: vec![ct0, ct1],
		};
		let serialized = rp.serialize();
		let deserialized = transport::ReceivedProposal::deserialize(&serialized);

		assert_eq!(Ok(rp), deserialized);
	}

	#[test]
	fn test_received_add() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([23u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 6, 7, 8, 9, 0],
			guid: id::Id([78u8; 32]),
			epoch: 102,
			gen: 2023,
			sender: nid::Nid::new(b"abcdef00", 9),
			iv: aes_gcm::Iv([98u8; 12]),
			sig: dilithium::Signature::new([30u8; 4595]),
			mac: hmac::Digest([71u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let rp = transport::ReceivedProposal { props: vec![ct] };
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 66, 77, 88, 99, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rc = transport::ReceivedCommit { cti, ctd };
		let ra = transport::ReceivedAdd {
			props: rp,
			commit: rc,
		};
		let serialized = ra.serialize();
		let deserialized = transport::ReceivedAdd::deserialize(&serialized);

		assert_eq!(Ok(ra), deserialized);
	}

	#[test]
	fn test_received_remove() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([23u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 6, 7, 8, 9, 0],
			guid: id::Id([78u8; 32]),
			epoch: 102,
			gen: 2023,
			sender: nid::Nid::new(b"abcdef00", 9),
			iv: aes_gcm::Iv([98u8; 12]),
			sig: dilithium::Signature::new([30u8; 4595]),
			mac: hmac::Digest([71u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let rp = transport::ReceivedProposal { props: vec![ct] };
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rr = transport::ReceivedRemove {
			props: rp.clone(),
			cti: cti.clone(),
			ctd: Some(ctd),
			delegated: true,
		};
		let serialized = rr.serialize();
		let deserialized = transport::ReceivedRemove::deserialize(&serialized);

		assert_eq!(Ok(rr), deserialized);

		let rr = transport::ReceivedRemove {
			props: rp,
			cti,
			ctd: None,
			delegated: false,
		};
		let serialized = rr.serialize();
		let deserialized = transport::ReceivedRemove::deserialize(&serialized);

		assert_eq!(Ok(rr), deserialized);
	}

	#[test]
	fn test_received_edit() {
		let prop = ciphertext::Ciphertext {
			content_id: id::Id([23u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 6, 7, 8, 9, 0],
			guid: id::Id([78u8; 32]),
			epoch: 102,
			gen: 2023,
			sender: nid::Nid::new(b"abcdef00", 9),
			iv: aes_gcm::Iv([98u8; 12]),
			sig: dilithium::Signature::new([30u8; 4595]),
			mac: hmac::Digest([71u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rr = transport::ReceivedEdit {
			prop,
			cti: cti.clone(),
			ctd,
		};
		let serialized = rr.serialize();
		let deserialized = transport::ReceivedEdit::deserialize(&serialized);

		assert_eq!(Ok(rr), deserialized);
	}

	#[test]
	fn test_received() {
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let cti = welcome::WlcmCti::new(cti, dilithium::Signature::new([57u8; 4595]));
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let wlcm = transport::ReceivedWelcome {
			cti,
			ctd,
			kp_id: id::Id([88u8; 32]),
		};
		let rcvd = transport::Received::Welcome(wlcm);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);

		let cti = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rc = transport::ReceivedCommit {
			cti: cti.clone(),
			ctd,
		};
		let rcvd = transport::Received::Commit(rc);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);

		let rp = transport::ReceivedProposal {
			props: vec![cti.clone()],
		};
		let rcvd = transport::Received::Props(rp);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);

		let ct = ciphertext::Ciphertext {
			content_id: id::Id([23u8; 32]),
			payload: vec![11, 22, 33, 44, 55, 6, 7, 8, 9, 0],
			guid: id::Id([78u8; 32]),
			epoch: 102,
			gen: 2023,
			sender: nid::Nid::new(b"abcdef00", 9),
			iv: aes_gcm::Iv([98u8; 12]),
			sig: dilithium::Signature::new([30u8; 4595]),
			mac: hmac::Digest([71u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let rp = transport::ReceivedProposal {
			props: vec![ct.clone()],
		};
		let ctd = hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]);
		let rc = transport::ReceivedCommit {
			cti: cti.clone(),
			ctd: ctd.clone(),
		};
		let ra = transport::ReceivedAdd {
			props: rp.clone(),
			commit: rc,
		};

		let rcvd = transport::Received::Add(ra);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);

		let rr = transport::ReceivedRemove {
			props: rp,
			cti: cti.clone(),
			ctd: Some(ctd),
			delegated: true,
		};

		let rcvd = transport::Received::Remove(rr);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);

		let rcvd = transport::Received::Msg(ct);
		let serialized = rcvd.serialize();
		let deserialized = transport::Received::deserialize(&serialized);

		assert_eq!(Ok(rcvd), deserialized);
	}

	#[test]
	fn test_ciphertext() {
		let ct = ciphertext::Ciphertext {
			content_id: id::Id([12u8; 32]),
			payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
			guid: id::Id([34u8; 32]),
			epoch: 77,
			gen: 1984,
			sender: nid::Nid::new(b"abcdefgh", 0),
			iv: aes_gcm::Iv([78u8; 12]),
			sig: dilithium::Signature::new([90u8; 4595]),
			mac: hmac::Digest([11u8; 32]),
			reuse_grd: reuse_guard::ReuseGuard::new(),
		};
		let serialized = ct.serialize();
		let deserialized = ciphertext::Ciphertext::deserialize(&serialized);

		assert_eq!(Ok(ct), deserialized);
	}
}

include!(concat!(env!("OUT_DIR"), "/main.rs"));

use crate::{
	aes_gcm, ciphertext, commit, dilithium, hpkencrypt, id, key_package, member, nid, proposal,
	protocol, roster,
	serializable::{Deserializable, Serializable},
	welcome,
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
	BadSendWelcomeFormat,
	BadCommitFormat,
	BadFramedCommitFormat,
	BadCommitCtdFormat,
	UnknownContentType,
	BadCiphertextFormat,
	WrongKeyPackageIdSize,
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
			key_id: val.key_id.as_bytes().to_vec(),
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
			key_id: id::Id(
				val.key_id
					.try_into()
					.or(Err(Error::WrongKeyPackageIdSize))?,
			),
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

// SendWelcome
impl From<&protocol::SendWelcome> for SendWelcome {
	fn from(val: &protocol::SendWelcome) -> Self {
		Self {
			cti: (&val.cti).into(),
			ctds: val.ctds.iter().map(|ctd| ctd.into()).collect(),
		}
	}
}

impl Serializable for protocol::SendWelcome {
	fn serialize(&self) -> Vec<u8> {
		SendWelcome::from(self).encode_to_vec()
	}
}

impl TryFrom<SendWelcome> for protocol::SendWelcome {
	type Error = Error;

	fn try_from(val: SendWelcome) -> Result<Self, Self::Error> {
		Ok(Self {
			cti: val.cti.try_into().or(Err(Error::BadWlcmCtiFormat))?,
			ctds: val
				.ctds
				.iter()
				.map(|ctd| {
					Ok(welcome::WlcmCtd::try_from(ctd.clone()).or(Err(Error::BadWlcmCtdFormat))?)
				})
				.collect::<Result<Vec<welcome::WlcmCtd>, Error>>()?,
		})
	}
}

impl Deserializable for protocol::SendWelcome {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(SendWelcome::decode(buf).or(Err(Error::BadSendWelcomeFormat))?)
	}
}

// Proposal
impl From<&proposal::Proposal> for Prop {
	fn from(val: &proposal::Proposal) -> Self {
		use prop::Variant;
		use proposal::Proposal::*;

		Self {
			variant: match val {
				Remove { id } => Some(Variant::Remove(prop::Remove {
					id: id.as_bytes().to_vec(),
				})),
				Update { kp } => Some(Variant::Update(prop::Update { kp: kp.into() })),
				Add { id, kp } => Some(Variant::Add(prop::Add {
					id: id.as_bytes().to_vec(),
					kp: kp.into(),
				})),
			},
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

impl From<&ciphertext::ContentType> for ContentType {
	fn from(val: &ciphertext::ContentType) -> Self {
		use ciphertext::ContentType as Cct;
		use ContentType as Pct;

		match val {
			Cct::App => Pct::App,
			Cct::Propose => Pct::Propsl,
			Cct::Commit => Pct::Commt,
		}
	}
}

impl From<ContentType> for ciphertext::ContentType {
	fn from(val: ContentType) -> Self {
		use ciphertext::ContentType as Cct;
		use ContentType as Pct;

		match val {
			Pct::App => Cct::App,
			Pct::Propsl => Cct::Propose,
			Pct::Commt => Cct::Commit,
		}
	}
}

impl TryFrom<i32> for ContentType {
	type Error = Error;

	fn try_from(val: i32) -> Result<Self, Self::Error> {
		match val {
			1 => Ok(Self::App),
			2 => Ok(Self::Propsl),
			3 => Ok(Self::Commt),
			_ => Err(Error::UnknownContentType),
		}
	}
}

// Ciphertext
impl From<&ciphertext::Ciphertext> for Ciphertext {
	fn from(val: &ciphertext::Ciphertext) -> Self {
		Self {
			content_type: ContentType::from(&val.content_type).into(),
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
			content_type: ciphertext::ContentType::from(
				ContentType::try_from(val.content_type).or(Err(Error::UnknownContentType))?,
			),
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

// Send

#[cfg(test)]
mod tests {
	use crate::{
		aes_gcm, ciphertext, commit, dilithium, hmac, hpkencrypt, id, key_package, member, nid,
		proposal, protocol, reuse_guard, roster,
		serializable::{Deserializable, Serializable},
		welcome, x448,
	};

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
	fn test_send_welcome() {
		let cti = hpkencrypt::CmpdCti::new(
			vec![1, 2, 3, 4, 5, 6, 7],
			vec![45u8; 56],
			aes_gcm::Iv([45u8; 12]),
			[123u8; 704],
		);
		let wcti = welcome::WlcmCti::new(cti, dilithium::Signature::new([57u8; 4595]));
		let sw = protocol::SendWelcome {
			cti: wcti,
			ctds: vec![
				welcome::WlcmCtd::new(
					nid::Nid::new(b"abcdefgh", 1),
					id::Id([22u8; 32]),
					hpkencrypt::CmpdCtd::new([11u8; 48], vec![1, 2, 3]),
				),
				welcome::WlcmCtd::new(
					nid::Nid::new(b"dhdsjdsj", 1),
					id::Id([42u8; 32]),
					hpkencrypt::CmpdCtd::new([51u8; 48], vec![8, 9, 0]),
				),
			],
		};

		let serialized = sw.serialize();
		let deserialized = protocol::SendWelcome::deserialize(&serialized);

		assert_eq!(Ok(sw), deserialized);
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
	fn test_ciphertext() {
		let ct = ciphertext::Ciphertext {
			content_type: ciphertext::ContentType::Propose,
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

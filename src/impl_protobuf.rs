include!(concat!(env!("OUT_DIR"), "/main.rs"));

use crate::{
	commit, dilithium, id, key_package, member, proposal, roster,
	serializable::{Deserializable, Serializable},
	welcome, hpkencrypt, aes_gcm,
};
use prost::Message;

#[derive(Debug, PartialEq)]
pub enum Error {
	BadFormat,
	WrongIlumKeySize,
	WrongDilithiumKeySize,
	WrongDilithiumSigSize,
	WrongIdSize,
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
	BadFramedProposalFormat,
	WrongCtiSize,
	WrongIvSize,
	BadCtiFormat,
}

// KeyPackage
impl From<&key_package::KeyPackage> for KeyPackage {
	fn from(val: &key_package::KeyPackage) -> Self {
		Self {
			ek: val.ek.to_vec(),
			svk: val.svk.as_bytes().to_vec(),
			signature: val.signature.as_bytes().to_vec(),
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
			ek: val.ek.try_into().or(Err(Error::WrongIlumKeySize))?,
			svk: dilithium::PublicKey::try_from(val.svk).or(Err(Error::WrongDilithiumKeySize))?,
			signature: dilithium::Signature::new(
				val.signature
					.try_into()
					.or(Err(Error::WrongDilithiumSigSize))?,
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
			id::Id(val.id.try_into().or(Err(Error::WrongIdSize))?),
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
			guid: val.guid.to_vec(),
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
			val.guid.try_into().or(Err(Error::WrongGuidSize))?,
			val.epoch,
			val.roster.try_into().or(Err(Error::BadRosterFormat))?,
			val.conf_trans_hash
				.try_into()
				.or(Err(Error::WrongConfTransHashSize))?,
			val.conf_tag.try_into().or(Err(Error::WrongConfTagSize))?,
			id::Id(val.inviter.try_into().or(Err(Error::WrongIdSize))?),
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
				id: id::Id(r.id.try_into().or(Err(Error::WrongIdSize))?),
			},
			Variant::Update(u) => Update {
				kp: u.kp.try_into().or(Err(Error::BadKeyPackageFormat))?,
			},
			Variant::Add(a) => Add {
				id: id::Id(a.id.try_into().or(Err(Error::WrongIdSize))?),
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
			guid: val.guid.to_vec(),
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
			val.guid.try_into().or(Err(Error::WrongGuidSize))?,
			val.epoch,
			id::Id(val.sender.try_into().or(Err(Error::WrongIdSize))?),
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
			cti: val.cti.to_vec(),
			iv: val.iv.as_bytes().to_vec(),
			sym_ct: val.sym_ct.to_vec(),
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
		Ok(hpkencrypt::CmpdCti::new(
			val.cti.try_into().or(Err(Error::WrongCtiSize))?,
			aes_gcm::Iv(val.iv.try_into().or(Err(Error::WrongIvSize))?),
			val.sym_ct
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

// FramedCommit
impl Serializable for commit::FramedCommit {
	fn serialize(&self) -> Vec<u8> {
		todo!()
	}
}

impl Deserializable for commit::FramedCommit {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		todo!()
	}
}

//--------

#[cfg(test)]
mod tests {
	use crate::{
		dilithium, hmac, id, key_package, member, proposal, roster, hpkencrypt, aes_gcm,
		serializable::{Deserializable, Serializable},
	};

	#[test]
	fn test_key_package() {
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let s_kp = dilithium::KeyPair::generate();
		let pack = key_package::KeyPackage::new(&e_kp.pk, &s_kp.public, &s_kp.private);
		let serialized = pack.serialize();
		let deserialized = key_package::KeyPackage::deserialize(&serialized);

		assert_eq!(Ok(pack), deserialized);
	}

	#[test]
	fn test_member() {
		let seed = b"1234567890abcdef";
		let e_kp = ilum::gen_keypair(seed);
		let s_kp = dilithium::KeyPair::generate();
		let pack = key_package::KeyPackage::new(&e_kp.pk, &s_kp.public, &s_kp.private);
		let member = member::Member::new(id::Id([42u8; 32]), pack);
		let serialized = member.serialize();
		let deserialized = member::Member::deserialize(&serialized);

		assert_eq!(Ok(member), deserialized);
	}

	#[test]
	fn test_roster() {
		let mut r = roster::Roster::new();

		_ = r.add(member::Member::new(
			id::Id([12u8; 32]),
			key_package::KeyPackage {
				ek: [34u8; 768],
				svk: dilithium::PublicKey::new([56u8; 2592]),
				signature: dilithium::Signature::new([78u8; 4595]),
			},
		));

		_ = r.add(member::Member::new(
			id::Id([34u8; 32]),
			key_package::KeyPackage {
				ek: [56u8; 768],
				svk: dilithium::PublicKey::new([78u8; 2592]),
				signature: dilithium::Signature::new([90u8; 4595]),
			},
		));

		_ = r.add(member::Member::new(
			id::Id([56u8; 32]),
			key_package::KeyPackage {
				ek: [78u8; 768],
				svk: dilithium::PublicKey::new([90u8; 2592]),
				signature: dilithium::Signature::new([12u8; 4595]),
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
			ek: [56u8; 768],
			svk: dilithium::PublicKey::new([78u8; 2592]),
			signature: dilithium::Signature::new([90u8; 4595]),
		};

		let prop = Proposal::Remove {
			id: id::Id([12u8; 32]),
		};
		let serialized = prop.serialize();
		let deserialized = Proposal::deserialize(&serialized);

		assert_eq!(Ok(prop), deserialized);

		let prop = Proposal::Update { kp: kp.clone() };
		let serialized = prop.serialize();
		let deserialized = Proposal::deserialize(&serialized);

		assert_eq!(Ok(prop), deserialized);

		let prop = Proposal::Add {
			id: id::Id([45u8; 32]),
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
			ek: [56u8; 768],
			svk: dilithium::PublicKey::new([78u8; 2592]),
			signature: dilithium::Signature::new([90u8; 4595]),
		};
		let prop = Proposal::Add {
			id: id::Id([15u8; 32]),
			kp,
		};
		let fc = proposal::FramedProposal::new(
			[123u8; 32],
			17u64,
			id::Id([45u8; 32]),
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
		let cti = hpkencrypt::CmpdCti::new([123u8; 704], aes_gcm::Iv([45u8; 12]), vec![1, 2, 3, 4, 5, 6, 7]);
		let serialized = cti.serialize();
		let deserialized = hpkencrypt::CmpdCti::deserialize(&serialized);

		assert_eq!(Ok(cti), deserialized);
	}
}

use crate::{aes_gcm, hash::Hashable, hkdf, x448};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum Error {
	IlumKeyPairMismatch,
	EccKeyPairMismatch,
	BadAesMaterial,
	BadAesFormat,
	BadEccKeyFormat,
}

pub struct IlumEncrypted {
	// key-independent encapsulation
	pub cti: IlumCti,
	// key-dependent encapsulations
	pub ctds: Vec<ilum::Ctd>,
}

// Compound, key-independent ciphertext
#[derive(Clone, Debug, PartialEq)]
pub struct IlumCti {
	// key-independent encapsulation
	pub cti: ilum::Cti,
	// aes iv
	pub iv: aes_gcm::Iv,
	// aes ciphertext, encrypted eph key in the mixed mode; decrypts by combining Cti with Ctd (= aes key)
	pub ct: Vec<u8>,
}

impl IlumCti {
	pub fn new(cti: ilum::Cti, iv: aes_gcm::Iv, ct: Vec<u8>) -> Self {
		Self { cti, iv, ct }
	}
}

const KDF_LABEL: &[u8] = b"hpkencrypt";

fn aes_expand_key(seed: &[u8]) -> aes_gcm::Key {
	let aes_key = hkdf::Hkdf::from_ikm(seed).expand::<{ aes_gcm::Key::SIZE }>(KDF_LABEL);

	aes_gcm::Key(aes_key)
}

fn aes_expand_key_iv(seed: &[u8]) -> aes_gcm::Aes {
	let material =
		hkdf::Hkdf::from_ikm(seed).expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();
	let key = aes_gcm::Key(material[..aes_gcm::Key::SIZE].try_into().unwrap());
	let iv = aes_gcm::Iv(material[aes_gcm::Key::SIZE..].try_into().unwrap());

	aes_gcm::Aes::new_with_key_iv(key, iv)
}

pub fn ilum_encrypt(pt: &[u8], seed: &ilum::Seed, keys: &[ilum::PublicKey]) -> IlumEncrypted {
	let encapsulated = ilum::enc(seed, keys);
	let aes_key = aes_expand_key(&encapsulated.ss);
	let aes = aes_gcm::Aes::new_with_key(aes_key);
	let ct = aes.encrypt(pt);

	IlumEncrypted {
		cti: IlumCti::new(encapsulated.cti, aes.iv, ct),
		ctds: encapsulated.ctds,
	}
}

pub fn ilum_decrypt(
	ct: &[u8],
	cti: &ilum::Cti,
	ctd: &ilum::Ctd,
	seed: &ilum::Seed,
	pk: &ilum::PublicKey,
	sk: &ilum::SecretKey,
	iv: &aes_gcm::Iv,
) -> Result<Vec<u8>, Error> {
	let ss = ilum::dec(cti, ctd, seed, pk, sk).ok_or(Error::IlumKeyPairMismatch)?;
	let aes_key = aes_expand_key(&ss);

	aes_gcm::Aes::new_with_key_iv(aes_key, iv.clone())
		.decrypt(ct)
		.or(Err(Error::BadAesMaterial))
}

#[derive(Debug, Clone, PartialEq)]
pub struct CmpdCtd {
	pub ilum_ctd: ilum::Ctd,
	pub ecc_ctd: EccCtd,
}

impl CmpdCtd {
	pub fn new(ilum_ctd: ilum::Ctd, ecc_ctd: EccCtd) -> Self {
		Self { ilum_ctd, ecc_ctd }
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmpdCti {
	pub ct: Vec<u8>,
	pub encrypted_eph_key: Vec<u8>,
	pub iv: aes_gcm::Iv,
	pub ilum_cti: ilum::Cti,
}

impl CmpdCti {
	pub fn new(
		ct: Vec<u8>,
		encrypted_eph_key: Vec<u8>,
		iv: aes_gcm::Iv,
		ilum_cti: ilum::Cti,
	) -> Self {
		Self {
			ct,
			encrypted_eph_key,
			iv,
			ilum_cti,
		}
	}
}

impl Hashable for CmpdCti {
	fn hash(&self) -> crate::hash::Hash {
		Sha256::digest(
			[
				self.ct.as_slice(),
				self.encrypted_eph_key.as_slice(),
				self.iv.as_bytes(),
				&self.ilum_cti.as_slice(),
			]
			.concat(),
		)
		.into()
	}
}

pub struct Encrypted {
	pub cti: CmpdCti,
	pub ctds: Vec<CmpdCtd>,
}

pub fn encrypt(
	pt: &[u8],
	seed: &ilum::Seed,
	keys: &[(ilum::PublicKey, x448::PublicKey)],
) -> Encrypted {
	// this keeps the encrypted ct of pt
	let EccEncrypted {
		eph_key,
		ct,
		ctds: ecc_ctds,
	} = ecc_encrypt(
		pt,
		&keys
			.iter()
			.map(|(_, key)| key.clone())
			.collect::<Vec<x448::PublicKey>>(),
	);

	// encrypt the emphemeral key used by the step above
	let IlumEncrypted {
		cti,
		ctds: ilum_ctds,
	} = ilum_encrypt(
		eph_key.as_bytes(),
		seed,
		&keys
			.iter()
			.map(|(key, _)| *key)
			.collect::<Vec<ilum::PublicKey>>(),
	);

	let ctds = ecc_ctds
		.into_iter()
		.zip(ilum_ctds.into_iter())
		.map(|(ecc_ctd, ilum_ctd)| CmpdCtd { ilum_ctd, ecc_ctd })
		.collect();

	Encrypted {
		cti: CmpdCti {
			ct,
			encrypted_eph_key: cti.ct,
			iv: cti.iv,
			ilum_cti: cti.cti,
		},
		ctds,
	}
}

pub fn decrypt(
	cti: &CmpdCti,
	ctd: &CmpdCtd,
	seed: &ilum::Seed,
	ilum_pk: &ilum::PublicKey,
	ilum_sk: &ilum::SecretKey,
	ecc_sk: &x448::PrivateKey,
) -> Result<Vec<u8>, Error> {
	let eph_key = ilum_decrypt(
		&cti.encrypted_eph_key,
		&cti.ilum_cti,
		&ctd.ilum_ctd,
		seed,
		ilum_pk,
		ilum_sk,
		&cti.iv,
	)?
	.try_into()
	.or(Err(Error::IlumKeyPairMismatch))?;

	ecc_decrypt(&cti.ct, &ctd.ecc_ctd, ecc_sk, &eph_key)
}

// TODO: can this be of a fixed size instead?
type EccCtd = Vec<u8>;

pub struct EccEncrypted {
	// ephemeral key used to dh with the supplied public keys
	pub eph_key: x448::PublicKey,
	// actual ct encrypted with randomly generated aes parameters (key, iv)
	pub ct: Vec<u8>,
	// aes key & iv encrypted to the supplied public keys by dh-ing each one with the generated eph key
	pub ctds: Vec<EccCtd>,
}

pub fn ecc_encrypt(pt: &[u8], keys: &[x448::PublicKey]) -> EccEncrypted {
	// TODO: consider rayon for parallel dh operations

	// generate a random aes key/iv pair
	let inner_aes = aes_gcm::Aes::new();
	// encrypt pt with the generated aes
	let ct = inner_aes.encrypt(pt);

	// TODO: this does not authenticate me, does it? Should I sign the ephemeral key (and iv)?
	let eph_kp = x448::KeyPair::generate();
	// encrypt the used aes to each specified public key
	let ctds = keys
		.iter()
		.map(|key| {
			let outer_aes = aes_expand_key_iv(x448::dh_exchange(&eph_kp.private, key).as_bytes());

			outer_aes.encrypt(&inner_aes.as_bytes())
		})
		.collect::<Vec<EccCtd>>();

	EccEncrypted {
		eph_key: eph_kp.public,
		ct,
		ctds,
	}
}

pub fn ecc_decrypt(
	ct: &[u8],
	ctd: &[u8],
	sk: &x448::PrivateKey,
	eph_key: &x448::PublicKey,
) -> Result<Vec<u8>, Error> {
	let outer_aes = aes_expand_key_iv(x448::dh_exchange(sk, eph_key).as_bytes());
	let inner_aes_bytes = outer_aes.decrypt(&ctd).or(Err(Error::EccKeyPairMismatch))?;
	let inner_aes =
		aes_gcm::Aes::try_from(inner_aes_bytes.as_ref()).or(Err(Error::BadAesFormat))?;

	inner_aes.decrypt(ct).or(Err(Error::BadAesMaterial))
}

#[cfg(test)]
mod tests {
	use super::{ecc_decrypt, ecc_encrypt, ilum_decrypt, ilum_encrypt, Error};
	use crate::{
		aes_gcm,
		hpkencrypt::{decrypt, encrypt},
	};

	#[test]
	fn test_encrypt_to_no_keys() {
		// TODO: implement
	}

	#[test]
	fn test_ilum_encrypt_decrypt() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = ilum_encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = ilum_decrypt(
				&sealed.cti.ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&kp.pk,
				&kp.sk,
				&sealed.cti.iv,
			);

			assert_eq!(r, Ok(msg.to_vec()));
		});
	}

	#[test]
	fn test_ilum_decrypt_fails_for_wrong_keys() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = ilum_encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		// fails for wrong sk
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = ilum_decrypt(
				&sealed.cti.ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&kp.pk,
				&ilum::gen_keypair(&seed).sk,
				&sealed.cti.iv,
			);

			assert_eq!(r, Err(Error::IlumKeyPairMismatch));
		});

		// fails for wrong pk
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = ilum_decrypt(
				&sealed.cti.ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&ilum::gen_keypair(&seed).pk,
				&kp.sk,
				&sealed.cti.iv,
			);

			assert_eq!(r, Err(Error::IlumKeyPairMismatch));
		});
	}

	#[test]
	fn test_ilum_decrypt_fails_for_wrong_iv() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = ilum_encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		// fails for wrong iv
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = ilum_decrypt(
				&sealed.cti.ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&kp.pk,
				&kp.sk,
				&aes_gcm::Iv::generate(),
			);

			assert_eq!(r, Err(Error::BadAesMaterial));
		});
	}

	#[test]
	fn test_ecc_encrypt_decrypt() {
		use crate::x448;

		let kps = (0..10)
			.map(|_| x448::KeyPair::generate())
			.collect::<Vec<x448::KeyPair>>();
		let pt = b"hey there";

		let encrypted = ecc_encrypt(
			pt,
			&kps.iter()
				.map(|kp| kp.public.clone())
				.collect::<Vec<x448::PublicKey>>(),
		);

		kps.iter().enumerate().for_each(|(idx, kp)| {
			assert_eq!(
				Ok(pt.to_vec()),
				ecc_decrypt(
					&encrypted.ct,
					&encrypted.ctds[idx],
					&kp.private,
					&encrypted.eph_key
				)
			);
		});
	}

	#[test]
	fn test_hpke_encrypt_decrypt() {
		use crate::x448;
		use ilum;

		let seed = [123u8; 16];
		let kps = (0..10)
			.map(|_| (x448::KeyPair::generate(), ilum::gen_keypair(&seed)))
			.collect::<Vec<(x448::KeyPair, ilum::KeyPair)>>();
		let pt = b"hey there";

		let encrypted = encrypt(
			pt,
			&seed,
			&kps.iter()
				.map(|(ecc, ilum)| (ilum.pk.clone(), ecc.public.clone()))
				.collect::<Vec<(ilum::PublicKey, x448::PublicKey)>>(),
		);

		kps.iter().enumerate().for_each(|(idx, (ecc, ilum))| {
			assert_eq!(
				Ok(pt.to_vec()),
				decrypt(
					&encrypted.cti,
					&encrypted.ctds[idx],
					&seed,
					&ilum.pk,
					&ilum.sk,
					&ecc.private
				)
			);
		})
	}
}

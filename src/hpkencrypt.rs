use crate::{aes_gcm, hash::Hashable, hkdf, x448};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum Error {
	KeyPairMismatch,
	BadAesMaterial,
	BadAesFormat,
}

pub struct Encryption {
	// key-independent encapsulation
	pub cti: CmpdCti,
	// key-dependent encapsulations
	pub ctds: Vec<ilum::Ctd>,
}

// Compound, key-independent ciphertext
// REVIEW: applies to CmPKEs only
#[derive(Clone, Debug, PartialEq)]
pub struct CmpdCti {
	// key-independent encapsulation
	pub cti: ilum::Cti,
	// aes iv
	pub iv: aes_gcm::Iv, // TODO: remove
	// aes ciphertext
	pub sym_ct: Vec<u8>,
}

impl CmpdCti {
	pub fn new(cti: ilum::Cti, iv: aes_gcm::Iv, sym_ct: Vec<u8>) -> Self {
		Self { cti, iv, sym_ct }
	}
}

impl Hashable for CmpdCti {
	fn hash(&self) -> crate::hash::Hash {
		Sha256::digest([self.cti.as_slice(), self.iv.as_bytes(), &self.sym_ct].concat()).into()
	}
}

const KDF_LABEL: &[u8] = b"hpkencrypt";

fn aes_expand_key(seed: &[u8]) -> aes_gcm::Key {
	let aes_key = hkdf::Hkdf::from_ikm(seed).expand::<{ aes_gcm::Key::SIZE }>(KDF_LABEL);

	aes_gcm::Key(aes_key)
}

// TODO: should expect a mixed PK type, eg CmpdPublicKey or something
pub fn encrypt(pt: &[u8], seed: &ilum::Seed, keys: &[ilum::PublicKey]) -> Encryption {
	let encapsulated = ilum::enc(seed, keys);
	let aes_key = aes_expand_key(&encapsulated.ss);
	let aes = aes_gcm::Aes::new_with_key(aes_key);
	let ct = aes.encrypt(pt);
	// eph = ecc_gen()
	// hpkencrypt(eph + aes_key1)
	// aes_key = ct + ecc_enc(ecc_key, eph, recipient_key)
	// hpkencrypt(eph)

	Encryption {
		cti: CmpdCti::new(encapsulated.cti, aes.iv, ct),
		ctds: encapsulated.ctds,
	}
}

type EccCtd = Vec<u8>;

pub struct EccEncryption {
	pub eph_key: x448::PublicKey,
	pub ct: Vec<u8>,
	pub ctds: Vec<EccCtd>,
}

pub fn ecc_encrypt(pt: &[u8], keys: &[x448::PublicKey]) -> EccEncryption {
	// TODO: consider rayon for parallel dh operations

	// generate a random aes key/iv pair
	let inner_aes = aes_gcm::Aes::new();
	// encrypt pt with the generated aes
	let ct = inner_aes.encrypt(pt);
	let eph_kp = x448::KeyPair::generate();
	// encrypt the used aes to each specified public key
	let ctds = keys
		.iter()
		.map(|key| {
			let ss = x448::dh_exchange(&eph_kp.private, key);
			let material = hkdf::Hkdf::from_ikm(ss.as_bytes())
				.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();
			let key = aes_gcm::Key(material[..aes_gcm::Key::SIZE].try_into().unwrap());
			let iv = aes_gcm::Iv(material[aes_gcm::Key::SIZE..].try_into().unwrap());
			let outer_aes = aes_gcm::Aes::new_with_key_iv(key, iv);

			outer_aes.encrypt(&inner_aes.as_bytes())
		})
		.collect::<Vec<EccCtd>>();

	EccEncryption {
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
	let ss = x448::dh_exchange(sk, eph_key);
	let material = hkdf::Hkdf::from_ikm(ss.as_bytes())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();
	let key = aes_gcm::Key(material[..aes_gcm::Key::SIZE].try_into().unwrap());
	let iv = aes_gcm::Iv(material[aes_gcm::Key::SIZE..].try_into().unwrap());
	let outer_aes = aes_gcm::Aes::new_with_key_iv(key, iv);
	let inner_aes_bytes = outer_aes.decrypt(&ctd).or(Err(Error::BadAesMaterial))?;
	let inner_aes =
		aes_gcm::Aes::try_from(inner_aes_bytes.as_ref()).or(Err(Error::BadAesFormat))?;

	inner_aes.decrypt(ct).or(Err(Error::BadAesMaterial))
}

pub fn decrypt(
	ct: &[u8],
	cti: &ilum::Cti,
	ctd: &ilum::Ctd,
	seed: &ilum::Seed,
	pk: &ilum::PublicKey,
	sk: &ilum::SecretKey,
	iv: &aes_gcm::Iv,
) -> Result<Vec<u8>, Error> {
	let ss = ilum::dec(cti, ctd, seed, pk, sk).ok_or(Error::KeyPairMismatch)?;
	let aes_key = aes_expand_key(&ss);

	aes_gcm::Aes::new_with_key_iv(aes_key, iv.clone())
		.decrypt(ct)
		.or(Err(Error::BadAesMaterial))
}

#[cfg(test)]
mod tests {
	use super::{decrypt, ecc_decrypt, ecc_encrypt, encrypt, Error};
	use crate::aes_gcm;

	#[test]
	fn test_encrypt_to_no_keys() {
		// TODO: implement
	}

	#[test]
	fn encrypt_decrypt() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = decrypt(
				&sealed.cti.sym_ct,
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
	fn decrypt_fails_for_wrong_keys() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		// fails for wrong sk
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = decrypt(
				&sealed.cti.sym_ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&kp.pk,
				&ilum::gen_keypair(&seed).sk,
				&sealed.cti.iv,
			);

			assert_eq!(r, Err(Error::KeyPairMismatch));
		});

		// fails for wrong pk
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = decrypt(
				&sealed.cti.sym_ct,
				&sealed.cti.cti,
				&sealed.ctds[idx],
				&seed,
				&ilum::gen_keypair(&seed).pk,
				&kp.sk,
				&sealed.cti.iv,
			);

			assert_eq!(r, Err(Error::KeyPairMismatch));
		});
	}

	#[test]
	fn decrypt_fails_for_wrong_iv() {
		let seed = [123u8; 16];
		let kps = (0..5)
			.map(|_| ilum::gen_keypair(&seed))
			.collect::<Vec<ilum::KeyPair>>();

		let msg = b"Hey there";
		let sealed = encrypt(
			msg,
			&seed,
			&kps.iter().map(|kp| kp.pk).collect::<Vec<ilum::PublicKey>>(),
		);

		// fails for wrong iv
		kps.iter().enumerate().for_each(|(idx, kp)| {
			let r = decrypt(
				&sealed.cti.sym_ct,
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
			assert_eq!(Ok(pt.to_vec()), ecc_decrypt(&encrypted.ct, &encrypted.ctds[idx], &kp.private, &encrypted.eph_key));
		});
	}
}

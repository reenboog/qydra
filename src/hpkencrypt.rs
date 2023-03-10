use crate::{
	aes_gcm::{self, Aes},
	hash::Hashable,
	hkdf,
};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum Error {
	KeyPairMismatch,
	BadAesMaterial,
}

pub struct Encryption {
	// key-independent encapsulation
	pub cti: CmpdCti,
	// key-dependent encapsulations
	pub ctds: Vec<ilum::Ctd>,
}

// Compound, key-independent ciphertext
// REVIEW: applies to CmPKEs only
#[derive(Clone)]
pub struct CmpdCti {
	// key-independent encapsulation
	pub cti: ilum::Cti,
	// aes iv
	pub iv: aes_gcm::Iv,
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
	let aes = Aes::new_with_key(aes_key);
	let ct = aes.encrypt(pt);

	Encryption {
		cti: CmpdCti::new(encapsulated.cti, aes.iv, ct),
		ctds: encapsulated.ctds,
	}
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

	Aes::new_with_key_iv(aes_key, iv.clone())
		.decrypt(ct)
		.or(Err(Error::BadAesMaterial))
}

#[cfg(test)]
mod tests {
	use crate::aes_gcm::Iv;

	use super::{decrypt, encrypt, Error};

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
				&Iv::generate(),
			);

			assert_eq!(r, Err(Error::BadAesMaterial));
		});
	}
}

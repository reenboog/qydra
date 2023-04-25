/*

	The backend is to ensure the same order for all received messages for all group members, eg if the backend
	*receives* m1, m2, m3 (*regardless* of what was sent earlier), everyone in the group is to receive m1, then m2 and finally m3:

										|		a		b		c		d		..	z
	b ----m2----->		|		m1	m1 	m1	m1	..	m1
	c ----m3---->			|		m2	m2 	m2	m2	..	m2
	d ----m1------>		|		m3	m3 	m3	m3	..	m3

	Updates with version lower than the most recent are to be ignored when received except for my own
	commits containing either adds or removes – if that's a case, resend by a higher level (for an updated epoch)

	Bth, there is no reason for the backend to refuse any commits anymore: the only thing it needs to do is
	to queue whatever comes in and whether a commit/proposal is still valid each recipient is to decide themselves.

	Adds and removes are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From thr sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message could look like this:

 // encrypt?
	struct Stage {
		proposals: Option<[FramedProposal]>,
		commit: Option<FramedCommid>,
	}

	A party should not issue a commit if there's an unacked proposal of its own: say, Alice proposes [upd_a] and commits immediately
	which for some reason makes the proposal to be either lost or received by the BE after the commit. When processing, recipients would not
	find the attached proposal which leads to an error by design.

	How to implement self-removes? One can't create a self-removing commit for he should not know the new com_secret.
	A Remove(id = self) proposal might be ignore by a concurrent commit. Sending a dedicated Leave message might not be sufficient as well,
	unless some one else commits immediately, but who?

	When a device/account is deleted, the backend could respond to users' messages by attaching a nack(user_deleted=[ids]), so that
	one could send a proposal-commit pair in order to fix the roster

*/

use std::sync::Arc;

use crate::{
	commit::FramedCommit,
	hash::Hash,
	id::Id,
	proposal::FramedProposal,
	welcome::{WlcmCtd, WlcmCti},
};

// a randomly generated public seed that is to be used for all instances of this protocol in order for mPKE to work
const ILUM_SEED: &[u8; 16] = b"\x96\x48\xb8\x08\x8b\x16\x1c\xf1\x22\xee\xb4\x5a\x29\x69\x02\x43";

// pub struct Owner {
// 	id: Id,
// 	kp: KeyPackage,
// 	ilum_dk: ilum::SecretKey,
// 	x448_dk: x448::PrivateKey,
// 	ssk: dilithium::PrivateKey,
// }

pub trait Storage {
	//
}

pub trait Api {
	//
}

pub struct Protocol<S, A> {
	storage: Arc<S>,
	api: Arc<A>,
}

impl<S, A> Protocol<S, A>
where
	S: Storage,
	A: Api,
{
	pub fn create_group() {
		// TODO: serialize
	}
}

// enum Message {
// 	App(Vec<u8>),
// 	Propose(FramedProposal),
// 	Commit(FramedCommit, ilum::Ctd),
// 	Welcome(WlcmCti, WlcmCtd),
// }

// fn decrypt(msg: Encrypted) -> Message {
// 1 get state for (guid, epoch)
// 2 get a chain tree for the given message type
// 3 get a detached key for the given tree & gen
// 4 derive mac_key and enc_key from the given detached key
// 5 verify mac of the payload
// 6 if msg.type == commit
//	6.1 if sender == me
//		6.1.1 if not_outdated apply_by_id
//		6.1.2 else resend_if_required_or_ignore
// 	6.2 else
//		6.2.1 if not_outdated decrypt_and_apply(cm, enc_key)
//		6.2.1 ignore
// 7 else if msg.type == proposal decrypt_and_store_if_not_outdated(p, enc_key)
// 8 else decrypt_and_store

// todo!()
// }

#[cfg(test)]
mod tests {
	#[test]
	fn test_create_group() {
		//
	}
}

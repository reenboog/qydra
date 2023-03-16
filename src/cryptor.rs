/*
	Epoch-based order is crucial for all operations: if Alice receives her own commit of epoch N after 
	Bob's message/update/another commit of epoch N + 1 she wouldn't be able to decrypt it. Hence, the backend
	is to queue all incoming messages based on epoch (+ optional ts).

	Updates with version lower than the most recent are to be ignored when received.

	Adds and removes are to be embedded in a commit to avoid state loss: say, Alice commits [upd_a, upb_b, upd_c] @ epoch 5
	while Charlie invites Dan at the same epoch. What should happen when Alice's commit is applied and produces epoch 6 while Charlie's
	proposal arrives afterwards? From the Alice's perspective it would be an outdated proposal, so Charlie would have to invite
	Dan again at least, but he could be offline. Then what if it's an eviction instead? From thr sender's perspective the evicted
	member should leave immediately, but things might go wrong under poor connectivity in particular. Hence by embedding adds/removes into
	a commit things become easier to handle (no resending logic) and "atomic". Such a message could look like this:

	struct Stage {
		proposals: Option<[FramedProposal]>,
		commit: Option<FramedCommid>,
	}

	A party should not issue a commit if there's an unacked proposal of its own: say, Alice proposes [upd_a] and commits immediately
	which for some reason makes the proposal to be either lost or received by the BE after the commit. When processing, recipients would not
	find the attached proposal which leads to an error by design.

	How to implement self-removes? One can't self a self-removing commit for he should not know the new com_secret.
	A Remove(id = self) proposal might be ignore by a concurrent commit. Sending a dedicated Leave message might not be sufficient as well,
	unless some one else commits immediately

	How could the backend reject commits without having the full state? If rejection is not feasible,
	how can participants advance given their epoch would be lower than of the corupt commit? By simply
	incrementing? By interactively negotiating the new version with the backend?

*/
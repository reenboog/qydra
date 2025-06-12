# qydra

[![Rust](https://github.com/reenboog/qydra/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/reenboog/qydra/actions/workflows/rust.yml)

qydra is an experimental implementation of a Continuous Group Key Agreement (CGKA) protocol — conceptually similar to MLS (Message Layer Security), but designed with a simpler internal structure and tighter integration with the ilum cryptographic primitive.

Unlike traditional CGKA protocols, qydra is built around a chained multi-recipient public key encryption scheme (ilum is used in this implementation, but any cmPKE can be used), allowing group members to efficiently exchange and update secrets without relying on complex tree structures.

Highlights
- End-to-End Security: Supports dynamic groups with forward secrecy and post-compromise security.
- Simplified State Management: Minimal and explicit group state, no ratchet trees or binary trees.
- Core Group Operations: Add/remove users, apply updates, handle invitations and epochs via a clean, state-driven API.
- Rust-first: Designed for secure backend or cryptographic infrastructure integration.

Use Case
qydra is suitable for applications requiring lightweight group messaging security, such as:

- Real-time collaboration tools
- Decentralized chat protocols
- Encrypted broadcast/multicast systems
- Experimental secure group transport layers

Just instantiate `Protocol` (qydra/src/protocol.rs) providing implementations for Storage and Api traits to create groups and manage groups. Also, checking `test_normal_flow` (playground/src/main.rs) could be helpful.

To run tests, an increased stack is required, eg 

```
env RUST_MIN_STACK=7194304 cargo test
```

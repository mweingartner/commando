# External issuer conformance fixture v1

Status: TEST FIXTURE ONLY

This directory is bounded known-answer evidence for MPD's offline
`sshsig-ed25519-v1` verifier. It is not a production issuer, is not referenced by
`.mpd/config.json`, and must never be promoted into an activated trust root.

The fixture signs the exact bytes in `message.txt` with OpenSSH namespace
`mpd-attestation-v1`. `public-key.txt` is the corresponding comment-free canonical
Ed25519 public key; `message.sig` is the armored SSHSIG result. The private key was
discarded and is intentionally absent.

Conformance checks must prove:

- the fixed namespace and exact public key verify the known message;
- another namespace returns `attestation.namespace` before verifier execution;
- another key returns `attestation.key` before verifier execution;
- a changed message/signature returns `attestation.signature`;
- an exact payload bound to another phase/model/actor/subject returns
  `attestation.signature`;
- verifier executable or reviewed tool-lock drift returns
  `attestation.verifier-drift`.

These checks establish verifier behavior only. They do not prove that any model or
session ran, do not authorize required-attestation mode, and do not supply benchmark,
gate, release, or deployment evidence.

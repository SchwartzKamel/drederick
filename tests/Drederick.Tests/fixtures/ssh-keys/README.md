# SSH key test fixtures (gap-039 passphrase brute)

Encrypted SSH private keys used by `SshKeyPassphraseBruteToolTests`.

## Files

- `ed25519-encrypted` / `.pub` — ed25519 keypair, passphrase
  `testpass-canary-passphrase`, default bcrypt-pbkdf rounds.
- `rsa-encrypted` / `.pub` — 2048-bit RSA keypair, PEM (`-m PEM`),
  passphrase `testpass-canary-passphrase`.

## Provenance

Generated locally with:

```bash
ssh-keygen -t ed25519 -N 'testpass-canary-passphrase' -f ed25519-encrypted -C 'drederick-test'
ssh-keygen -t rsa -b 2048 -m PEM -N 'testpass-canary-passphrase' -f rsa-encrypted -C 'drederick-test'
```

These keys exist solely as test material — they have **no** corresponding
authorized account anywhere. Do not deploy them.

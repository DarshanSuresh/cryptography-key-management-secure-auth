# Secure Key & Secret Management

## 1. Storage

Never commit:
- Private keys
- API keys
- Passwords
- Database credentials
- JWT signing secrets
- Cloud access keys

Preferred production options:
- Cloud KMS/HSM
- Managed secrets manager
- OS-level protected secret stores
- Hardware-backed key storage for high-assurance use cases

Use environment variables only as a basic deployment mechanism; they are not equivalent to a dedicated secrets manager.

## 2. Access Control

Apply least privilege:
- Separate encryption/signing keys by purpose.
- Restrict which services can read each secret.
- Require strong administrative authentication.
- Audit key access.

## 3. Rotation

A practical rotation lifecycle is:

```text
Generate → Distribute → Activate → Monitor → Rotate → Revoke → Destroy
```

Keep a key version identifier with encrypted data when your design needs migration between key versions.

For AES-GCM, never reuse a nonce with the same key. During rotation, decrypt legacy ciphertext with its recorded key version and re-encrypt with the current key.

## 4. Backup & Recovery

Protect backups with equivalent or stronger controls than production:
- Encrypt backups.
- Restrict access.
- Test recovery procedures.
- Document key ownership and recovery responsibilities.

## 5. Compromise Response

If a key is suspected to be compromised:
1. Revoke/disable it where possible.
2. Identify affected data/signatures.
3. Generate a replacement key.
4. Migrate data where necessary.
5. Review audit logs.
6. Document the incident.

## 6. Cryptographic Hygiene

Do not invent cryptographic algorithms or protocols. Use vetted libraries and current standards. Keep dependencies patched and review cryptographic parameters periodically.

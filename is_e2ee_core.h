// Portable crypto core for InstanceSwitcher's E2EE support.
// Matches meowcord's client/e2ee: HPKE base mode (DHKEM X25519 / HKDF-SHA256 / AES-256-GCM), AES-256-GCM boxes,
// Argon2id key backup. v14 adds the sealing half (is_random, is_b64u_encode, is_gcm_seal, is_hpke_seal) so
// messages can be encrypted as well as decrypted. Nothing here talks to the network or touches key storage.
#ifndef IS_E2EE_CORE_H
#define IS_E2EE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// base64url without padding. Returns decoded length, or -1 on invalid input / not enough room.
int is_b64u_decode(const char *s, size_t slen, uint8_t *out, size_t cap);

void is_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

// HKDF-SHA256 (extract + expand). out_len <= 255 * 32. A NULL/empty salt behaves as 32 zero bytes.
void is_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

// AES-256-GCM open. ct holds ciphertext||16-byte tag. Returns plaintext length or -1 if authentication fails.
int is_gcm_open(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                const uint8_t *ct, size_t ct_len, uint8_t *out);

// RFC 9180 base-mode HPKE open. sk = recipient X25519 private key, enc = 32-byte encapsulated key.
// Returns plaintext length or -1.
int is_hpke_open(const uint8_t sk[32], const uint8_t enc[32], const uint8_t *info, size_t info_len,
                 const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, uint8_t *out);

// ---- v14: sealing ----------------------------------------------------------------------------------------------

// Fills buf with n random bytes from the OS (getentropy). Returns 0 or -1.
int is_random(uint8_t *buf, size_t n);

// base64url without padding. Writes a NUL-terminated string; returns its length, or -1 if cap is too small
// (cap must be at least ceil(len*4/3)+1).
int is_b64u_encode(const uint8_t *in, size_t len, char *out, size_t cap);

// AES-256-GCM seal. out receives ciphertext||16-byte tag (pt_len + 16 bytes). Returns pt_len + 16.
int is_gcm_seal(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                const uint8_t *pt, size_t pt_len, uint8_t *out);

// RFC 9180 base-mode HPKE seal to the recipient X25519 public key pk. A fresh ephemeral key is drawn from the OS.
// enc_out receives the 32-byte encapsulated key, ct_out receives pt_len + 16 bytes. Returns pt_len + 16, or -1.
int is_hpke_seal(const uint8_t pk[32], const uint8_t *info, size_t info_len, const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t pt_len, uint8_t enc_out[32], uint8_t *ct_out);

// Same, with a caller-supplied ephemeral private key. Only for tests - never reuse an ephemeral key.
int is_hpke_seal_det(const uint8_t sk_e[32], const uint8_t pk[32], const uint8_t *info, size_t info_len,
                     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
                     uint8_t enc_out[32], uint8_t *ct_out);

// ---- v14: standard Ed25519 (RFC 8032, SHA-512) -------------------------------------------------------------------
// monocypher's own EdDSA uses BLAKE2b and is NOT interoperable; these build real Ed25519 from its primitives.

void is_sha512(const uint8_t *data, size_t len, uint8_t out[64]);
void is_ed25519_public_key(const uint8_t seed[32], uint8_t pk[32]);
void is_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t len, uint8_t sig[64]);
// Returns 1 if the signature is valid, 0 otherwise.
int is_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const uint8_t *msg, size_t len);

// Argon2id, 32-byte output. mem_kib = memory in KiB. Returns 0 on success, -1 on allocation failure.
int is_argon2id(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                uint32_t mem_kib, uint32_t iters, uint32_t lanes, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif

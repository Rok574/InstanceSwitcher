#include "is_e2ee_core.h"
#include "monocypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ base64url */

int is_b64u_decode(const char *s, size_t slen, uint8_t *out, size_t cap) {
    if (slen % 4 == 1) return -1;
    size_t need = slen / 4 * 3 + (slen % 4 == 2 ? 1 : slen % 4 == 3 ? 2 : 0);
    if (need > cap) return -1;
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < slen; i++) {
        char c = s[i];
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '-') v = 62;
        else if (c == '_') v = 63;
        else return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)n;
}

int is_b64u_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t need = (len / 3) * 4 + (len % 3 == 0 ? 0 : len % 3 + 1);
    if (need + 1 > cap) return -1;
    size_t o = 0, i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63]; out[o++] = T[(v >> 6) & 63]; out[o++] = T[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63]; out[o++] = T[(v >> 6) & 63];
    }
    out[o] = 0;
    return (int)o;
}

int is_random(uint8_t *buf, size_t n) {
#if defined(__APPLE__)
    arc4random_buf(buf, n);                   // always succeeds on iOS/macOS
    return 0;
#else
    while (n) {
        size_t t = n > 256 ? 256 : n;
        if (getentropy(buf, t) != 0) return -1;
        buf += t;
        n -= t;
    }
    return 0;
#endif
}

/* --------------------------------------------------------------------- SHA-256 */

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t total;
    size_t blen;
} sha_ctx;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(sha_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha_init(sha_ctx *c) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->blen = 0;
}

static void sha_update(sha_ctx *c, const uint8_t *d, size_t n) {
    c->total += n;
    while (n) {
        size_t take = 64 - c->blen;
        if (take > n) take = n;
        memcpy(c->buf + c->blen, d, take);
        c->blen += take; d += take; n -= take;
        if (c->blen == 64) { sha_block(c, c->buf); c->blen = 0; }
    }
}

static void sha_final(sha_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->blen != 56) sha_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void is_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha_ctx c;
    sha_init(&c);
    sha_update(&c, data, len);
    sha_final(&c, out);
}

/* ------------------------------------------------------------- HMAC / HKDF */

// HMAC-SHA256 over the concatenation of up to 4 message parts.
static void hmac_parts(const uint8_t *key, size_t klen, const uint8_t *p0, size_t l0, const uint8_t *p1, size_t l1,
                       const uint8_t *p2, size_t l2, const uint8_t *p3, size_t l3, uint8_t out[32]) {
    uint8_t k[64] = {0};
    if (klen > 64) is_sha256(key, klen, k);
    else if (klen) memcpy(k, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    uint8_t inner[32];
    sha_ctx c;
    sha_init(&c);
    sha_update(&c, ipad, 64);
    if (l0) sha_update(&c, p0, l0);
    if (l1) sha_update(&c, p1, l1);
    if (l2) sha_update(&c, p2, l2);
    if (l3) sha_update(&c, p3, l3);
    sha_final(&c, inner);
    sha_init(&c);
    sha_update(&c, opad, 64);
    sha_update(&c, inner, 32);
    sha_final(&c, out);
}

static void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t t[32];
    size_t tlen = 0, pos = 0;
    for (uint8_t i = 1; pos < out_len; i++) {
        hmac_parts(prk, 32, t, tlen, info, info_len, &i, 1, NULL, 0, t);
        tlen = 32;
        size_t take = out_len - pos < 32 ? out_len - pos : 32;
        memcpy(out + pos, t, take);
        pos += take;
    }
}

void is_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t zero[32] = {0};
    uint8_t prk[32];
    if (!salt || !salt_len) { salt = zero; salt_len = 32; }
    hmac_parts(salt, salt_len, ikm, ikm_len, NULL, 0, NULL, 0, NULL, 0, prk);
    hkdf_expand(prk, info, info_len, out, out_len);
}

/* ------------------------------------------------------------------ AES-256 */

static uint8_t g_sbox[256];
static int g_sbox_ready;

static uint8_t xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static uint8_t rotl8(uint8_t x, int s) { return (uint8_t)((x << s) | (x >> (8 - s))); }

static void init_sbox(void) {
    if (g_sbox_ready) return;
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0));
        q ^= (uint8_t)(q << 1);
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        uint8_t x = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4));
        g_sbox[p] = (uint8_t)(x ^ 0x63);
    } while (p != 1);
    g_sbox[0] = 0x63;
    g_sbox_ready = 1;
}

typedef struct { uint8_t rk[240]; } aes_ctx;

static void aes256_expand(aes_ctx *c, const uint8_t key[32]) {
    init_sbox();
    memcpy(c->rk, key, 32);
    uint8_t rcon = 1;
    for (int i = 32; i < 240; i += 4) {
        uint8_t t[4];
        memcpy(t, c->rk + i - 4, 4);
        if (i % 32 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[tmp];
            rcon = xt(rcon);
        } else if (i % 32 == 16) {
            for (int k = 0; k < 4; k++) t[k] = g_sbox[t[k]];
        }
        for (int k = 0; k < 4; k++) c->rk[i + k] = (uint8_t)(c->rk[i - 32 + k] ^ t[k]);
    }
}

static void aes_sub_shift(uint8_t s[16]) {
    uint8_t t[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) t[4 * c + r] = g_sbox[s[4 * ((c + r) & 3) + r]];
    memcpy(s, t, 16);
}

static void aes_mix(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (uint8_t)(xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3);
        p[1] = (uint8_t)(a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3);
        p[2] = (uint8_t)(a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3);
        p[3] = (uint8_t)(xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3));
    }
}

static void aes256_encrypt(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ c->rk[i];
    for (int round = 1; round < 14; round++) {
        aes_sub_shift(s);
        aes_mix(s);
        for (int i = 0; i < 16; i++) s[i] ^= c->rk[round * 16 + i];
    }
    aes_sub_shift(s);
    for (int i = 0; i < 16; i++) out[i] = s[i] ^ c->rk[14 * 16 + i];
}

/* ---------------------------------------------------------------------- GCM */

// y = y * h in GF(2^128), GCM bit order.
static void gf_mul(uint8_t y[16], const uint8_t h[16]) {
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if (y[i / 8] & (0x80 >> (i % 8)))
            for (int k = 0; k < 16; k++) z[k] ^= v[k];
        int lsb = v[15] & 1;
        for (int k = 15; k > 0; k--) v[k] = (uint8_t)((v[k] >> 1) | (v[k - 1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(y, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *d, size_t n) {
    while (n) {
        size_t take = n < 16 ? n : 16;
        for (size_t i = 0; i < take; i++) y[i] ^= d[i];
        gf_mul(y, h);
        d += take;
        n -= take;
    }
}

int is_gcm_open(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                const uint8_t *ct, size_t ct_len, uint8_t *out) {
    if (ct_len < 16) return -1;
    size_t n = ct_len - 16;
    aes_ctx c;
    aes256_expand(&c, key);
    uint8_t zero[16] = {0}, h[16];
    aes256_encrypt(&c, zero, h);

    uint8_t y[16] = {0};
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, ct, n);
    uint8_t lens[16];
    uint64_t ab = (uint64_t)aad_len * 8, cb = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) { lens[i] = (uint8_t)(ab >> (56 - 8 * i)); lens[8 + i] = (uint8_t)(cb >> (56 - 8 * i)); }
    ghash_update(y, h, lens, 16);

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    uint8_t ek[16];
    aes256_encrypt(&c, j0, ek);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)((y[i] ^ ek[i]) ^ ct[n + i]);
    if (diff) return -1;

    uint8_t ctr[16], ks[16];
    memcpy(ctr, j0, 16);
    for (size_t off = 0; off < n; off += 16) {
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;     // inc32
        aes256_encrypt(&c, ctr, ks);
        size_t take = n - off < 16 ? n - off : 16;
        for (size_t i = 0; i < take; i++) out[off + i] = ct[off + i] ^ ks[i];
    }
    return (int)n;
}

int is_gcm_seal(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                const uint8_t *pt, size_t pt_len, uint8_t *out) {
    aes_ctx c;
    aes256_expand(&c, key);
    uint8_t zero[16] = {0}, h[16];
    aes256_encrypt(&c, zero, h);

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    uint8_t ctr[16], ks[16];
    memcpy(ctr, j0, 16);
    for (size_t off = 0; off < pt_len; off += 16) {
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;     // inc32
        aes256_encrypt(&c, ctr, ks);
        size_t take = pt_len - off < 16 ? pt_len - off : 16;
        for (size_t i = 0; i < take; i++) out[off + i] = pt[off + i] ^ ks[i];
    }

    uint8_t y[16] = {0};
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, out, pt_len);
    uint8_t lens[16];
    uint64_t ab = (uint64_t)aad_len * 8, cb = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; i++) { lens[i] = (uint8_t)(ab >> (56 - 8 * i)); lens[8 + i] = (uint8_t)(cb >> (56 - 8 * i)); }
    ghash_update(y, h, lens, 16);

    uint8_t ek[16];
    aes256_encrypt(&c, j0, ek);
    for (int i = 0; i < 16; i++) out[pt_len + i] = (uint8_t)(y[i] ^ ek[i]);
    return (int)(pt_len + 16);
}

/* --------------------------------------------------------------------- HPKE */

static const uint8_t SUITE_KEM[5] = {'K', 'E', 'M', 0x00, 0x20};
static const uint8_t SUITE_HPKE[10] = {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x02};

// LabeledExtract(salt, label, ikm) with empty or 32-byte salt.
static void labeled_extract(const uint8_t *suite, size_t suite_len, const uint8_t *salt, size_t salt_len,
                            const char *label, const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    static const uint8_t ver[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};
    size_t ll = strlen(label);
    size_t total = 7 + suite_len + ll + ikm_len;
    uint8_t *msg = (uint8_t *)malloc(total ? total : 1);
    size_t p = 0;
    memcpy(msg + p, ver, 7); p += 7;
    memcpy(msg + p, suite, suite_len); p += suite_len;
    memcpy(msg + p, label, ll); p += ll;
    if (ikm_len) memcpy(msg + p, ikm, ikm_len);
    uint8_t zero[32] = {0};
    if (!salt || !salt_len) { salt = zero; salt_len = 32; }
    hmac_parts(salt, salt_len, msg, total, NULL, 0, NULL, 0, NULL, 0, out);
    free(msg);
}

static void labeled_expand(const uint8_t *suite, size_t suite_len, const uint8_t prk[32], const char *label,
                           const uint8_t *info, size_t info_len, size_t L, uint8_t *out) {
    static const uint8_t ver[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};
    size_t ll = strlen(label);
    size_t total = 2 + 7 + suite_len + ll + info_len;
    uint8_t *msg = (uint8_t *)malloc(total);
    size_t p = 0;
    msg[p++] = (uint8_t)(L >> 8);
    msg[p++] = (uint8_t)L;
    memcpy(msg + p, ver, 7); p += 7;
    memcpy(msg + p, suite, suite_len); p += suite_len;
    memcpy(msg + p, label, ll); p += ll;
    if (info_len) memcpy(msg + p, info, info_len);
    hkdf_expand(prk, msg, total, out, L);
    free(msg);
}

int is_hpke_open(const uint8_t sk[32], const uint8_t enc[32], const uint8_t *info, size_t info_len,
                 const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, uint8_t *out) {
    uint8_t dh[32], pk[32];
    crypto_x25519(dh, sk, enc);
    uint8_t nz = 0;
    for (int i = 0; i < 32; i++) nz |= dh[i];
    if (!nz) return -1;                       // low-order point
    crypto_x25519_public_key(pk, sk);

    uint8_t kem_ctx[64], eae[32], shared[32];
    memcpy(kem_ctx, enc, 32);
    memcpy(kem_ctx + 32, pk, 32);
    labeled_extract(SUITE_KEM, sizeof SUITE_KEM, NULL, 0, "eae_prk", dh, 32, eae);
    labeled_expand(SUITE_KEM, sizeof SUITE_KEM, eae, "shared_secret", kem_ctx, 64, 32, shared);

    uint8_t psk_id_hash[32], info_hash[32], ctx[65], secret[32], key[32], nonce[12];
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, NULL, 0, "psk_id_hash", NULL, 0, psk_id_hash);
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, NULL, 0, "info_hash", info, info_len, info_hash);
    ctx[0] = 0x00;                            // base mode
    memcpy(ctx + 1, psk_id_hash, 32);
    memcpy(ctx + 33, info_hash, 32);
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, shared, 32, "secret", NULL, 0, secret);
    labeled_expand(SUITE_HPKE, sizeof SUITE_HPKE, secret, "key", ctx, 65, 32, key);
    labeled_expand(SUITE_HPKE, sizeof SUITE_HPKE, secret, "base_nonce", ctx, 65, 12, nonce);
    int r = is_gcm_open(key, nonce, aad, aad_len, ct, ct_len, out);
    crypto_wipe(key, 32); crypto_wipe(secret, 32); crypto_wipe(shared, 32); crypto_wipe(dh, 32);
    return r;
}

int is_hpke_seal_det(const uint8_t sk_e[32], const uint8_t pk[32], const uint8_t *info, size_t info_len,
                     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
                     uint8_t enc_out[32], uint8_t *ct_out) {
    uint8_t dh[32];
    crypto_x25519_public_key(enc_out, sk_e);
    crypto_x25519(dh, sk_e, pk);
    uint8_t nz = 0;
    for (int i = 0; i < 32; i++) nz |= dh[i];
    if (!nz) return -1;                       // low-order recipient key

    uint8_t kem_ctx[64], eae[32], shared[32];
    memcpy(kem_ctx, enc_out, 32);
    memcpy(kem_ctx + 32, pk, 32);
    labeled_extract(SUITE_KEM, sizeof SUITE_KEM, NULL, 0, "eae_prk", dh, 32, eae);
    labeled_expand(SUITE_KEM, sizeof SUITE_KEM, eae, "shared_secret", kem_ctx, 64, 32, shared);

    uint8_t psk_id_hash[32], info_hash[32], ctx[65], secret[32], key[32], nonce[12];
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, NULL, 0, "psk_id_hash", NULL, 0, psk_id_hash);
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, NULL, 0, "info_hash", info, info_len, info_hash);
    ctx[0] = 0x00;                            // base mode
    memcpy(ctx + 1, psk_id_hash, 32);
    memcpy(ctx + 33, info_hash, 32);
    labeled_extract(SUITE_HPKE, sizeof SUITE_HPKE, shared, 32, "secret", NULL, 0, secret);
    labeled_expand(SUITE_HPKE, sizeof SUITE_HPKE, secret, "key", ctx, 65, 32, key);
    labeled_expand(SUITE_HPKE, sizeof SUITE_HPKE, secret, "base_nonce", ctx, 65, 12, nonce);
    int r = is_gcm_seal(key, nonce, aad, aad_len, pt, pt_len, ct_out);
    crypto_wipe(key, 32); crypto_wipe(secret, 32); crypto_wipe(shared, 32); crypto_wipe(dh, 32);
    return r;
}

int is_hpke_seal(const uint8_t pk[32], const uint8_t *info, size_t info_len, const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t pt_len, uint8_t enc_out[32], uint8_t *ct_out) {
    uint8_t sk_e[32];
    if (is_random(sk_e, 32) != 0) return -1;
    int r = is_hpke_seal_det(sk_e, pk, info, info_len, aad, aad_len, pt, pt_len, enc_out, ct_out);
    crypto_wipe(sk_e, 32);
    return r;
}

/* ------------------------------------------------------------ SHA-512 / Ed25519 */

typedef struct { uint64_t h[8]; uint8_t buf[128]; uint64_t total; size_t blen; } sha512_ctx;

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_block(sha512_ctx *c, const uint8_t *p) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int k = 0; k < 8; k++) w[i] = (w[i] << 8) | p[8 * i + k];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
        uint64_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint64_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha512_init(sha512_ctx *c) {
    static const uint64_t iv[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                                   0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->blen = 0;
}

static void sha512_update(sha512_ctx *c, const uint8_t *d, size_t n) {
    c->total += n;
    while (n) {
        size_t take = 128 - c->blen;
        if (take > n) take = n;
        memcpy(c->buf + c->blen, d, take);
        c->blen += take; d += take; n -= take;
        if (c->blen == 128) { sha512_block(c, c->buf); c->blen = 0; }
    }
}

static void sha512_final(sha512_ctx *c, uint8_t out[64]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, z = 0;
    sha512_update(c, &pad, 1);
    while (c->blen != 112) sha512_update(c, &z, 1);
    for (int i = 0; i < 8; i++) sha512_update(c, &z, 1);                 // high 64 bits of the 128-bit length
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha512_update(c, lenb, 8);
    for (int i = 0; i < 8; i++)
        for (int k = 0; k < 8; k++) out[8 * i + k] = (uint8_t)(c->h[i] >> (56 - 8 * k));
}

void is_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, data, len);
    sha512_final(&c, out);
}

void is_ed25519_public_key(const uint8_t seed[32], uint8_t pk[32]) {
    uint8_t h[64], a[32];
    is_sha512(seed, 32, h);
    crypto_eddsa_trim_scalar(a, h);
    crypto_eddsa_scalarbase(pk, a);
    crypto_wipe(h, 64); crypto_wipe(a, 32);
}

void is_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t len, uint8_t sig[64]) {
    uint8_t h[64], a[32], pk[32], r[32], k[32], hash[64];
    is_sha512(seed, 32, h);
    crypto_eddsa_trim_scalar(a, h);
    crypto_eddsa_scalarbase(pk, a);

    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, h + 32, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, hash);
    crypto_eddsa_reduce(r, hash);
    crypto_eddsa_scalarbase(sig, r);                                      // R

    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, hash);
    crypto_eddsa_reduce(k, hash);
    crypto_eddsa_mul_add(sig + 32, k, a, r);                              // S = k*a + r mod L
    crypto_wipe(h, 64); crypto_wipe(a, 32); crypto_wipe(r, 32);
}

int is_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const uint8_t *msg, size_t len) {
    uint8_t hash[64], k[32];
    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, hash);
    crypto_eddsa_reduce(k, hash);
    return crypto_eddsa_check_equation(sig, pk, k) == 0;
}

/* ------------------------------------------------------------------ Argon2id */

int is_argon2id(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                uint32_t mem_kib, uint32_t iters, uint32_t lanes, uint8_t out[32]) {
    if (mem_kib < 8 * lanes || !iters || !lanes) return -1;
    void *work = malloc((size_t)mem_kib * 1024);
    if (!work) return -1;
    crypto_argon2_config cfg = {CRYPTO_ARGON2_ID, mem_kib, iters, lanes};
    crypto_argon2_inputs in = {pw, salt, (uint32_t)pw_len, (uint32_t)salt_len};
    crypto_argon2(out, 32, work, cfg, in, crypto_argon2_no_extras);
    free(work);
    return 0;
}

/* --------------------------------------------------------- message envelope */

typedef struct { char *p; size_t n, cap; int err; } sbuf;

static void sb_put(sbuf *b, const char *s, size_t n) {
    if (b->err) return;
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n + 1) cap *= 2;
        char *np = (char *)realloc(b->p, cap);
        if (!np) { b->err = 1; return; }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void sb_str(sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }

static void sb_int(sbuf *b, int64_t v) {
    char t[32];
    int n = snprintf(t, sizeof t, "%lld", (long long)v);
    sb_put(b, t, (size_t)n);
}

// JSON string for a value already known to be [A-Za-z0-9_-] only (so nothing needs escaping).
static void sb_q(sbuf *b, const char *s) { sb_put(b, "\"", 1); sb_str(b, s); sb_put(b, "\"", 1); }

static int safe_token(const char *s) {
    if (!s || !*s || strlen(s) > 128) return 0;
    for (; *s; s++) {
        char c = *s;
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_')) return 0;
    }
    return 1;
}

static char *b64_alloc(const uint8_t *d, size_t n) {
    size_t cap = (n / 3 + 1) * 4 + 1;
    char *s = (char *)malloc(cap);
    if (s && is_b64u_encode(d, n, s, cap) < 0) { free(s); return NULL; }
    return s;
}

static int by_device(const is_env_target *t, size_t a, size_t b) { return strcmp(t[a].device_id, t[b].device_id); }
static int by_user(const is_env_backup *t, size_t a, size_t b) { return strcmp(t[a].user_id, t[b].user_id); }

char *is_e2ee_seal_envelope(const char *channel_id, const char *sender_user_id, const char *sender_device_id,
                            const uint8_t device_seed[32], const char *nonce, const char *mid,
                            const uint8_t *payload, size_t payload_len,
                            const is_env_target *targets, size_t ntargets,
                            const is_env_backup *backups, size_t nbackups) {
    static const char ALG[] = "x25519-hpke-aes256gcm-ed25519";
    static const char WRAP_INFO[] = "fosscord-e2ee/v1/wrap";
    static const char BACKUP_INFO[] = "fosscord-e2ee/v1/backup-wrap";
    if (!safe_token(channel_id) || !safe_token(sender_user_id) || !safe_token(sender_device_id) || !ntargets) return NULL;
    if (mid ? !safe_token(mid) : !safe_token(nonce)) return NULL;
    for (size_t i = 0; i < ntargets; i++)
        if (!safe_token(targets[i].user_id) || !safe_token(targets[i].device_id) || targets[i].prekey_id < 0) return NULL;
    for (size_t i = 0; i < nbackups; i++)
        if (!safe_token(backups[i].user_id)) return NULL;

    char *result = NULL, *iv_b = NULL, *ct_b = NULL, *aad = NULL, *bind = NULL;
    char **t_enc = NULL, **t_wr = NULL, **b_enc = NULL, **b_wr = NULL;
    size_t *t_ord = NULL, *b_ord = NULL;
    uint8_t ckey[32], iv[12];
    uint8_t *ct = NULL;
    sbuf sp = {0}, env = {0};
    int ok = 0;

    t_enc = (char **)calloc(ntargets, sizeof *t_enc);
    t_wr = (char **)calloc(ntargets, sizeof *t_wr);
    t_ord = (size_t *)malloc(ntargets * sizeof *t_ord);
    b_enc = (char **)calloc(nbackups + 1, sizeof *b_enc);
    b_wr = (char **)calloc(nbackups + 1, sizeof *b_wr);
    b_ord = (size_t *)malloc((nbackups + 1) * sizeof *b_ord);
    ct = (uint8_t *)malloc(payload_len + 16);
    size_t bl = strlen(mid ? mid : nonce) + 3;
    bind = (char *)malloc(bl);
    size_t al = 64 + strlen(channel_id) + strlen(sender_user_id) + strlen(sender_device_id) + bl;
    aad = (char *)malloc(al);
    if (!t_enc || !t_wr || !t_ord || !b_enc || !b_wr || !b_ord || !ct || !bind || !aad) goto done;
    snprintf(bind, bl, "%s:%s", mid ? "m" : "n", mid ? mid : nonce);
    snprintf(aad, al, "fosscord-e2ee/v1/msg\n%s\n%s\n%s\n%s", channel_id, sender_user_id, sender_device_id, bind);

    if (is_random(ckey, 32) != 0 || is_random(iv, 12) != 0) goto done;
    if (is_gcm_seal(ckey, iv, (const uint8_t *)aad, strlen(aad), payload, payload_len, ct) != (int)(payload_len + 16)) goto done;
    iv_b = b64_alloc(iv, 12);
    ct_b = b64_alloc(ct, payload_len + 16);
    if (!iv_b || !ct_b) goto done;

    for (size_t i = 0; i < ntargets; i++) {
        size_t wl = strlen(aad) + strlen(targets[i].device_id) + 2;
        char *waad = (char *)malloc(wl);
        uint8_t enc[32], wrapped[48];
        if (!waad) goto done;
        snprintf(waad, wl, "%s\n%s", aad, targets[i].device_id);
        int r = is_hpke_seal(targets[i].prekey_pub, (const uint8_t *)WRAP_INFO, sizeof WRAP_INFO - 1, (const uint8_t *)waad, strlen(waad), ckey, 32, enc, wrapped);
        free(waad);
        if (r != 48) goto done;
        t_enc[i] = b64_alloc(enc, 32);
        t_wr[i] = b64_alloc(wrapped, 48);
        if (!t_enc[i] || !t_wr[i]) goto done;
        t_ord[i] = i;
    }
    for (size_t i = 0; i < nbackups; i++) {
        size_t wl = strlen(aad) + strlen(backups[i].user_id) + 10;
        char *waad = (char *)malloc(wl);
        uint8_t enc[32], wrapped[48];
        if (!waad) goto done;
        snprintf(waad, wl, "%s\nbackup:%s", aad, backups[i].user_id);
        int r = is_hpke_seal(backups[i].pub, (const uint8_t *)BACKUP_INFO, sizeof BACKUP_INFO - 1, (const uint8_t *)waad, strlen(waad), ckey, 32, enc, wrapped);
        free(waad);
        if (r != 48) goto done;
        b_enc[i] = b64_alloc(enc, 32);
        b_wr[i] = b64_alloc(wrapped, 48);
        if (!b_enc[i] || !b_wr[i]) goto done;
        b_ord[i] = i;
    }

    for (size_t i = 1; i < ntargets; i++)
        for (size_t j = i; j > 0 && by_device(targets, t_ord[j - 1], t_ord[j]) > 0; j--) { size_t x = t_ord[j]; t_ord[j] = t_ord[j - 1]; t_ord[j - 1] = x; }
    for (size_t i = 1; i < nbackups; i++)
        for (size_t j = i; j > 0 && by_user(backups, b_ord[j - 1], b_ord[j]) > 0; j--) { size_t x = b_ord[j]; b_ord[j] = b_ord[j - 1]; b_ord[j - 1] = x; }

    // The signed text must match JSON.stringify of the same array in the web client byte for byte.
    sb_str(&sp, "[\"fosscord-e2ee/v1/sig\",");
    sb_q(&sp, channel_id); sb_put(&sp, ",", 1);
    sb_q(&sp, sender_user_id); sb_put(&sp, ",", 1);
    sb_q(&sp, bind); sb_str(&sp, ",1,");
    sb_q(&sp, ALG); sb_put(&sp, ",", 1);
    sb_q(&sp, sender_device_id); sb_put(&sp, ",", 1);
    if (mid) sb_q(&sp, mid); else sb_str(&sp, "null");
    sb_put(&sp, ",", 1);
    sb_q(&sp, iv_b); sb_put(&sp, ",", 1);
    sb_q(&sp, ct_b); sb_str(&sp, ",[");
    for (size_t k = 0; k < ntargets; k++) {
        size_t i = t_ord[k];
        if (k) sb_put(&sp, ",", 1);
        sb_put(&sp, "[", 1);
        sb_q(&sp, targets[i].user_id); sb_put(&sp, ",", 1);
        sb_q(&sp, targets[i].device_id); sb_put(&sp, ",", 1);
        sb_int(&sp, targets[i].prekey_id); sb_put(&sp, ",", 1);
        sb_q(&sp, t_enc[i]); sb_put(&sp, ",", 1);
        sb_q(&sp, t_wr[i]); sb_put(&sp, "]", 1);
    }
    sb_put(&sp, "]", 1);
    if (nbackups) {
        sb_str(&sp, ",[");
        for (size_t k = 0; k < nbackups; k++) {
            size_t i = b_ord[k];
            if (k) sb_put(&sp, ",", 1);
            sb_put(&sp, "[", 1);
            sb_q(&sp, backups[i].user_id); sb_put(&sp, ",", 1);
            sb_q(&sp, b_enc[i]); sb_put(&sp, ",", 1);
            sb_q(&sp, b_wr[i]); sb_put(&sp, "]", 1);
        }
        sb_put(&sp, "]", 1);
    }
    sb_put(&sp, "]", 1);
    if (sp.err) goto done;

    uint8_t sig[64];
    is_ed25519_sign(device_seed, (const uint8_t *)sp.p, sp.n, sig);
    char *sig_b = b64_alloc(sig, 64);
    if (!sig_b) goto done;

    sb_str(&env, "{\"v\":1,\"alg\":"); sb_q(&env, ALG);
    sb_str(&env, ",\"sender_device\":"); sb_q(&env, sender_device_id);
    if (mid) { sb_str(&env, ",\"mid\":"); sb_q(&env, mid); }
    sb_str(&env, ",\"iv\":"); sb_q(&env, iv_b);
    sb_str(&env, ",\"ct\":"); sb_q(&env, ct_b);
    sb_str(&env, ",\"keys\":[");
    for (size_t i = 0; i < ntargets; i++) {
        if (i) sb_put(&env, ",", 1);
        sb_str(&env, "{\"user_id\":"); sb_q(&env, targets[i].user_id);
        sb_str(&env, ",\"device_id\":"); sb_q(&env, targets[i].device_id);
        sb_str(&env, ",\"prekey_id\":"); sb_int(&env, targets[i].prekey_id);
        sb_str(&env, ",\"enc\":"); sb_q(&env, t_enc[i]);
        sb_str(&env, ",\"wrapped\":"); sb_q(&env, t_wr[i]); sb_put(&env, "}", 1);
    }
    sb_put(&env, "]", 1);
    if (nbackups) {
        sb_str(&env, ",\"backup\":[");
        for (size_t i = 0; i < nbackups; i++) {
            if (i) sb_put(&env, ",", 1);
            sb_str(&env, "{\"user_id\":"); sb_q(&env, backups[i].user_id);
            sb_str(&env, ",\"enc\":"); sb_q(&env, b_enc[i]);
            sb_str(&env, ",\"wrapped\":"); sb_q(&env, b_wr[i]); sb_put(&env, "}", 1);
        }
        sb_put(&env, "]", 1);
    }
    sb_str(&env, ",\"sig\":"); sb_q(&env, sig_b); sb_put(&env, "}", 1);
    free(sig_b);
    if (env.err) goto done;
    result = env.p;
    env.p = NULL;
    ok = 1;

done:
    crypto_wipe(ckey, 32);
    free(sp.p);
    free(env.p);
    free(iv_b); free(ct_b); free(aad); free(bind); free(ct); free(t_ord); free(b_ord);
    for (size_t i = 0; t_enc && i < ntargets; i++) { free(t_enc[i]); free(t_wr[i]); }
    for (size_t i = 0; b_enc && i < nbackups; i++) { free(b_enc[i]); free(b_wr[i]); }
    free(t_enc); free(t_wr); free(b_enc); free(b_wr);
    return ok ? result : NULL;
}

#include "is_e2ee_core.h"
#include "monocypher.h"
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

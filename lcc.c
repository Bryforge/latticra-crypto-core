// Latticra Cryptographic Core v0.1
// Primitive stack: XChaCha20-Poly1305 + BLAKE2b + Ed25519ph via libsodium.
//
// Theory mapping:
//   Λ  = domain-separated Latticra context
//   Σ  = signature/proof context
//   κ  = 256-bit random master key
//   r  = 192-bit random XChaCha nonce
//   c  = AEAD ciphertext
//   τ  = BLAKE2b transcript hash
//   π  = Ed25519ph transcript proof/signature
//   Δ  = BLAKE2b seal identifier: H(c || π || τ)

#define _POSIX_C_SOURCE 200809L

#include <sodium.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define LCC_MAGIC "LCC1"
#define LCC_VERSION 1u
#define LCC_ALG_XCHACHA20_BLAKE2B_ED25519 1u

#define LCC_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define LCC_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define LCC_ABYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define LCC_HASH_BYTES crypto_generichash_BYTES
#define LCC_SIG_BYTES crypto_sign_BYTES
#define LCC_SIGN_PK_BYTES crypto_sign_PUBLICKEYBYTES
#define LCC_SIGN_SK_BYTES crypto_sign_SECRETKEYBYTES

#define LCC_PREFIX_BYTES (4u + 1u + 1u + 2u + LCC_NONCE_BYTES)
#define LCC_HEADER_BYTES (LCC_PREFIX_BYTES + LCC_HASH_BYTES + LCC_SIG_BYTES)

static const unsigned char LCC_LAMBDA[] = "latticra.lambda.lattice.v1";
static const unsigned char LCC_SIGMA[]  = "latticra.sigma.signature.v1";
static const unsigned char D_AD[]       = "LCC-AAD-v1";
static const unsigned char D_KDF[]      = "LCC-KDF-v1";
static const unsigned char D_TAU[]      = "LCC-TAU-v1";
static const unsigned char D_PI[]       = "LCC-PI-ED25519PH-v1";
static const unsigned char D_DELTA[]    = "LCC-DELTA-SEAL-v1";

typedef struct {
    unsigned char magic[4];
    unsigned char version;
    unsigned char alg;
    unsigned char flags[2];
    unsigned char nonce[LCC_NONCE_BYTES];
    unsigned char tau[LCC_HASH_BYTES];
    unsigned char pi[LCC_SIG_BYTES];
} LccHeader;

_Static_assert(sizeof(LccHeader) == LCC_HEADER_BYTES, "bad LCC header size");

static void die(const char *msg) {
    fprintf(stderr, "lcc: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void die_errno(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void dief(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "lcc: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static unsigned char *xmalloc(size_t n) {
    unsigned char *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void print_hex(const char *label, const unsigned char *x, size_t n) {
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) printf("%02x", x[i]);
    putchar('\n');
}

static void path_join(char out[PATH_MAX], const char *dir, const char *name) {
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= PATH_MAX) die("path too long");
}

static unsigned char *read_file(const char *path, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die_errno(path);

    struct stat st;
    if (fstat(fd, &st) != 0) die_errno("fstat");
    if (st.st_size < 0) die("negative file size");

    *len = (size_t)st.st_size;
    unsigned char *buf = xmalloc(*len);

    size_t off = 0;
    while (off < *len) {
        ssize_t r = read(fd, buf + off, *len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            die_errno("read");
        }
        if (r == 0) break;
        off += (size_t)r;
    }

    if (close(fd) != 0) die_errno("close");
    if (off != *len) die("short read");

    return buf;
}

static void write_file_mode(const char *path, const unsigned char *buf, size_t len, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) die_errno(path);

    if (fchmod(fd, mode) != 0) die_errno("fchmod");

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            die_errno("write");
        }
        off += (size_t)w;
    }

    if (fsync(fd) != 0) die_errno("fsync");
    if (close(fd) != 0) die_errno("close");
}

static void read_exact_file(const char *path, unsigned char *dst, size_t want, int secret) {
    size_t n = 0;
    unsigned char *buf = read_file(path, &n);

    if (n != want) {
        if (secret) sodium_memzero(buf, n);
        free(buf);
        dief("%s has wrong size: got %zu bytes, wanted %zu", path, n, want);
    }

    memcpy(dst, buf, want);

    if (secret) sodium_memzero(buf, n);
    free(buf);
}

static void gh_update(crypto_generichash_state *st, const void *p, size_t n) {
    if (crypto_generichash_update(st, (const unsigned char *)p, (unsigned long long)n) != 0)
        die("BLAKE2b update failed");
}

static void header_prefix(const LccHeader *h, unsigned char out[LCC_PREFIX_BYTES]) {
    size_t o = 0;

    memcpy(out + o, h->magic, 4); o += 4;
    out[o++] = h->version;
    out[o++] = h->alg;
    memcpy(out + o, h->flags, 2); o += 2;
    memcpy(out + o, h->nonce, LCC_NONCE_BYTES); o += LCC_NONCE_BYTES;

    if (o != LCC_PREFIX_BYTES) die("internal prefix size mismatch");
}

static void compute_ad(const LccHeader *h, unsigned char ad[LCC_HASH_BYTES]) {
    unsigned char prefix[LCC_PREFIX_BYTES];
    crypto_generichash_state st;

    header_prefix(h, prefix);

    if (crypto_generichash_init(&st, NULL, 0, LCC_HASH_BYTES) != 0)
        die("BLAKE2b init failed");

    gh_update(&st, D_AD, sizeof D_AD - 1);
    gh_update(&st, LCC_LAMBDA, sizeof LCC_LAMBDA - 1);
    gh_update(&st, LCC_SIGMA, sizeof LCC_SIGMA - 1);
    gh_update(&st, prefix, sizeof prefix);

    if (crypto_generichash_final(&st, ad, LCC_HASH_BYTES) != 0)
        die("BLAKE2b final failed");
}

static void derive_msg_key(
    const unsigned char master[LCC_KEY_BYTES],
    const LccHeader *h,
    unsigned char msg_key[LCC_KEY_BYTES]
) {
    unsigned char prefix[LCC_PREFIX_BYTES];
    crypto_generichash_state st;

    header_prefix(h, prefix);

    if (crypto_generichash_init(&st, master, LCC_KEY_BYTES, LCC_KEY_BYTES) != 0)
        die("keyed BLAKE2b init failed");

    gh_update(&st, D_KDF, sizeof D_KDF - 1);
    gh_update(&st, LCC_LAMBDA, sizeof LCC_LAMBDA - 1);
    gh_update(&st, LCC_SIGMA, sizeof LCC_SIGMA - 1);
    gh_update(&st, prefix, sizeof prefix);

    if (crypto_generichash_final(&st, msg_key, LCC_KEY_BYTES) != 0)
        die("keyed BLAKE2b final failed");
}

static void compute_tau(
    const LccHeader *h,
    const unsigned char *c,
    size_t clen,
    unsigned char tau[LCC_HASH_BYTES]
) {
    unsigned char ad[LCC_HASH_BYTES];
    crypto_generichash_state st;

    compute_ad(h, ad);

    if (crypto_generichash_init(&st, NULL, 0, LCC_HASH_BYTES) != 0)
        die("BLAKE2b init failed");

    gh_update(&st, D_TAU, sizeof D_TAU - 1);
    gh_update(&st, ad, sizeof ad);
    gh_update(&st, c, clen);

    if (crypto_generichash_final(&st, tau, LCC_HASH_BYTES) != 0)
        die("BLAKE2b final failed");
}

static void compute_delta(
    const LccHeader *h,
    const unsigned char *c,
    size_t clen,
    unsigned char delta[LCC_HASH_BYTES]
) {
    crypto_generichash_state st;

    if (crypto_generichash_init(&st, NULL, 0, LCC_HASH_BYTES) != 0)
        die("BLAKE2b init failed");

    gh_update(&st, D_DELTA, sizeof D_DELTA - 1);
    gh_update(&st, c, clen);
    gh_update(&st, h->pi, LCC_SIG_BYTES);
    gh_update(&st, h->tau, LCC_HASH_BYTES);

    if (crypto_generichash_final(&st, delta, LCC_HASH_BYTES) != 0)
        die("BLAKE2b final failed");
}

static int sign_transcript(
    LccHeader *h,
    const unsigned char *c,
    size_t clen,
    const unsigned char sk[LCC_SIGN_SK_BYTES]
) {
    unsigned char prefix[LCC_PREFIX_BYTES];
    crypto_sign_state st;

    header_prefix(h, prefix);

    if (crypto_sign_init(&st) != 0) return -1;
    if (crypto_sign_update(&st, D_PI, sizeof D_PI - 1) != 0) return -1;
    if (crypto_sign_update(&st, prefix, sizeof prefix) != 0) return -1;
    if (crypto_sign_update(&st, h->tau, LCC_HASH_BYTES) != 0) return -1;
    if (crypto_sign_update(&st, c, (unsigned long long)clen) != 0) return -1;

    return crypto_sign_final_create(&st, h->pi, NULL, sk);
}

static int verify_transcript(
    const LccHeader *h,
    const unsigned char *c,
    size_t clen,
    const unsigned char pk[LCC_SIGN_PK_BYTES]
) {
    unsigned char prefix[LCC_PREFIX_BYTES];
    crypto_sign_state st;

    header_prefix(h, prefix);

    if (crypto_sign_init(&st) != 0) return -1;
    if (crypto_sign_update(&st, D_PI, sizeof D_PI - 1) != 0) return -1;
    if (crypto_sign_update(&st, prefix, sizeof prefix) != 0) return -1;
    if (crypto_sign_update(&st, h->tau, LCC_HASH_BYTES) != 0) return -1;
    if (crypto_sign_update(&st, c, (unsigned long long)clen) != 0) return -1;

    return crypto_sign_final_verify(&st, h->pi, pk);
}

static void init_header(LccHeader *h) {
    sodium_memzero(h, sizeof *h);
    memcpy(h->magic, LCC_MAGIC, 4);
    h->version = LCC_VERSION;
    h->alg = LCC_ALG_XCHACHA20_BLAKE2B_ED25519;
    h->flags[0] = 0;
    h->flags[1] = 0;
    randombytes_buf(h->nonce, LCC_NONCE_BYTES);
}

static int valid_header(const LccHeader *h) {
    return memcmp(h->magic, LCC_MAGIC, 4) == 0 &&
           h->version == LCC_VERSION &&
           h->alg == LCC_ALG_XCHACHA20_BLAKE2B_ED25519 &&
           h->flags[0] == 0 &&
           h->flags[1] == 0;
}

static int lcc_seal_buf(
    const unsigned char master_key[LCC_KEY_BYTES],
    const unsigned char sign_sk[LCC_SIGN_SK_BYTES],
    const unsigned char *m,
    size_t mlen,
    unsigned char **sealed,
    size_t *sealed_len
) {
    if (mlen > SIZE_MAX - LCC_HEADER_BYTES - LCC_ABYTES) return -1;

    LccHeader h;
    unsigned char ad[LCC_HASH_BYTES];
    unsigned char msg_key[LCC_KEY_BYTES];

    init_header(&h);
    compute_ad(&h, ad);
    derive_msg_key(master_key, &h, msg_key);

    size_t clen = mlen + LCC_ABYTES;
    size_t total = LCC_HEADER_BYTES + clen;
    unsigned char *out = xmalloc(total);
    unsigned char *c = out + LCC_HEADER_BYTES;

    unsigned long long real_clen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            c,
            &real_clen,
            m,
            (unsigned long long)mlen,
            ad,
            sizeof ad,
            NULL,
            h.nonce,
            msg_key
        ) != 0) {
        sodium_memzero(msg_key, sizeof msg_key);
        free(out);
        return -1;
    }

    if ((size_t)real_clen != clen) {
        sodium_memzero(msg_key, sizeof msg_key);
        free(out);
        return -1;
    }

    compute_tau(&h, c, clen, h.tau);

    if (sign_transcript(&h, c, clen, sign_sk) != 0) {
        sodium_memzero(msg_key, sizeof msg_key);
        free(out);
        return -1;
    }

    memcpy(out, &h, LCC_HEADER_BYTES);

    sodium_memzero(msg_key, sizeof msg_key);
    *sealed = out;
    *sealed_len = total;
    return 0;
}

static int lcc_open_buf(
    const unsigned char master_key[LCC_KEY_BYTES],
    const unsigned char sign_pk[LCC_SIGN_PK_BYTES],
    const unsigned char *sealed,
    size_t sealed_len,
    unsigned char **m,
    size_t *mlen
) {
    if (sealed_len < LCC_HEADER_BYTES + LCC_ABYTES) return -1;

    LccHeader h;
    memcpy(&h, sealed, LCC_HEADER_BYTES);

    if (!valid_header(&h)) return -2;

    const unsigned char *c = sealed + LCC_HEADER_BYTES;
    size_t clen = sealed_len - LCC_HEADER_BYTES;

    unsigned char tau[LCC_HASH_BYTES];
    compute_tau(&h, c, clen, tau);

    if (sodium_memcmp(tau, h.tau, LCC_HASH_BYTES) != 0) return -3;
    if (verify_transcript(&h, c, clen, sign_pk) != 0) return -4;

    unsigned char ad[LCC_HASH_BYTES];
    unsigned char msg_key[LCC_KEY_BYTES];

    compute_ad(&h, ad);
    derive_msg_key(master_key, &h, msg_key);

    size_t plain_len = clen - LCC_ABYTES;
    unsigned char *plain = xmalloc(plain_len);

    unsigned long long real_mlen = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plain,
        &real_mlen,
        NULL,
        c,
        (unsigned long long)clen,
        ad,
        sizeof ad,
        h.nonce,
        msg_key
    );

    sodium_memzero(msg_key, sizeof msg_key);

    if (rc != 0) {
        sodium_memzero(plain, plain_len);
        free(plain);
        return -5;
    }

    if ((size_t)real_mlen != plain_len) {
        sodium_memzero(plain, plain_len);
        free(plain);
        return -5;
    }

    *m = plain;
    *mlen = plain_len;
    return 0;
}

static const char *open_error(int rc) {
    switch (rc) {
        case -1: return "truncated or malformed seal";
        case -2: return "unsupported LCC header";
        case -3: return "tau transcript hash mismatch";
        case -4: return "signature/proof verification failed";
        case -5: return "AEAD authentication/decryption failed";
        default: return "unknown open failure";
    }
}

static void cmd_keygen(const char *dir) {
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) die_errno("mkdir");
    if (chmod(dir, 0700) != 0) die_errno("chmod key directory");

    unsigned char key[LCC_KEY_BYTES];
    unsigned char pk[LCC_SIGN_PK_BYTES];
    unsigned char sk[LCC_SIGN_SK_BYTES];

    randombytes_buf(key, sizeof key);
    crypto_sign_keypair(pk, sk);

    char p_key[PATH_MAX], p_pk[PATH_MAX], p_sk[PATH_MAX];

    path_join(p_key, dir, "lcc.key");
    path_join(p_pk,  dir, "lcc.sign.pk");
    path_join(p_sk,  dir, "lcc.sign.sk");

    write_file_mode(p_key, key, sizeof key, 0600);
    write_file_mode(p_pk, pk, sizeof pk, 0644);
    write_file_mode(p_sk, sk, sizeof sk, 0600);

    sodium_memzero(key, sizeof key);
    sodium_memzero(sk, sizeof sk);

    printf("created %s\n", p_key);
    printf("created %s\n", p_pk);
    printf("created %s\n", p_sk);
}

static void cmd_seal(const char *key_path, const char *sk_path, const char *in_path, const char *out_path) {
    unsigned char key[LCC_KEY_BYTES];
    unsigned char sk[LCC_SIGN_SK_BYTES];

    read_exact_file(key_path, key, sizeof key, 1);
    read_exact_file(sk_path, sk, sizeof sk, 1);

    size_t mlen = 0;
    unsigned char *m = read_file(in_path, &mlen);

    unsigned char *sealed = NULL;
    size_t sealed_len = 0;

    if (lcc_seal_buf(key, sk, m, mlen, &sealed, &sealed_len) != 0)
        die("seal failed");

    write_file_mode(out_path, sealed, sealed_len, 0644);

    LccHeader h;
    memcpy(&h, sealed, LCC_HEADER_BYTES);

    unsigned char delta[LCC_HASH_BYTES];
    compute_delta(&h, sealed + LCC_HEADER_BYTES, sealed_len - LCC_HEADER_BYTES, delta);

    printf("sealed_bytes=%zu\n", sealed_len);
    print_hex("tau", h.tau, sizeof h.tau);
    print_hex("pi", h.pi, sizeof h.pi);
    print_hex("delta_seal", delta, sizeof delta);

    sodium_memzero(key, sizeof key);
    sodium_memzero(sk, sizeof sk);
    sodium_memzero(m, mlen);
    free(m);
    free(sealed);
}

static void cmd_open(const char *key_path, const char *pk_path, const char *in_path, const char *out_path) {
    unsigned char key[LCC_KEY_BYTES];
    unsigned char pk[LCC_SIGN_PK_BYTES];

    read_exact_file(key_path, key, sizeof key, 1);
    read_exact_file(pk_path, pk, sizeof pk, 0);

    size_t sealed_len = 0;
    unsigned char *sealed = read_file(in_path, &sealed_len);

    unsigned char *m = NULL;
    size_t mlen = 0;

    int rc = lcc_open_buf(key, pk, sealed, sealed_len, &m, &mlen);
    if (rc != 0) dief("open failed: %s", open_error(rc));

    write_file_mode(out_path, m, mlen, 0644);

    printf("opened_bytes=%zu\n", mlen);

    sodium_memzero(key, sizeof key);
    sodium_memzero(sealed, sealed_len);
    sodium_memzero(m, mlen);
    free(sealed);
    free(m);
}

static void cmd_inspect(const char *path) {
    size_t n = 0;
    unsigned char *sealed = read_file(path, &n);

    if (n < LCC_HEADER_BYTES) die("file too small for LCC header");

    LccHeader h;
    memcpy(&h, sealed, LCC_HEADER_BYTES);

    printf("magic=%c%c%c%c\n", h.magic[0], h.magic[1], h.magic[2], h.magic[3]);
    printf("version=%u\n", (unsigned)h.version);
    printf("alg=%u\n", (unsigned)h.alg);
    printf("ciphertext_bytes=%zu\n", n - LCC_HEADER_BYTES);

    print_hex("nonce", h.nonce, sizeof h.nonce);
    print_hex("tau", h.tau, sizeof h.tau);
    print_hex("pi", h.pi, sizeof h.pi);

    if (valid_header(&h)) {
        unsigned char delta[LCC_HASH_BYTES];
        compute_delta(&h, sealed + LCC_HEADER_BYTES, n - LCC_HEADER_BYTES, delta);
        print_hex("delta_seal", delta, sizeof delta);
    } else {
        printf("valid_header=0\n");
    }

    free(sealed);
}

static void cmd_selftest(void) {
    unsigned char key[LCC_KEY_BYTES];
    unsigned char pk[LCC_SIGN_PK_BYTES];
    unsigned char sk[LCC_SIGN_SK_BYTES];

    randombytes_buf(key, sizeof key);
    crypto_sign_keypair(pk, sk);

    const unsigned char msg[] = "Latticra Crypto Core self-test message.";

    unsigned char *sealed = NULL;
    size_t sealed_len = 0;

    if (lcc_seal_buf(key, sk, msg, sizeof msg - 1, &sealed, &sealed_len) != 0)
        die("selftest seal failed");

    unsigned char *plain = NULL;
    size_t plain_len = 0;

    int rc = lcc_open_buf(key, pk, sealed, sealed_len, &plain, &plain_len);
    if (rc != 0) dief("selftest open failed: %s", open_error(rc));

    if (plain_len != sizeof msg - 1 || memcmp(plain, msg, sizeof msg - 1) != 0)
        die("selftest plaintext mismatch");

    sealed[LCC_HEADER_BYTES] ^= 0x01;

    unsigned char *bad = NULL;
    size_t bad_len = 0;
    rc = lcc_open_buf(key, pk, sealed, sealed_len, &bad, &bad_len);

    if (rc == 0) {
        sodium_memzero(bad, bad_len);
        free(bad);
        die("selftest tamper check failed");
    }

    sodium_memzero(key, sizeof key);
    sodium_memzero(sk, sizeof sk);
    sodium_memzero(plain, plain_len);
    sodium_memzero(sealed, sealed_len);

    free(plain);
    free(sealed);

    puts("selftest=ok");
}

static void usage(FILE *f) {
    fprintf(f,
        "Latticra Cryptographic Core v0.1\n\n"
        "Usage:\n"
        "  lcc keygen <dir>\n"
        "  lcc seal <lcc.key> <lcc.sign.sk> <in> <out.lcc>\n"
        "  lcc open <lcc.key> <lcc.sign.pk> <in.lcc> <out>\n"
        "  lcc inspect <in.lcc>\n"
        "  lcc selftest\n\n"
        "Files:\n"
        "  lcc.key      32-byte symmetric master key; keep secret\n"
        "  lcc.sign.sk  Ed25519 signing secret key; keep secret\n"
        "  lcc.sign.pk  Ed25519 public verification key\n"
    );
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) die("sodium_init failed");

    if (argc < 2) {
        usage(stderr);
        return 2;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 3) {
            usage(stderr);
            return 2;
        }
        cmd_keygen(argv[2]);
        return 0;
    }

    if (strcmp(argv[1], "seal") == 0) {
        if (argc != 6) {
            usage(stderr);
            return 2;
        }
        cmd_seal(argv[2], argv[3], argv[4], argv[5]);
        return 0;
    }

    if (strcmp(argv[1], "open") == 0) {
        if (argc != 6) {
            usage(stderr);
            return 2;
        }
        cmd_open(argv[2], argv[3], argv[4], argv[5]);
        return 0;
    }

    if (strcmp(argv[1], "inspect") == 0) {
        if (argc != 3) {
            usage(stderr);
            return 2;
        }
        cmd_inspect(argv[2]);
        return 0;
    }

    if (strcmp(argv[1], "selftest") == 0) {
        if (argc != 2) {
            usage(stderr);
            return 2;
        }
        cmd_selftest();
        return 0;
    }

    usage(stderr);
    return 2;
}

#ifndef KERN_USH_SHA256_H
#define KERN_USH_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  size_t datalen;
} ush_sha256_ctx;

void ush_sha256_init(ush_sha256_ctx *ctx);
void ush_sha256_update(ush_sha256_ctx *ctx, const uint8_t *data, size_t len);
void ush_sha256_final(ush_sha256_ctx *ctx, uint8_t out[32]);
void ush_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data). */
void ush_sha256_tagged_init(ush_sha256_ctx *ctx, const char *tag);
void ush_sha256_tagged(const char *tag, const uint8_t *data, size_t len,
                   uint8_t out[32]);

/* double SHA256 */
void ush_sha256d(const uint8_t *data, size_t len, uint8_t out[32]);

#endif

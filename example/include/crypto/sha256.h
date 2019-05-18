#ifndef OPENSSL_SHA256_H
#define OPENSSL_SHA256_H

#include <endian.h>
#include <iostream>
#include <memory.h>
#include <stdint.h>

namespace {
uint16_t static inline ReadLE16(const unsigned char *ptr) {
  uint16_t x;
  memcpy((char *)&x, ptr, 2);
  return le16toh(x);
}

uint32_t static inline ReadLE32(const unsigned char *ptr) {
  uint32_t x;
  memcpy((char *)&x, ptr, 4);
  return le32toh(x);
}

uint64_t static inline ReadLE64(const unsigned char *ptr) {
  uint64_t x;
  memcpy((char *)&x, ptr, 8);
  return le64toh(x);
}

void static inline WriteLE16(unsigned char *ptr, uint16_t x) {
  uint16_t v = htole16(x);
  memcpy(ptr, (char *)&v, 2);
}

void static inline WriteLE32(unsigned char *ptr, uint32_t x) {
  uint32_t v = htole32(x);
  memcpy(ptr, (char *)&v, 4);
}

void static inline WriteLE64(unsigned char *ptr, uint64_t x) {
  uint64_t v = htole64(x);
  memcpy(ptr, (char *)&v, 8);
}

uint32_t static inline ReadBE32(const unsigned char *ptr) {
  uint32_t x;
  memcpy((char *)&x, ptr, 4);
  return be32toh(x);
}

uint64_t static inline ReadBE64(const unsigned char *ptr) {
  uint64_t x;
  memcpy((char *)&x, ptr, 8);
  return be64toh(x);
}

void static inline WriteBE32(unsigned char *ptr, uint32_t x) {
  uint32_t v = htobe32(x);
  memcpy(ptr, (char *)&v, 4);
}

void static inline WriteBE64(unsigned char *ptr, uint64_t x) {
  uint64_t v = htobe64(x);
  memcpy(ptr, (char *)&v, 8);
}
} // namespace

namespace sha256 {
uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) {
  return z ^ (x & (y ^ z));
}
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (z & (x | y));
}
uint32_t inline Sigma0(uint32_t x) {
  return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
}
uint32_t inline Sigma1(uint32_t x) {
  return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
}
uint32_t inline sigma0(uint32_t x) {
  return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
}
uint32_t inline sigma1(uint32_t x) {
  return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
}

/** One round of SHA-256. */
void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t &d, uint32_t e,
                  uint32_t f, uint32_t g, uint32_t &h, uint32_t k) {
  uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k;
  uint32_t t2 = Sigma0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
}

/** Initialize SHA-256 state. */
void inline Initialize(uint32_t *s) {
  s[0] = 0x6a09e667ul;
  s[1] = 0xbb67ae85ul;
  s[2] = 0x3c6ef372ul;
  s[3] = 0xa54ff53aul;
  s[4] = 0x510e527ful;
  s[5] = 0x9b05688cul;
  s[6] = 0x1f83d9abul;
  s[7] = 0x5be0cd19ul;
}

/** Perform a number of SHA-256 transformations, processing 64-byte chunks. */
void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks) {
  while (blocks--) {
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5],
             g = s[6], h = s[7];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14,
        w15;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98 + (w0 = ReadBE32(chunk + 0)));
    Round(h, a, b, c, d, e, f, g, 0x71374491 + (w1 = ReadBE32(chunk + 4)));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf + (w2 = ReadBE32(chunk + 8)));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5 + (w3 = ReadBE32(chunk + 12)));
    Round(e, f, g, h, a, b, c, d, 0x3956c25b + (w4 = ReadBE32(chunk + 16)));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1 + (w5 = ReadBE32(chunk + 20)));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4 + (w6 = ReadBE32(chunk + 24)));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5 + (w7 = ReadBE32(chunk + 28)));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98 + (w8 = ReadBE32(chunk + 32)));
    Round(h, a, b, c, d, e, f, g, 0x12835b01 + (w9 = ReadBE32(chunk + 36)));
    Round(g, h, a, b, c, d, e, f, 0x243185be + (w10 = ReadBE32(chunk + 40)));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3 + (w11 = ReadBE32(chunk + 44)));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74 + (w12 = ReadBE32(chunk + 48)));
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe + (w13 = ReadBE32(chunk + 52)));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7 + (w14 = ReadBE32(chunk + 56)));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174 + (w15 = ReadBE32(chunk + 60)));

    Round(a, b, c, d, e, f, g, h,
          0xe49b69c1 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g,
          0xefbe4786 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f,
          0x0fc19dc6 + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e,
          0x240ca1cc + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d,
          0x2de92c6f + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c,
          0x4a7484aa + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b,
          0x5cb0a9dc + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a,
          0x76f988da + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h,
          0x983e5152 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g,
          0xa831c66d + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f,
          0xb00327c8 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e,
          0xbf597fc7 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d,
          0xc6e00bf3 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c,
          0xd5a79147 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b,
          0x06ca6351 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a,
          0x14292967 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

    Round(a, b, c, d, e, f, g, h,
          0x27b70a85 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g,
          0x2e1b2138 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f,
          0x4d2c6dfc + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e,
          0x53380d13 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d,
          0x650a7354 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c,
          0x766a0abb + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b,
          0x81c2c92e + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a,
          0x92722c85 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h,
          0xa2bfe8a1 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g,
          0xa81a664b + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f,
          0xc24b8b70 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e,
          0xc76c51a3 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d,
          0xd192e819 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c,
          0xd6990624 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b,
          0xf40e3585 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a,
          0x106aa070 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

    Round(a, b, c, d, e, f, g, h,
          0x19a4c116 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g,
          0x1e376c08 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f,
          0x2748774c + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e,
          0x34b0bcb5 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d,
          0x391c0cb3 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c,
          0x4ed8aa4a + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b,
          0x5b9cca4f + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a,
          0x682e6ff3 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h,
          0x748f82ee + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g,
          0x78a5636f + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f,
          0x84c87814 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e,
          0x8cc70208 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d,
          0x90befffa + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c,
          0xa4506ceb + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b,
          0xbef9a3f7 + (w14 + sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a,
          0xc67178f2 + (w15 + sigma1(w13) + w8 + sigma0(w0)));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
    chunk += 64;
  }
}

void TransformD64(unsigned char *out, const unsigned char *in) {
  // Transform 1
  uint32_t a = 0x6a09e667ul;
  uint32_t b = 0xbb67ae85ul;
  uint32_t c = 0x3c6ef372ul;
  uint32_t d = 0xa54ff53aul;
  uint32_t e = 0x510e527ful;
  uint32_t f = 0x9b05688cul;
  uint32_t g = 0x1f83d9abul;
  uint32_t h = 0x5be0cd19ul;

  uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

  Round(a, b, c, d, e, f, g, h, 0x428a2f98ul + (w0 = ReadBE32(in + 0)));
  Round(h, a, b, c, d, e, f, g, 0x71374491ul + (w1 = ReadBE32(in + 4)));
  Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful + (w2 = ReadBE32(in + 8)));
  Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul + (w3 = ReadBE32(in + 12)));
  Round(e, f, g, h, a, b, c, d, 0x3956c25bul + (w4 = ReadBE32(in + 16)));
  Round(d, e, f, g, h, a, b, c, 0x59f111f1ul + (w5 = ReadBE32(in + 20)));
  Round(c, d, e, f, g, h, a, b, 0x923f82a4ul + (w6 = ReadBE32(in + 24)));
  Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul + (w7 = ReadBE32(in + 28)));
  Round(a, b, c, d, e, f, g, h, 0xd807aa98ul + (w8 = ReadBE32(in + 32)));
  Round(h, a, b, c, d, e, f, g, 0x12835b01ul + (w9 = ReadBE32(in + 36)));
  Round(g, h, a, b, c, d, e, f, 0x243185beul + (w10 = ReadBE32(in + 40)));
  Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul + (w11 = ReadBE32(in + 44)));
  Round(e, f, g, h, a, b, c, d, 0x72be5d74ul + (w12 = ReadBE32(in + 48)));
  Round(d, e, f, g, h, a, b, c, 0x80deb1feul + (w13 = ReadBE32(in + 52)));
  Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul + (w14 = ReadBE32(in + 56)));
  Round(b, c, d, e, f, g, h, a, 0xc19bf174ul + (w15 = ReadBE32(in + 60)));
  Round(a, b, c, d, e, f, g, h,
        0xe49b69c1ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
  Round(h, a, b, c, d, e, f, g,
        0xefbe4786ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f,
        0x0fc19dc6ul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e,
        0x240ca1ccul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d,
        0x2de92c6ful + (w4 += sigma1(w2) + w13 + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c,
        0x4a7484aaul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x5cb0a9dcul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x76f988daul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
  Round(a, b, c, d, e, f, g, h,
        0x983e5152ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
  Round(h, a, b, c, d, e, f, g,
        0xa831c66dul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
  Round(g, h, a, b, c, d, e, f,
        0xb00327c8ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
  Round(f, g, h, a, b, c, d, e,
        0xbf597fc7ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
  Round(e, f, g, h, a, b, c, d,
        0xc6e00bf3ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
  Round(d, e, f, g, h, a, b, c,
        0xd5a79147ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
  Round(c, d, e, f, g, h, a, b,
        0x06ca6351ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
  Round(b, c, d, e, f, g, h, a,
        0x14292967ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
  Round(a, b, c, d, e, f, g, h,
        0x27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
  Round(h, a, b, c, d, e, f, g,
        0x2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f,
        0x4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e,
        0x53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d,
        0x650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c,
        0x766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
  Round(a, b, c, d, e, f, g, h,
        0xa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
  Round(h, a, b, c, d, e, f, g,
        0xa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
  Round(g, h, a, b, c, d, e, f,
        0xc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
  Round(f, g, h, a, b, c, d, e,
        0xc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
  Round(e, f, g, h, a, b, c, d,
        0xd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
  Round(d, e, f, g, h, a, b, c,
        0xd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
  Round(c, d, e, f, g, h, a, b,
        0xf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
  Round(b, c, d, e, f, g, h, a,
        0x106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
  Round(a, b, c, d, e, f, g, h,
        0x19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
  Round(h, a, b, c, d, e, f, g,
        0x1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f,
        0x2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e,
        0x34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d,
        0x391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c,
        0x4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
  Round(a, b, c, d, e, f, g, h,
        0x748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
  Round(h, a, b, c, d, e, f, g,
        0x78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
  Round(g, h, a, b, c, d, e, f,
        0x84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
  Round(f, g, h, a, b, c, d, e,
        0x8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
  Round(e, f, g, h, a, b, c, d,
        0x90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
  Round(d, e, f, g, h, a, b, c,
        0xa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
  Round(c, d, e, f, g, h, a, b,
        0xbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
  Round(b, c, d, e, f, g, h, a,
        0xc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

  a += 0x6a09e667ul;
  b += 0xbb67ae85ul;
  c += 0x3c6ef372ul;
  d += 0xa54ff53aul;
  e += 0x510e527ful;
  f += 0x9b05688cul;
  g += 0x1f83d9abul;
  h += 0x5be0cd19ul;

  uint32_t t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

  // Transform 2
  Round(a, b, c, d, e, f, g, h, 0xc28a2f98ul);
  Round(h, a, b, c, d, e, f, g, 0x71374491ul);
  Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful);
  Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul);
  Round(e, f, g, h, a, b, c, d, 0x3956c25bul);
  Round(d, e, f, g, h, a, b, c, 0x59f111f1ul);
  Round(c, d, e, f, g, h, a, b, 0x923f82a4ul);
  Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul);
  Round(a, b, c, d, e, f, g, h, 0xd807aa98ul);
  Round(h, a, b, c, d, e, f, g, 0x12835b01ul);
  Round(g, h, a, b, c, d, e, f, 0x243185beul);
  Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul);
  Round(e, f, g, h, a, b, c, d, 0x72be5d74ul);
  Round(d, e, f, g, h, a, b, c, 0x80deb1feul);
  Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul);
  Round(b, c, d, e, f, g, h, a, 0xc19bf374ul);
  Round(a, b, c, d, e, f, g, h, 0x649b69c1ul);
  Round(h, a, b, c, d, e, f, g, 0xf0fe4786ul);
  Round(g, h, a, b, c, d, e, f, 0x0fe1edc6ul);
  Round(f, g, h, a, b, c, d, e, 0x240cf254ul);
  Round(e, f, g, h, a, b, c, d, 0x4fe9346ful);
  Round(d, e, f, g, h, a, b, c, 0x6cc984beul);
  Round(c, d, e, f, g, h, a, b, 0x61b9411eul);
  Round(b, c, d, e, f, g, h, a, 0x16f988faul);
  Round(a, b, c, d, e, f, g, h, 0xf2c65152ul);
  Round(h, a, b, c, d, e, f, g, 0xa88e5a6dul);
  Round(g, h, a, b, c, d, e, f, 0xb019fc65ul);
  Round(f, g, h, a, b, c, d, e, 0xb9d99ec7ul);
  Round(e, f, g, h, a, b, c, d, 0x9a1231c3ul);
  Round(d, e, f, g, h, a, b, c, 0xe70eeaa0ul);
  Round(c, d, e, f, g, h, a, b, 0xfdb1232bul);
  Round(b, c, d, e, f, g, h, a, 0xc7353eb0ul);
  Round(a, b, c, d, e, f, g, h, 0x3069bad5ul);
  Round(h, a, b, c, d, e, f, g, 0xcb976d5ful);
  Round(g, h, a, b, c, d, e, f, 0x5a0f118ful);
  Round(f, g, h, a, b, c, d, e, 0xdc1eeefdul);
  Round(e, f, g, h, a, b, c, d, 0x0a35b689ul);
  Round(d, e, f, g, h, a, b, c, 0xde0b7a04ul);
  Round(c, d, e, f, g, h, a, b, 0x58f4ca9dul);
  Round(b, c, d, e, f, g, h, a, 0xe15d5b16ul);
  Round(a, b, c, d, e, f, g, h, 0x007f3e86ul);
  Round(h, a, b, c, d, e, f, g, 0x37088980ul);
  Round(g, h, a, b, c, d, e, f, 0xa507ea32ul);
  Round(f, g, h, a, b, c, d, e, 0x6fab9537ul);
  Round(e, f, g, h, a, b, c, d, 0x17406110ul);
  Round(d, e, f, g, h, a, b, c, 0x0d8cd6f1ul);
  Round(c, d, e, f, g, h, a, b, 0xcdaa3b6dul);
  Round(b, c, d, e, f, g, h, a, 0xc0bbbe37ul);
  Round(a, b, c, d, e, f, g, h, 0x83613bdaul);
  Round(h, a, b, c, d, e, f, g, 0xdb48a363ul);
  Round(g, h, a, b, c, d, e, f, 0x0b02e931ul);
  Round(f, g, h, a, b, c, d, e, 0x6fd15ca7ul);
  Round(e, f, g, h, a, b, c, d, 0x521afacaul);
  Round(d, e, f, g, h, a, b, c, 0x31338431ul);
  Round(c, d, e, f, g, h, a, b, 0x6ed41a95ul);
  Round(b, c, d, e, f, g, h, a, 0x6d437890ul);
  Round(a, b, c, d, e, f, g, h, 0xc39c91f2ul);
  Round(h, a, b, c, d, e, f, g, 0x9eccabbdul);
  Round(g, h, a, b, c, d, e, f, 0xb5c9a0e6ul);
  Round(f, g, h, a, b, c, d, e, 0x532fb63cul);
  Round(e, f, g, h, a, b, c, d, 0xd2c741c6ul);
  Round(d, e, f, g, h, a, b, c, 0x07237ea3ul);
  Round(c, d, e, f, g, h, a, b, 0xa4954b68ul);
  Round(b, c, d, e, f, g, h, a, 0x4c191d76ul);

  w0 = t0 + a;
  w1 = t1 + b;
  w2 = t2 + c;
  w3 = t3 + d;
  w4 = t4 + e;
  w5 = t5 + f;
  w6 = t6 + g;
  w7 = t7 + h;

  // Transform 3
  a = 0x6a09e667ul;
  b = 0xbb67ae85ul;
  c = 0x3c6ef372ul;
  d = 0xa54ff53aul;
  e = 0x510e527ful;
  f = 0x9b05688cul;
  g = 0x1f83d9abul;
  h = 0x5be0cd19ul;

  Round(a, b, c, d, e, f, g, h, 0x428a2f98ul + w0);
  Round(h, a, b, c, d, e, f, g, 0x71374491ul + w1);
  Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful + w2);
  Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul + w3);
  Round(e, f, g, h, a, b, c, d, 0x3956c25bul + w4);
  Round(d, e, f, g, h, a, b, c, 0x59f111f1ul + w5);
  Round(c, d, e, f, g, h, a, b, 0x923f82a4ul + w6);
  Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul + w7);
  Round(a, b, c, d, e, f, g, h, 0x5807aa98ul);
  Round(h, a, b, c, d, e, f, g, 0x12835b01ul);
  Round(g, h, a, b, c, d, e, f, 0x243185beul);
  Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul);
  Round(e, f, g, h, a, b, c, d, 0x72be5d74ul);
  Round(d, e, f, g, h, a, b, c, 0x80deb1feul);
  Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul);
  Round(b, c, d, e, f, g, h, a, 0xc19bf274ul);
  Round(a, b, c, d, e, f, g, h, 0xe49b69c1ul + (w0 += sigma0(w1)));
  Round(h, a, b, c, d, e, f, g, 0xefbe4786ul + (w1 += 0xa00000ul + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f, 0x0fc19dc6ul + (w2 += sigma1(w0) + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e, 0x240ca1ccul + (w3 += sigma1(w1) + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d, 0x2de92c6ful + (w4 += sigma1(w2) + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c, 0x4a7484aaul + (w5 += sigma1(w3) + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x5cb0a9dcul + (w6 += sigma1(w4) + 0x100ul + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x76f988daul + (w7 += sigma1(w5) + w0 + 0x11002000ul));
  Round(a, b, c, d, e, f, g, h,
        0x983e5152ul + (w8 = 0x80000000ul + sigma1(w6) + w1));
  Round(h, a, b, c, d, e, f, g, 0xa831c66dul + (w9 = sigma1(w7) + w2));
  Round(g, h, a, b, c, d, e, f, 0xb00327c8ul + (w10 = sigma1(w8) + w3));
  Round(f, g, h, a, b, c, d, e, 0xbf597fc7ul + (w11 = sigma1(w9) + w4));
  Round(e, f, g, h, a, b, c, d, 0xc6e00bf3ul + (w12 = sigma1(w10) + w5));
  Round(d, e, f, g, h, a, b, c, 0xd5a79147ul + (w13 = sigma1(w11) + w6));
  Round(c, d, e, f, g, h, a, b,
        0x06ca6351ul + (w14 = sigma1(w12) + w7 + 0x400022ul));
  Round(b, c, d, e, f, g, h, a,
        0x14292967ul + (w15 = 0x100ul + sigma1(w13) + w8 + sigma0(w0)));
  Round(a, b, c, d, e, f, g, h,
        0x27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
  Round(h, a, b, c, d, e, f, g,
        0x2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f,
        0x4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e,
        0x53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d,
        0x650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c,
        0x766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
  Round(a, b, c, d, e, f, g, h,
        0xa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
  Round(h, a, b, c, d, e, f, g,
        0xa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
  Round(g, h, a, b, c, d, e, f,
        0xc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
  Round(f, g, h, a, b, c, d, e,
        0xc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
  Round(e, f, g, h, a, b, c, d,
        0xd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
  Round(d, e, f, g, h, a, b, c,
        0xd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
  Round(c, d, e, f, g, h, a, b,
        0xf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
  Round(b, c, d, e, f, g, h, a,
        0x106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
  Round(a, b, c, d, e, f, g, h,
        0x19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
  Round(h, a, b, c, d, e, f, g,
        0x1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
  Round(g, h, a, b, c, d, e, f,
        0x2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
  Round(f, g, h, a, b, c, d, e,
        0x34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
  Round(e, f, g, h, a, b, c, d,
        0x391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
  Round(d, e, f, g, h, a, b, c,
        0x4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
  Round(c, d, e, f, g, h, a, b,
        0x5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
  Round(b, c, d, e, f, g, h, a,
        0x682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
  Round(a, b, c, d, e, f, g, h,
        0x748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
  Round(h, a, b, c, d, e, f, g,
        0x78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
  Round(g, h, a, b, c, d, e, f,
        0x84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
  Round(f, g, h, a, b, c, d, e,
        0x8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
  Round(e, f, g, h, a, b, c, d,
        0x90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
  Round(d, e, f, g, h, a, b, c,
        0xa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
  Round(c, d, e, f, g, h, a, b,
        0xbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
  Round(b, c, d, e, f, g, h, a,
        0xc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

  // Output
  WriteBE32(out + 0, a + 0x6a09e667ul);
  WriteBE32(out + 4, b + 0xbb67ae85ul);
  WriteBE32(out + 8, c + 0x3c6ef372ul);
  WriteBE32(out + 12, d + 0xa54ff53aul);
  WriteBE32(out + 16, e + 0x510e527ful);
  WriteBE32(out + 20, f + 0x9b05688cul);
  WriteBE32(out + 24, g + 0x1f83d9abul);
  WriteBE32(out + 28, h + 0x5be0cd19ul);
}
} // namespace sha256

class SHA256 {
private:
  uint32_t s[8];
  unsigned char buf[64];
  uint64_t bytes;

public:
  static const size_t OUTPUT_SIZE = 32;

  SHA256() : bytes(0) { sha256::Initialize(s); }

  SHA256 &Write(const unsigned char *data, size_t len) {
    const unsigned char *end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
      // Fill the buffer, and process it.
      memcpy(buf + bufsize, data, 64 - bufsize);
      bytes += 64 - bufsize;
      data += 64 - bufsize;
      sha256::Transform(s, buf, 1);
      bufsize = 0;
    }
    if (end - data >= 64) {
      size_t blocks = (end - data) / 64;
      sha256::Transform(s, data, blocks);
      data += 64 * blocks;
      bytes += 64 * blocks;
    }
    if (end > data) {
      // Fill the buffer with what remains.
      memcpy(buf + bufsize, data, end - data);
      bytes += end - data;
    }
    return *this;
  }

  void Finalize(unsigned char hash[OUTPUT_SIZE]) {
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
  }

  SHA256 &Reset() {
    bytes = 0;
    sha256::Initialize(s);
    return *this;
  }
};

namespace ripemd160 {
uint32_t inline f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
uint32_t inline f2(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (~x & z);
}
uint32_t inline f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
uint32_t inline f4(uint32_t x, uint32_t y, uint32_t z) {
  return (x & z) | (y & ~z);
}
uint32_t inline f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

/** Initialize RIPEMD-160 state. */
void inline Initialize(uint32_t *s) {
  s[0] = 0x67452301ul;
  s[1] = 0xEFCDAB89ul;
  s[2] = 0x98BADCFEul;
  s[3] = 0x10325476ul;
  s[4] = 0xC3D2E1F0ul;
}

uint32_t inline rol(uint32_t x, int i) { return (x << i) | (x >> (32 - i)); }

void inline Round(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                  uint32_t f, uint32_t x, uint32_t k, int r) {
  a = rol(a + f + x + k, r) + e;
  c = rol(c, 10);
}

void inline R11(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f1(b, c, d), x, 0, r);
}
void inline R21(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f2(b, c, d), x, 0x5A827999ul, r);
}
void inline R31(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f3(b, c, d), x, 0x6ED9EBA1ul, r);
}
void inline R41(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f4(b, c, d), x, 0x8F1BBCDCul, r);
}
void inline R51(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f5(b, c, d), x, 0xA953FD4Eul, r);
}

void inline R12(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f5(b, c, d), x, 0x50A28BE6ul, r);
}
void inline R22(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f4(b, c, d), x, 0x5C4DD124ul, r);
}
void inline R32(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f3(b, c, d), x, 0x6D703EF3ul, r);
}
void inline R42(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f2(b, c, d), x, 0x7A6D76E9ul, r);
}
void inline R52(uint32_t &a, uint32_t b, uint32_t &c, uint32_t d, uint32_t e,
                uint32_t x, int r) {
  Round(a, b, c, d, e, f1(b, c, d), x, 0, r);
}

/** Perform a RIPEMD-160 transformation, processing a 64-byte chunk. */
void Transform(uint32_t *s, const unsigned char *chunk) {
  uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
  uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
  uint32_t w0 = ReadLE32(chunk + 0), w1 = ReadLE32(chunk + 4),
           w2 = ReadLE32(chunk + 8), w3 = ReadLE32(chunk + 12);
  uint32_t w4 = ReadLE32(chunk + 16), w5 = ReadLE32(chunk + 20),
           w6 = ReadLE32(chunk + 24), w7 = ReadLE32(chunk + 28);
  uint32_t w8 = ReadLE32(chunk + 32), w9 = ReadLE32(chunk + 36),
           w10 = ReadLE32(chunk + 40), w11 = ReadLE32(chunk + 44);
  uint32_t w12 = ReadLE32(chunk + 48), w13 = ReadLE32(chunk + 52),
           w14 = ReadLE32(chunk + 56), w15 = ReadLE32(chunk + 60);

  R11(a1, b1, c1, d1, e1, w0, 11);
  R12(a2, b2, c2, d2, e2, w5, 8);
  R11(e1, a1, b1, c1, d1, w1, 14);
  R12(e2, a2, b2, c2, d2, w14, 9);
  R11(d1, e1, a1, b1, c1, w2, 15);
  R12(d2, e2, a2, b2, c2, w7, 9);
  R11(c1, d1, e1, a1, b1, w3, 12);
  R12(c2, d2, e2, a2, b2, w0, 11);
  R11(b1, c1, d1, e1, a1, w4, 5);
  R12(b2, c2, d2, e2, a2, w9, 13);
  R11(a1, b1, c1, d1, e1, w5, 8);
  R12(a2, b2, c2, d2, e2, w2, 15);
  R11(e1, a1, b1, c1, d1, w6, 7);
  R12(e2, a2, b2, c2, d2, w11, 15);
  R11(d1, e1, a1, b1, c1, w7, 9);
  R12(d2, e2, a2, b2, c2, w4, 5);
  R11(c1, d1, e1, a1, b1, w8, 11);
  R12(c2, d2, e2, a2, b2, w13, 7);
  R11(b1, c1, d1, e1, a1, w9, 13);
  R12(b2, c2, d2, e2, a2, w6, 7);
  R11(a1, b1, c1, d1, e1, w10, 14);
  R12(a2, b2, c2, d2, e2, w15, 8);
  R11(e1, a1, b1, c1, d1, w11, 15);
  R12(e2, a2, b2, c2, d2, w8, 11);
  R11(d1, e1, a1, b1, c1, w12, 6);
  R12(d2, e2, a2, b2, c2, w1, 14);
  R11(c1, d1, e1, a1, b1, w13, 7);
  R12(c2, d2, e2, a2, b2, w10, 14);
  R11(b1, c1, d1, e1, a1, w14, 9);
  R12(b2, c2, d2, e2, a2, w3, 12);
  R11(a1, b1, c1, d1, e1, w15, 8);
  R12(a2, b2, c2, d2, e2, w12, 6);

  R21(e1, a1, b1, c1, d1, w7, 7);
  R22(e2, a2, b2, c2, d2, w6, 9);
  R21(d1, e1, a1, b1, c1, w4, 6);
  R22(d2, e2, a2, b2, c2, w11, 13);
  R21(c1, d1, e1, a1, b1, w13, 8);
  R22(c2, d2, e2, a2, b2, w3, 15);
  R21(b1, c1, d1, e1, a1, w1, 13);
  R22(b2, c2, d2, e2, a2, w7, 7);
  R21(a1, b1, c1, d1, e1, w10, 11);
  R22(a2, b2, c2, d2, e2, w0, 12);
  R21(e1, a1, b1, c1, d1, w6, 9);
  R22(e2, a2, b2, c2, d2, w13, 8);
  R21(d1, e1, a1, b1, c1, w15, 7);
  R22(d2, e2, a2, b2, c2, w5, 9);
  R21(c1, d1, e1, a1, b1, w3, 15);
  R22(c2, d2, e2, a2, b2, w10, 11);
  R21(b1, c1, d1, e1, a1, w12, 7);
  R22(b2, c2, d2, e2, a2, w14, 7);
  R21(a1, b1, c1, d1, e1, w0, 12);
  R22(a2, b2, c2, d2, e2, w15, 7);
  R21(e1, a1, b1, c1, d1, w9, 15);
  R22(e2, a2, b2, c2, d2, w8, 12);
  R21(d1, e1, a1, b1, c1, w5, 9);
  R22(d2, e2, a2, b2, c2, w12, 7);
  R21(c1, d1, e1, a1, b1, w2, 11);
  R22(c2, d2, e2, a2, b2, w4, 6);
  R21(b1, c1, d1, e1, a1, w14, 7);
  R22(b2, c2, d2, e2, a2, w9, 15);
  R21(a1, b1, c1, d1, e1, w11, 13);
  R22(a2, b2, c2, d2, e2, w1, 13);
  R21(e1, a1, b1, c1, d1, w8, 12);
  R22(e2, a2, b2, c2, d2, w2, 11);

  R31(d1, e1, a1, b1, c1, w3, 11);
  R32(d2, e2, a2, b2, c2, w15, 9);
  R31(c1, d1, e1, a1, b1, w10, 13);
  R32(c2, d2, e2, a2, b2, w5, 7);
  R31(b1, c1, d1, e1, a1, w14, 6);
  R32(b2, c2, d2, e2, a2, w1, 15);
  R31(a1, b1, c1, d1, e1, w4, 7);
  R32(a2, b2, c2, d2, e2, w3, 11);
  R31(e1, a1, b1, c1, d1, w9, 14);
  R32(e2, a2, b2, c2, d2, w7, 8);
  R31(d1, e1, a1, b1, c1, w15, 9);
  R32(d2, e2, a2, b2, c2, w14, 6);
  R31(c1, d1, e1, a1, b1, w8, 13);
  R32(c2, d2, e2, a2, b2, w6, 6);
  R31(b1, c1, d1, e1, a1, w1, 15);
  R32(b2, c2, d2, e2, a2, w9, 14);
  R31(a1, b1, c1, d1, e1, w2, 14);
  R32(a2, b2, c2, d2, e2, w11, 12);
  R31(e1, a1, b1, c1, d1, w7, 8);
  R32(e2, a2, b2, c2, d2, w8, 13);
  R31(d1, e1, a1, b1, c1, w0, 13);
  R32(d2, e2, a2, b2, c2, w12, 5);
  R31(c1, d1, e1, a1, b1, w6, 6);
  R32(c2, d2, e2, a2, b2, w2, 14);
  R31(b1, c1, d1, e1, a1, w13, 5);
  R32(b2, c2, d2, e2, a2, w10, 13);
  R31(a1, b1, c1, d1, e1, w11, 12);
  R32(a2, b2, c2, d2, e2, w0, 13);
  R31(e1, a1, b1, c1, d1, w5, 7);
  R32(e2, a2, b2, c2, d2, w4, 7);
  R31(d1, e1, a1, b1, c1, w12, 5);
  R32(d2, e2, a2, b2, c2, w13, 5);

  R41(c1, d1, e1, a1, b1, w1, 11);
  R42(c2, d2, e2, a2, b2, w8, 15);
  R41(b1, c1, d1, e1, a1, w9, 12);
  R42(b2, c2, d2, e2, a2, w6, 5);
  R41(a1, b1, c1, d1, e1, w11, 14);
  R42(a2, b2, c2, d2, e2, w4, 8);
  R41(e1, a1, b1, c1, d1, w10, 15);
  R42(e2, a2, b2, c2, d2, w1, 11);
  R41(d1, e1, a1, b1, c1, w0, 14);
  R42(d2, e2, a2, b2, c2, w3, 14);
  R41(c1, d1, e1, a1, b1, w8, 15);
  R42(c2, d2, e2, a2, b2, w11, 14);
  R41(b1, c1, d1, e1, a1, w12, 9);
  R42(b2, c2, d2, e2, a2, w15, 6);
  R41(a1, b1, c1, d1, e1, w4, 8);
  R42(a2, b2, c2, d2, e2, w0, 14);
  R41(e1, a1, b1, c1, d1, w13, 9);
  R42(e2, a2, b2, c2, d2, w5, 6);
  R41(d1, e1, a1, b1, c1, w3, 14);
  R42(d2, e2, a2, b2, c2, w12, 9);
  R41(c1, d1, e1, a1, b1, w7, 5);
  R42(c2, d2, e2, a2, b2, w2, 12);
  R41(b1, c1, d1, e1, a1, w15, 6);
  R42(b2, c2, d2, e2, a2, w13, 9);
  R41(a1, b1, c1, d1, e1, w14, 8);
  R42(a2, b2, c2, d2, e2, w9, 12);
  R41(e1, a1, b1, c1, d1, w5, 6);
  R42(e2, a2, b2, c2, d2, w7, 5);
  R41(d1, e1, a1, b1, c1, w6, 5);
  R42(d2, e2, a2, b2, c2, w10, 15);
  R41(c1, d1, e1, a1, b1, w2, 12);
  R42(c2, d2, e2, a2, b2, w14, 8);

  R51(b1, c1, d1, e1, a1, w4, 9);
  R52(b2, c2, d2, e2, a2, w12, 8);
  R51(a1, b1, c1, d1, e1, w0, 15);
  R52(a2, b2, c2, d2, e2, w15, 5);
  R51(e1, a1, b1, c1, d1, w5, 5);
  R52(e2, a2, b2, c2, d2, w10, 12);
  R51(d1, e1, a1, b1, c1, w9, 11);
  R52(d2, e2, a2, b2, c2, w4, 9);
  R51(c1, d1, e1, a1, b1, w7, 6);
  R52(c2, d2, e2, a2, b2, w1, 12);
  R51(b1, c1, d1, e1, a1, w12, 8);
  R52(b2, c2, d2, e2, a2, w5, 5);
  R51(a1, b1, c1, d1, e1, w2, 13);
  R52(a2, b2, c2, d2, e2, w8, 14);
  R51(e1, a1, b1, c1, d1, w10, 12);
  R52(e2, a2, b2, c2, d2, w7, 6);
  R51(d1, e1, a1, b1, c1, w14, 5);
  R52(d2, e2, a2, b2, c2, w6, 8);
  R51(c1, d1, e1, a1, b1, w1, 12);
  R52(c2, d2, e2, a2, b2, w2, 13);
  R51(b1, c1, d1, e1, a1, w3, 13);
  R52(b2, c2, d2, e2, a2, w13, 6);
  R51(a1, b1, c1, d1, e1, w8, 14);
  R52(a2, b2, c2, d2, e2, w14, 5);
  R51(e1, a1, b1, c1, d1, w11, 11);
  R52(e2, a2, b2, c2, d2, w0, 15);
  R51(d1, e1, a1, b1, c1, w6, 8);
  R52(d2, e2, a2, b2, c2, w3, 13);
  R51(c1, d1, e1, a1, b1, w15, 5);
  R52(c2, d2, e2, a2, b2, w9, 11);
  R51(b1, c1, d1, e1, a1, w13, 6);
  R52(b2, c2, d2, e2, a2, w11, 11);

  uint32_t t = s[0];
  s[0] = s[1] + c1 + d2;
  s[1] = s[2] + d1 + e2;
  s[2] = s[3] + e1 + a2;
  s[3] = s[4] + a1 + b2;
  s[4] = t + b1 + c2;
}

} // namespace ripemd160

class RIPEMD160 {
private:
  uint32_t s[5];
  unsigned char buf[64];
  uint64_t bytes;

public:
  static const size_t OUTPUT_SIZE = 20;

  RIPEMD160() : bytes(0) { ripemd160::Initialize(s); }

  RIPEMD160 &Write(const unsigned char *data, size_t len) {
    const unsigned char *end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
      // Fill the buffer, and process it.
      memcpy(buf + bufsize, data, 64 - bufsize);
      bytes += 64 - bufsize;
      data += 64 - bufsize;
      ripemd160::Transform(s, buf);
      bufsize = 0;
    }
    while (end >= data + 64) {
      // Process full chunks directly from the source.
      ripemd160::Transform(s, data);
      bytes += 64;
      data += 64;
    }
    if (end > data) {
      // Fill the buffer with what remains.
      memcpy(buf + bufsize, data, end - data);
      bytes += end - data;
    }
    return *this;
  }

  void Finalize(unsigned char hash[OUTPUT_SIZE]) {
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteLE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteLE32(hash, s[0]);
    WriteLE32(hash + 4, s[1]);
    WriteLE32(hash + 8, s[2]);
    WriteLE32(hash + 12, s[3]);
    WriteLE32(hash + 16, s[4]);
  }

  RIPEMD160 &Reset() {
    bytes = 0;
    ripemd160::Initialize(s);
    return *this;
  }
};

#endif

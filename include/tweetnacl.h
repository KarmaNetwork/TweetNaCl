#ifndef TWEETNACL_H
#define TWEETNACL_H

#include "tweetnacl.config.h"

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
extern void randombytes(u8 *,u64);

#define crypto_box_PUBLICKEYBYTES 32
#define crypto_box_SECRETKEYBYTES 32
#define crypto_box_BEFORENMBYTES 32
#define crypto_box_NONCEBYTES 24
#define crypto_box_ZEROBYTES 32
#define crypto_box_BOXZEROBYTES 16
int crypto_box_keypair(u8 *y,u8 *x);
int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x);
int crypto_box_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);
int crypto_box_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);
int crypto_box(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x);
int crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x);

#define crypto_core_salsa20_OUTPUTBYTES 64
#define crypto_core_salsa20_INPUTBYTES 16
#define crypto_core_salsa20_KEYBYTES 32
#define crypto_core_salsa20_CONSTBYTES 16
int crypto_core_salsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c);

#define crypto_core_hsalsa20_OUTPUTBYTES 32
#define crypto_core_hsalsa20_INPUTBYTES 16
#define crypto_core_hsalsa20_KEYBYTES 32
#define crypto_core_hsalsa20_CONSTBYTES 16
int crypto_core_hsalsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c);

#define crypto_hashblocks_STATEBYTES 64
#define crypto_hashblocks_BLOCKBYTES 128
#define crypto_hash_BYTES 64
int crypto_hashblocks(u8 *x,const u8 *m,u64 n);
int crypto_hash(u8 *out,const u8 *m,u64 n);

#define crypto_onetimeauth_BYTES 16
#define crypto_onetimeauth_KEYBYTES 32
int crypto_onetimeauth(u8 *out,const u8 *m,u64 n,const u8 *k);
int crypto_onetimeauth_verify(const u8 *h,const u8 *m,u64 n,const u8 *k);

#define crypto_scalarmult_BYTES 32
#define crypto_scalarmult_SCALARBYTES 32
int crypto_scalarmult(u8 *q,const u8 *n,const u8 *p);
int crypto_scalarmult_base(u8 *q,const u8 *n);

#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 24
#define crypto_secretbox_ZEROBYTES 32
#define crypto_secretbox_BOXZEROBYTES 16
int crypto_secretbox(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);
int crypto_secretbox_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);

#define crypto_sign_BYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_SECRETKEYBYTES 64
int crypto_sign_keypair(u8 *pk, u8 *sk);
int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk);
int crypto_sign_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk);

#define crypto_stream_salsa20_tweet_KEYBYTES 32
#define crypto_stream_salsa20_tweet_NONCEBYTES 8
#define crypto_stream_KEYBYTES 32
#define crypto_stream_NONCEBYTES 24
int crypto_stream_salsa20_xor(u8 *c,const u8 *m,u64 b,const u8 *n,const u8 *k);
int crypto_stream_salsa20(u8 *c,u64 d,const u8 *n,const u8 *k);
int crypto_stream(u8 *c,u64 d,const u8 *n,const u8 *k);
int crypto_stream_xor(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);

#define crypto_verify_16_BYTES 16
#define crypto_verify_32_BYTES 32
int crypto_verify_16(const u8 *x,const u8 *y);
int crypto_verify_32(const u8 *x,const u8 *y);


#endif

//
//  crypto_drv_ios.c
//  Couchbase Mobile
//
//  Created by Jens Alfke on 9/13/11 (based on original Erlang crypto_drv.c)
//  Copyright 2011 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// The implementation of the Erlang crypto driver uses iOS/Mac OS APIs instead of OpenSSL.
// It currently only implements the small number of functions needed by Couchbase Mobile:
// DRV_MD5, DRV_RAND_BYTES, DRV_RAND_UNIFORM.
// The spec for the Erlang APIs is at http://www.erlang.org/doc/man/crypto.html

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "erl_driver.h"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecRandom.h>

#define OPENSSL_THREAD_DEFINES
#define RC4_INT unsigned int
#include "openssl/opensslconf.h"
#ifndef OPENSSL_THREADS
#  ifdef __GNUC__
#    warning No thread support by openssl. Driver will use coarse grain locking.
#  endif
#endif

#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/dh.h"
#include "openssl/rsa.h"
#include "openssl/md5.h"
#include "openssl/objects.h"
#include "openssl/sha.h"
#include "openssl/rc4.h"


#define get_int32(s) CFSwapInt32BigToHost(*(const int32_t*)(s))
#define put_int32(s,i) {*(int32_t*)(s) = CFSwapInt32HostToBig((i));}

#define ERL_VALGRIND_MAKE_MEM_DEFINED(ptr,size)
#define ERL_VALGRIND_ASSERT_MEM_DEFINED(ptr,size)

static unsigned char* return_binary(char **rbuf, int rlen, int len);
static unsigned char* return_binary_shrink(char **rbuf, int rlen, unsigned char* data, int len);
static int generateUniformRandom(int from_len, const void* from_ptr,
								 int to_len, const void* to_ptr,
								 void* result_ptr);
static void hmac_md5(char *key, int klen, char *dbuf, int dlen, char *hmacbuf);
static void hmac_sha1(char *key, int klen, char *dbuf, int dlen,  char *hmacbuf);

/* openssl callbacks */
#ifdef OPENSSL_THREADS
static void locking_function(int mode, int n, const char *file, int line);
static unsigned long id_function(void);
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file,
                                                 int line);
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr,
                       const char *file, int line);
static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr,
                          const char *file, int line);
#endif /* OPENSSL_THREADS */


#pragma mark - DRIVER INTERFACE

static int crypto_init();
static void crypto_finish();
static ErlDrvData crypto_start(ErlDrvPort port, char *command);
static void crypto_stop(ErlDrvData drv_data);
static int crypto_control(ErlDrvData drv_data, unsigned int command, char *buf,
                   int len, char **rbuf, int rlen);

ErlDrvEntry crypto_driver_entry = {
    crypto_init,
    crypto_start,
    crypto_stop,
    NULL,                       /* output */
    NULL,                       /* ready_input */
    NULL,                       /* ready_output */
    "crypto_drv",
    crypto_finish,
    NULL,                       /* handle */
    crypto_control,
    NULL,                       /* timeout */
    NULL,                       /* outputv */

    NULL,                       /* ready_async */
    NULL,                       /* flush */
    NULL,                       /* call */
    NULL,                       /* event */
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
#ifdef OPENSSL_THREADS
    ERL_DRV_FLAG_USE_PORT_LOCKING,
#else
    0,
#endif
    NULL,                       /* handle2 */
    NULL                        /* process_exit */
};


/* Keep the following definitions in alignment with the FUNC_LIST
 * in crypto.erl.
 */

#define DRV_INFO                0
#define DRV_MD5                 1
#define DRV_MD5_INIT            2
#define DRV_MD5_UPDATE          3
#define DRV_MD5_FINAL           4
#define DRV_SHA                 5
#define DRV_SHA_INIT            6
#define DRV_SHA_UPDATE          7
#define DRV_SHA_FINAL           8
#define DRV_MD5_MAC             9
#define DRV_MD5_MAC_96          10
#define DRV_SHA_MAC             11
#define DRV_SHA_MAC_96          12
#define DRV_CBC_DES_ENCRYPT     13
#define DRV_CBC_DES_DECRYPT     14
#define DRV_EDE3_CBC_DES_ENCRYPT 15
#define DRV_EDE3_CBC_DES_DECRYPT 16
#define DRV_AES_CFB_128_ENCRYPT 17
#define DRV_AES_CFB_128_DECRYPT 18
#define DRV_RAND_BYTES          19
#define DRV_RAND_UNIFORM        20
#define DRV_MOD_EXP             21
#define DRV_DSS_VERIFY          22
#define DRV_RSA_VERIFY_SHA      23
/* #define DRV_RSA_VERIFY_MD5      35 */
#define DRV_CBC_AES128_ENCRYPT  24
#define DRV_CBC_AES128_DECRYPT  25
#define DRV_XOR                 26
#define DRV_RC4_ENCRYPT         27 /* no decrypt needed; symmetric */
#define DRV_RC4_SETKEY          28
#define DRV_RC4_ENCRYPT_WITH_STATE 29
#define DRV_CBC_RC2_40_ENCRYPT     30
#define DRV_CBC_RC2_40_DECRYPT     31
#define DRV_CBC_AES256_ENCRYPT  32
#define DRV_CBC_AES256_DECRYPT  33
#define DRV_INFO_LIB            34
/* #define DRV_RSA_VERIFY_SHA      23 */
#define DRV_RSA_VERIFY_MD5      35
#define DRV_RSA_SIGN_SHA        36
#define DRV_RSA_SIGN_MD5        37
#define DRV_DSS_SIGN            38
#define DRV_RSA_PUBLIC_ENCRYPT  39
#define DRV_RSA_PRIVATE_DECRYPT 40
#define DRV_RSA_PRIVATE_ENCRYPT 41
#define DRV_RSA_PUBLIC_DECRYPT  42
#define DRV_DH_GENERATE_PARAMS  43
#define DRV_DH_CHECK            44
#define DRV_DH_GENERATE_KEY     45
#define DRV_DH_COMPUTE_KEY      46
#define DRV_MD4                 47
#define DRV_MD4_INIT            48
#define DRV_MD4_UPDATE          49
#define DRV_MD4_FINAL           50

#define SSL_VERSION_0_9_8 0
#if SSL_VERSION_0_9_8
#define DRV_SHA256              51
#define DRV_SHA256_INIT         52
#define DRV_SHA256_UPDATE       53
#define DRV_SHA256_FINAL        54
#define DRV_SHA512              55
#define DRV_SHA512_INIT         56
#define DRV_SHA512_UPDATE       57
#define DRV_SHA512_FINAL        58
#endif

#define DRV_BF_CFB64_ENCRYPT     59
#define DRV_BF_CFB64_DECRYPT     60

/* #define DRV_CBC_IDEA_ENCRYPT    34 */
/* #define DRV_CBC_IDEA_DECRYPT    35 */

/* Not DRV_DH_GENERATE_PARAMS DRV_DH_CHECK
 * Calc RSA_VERIFY_*  and RSA_SIGN once */
#define NUM_CRYPTO_FUNCS        46

#define MD5_LEN_96      12


/* List of implemented commands. Returned by DRV_INFO. */
static const uint8_t kImplementedFuncs[] = {
	DRV_MD5,
	DRV_MD5_INIT,
	DRV_MD5_UPDATE,
	DRV_MD5_FINAL,
	DRV_SHA,
    DRV_SHA_INIT,
    DRV_SHA_UPDATE,
    DRV_SHA_FINAL,
    DRV_MD5_MAC,
    DRV_MD5_MAC_96,
	DRV_SHA_MAC,
	DRV_RAND_BYTES,
	DRV_RAND_UNIFORM,
    DRV_RSA_VERIFY_MD5,
    DRV_XOR,
    DRV_CBC_AES128_ENCRYPT,
    DRV_CBC_AES128_DECRYPT,
    DRV_CBC_AES256_ENCRYPT,
    DRV_CBC_AES256_DECRYPT,
    DRV_RSA_VERIFY_SHA,
    DRV_RSA_PUBLIC_ENCRYPT,
    DRV_RSA_PUBLIC_DECRYPT,
    DRV_DH_GENERATE_KEY,
    DRV_DH_COMPUTE_KEY
};


static ErlDrvRWLock** lock_vec = NULL; /* Static locks used by openssl */


#pragma mark - DRIVER INTERFACE

static int crypto_init(void)
{
    ErlDrvSysInfo sys_info;
    int i;

    CRYPTO_set_mem_functions(driver_alloc, driver_realloc, driver_free);

#ifdef OPENSSL_THREADS
    driver_system_info(&sys_info, sizeof(sys_info));

    if(sys_info.scheduler_threads > 1) {
        lock_vec = driver_alloc(CRYPTO_num_locks()*sizeof(*lock_vec));
        if (lock_vec==NULL) return -1;
        memset(lock_vec,0,CRYPTO_num_locks()*sizeof(*lock_vec));

        for(i=CRYPTO_num_locks()-1; i>=0; --i) {
            lock_vec[i] = erl_drv_rwlock_create("crypto_drv_stat");
            if (lock_vec[i]==NULL) return -1;
        }
        CRYPTO_set_locking_callback(locking_function);
        CRYPTO_set_id_callback(id_function);
        CRYPTO_set_dynlock_create_callback(dyn_create_function);
        CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
        CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
    }
    /* else no need for locks */
#endif /* OPENSSL_THREADS */

    return 0;
}

static void crypto_finish(void)
{
}

static ErlDrvData crypto_start(ErlDrvPort port, char *command)
{
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    return 0; /* not used */
}

static void crypto_stop(ErlDrvData drv_data)
{
}

/* Main entry point for crypto functions. Spec is at http://www.erlang.org/doc/man/crypto.html */
static int crypto_control(ErlDrvData drv_data, unsigned int command,
				   char *buf, int len,
				   char **rbuf, int rlen)
{
	unsigned char* bin;
    switch(command) {
		case DRV_INFO: {
			bin = return_binary(rbuf,rlen,sizeof(kImplementedFuncs));
			if (bin==NULL) return -1;
			memcpy(bin, kImplementedFuncs, sizeof(kImplementedFuncs));
			return sizeof(kImplementedFuncs);
		}

		case DRV_MD5: {
			bin = return_binary(rbuf,rlen,CC_MD5_DIGEST_LENGTH);
			if (bin==NULL) return -1;
			CC_MD5(buf, len, bin);
			return CC_MD5_DIGEST_LENGTH;
		}
		case DRV_MD5_INIT: {
			bin = return_binary(rbuf,rlen,sizeof(CC_MD5_CTX));
			if (bin==NULL) return -1;
			CC_MD5_Init((CC_MD5_CTX*)bin);
			return sizeof(CC_MD5_CTX);
		}
		case DRV_MD5_UPDATE: {
			if (len < sizeof(CC_MD5_CTX))
				return -1;
			bin = return_binary(rbuf,rlen,sizeof(CC_MD5_CTX));
			if (bin==NULL) return -1;
			memcpy(bin, buf, sizeof(CC_MD5_CTX));
			CC_MD5_Update((CC_MD5_CTX*)bin, buf + sizeof(CC_MD5_CTX), len - sizeof(CC_MD5_CTX));
			return sizeof(CC_MD5_CTX);
		}
		case DRV_MD5_FINAL: {
			if (len != sizeof(CC_MD5_CTX))
				return -1;
			bin = return_binary(rbuf, rlen, CC_MD5_DIGEST_LENGTH);
			if (bin==NULL) return -1;
            CC_MD5_CTX ctx = *(CC_MD5_CTX*)buf;  // not safe to modify contents of buf, so copy
			CC_MD5_Final(bin, &ctx);
			return CC_MD5_DIGEST_LENGTH;
		}

		case DRV_SHA: {
			bin = return_binary(rbuf,rlen,CC_SHA1_DIGEST_LENGTH);
			if (bin==NULL) return -1;
			CC_SHA1(buf, len, bin);
			return CC_SHA1_DIGEST_LENGTH;
		}
		case DRV_SHA_INIT: {
			bin = return_binary(rbuf,rlen,sizeof(CC_SHA1_CTX));
			if (bin==NULL) return -1;
			CC_SHA1_Init((CC_SHA1_CTX*)bin);
			return sizeof(CC_SHA1_CTX);
		}
		case DRV_SHA_UPDATE: {
			if (len < sizeof(CC_SHA1_CTX))
				return -1;
			bin = return_binary(rbuf,rlen,sizeof(CC_SHA1_CTX));
			if (bin==NULL) return -1;
			memcpy(bin, buf, sizeof(CC_SHA1_CTX));
			CC_SHA1_Update((CC_SHA1_CTX*)bin, buf + sizeof(CC_SHA1_CTX), len - sizeof(CC_SHA1_CTX));
			return sizeof(CC_SHA1_CTX);
		}
		case DRV_SHA_FINAL: {
			if (len != sizeof(CC_SHA1_CTX))
				return -1;
			bin = return_binary(rbuf, rlen, CC_SHA1_DIGEST_LENGTH);
			if (bin==NULL) return -1;
            CC_SHA1_CTX ctx = *(CC_SHA1_CTX*)buf;  // not safe to modify contents of buf, so copy
			CC_SHA1_Final(bin, &ctx);
			return CC_SHA1_DIGEST_LENGTH;
		}

        case DRV_MD5_MAC:
        case DRV_MD5_MAC_96: {
            /* buf = klen[4] key data */
            int klen = get_int32(buf);
            char* key = buf + 4;
            int dlen = len - klen - 4;
            char* dbuf = key + klen;
            char hmacbuf[CC_MD5_DIGEST_LENGTH];
            hmac_md5(key, klen, dbuf, dlen, hmacbuf);
            int macsize = (command == DRV_MD5_MAC) ? CC_MD5_DIGEST_LENGTH : MD5_LEN_96;
            bin = return_binary(rbuf,rlen,macsize);
            if (bin==NULL) return -1;
            memcpy(bin, hmacbuf, macsize);
            return macsize;
        }

		case DRV_SHA_MAC: {
			/* buf = klen:32/integer,key:klen/binary,dbuf:remainder/binary */
			if (len < 4)
				return -1;
			int klen = get_int32(buf);
			if (klen < 0 || klen > len - 4)
				return -1;
			const char* key = buf + 4;
			int dlen = len - klen - 4;
			const char* dbuf = key + klen;
			bin = return_binary(rbuf,rlen,CC_SHA1_DIGEST_LENGTH);
			if (bin==NULL) return -1;

			CCHmac(kCCHmacAlgSHA1, key, klen, dbuf, dlen, bin);
			return CC_SHA1_DIGEST_LENGTH;
		}

		case DRV_RAND_BYTES: {
			/* buf = <<rlen:32/integer,topmask:8/integer,bottommask:8/integer>> */
			if (len != 6)
				return -1;
			int dlen = get_int32(buf);
			bin = return_binary(rbuf,rlen,dlen);
			if (bin==NULL) return -1;
			if (SecRandomCopyBytes(NULL, dlen, bin) != 0)
				return -1;
			int or_mask = ((unsigned char*)buf)[4];
			bin[dlen-1] |= or_mask; /* topmask */
			or_mask = ((unsigned char*)buf)[5];
			bin[0] |= or_mask; /* bottommask */
			return dlen;
		}
		case DRV_RAND_UNIFORM: {
			/* buf = <<from_len:32/integer,bn_from:from_len/binary,   *
			 *         to_len:32/integer,bn_to:to_len/binary>>        */
			if (len < 8)
				return -1;
			int from_len = get_int32(buf);
			if (from_len < 0 || len < (8 + from_len))
				return -1;
			int to_len = get_int32(buf + 4 + from_len);
			if (to_len < 0 || len != (8 + from_len + to_len))
				return -1;

			int result_len;
			char result[8];
			result_len = generateUniformRandom(from_len, buf + 4,
											   to_len, buf + 4 + from_len + 4,
											   &result);
			if (result_len < 0)
				return -1;

			bin = return_binary(rbuf,rlen,4+result_len);
			put_int32(bin, result_len);
			memcpy(bin+4, result, result_len);
			return 4+result_len;
		}

        case DRV_CBC_AES128_ENCRYPT:
        case DRV_CBC_AES256_ENCRYPT:
        case DRV_CBC_AES128_DECRYPT:
        case DRV_CBC_AES256_DECRYPT: {
            /* buf = key[klen] ivec[16] data */
            bool encrypting = (command==DRV_CBC_AES128_ENCRYPT || command==DRV_CBC_AES256_ENCRYPT);
            int klen;
            if (command == DRV_CBC_AES256_ENCRYPT || command == DRV_CBC_AES256_DECRYPT)
                klen = 32;
            else
                klen = 16;
            const char* key = buf;
            const char* ivec = buf + klen;
            const char* data = ivec + 16;
            int dlen = len - klen - 16;
            if (dlen < 0)
                return -1;
            if (dlen % 16 != 0)
                return -1;
            bin = return_binary(rbuf,rlen,dlen);
            if (bin==NULL) return -1;
            size_t actual_dlen;
            CCCryptorStatus result = CCCrypt(encrypting ? kCCEncrypt : kCCDecrypt,
                                             kCCAlgorithmAES128, 0,
                                             key, klen, ivec,
                                             data, dlen,
                                             bin, dlen, &actual_dlen);
            if (result != kCCSuccess) {
                fprintf(stderr, "ERROR: crypto_drv_ios: CCCrypt returned %i\n", result);
                return -1;
            }
            return actual_dlen;
        }

        case DRV_RC4_SETKEY: {
            /* buf = key */
            RC4_KEY rc4_key;
            int dlen = sizeof(rc4_key);
            bin = return_binary(rbuf,rlen,dlen);
            if (bin==NULL) return -1;
            RC4_set_key(&rc4_key, len, (unsigned char *) buf);
            memcpy(bin, &rc4_key, dlen);
            return dlen;
        }
        case DRV_RC4_ENCRYPT_WITH_STATE: {
            /* buf = statelength[4] state data, return statelength[4] state data */
            int klen = get_int32(buf);
            char* key = buf + 4;
            int dlen = len - klen - 4;
            char* dbuf = key + klen;
            bin = return_binary(rbuf,rlen,len);
            if (bin==NULL) return -1;
            RC4_KEY rc4_key;
            memcpy(&rc4_key, key, klen);
            RC4(&rc4_key, dlen, (unsigned char *) dbuf, bin + klen + 4);
            memcpy(bin, buf, 4);
            memcpy(bin + 4, &rc4_key, klen);
            return len;
        }
            
        case DRV_XOR: {
            /* buf = data1, data2 with same size */
            int dlen = len / 2;
            if (len != dlen * 2)
                return -1;
            bin = return_binary(rbuf,rlen,dlen);
            if (bin==NULL) return -1;
            unsigned char* p = bin;
            char* dbuf = buf + dlen;
            for (char* key = buf, *key2 = dbuf; key != dbuf; ++key, ++key2, ++p)
                *p = *key ^ *key2;
            return dlen;
        }

        case DRV_RSA_VERIFY_MD5:
        case DRV_RSA_VERIFY_SHA: {
            /* buf = <<data_len:32/integer, data:data_len/binary,
             *         rsa_s_len:32/integer, rsa_s:rsa_s_len/binary,
             *         rsa_e_len:32/integer, rsa_e:rsa_e_len/binary,
             *         rsa_n_len:32/integer, rsa_n:rsa_n_len/binary>> */
            int i = 0;
            int j = 0;
            if (len < 16)
                return -1;
            int data_len = get_int32(buf + i + j);
            j += data_len; i += 4;
            if (len < (16 + j))
                return -1;
            int rsa_s_len = get_int32(buf + i + j);
            j += rsa_s_len; i += 4;
            if (len < (16 + j))
                return -1;
            int rsa_e_len = get_int32(buf + i + j);
            j += rsa_e_len; i += 4;
            if (len < (16 + j))
                return -1;
            int rsa_n_len = get_int32(buf + i + j);
            j += rsa_n_len; i += 4;
            if (len != (16 + j))
                return -1;
            i = 4;
            i += (data_len + 4);
            unsigned char* rsa_s = (unsigned char *)(buf + i);
            i += (rsa_s_len + 4);
            BIGNUM* rsa_e = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), rsa_e_len, rsa_e);
            i += (rsa_e_len + 4);
            BIGNUM* rsa_n = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), rsa_n_len, rsa_n);
            RSA* rsa = RSA_new();
            rsa->n = rsa_n;
            rsa->e = rsa_e;
            i = 4;
            char hmacbuf[CC_SHA1_DIGEST_LENGTH];
            if(command == DRV_RSA_VERIFY_SHA) {
                SHA1((unsigned char *) (buf + i), data_len,
                     (unsigned char *) hmacbuf);
                i = RSA_verify(NID_sha1, (unsigned char *) hmacbuf, SHA_DIGEST_LENGTH,
                               rsa_s, rsa_s_len, rsa);
            } else {
                MD5((unsigned char *) (buf + i), data_len, (unsigned char *) hmacbuf);
                i =  RSA_verify(NID_md5, (unsigned char *) hmacbuf, MD5_DIGEST_LENGTH,
                                rsa_s, rsa_s_len, rsa);
            }

            bin = return_binary(rbuf,rlen,1);
            if (bin==NULL) return -1;
            bin[0] = (char)(i & 0xff);
            RSA_free(rsa);
            return 1;
        }

        case DRV_RSA_PUBLIC_ENCRYPT:
        case DRV_RSA_PUBLIC_DECRYPT: {
            /* buf = <<data_len:32/integer, data:data_len/binary,
             *         rsa_e_len:32/integer, rsa_e:rsa_e_len/binary,
             *         rsa_n_len:32/integer, rsa_n:rsa_n_len/binary,
             *         pad:8/integer >> */

            ERL_VALGRIND_ASSERT_MEM_DEFINED(buf,len);
            int i = 0;
            int j = 0;

            if (len < 13)
                return -1;
            int data_len = get_int32(buf + i + j);
            j += data_len; i += 4;
            if (len < (13 + j))
                return -1;
            int rsa_e_len = get_int32(buf + i + j);
            j += rsa_e_len; i += 4;
            if (len < (13 + j))
                return -1;
            int rsa_n_len = get_int32(buf + i + j);
            j += rsa_n_len; i += 4;
            if (len < (13 + j))
                return -1;
            int padding = *(unsigned char *) (buf + i + j);
            if (len != (13 + j))
                return -1;

            i = 4;
            i += (data_len + 4);
            BIGNUM* rsa_e = BN_new();
            ERL_VALGRIND_ASSERT_MEM_DEFINED(buf+i,rsa_e_len);
            BN_bin2bn((unsigned char *)(buf + i), rsa_e_len, rsa_e);
            i += (rsa_e_len + 4);
            BIGNUM* rsa_n = BN_new();
            ERL_VALGRIND_ASSERT_MEM_DEFINED(buf+i,rsa_n_len);
            BN_bin2bn((unsigned char *)(buf + i), rsa_n_len, rsa_n);
            i += (rsa_n_len + 4);

            switch(padding) {
                case 0:
                    padding = RSA_NO_PADDING;
                    break;
                case 1:
                    padding = RSA_PKCS1_PADDING;
                    break;
                case 2:
                    padding = RSA_PKCS1_OAEP_PADDING;
                    break;
                case 3:
                    padding = RSA_SSLV23_PADDING;
                    break;
                default:
                    return -1;
            }

            RSA* rsa = RSA_new();
            rsa->e = rsa_e;
            rsa->n = rsa_n;

            int dlen = RSA_size(rsa) + 1;
            bin = return_binary(rbuf,rlen,dlen);
            if (bin==NULL) return -1;
            i = 4;
            if(command == DRV_RSA_PUBLIC_ENCRYPT) {
                ERL_VALGRIND_ASSERT_MEM_DEFINED(buf+i,data_len);
                i = RSA_public_encrypt(data_len, (unsigned char *) (buf+i),
                                       (unsigned char *) &bin[1],
                                       rsa, padding);
                if (i > 0) {
                    ERL_VALGRIND_MAKE_MEM_DEFINED(bin+1, i);
                }
            } else {
                i = RSA_public_decrypt(data_len, (unsigned char *) (buf+i),
                                       (unsigned char *) &bin[1],
                                       rsa, padding);
                if(i > 0) {
                    ERL_VALGRIND_MAKE_MEM_DEFINED(bin+1, i);
                    bin = return_binary_shrink(rbuf,rlen,bin, i+1);
                    if (bin==NULL) return -1;
                }
            }

            RSA_free(rsa);
            if(i > 0) {
                bin[0] = 1;
                return i + 1;
            } else {
                /* 	  ERR_load_crypto_strings(); */
                /* 	  fprintf(stderr, "%d: %s \r\n", __LINE__, ERR_reason_error_string(ERR_get_error())); */
                bin[0] = 0;
                return 1;
            }
            break;
        }

        case DRV_DH_GENERATE_KEY: {
            /* buf = <<key_len:32,  key:key_len/binary,            *
             *         dh_p_len:32/integer, dh_p:dh_p_len/binary,  *
             *         dh_g_len:32/integer, dh_g:dh_g_len/binary>> */
            ERL_VALGRIND_ASSERT_MEM_DEFINED(buf,len);
            int i = 0;
            int j = 0;
            if(len < 12)        return -1;
            int base_len = get_int32(buf + i + j);
            j += base_len; i += 4;
            if (len < (12 + j)) return -1;
            int dh_p_len = get_int32(buf + i + j);
            j += dh_p_len; i += 4;
            if (len < (12 + j)) return -1;
            int dh_g_len = get_int32(buf + i + j);
            j += dh_g_len; i += 4;
            if(len != (12 + j))   return -1;
            i=4;
            i += (base_len + 4);
            BIGNUM* dh_p = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), dh_p_len, dh_p);
            i += (dh_p_len + 4);
            BIGNUM* dh_g = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), dh_g_len, dh_g);
            /* i += (dsa_g_len + 4); */

            DH* dh_params = DH_new();
            dh_params->p = dh_p;
            dh_params->g = dh_g;
            if(base_len > 0) {
                dh_params->priv_key = BN_new();
                BN_bin2bn((unsigned char *)(buf + i), base_len,
                          dh_params->priv_key);
            }
            i=0;
            int dlen;
            if(DH_generate_key(dh_params)) {
                int privkey_len = BN_num_bytes(dh_params->priv_key);
                int pubkey_len = BN_num_bytes(dh_params->pub_key);
                dlen = 1 + 4 + 4 + pubkey_len + privkey_len;
                bin = return_binary(rbuf,rlen, dlen);
                if (bin==NULL) return -1;
                bin[0] = 1;
                put_int32(bin+1, pubkey_len);
                BN_bn2bin(dh_params->pub_key, bin+5);
                ERL_VALGRIND_MAKE_MEM_DEFINED(bin+5, pubkey_len);
                put_int32(bin+5+pubkey_len, privkey_len);
                BN_bn2bin(dh_params->priv_key, bin+5+pubkey_len+4);
                ERL_VALGRIND_MAKE_MEM_DEFINED(bin+5+pubkey_len+4, privkey_len);
            } else {
                dlen = 1;
                bin = return_binary(rbuf,rlen,dlen);
                if (bin==NULL) return -1;
                bin[0] = 0;
            }
            DH_free(dh_params);
            return dlen;
        }

        case DRV_DH_COMPUTE_KEY: {
            /* buf = <<pubkey_len:32,  pubkey:pubkey_len/binary,   *
             *         privkey_len:32, privkey:privkey_len/binary, *
             *         dh_p_len:32/integer, dh_p:dh_p_len/binary,  *
             *         dh_g_len:32/integer, dh_g:dh_g_len/binary>> */
            int i = 0;
            int j = 0;
            if(len < 16)        return -1;
            int pubkey_len = get_int32(buf + i + j);
            j += pubkey_len; i += 4;
            if (len < (16 + j)) return -1;
            int privkey_len = get_int32(buf + i + j);
            j += privkey_len; i += 4;
            if (len < (16 + j)) return -1;
            int dh_p_len = get_int32(buf + i + j);
            j += dh_p_len; i += 4;
            if (len < (16 + j)) return -1;
            int dh_g_len = get_int32(buf + i + j);
            j += dh_g_len; i += 4;
            if(len != (16 + j))   return -1;
            i=4;
            BIGNUM* pubkey = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), pubkey_len, pubkey);
            i += (pubkey_len + 4);
            BIGNUM* privkey = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), privkey_len, privkey);
            i += (privkey_len + 4);
            BIGNUM* dh_p = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), dh_p_len, dh_p);
            i += (dh_p_len + 4);
            BIGNUM* dh_g = BN_new();
            BN_bin2bn((unsigned char *)(buf + i), dh_g_len, dh_g);
            /* i += (dsa_g_len + 4); */

            DH* dh_params = DH_new();
            dh_params->p = dh_p;
            dh_params->g = dh_g;
            dh_params->priv_key = privkey;

            int klen = DH_size(dh_params);
            bin = return_binary(rbuf,rlen,1+klen);
            if (bin==NULL) return -1;
            i = DH_compute_key(&bin[1], pubkey, dh_params);
            DH_free(dh_params);
            if (i > 0) {
                if (i != klen) {
                    bin = return_binary_shrink(rbuf,rlen,bin,1+i);
                }
                bin[0] = 1;
                return i + 1;
            }
            else {
                bin[0] = 0;
                return 1;
            }
        }

		// NOTE: If you implement more cases, you must add them to kImplementedFuncs[].
		default: {
            fprintf(stderr, "ERROR: crypto_drv_ios.c: unsupported crypto_control command %u\n",
                    command);
			return -1;
		}
    }
}


#pragma mark - HELPER FUNCTIONS:


static unsigned char* return_binary(char **rbuf, int rlen, int len)
{
    if (len <= rlen) {
		return (unsigned char *) *rbuf;
    }
    else {
		ErlDrvBinary* bin;
		*rbuf = (char*) (bin = driver_alloc_binary(len));
		return (bin==NULL) ? NULL : (unsigned char *) bin->orig_bytes;
    }
}

static unsigned char* return_binary_shrink(char **rbuf, int rlen, unsigned char* data, int len)
{
    if ((char *) data == *rbuf) { /* default buffer */
        assert(len <= rlen);
        return (unsigned char *) data;
    }
    else {
        ErlDrvBinary* bin = (ErlDrvBinary*) *rbuf;
        *rbuf = (char*) (bin=driver_realloc_binary(bin, len));
        return (bin==NULL) ? NULL : (unsigned char *) bin->orig_bytes;
    }
}


/* Returns a random number n such that from <= n < to.  On failure returns 'to'. */
static uint64_t randomNumberInRange(uint64_t from, uint64_t to) {
	if (to <= from)
		return to;
	uint64_t range = to - from;

	int shift = 64;
	for (uint64_t shiftedRange = range; shiftedRange != 0; shiftedRange >>= 1)
		--shift;

	uint64_t n;
	do {
		if (SecRandomCopyBytes(NULL, sizeof(n), (uint8_t*)&n) != 0)
			return to; // error
		n >>= shift;
	} while (n >= range);
	return from + n;
}


/* Fake implementation of bignum rand_uniform function. Only handles numbers up to 8 bytes long. */
static int generateUniformRandom(int from_len, const void* from_ptr,
								 int to_len, const void* to_ptr,
								 void* result_ptr)
{
	// Convert the from and to numbers into native long ints:
	if (from_len > 8 || to_len > 8)
		return -1;
	uint64_t from = 0;
	memcpy((char*)&from + 8 - from_len, from_ptr, from_len);
	from = CFSwapInt64BigToHost(from);
	uint64_t to = 0;
	memcpy((char*)&to + 8 - to_len, to_ptr, to_len);
	to = CFSwapInt64BigToHost(to);

	// Generate the random number.
	uint64_t result = randomNumberInRange(from, to);
	if (result >= to)
		return -1;

	*(uint64_t*)result_ptr = CFSwapInt64HostToBig(result);
	return sizeof(result);
}


#define HMAC_INT_LEN    64
#define HMAC_IPAD       0x36
#define HMAC_OPAD       0x5c

static void hmac_md5(char *key, int klen, char *dbuf, int dlen, char *hmacbuf)
{
    CC_MD5_CTX ctx;
    char ipad[HMAC_INT_LEN];
    char opad[HMAC_INT_LEN];
    unsigned char nkey[CC_MD5_DIGEST_LENGTH];
    int i;

    /* Change key if longer than 64 bytes */
    if (klen > HMAC_INT_LEN) {
        CC_MD5(key, klen, nkey);
        key = (char *) nkey;
        klen = CC_MD5_DIGEST_LENGTH;
    }

    memset(ipad, '\0', sizeof(ipad));
    memset(opad, '\0', sizeof(opad));
    memcpy(ipad, key, klen);
    memcpy(opad, key, klen);

    for (i = 0; i < HMAC_INT_LEN; i++) {
        ipad[i] ^= HMAC_IPAD;
        opad[i] ^= HMAC_OPAD;
    }

    /* inner MD5 */
    CC_MD5_Init(&ctx);
    CC_MD5_Update(&ctx, ipad, HMAC_INT_LEN);
    CC_MD5_Update(&ctx, dbuf, dlen);
    CC_MD5_Final((unsigned char *) hmacbuf, &ctx);
    /* outer MD5 */
    CC_MD5_Init(&ctx);
    CC_MD5_Update(&ctx, opad, HMAC_INT_LEN);
    CC_MD5_Update(&ctx, hmacbuf, CC_MD5_DIGEST_LENGTH);
    CC_MD5_Final((unsigned char *) hmacbuf, &ctx);
}

static void hmac_sha1(char *key, int klen, char *dbuf, int dlen,  char *hmacbuf)
{
    CC_SHA1_CTX ctx;
    char ipad[HMAC_INT_LEN];
    char opad[HMAC_INT_LEN];
    unsigned char nkey[CC_SHA1_DIGEST_LENGTH];
    int i;

    /* Change key if longer than 64 bytes */
    if (klen > HMAC_INT_LEN) {
        CC_SHA1(key, klen, nkey);
        key = (char *) nkey;
        klen = CC_SHA1_DIGEST_LENGTH;
    }

    memset(ipad, '\0', sizeof(ipad));
    memset(opad, '\0', sizeof(opad));
    memcpy(ipad, key, klen);
    memcpy(opad, key, klen);

    for (i = 0; i < HMAC_INT_LEN; i++) {
        ipad[i] ^= HMAC_IPAD;
        opad[i] ^= HMAC_OPAD;
    }

    /* inner SHA */
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, ipad, HMAC_INT_LEN);
    CC_SHA1_Update(&ctx, dbuf, dlen);
    CC_SHA1_Final((unsigned char *) hmacbuf, &ctx);
    /* outer SHA */
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, opad, HMAC_INT_LEN);
    CC_SHA1_Update(&ctx, hmacbuf, CC_SHA1_DIGEST_LENGTH);
    CC_SHA1_Final((unsigned char *) hmacbuf, &ctx);
}


#ifdef OPENSSL_THREADS /* vvvvvvvvvvvvvvv OPENSSL_THREADS vvvvvvvvvvvvvvvv */

static void locking(int mode, ErlDrvRWLock* lock)
{
    switch(mode) {
        case CRYPTO_LOCK|CRYPTO_READ:
            erl_drv_rwlock_rlock(lock);
            break;
        case CRYPTO_LOCK|CRYPTO_WRITE:
            erl_drv_rwlock_rwlock(lock);
            break;
        case CRYPTO_UNLOCK|CRYPTO_READ:
            erl_drv_rwlock_runlock(lock);
            break;
        case CRYPTO_UNLOCK|CRYPTO_WRITE:
            erl_drv_rwlock_rwunlock(lock);
            break;
        default:
            assert(!"Invalid lock mode");
    }
}

/* Callback from openssl for static locking
 */
static void locking_function(int mode, int n, const char *file, int line)
{
    assert(n>=0 && n<CRYPTO_num_locks());

    locking(mode, lock_vec[n]);
}

/* Callback from openssl for thread id
 */
static unsigned long id_function(void)
{
    return (unsigned long) erl_drv_thread_self();
}

/* Callbacks for dynamic locking, not used by current openssl version (0.9.8)
 */
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file, int line)
{
    return (struct CRYPTO_dynlock_value*) erl_drv_rwlock_create("crypto_drv_dyn");
}
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr,const char *file, int line)
{
    locking(mode, (ErlDrvRWLock*)ptr);
}
static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr, const char *file, int line)
{
    erl_drv_rwlock_destroy((ErlDrvRWLock*)ptr);
}

#endif /* ^^^^^^^^^^^^^^^^^^^^^^ OPENSSL_THREADS ^^^^^^^^^^^^^^^^^^^^^^ */

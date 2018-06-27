#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/sph_sha2.h>
#include <sha3/sph_haval.h>

//#define DEBUG_ALGO

void hmq1725hash(void *output, const void *input)
{
	uint32_t _ALIGN(64) hashA[16], hashB[16];

	const uint32_t mask = 24;

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_skein512_context     ctx_skein;
	sph_luffa512_context     ctx_luffa;
	sph_cubehash512_context  ctx_cubehash;
	sph_shavite512_context   ctx_shavite;
	sph_simd512_context      ctx_simd;
	sph_echo512_context      ctx_echo;
	sph_hamsi512_context     ctx_hamsi;
	sph_fugue512_context     ctx_fugue;
	sph_shabal512_context    ctx_shabal;
	sph_whirlpool_context    ctx_whirlpool;
	sph_sha512_context       ctx_sha512;
	sph_haval256_5_context   ctx_haval;

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, input, 80);
	sph_bmw512_close(&ctx_bmw, hashA);

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool(&ctx_whirlpool, hashA, 64);
	sph_whirlpool_close(&ctx_whirlpool, hashB);

	if (hashB[0] & mask) {
		sph_groestl512_init(&ctx_groestl);
		sph_groestl512(&ctx_groestl, hashB, 64);
		sph_groestl512_close(&ctx_groestl, hashA);
	} else {
		sph_skein512_init(&ctx_skein);
		sph_skein512(&ctx_skein, hashB, 64);
		sph_skein512_close(&ctx_skein, hashA);
	}

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, hashA, 64);
	sph_jh512_close(&ctx_jh, hashB);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, hashB, 64);
	sph_keccak512_close(&ctx_keccak, hashA);

	if (hashA[0] & mask) {
		sph_blake512_init(&ctx_blake);
		sph_blake512(&ctx_blake, hashA, 64);
		sph_blake512_close(&ctx_blake, hashB);
	} else {
		sph_bmw512_init(&ctx_bmw);
		sph_bmw512(&ctx_bmw, hashA, 64);
		sph_bmw512_close(&ctx_bmw, hashB);
	}

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hashB, 64);
	sph_luffa512_close(&ctx_luffa, hashA);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, hashA, 64);
	sph_cubehash512_close(&ctx_cubehash, hashB);


	if (hashB[0] & mask) {
		sph_keccak512_init(&ctx_keccak);
		sph_keccak512(&ctx_keccak, hashB, 64);
		sph_keccak512_close(&ctx_keccak, hashA);
	} else {
		sph_jh512_init(&ctx_jh);
		sph_jh512(&ctx_jh, hashB, 64);
		sph_jh512_close(&ctx_jh, hashA);
	}

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hashA, 64);
	sph_shavite512_close(&ctx_shavite, hashB);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hashB, 64);
	sph_simd512_close(&ctx_simd, hashA);

	if (hashA[0] & mask) {
		sph_whirlpool_init(&ctx_whirlpool);
		sph_whirlpool(&ctx_whirlpool, hashA, 64);
		sph_whirlpool_close(&ctx_whirlpool, hashB);
	} else {
		sph_haval256_5_init(&ctx_haval);
		sph_haval256_5(&ctx_haval, hashA, 64);
		sph_haval256_5_close(&ctx_haval, hashB);
		memset(&hashB[8], 0, 32);
	}

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hashB, 64);
	sph_echo512_close(&ctx_echo, hashA);

	sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, hashA, 64);
	sph_blake512_close(&ctx_blake, hashB);

	if (hashB[0] & mask) {
		sph_shavite512_init(&ctx_shavite);
		sph_shavite512(&ctx_shavite, hashB, 64);
		sph_shavite512_close(&ctx_shavite, hashA);
	} else {
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512(&ctx_luffa, hashB, 64);
		sph_luffa512_close(&ctx_luffa, hashA);
	}

	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512(&ctx_hamsi, hashA, 64);
	sph_hamsi512_close(&ctx_hamsi, hashB);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hashB, 64);
	sph_fugue512_close(&ctx_fugue, hashA);

	if (hashA[0] & mask) {
		sph_echo512_init(&ctx_echo);
		sph_echo512(&ctx_echo, hashA, 64);
		sph_echo512_close(&ctx_echo, hashB);
	} else {
		sph_simd512_init(&ctx_simd);
		sph_simd512(&ctx_simd, hashA, 64);
		sph_simd512_close(&ctx_simd, hashB);
	}

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hashB, 64);
	sph_shabal512_close(&ctx_shabal, hashA);

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool(&ctx_whirlpool, hashA, 64);
	sph_whirlpool_close(&ctx_whirlpool, hashB);

	if (hashB[0] & mask) {
		sph_fugue512_init(&ctx_fugue);
		sph_fugue512(&ctx_fugue, hashB, 64);
		sph_fugue512_close(&ctx_fugue, hashA);
	} else {
		sph_sha512_init(&ctx_sha512);
		sph_sha512(&ctx_sha512, hashB, 64);
		sph_sha512_close(&ctx_sha512, hashA);
	}

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, hashA, 64);
	sph_groestl512_close(&ctx_groestl, hashB);

	sph_sha512_init(&ctx_sha512);
	sph_sha512(&ctx_sha512,hashB, 64);
	sph_sha512_close(&ctx_sha512,hashA);

	if (hashA[0] & mask) {
		sph_haval256_5_init(&ctx_haval);
		sph_haval256_5(&ctx_haval, hashA, 64);
		sph_haval256_5_close(&ctx_haval, hashB);
		memset(&hashB[8], 0, 32);
	} else {
		sph_whirlpool_init(&ctx_whirlpool);
		sph_whirlpool(&ctx_whirlpool, hashA, 64);
		sph_whirlpool_close(&ctx_whirlpool, hashB);
	}

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, hashB, 64);
	sph_bmw512_close(&ctx_bmw, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_hmq1725(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		hmq1725hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

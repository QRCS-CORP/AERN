#include "crypto.h"
#include "acp.h"
#include "cpuidex.h"
#include "intutils.h"
#include "memutils.h"
#include "netutils.h"
#include "scb.h"
#include "sysutils.h"

uint8_t* aern_crypto_secure_memory_allocate(size_t length)
{
	AERN_ASSERT(length != 0U);

	uint8_t* pblk;

	pblk = NULL;

	if (length != 0U)
	{
		pblk = qsc_memutils_secure_malloc(length);

		if (pblk != NULL)
		{
			qsc_memutils_secure_erase(pblk, length);
		}
	}

	return pblk;
}

void aern_crypto_secure_memory_deallocate(uint8_t* block, size_t length)
{
	AERN_ASSERT(block != NULL);
	AERN_ASSERT(length != 0U);

	if (block != NULL && length != 0U)
	{
		qsc_memutils_secure_erase(block, length);
		qsc_memutils_secure_free(block, length);
		block = NULL;
	}
}

void aern_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen)
{
	AERN_ASSERT(seed != NULL);
	AERN_ASSERT(seedlen != 0U);
	AERN_ASSERT(password != NULL);
	AERN_ASSERT(passlen != 0U);
	AERN_ASSERT(username != NULL);
	AERN_ASSERT(userlen != 0U);

	if (seed != NULL && seedlen != 0U && password != NULL && passlen != 0U && username != NULL && userlen != 0U)
	{
		uint8_t salt[QSC_SHA3_256_HASH_SIZE] = { 0 };
		uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
		qsc_scb_state scbx = { 0 };

		aern_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_cshake256_compute(phash, sizeof(phash), (const uint8_t*)password, passlen, NULL, 0U, (const uint8_t*)username, userlen);

		/* use cost based kdf to generate the stored comparison value */
		qsc_scb_initialize(&scbx, phash, sizeof(phash), salt, sizeof(salt), AERN_CRYPTO_PHASH_CPU_COST, AERN_CRYPTO_PHASH_MEMORY_COST);
		qsc_scb_generate(&scbx, seed, seedlen);
		qsc_scb_dispose(&scbx);
	}
}

bool aern_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(seed != NULL);
	AERN_ASSERT(input != NULL);
	AERN_ASSERT(length != 0U);

	bool res;

	res = false;

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		aern_cipher_state ctx = { 0 };

		const aern_cipher_keyparams kp = {
			.key = seed,
			.keylen = AERN_CRYPTO_SYMMETRIC_KEY_SIZE,
			.nonce = (uint8_t*)seed + AERN_CRYPTO_SYMMETRIC_KEY_SIZE,
			.info = NULL,
			.infolen = 0 };

		aern_cipher_initialize(&ctx, &kp, false);
		res = aern_cipher_transform(&ctx, output, input, length);
		aern_cipher_dispose(&ctx);
	}

	return res;
}

void aern_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(seed != NULL);
	AERN_ASSERT(input != NULL);
	AERN_ASSERT(length != 0U);

	aern_cipher_state ctx = { 0 };

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		const aern_cipher_keyparams kp = {
		.key = seed,
		.keylen = AERN_CRYPTO_SYMMETRIC_KEY_SIZE,
		.nonce = (uint8_t*)seed + AERN_CRYPTO_SYMMETRIC_KEY_SIZE,
		.info = NULL,
		.infolen = 0U };

		aern_cipher_initialize(&ctx, &kp, true);
		aern_cipher_transform(&ctx, output, input, length);
		aern_cipher_dispose(&ctx);
	}
}

void aern_crypto_generate_application_salt(uint8_t* output, size_t outlen)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(outlen != 0U);

	if (output != NULL && outlen != 0U)
	{
		uint8_t buff[QSC_SYSUTILS_SYSTEM_NAME_MAX + QSC_USERNAME_SYSTEM_NAME_MAX + QSC_NETUTILS_MAC_ADDRESS_SIZE] = { 0U };
		size_t pos;

		pos = qsc_sysutils_computer_name((char*)buff);
		pos += qsc_sysutils_user_name((char*)buff + pos);

		qsc_netutils_get_mac_address(buff + pos);
		pos += QSC_NETUTILS_MAC_ADDRESS_SIZE;

		qsc_shake256_compute(output, outlen, buff, pos);
	}
}

void aern_crypto_generate_hash_code(uint8_t* output, const uint8_t* message, size_t msglen)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);

	if (output != NULL && message != NULL && msglen != 0U)
	{
		qsc_sha3_compute256(output, message, msglen);
	}
}

void aern_crypto_generate_mac_code(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(outlen != 0U);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);
	AERN_ASSERT(key != NULL);
	AERN_ASSERT(keylen != 0U);

	if (output != NULL && outlen != 0U && message != NULL && msglen != 0 && key != NULL && keylen != 0U)
	{
		qsc_kmac256_compute(output, outlen, message, msglen, key, keylen, NULL, 0U);
	}
}

void aern_crypto_hash_password(uint8_t* output, size_t outlen, const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(outlen != 0U);
	AERN_ASSERT(username != NULL);
	AERN_ASSERT(userlen != 0U);
	AERN_ASSERT(password != NULL);
	AERN_ASSERT(passlen != 0U);

	if (output != NULL && outlen != 0U && username != NULL && userlen != 0U && password != NULL && passlen != 0U)
	{
		uint8_t salt[AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };

		aern_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_kmac256_compute(output, outlen, username, userlen, password, passlen, salt, sizeof(salt));
	}
}

bool aern_crypto_password_minimum_check(const char* password, size_t passlen)
{
	AERN_ASSERT(password != NULL);
	AERN_ASSERT(passlen != 0U);

	bool res;
	uint8_t hsp;
	uint8_t lsp;
	uint8_t nsp;

	res = false;
	hsp = 0;
	lsp = 0;
	nsp = 0;

	if (password != NULL && passlen != 0U)
	{
		if (passlen >= AERN_STORAGE_PASSWORD_MIN && passlen <= AERN_STORAGE_PASSWORD_MAX)
		{
			for (size_t i = 0U; i < passlen; ++i)
			{
				if (((uint8_t)password[i] >= 65 && (uint8_t)password[i] <= 90) ||
					((uint8_t)password[i] >= 97 && (uint8_t)password[i] <= 122))
				{
					++lsp;
				}

				if (((uint8_t)password[i] >= 33 && (uint8_t)password[i] <= 46) ||
					((uint8_t)password[i] >= 58 && (uint8_t)password[i] <= 64))
				{
					++hsp;
				}

				if ((uint8_t)password[i] >= 48 && (uint8_t)password[i] <= 57)
				{
					++nsp;
				}
			}

			if ((lsp > 0 && hsp > 0 && nsp > 0) && (lsp + hsp + nsp) >= 8)
			{
				res = true;
			}
		}
	}

	return res;
}

bool aern_crypto_password_verify(const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen, const uint8_t* hash, size_t hashlen)
{
	AERN_ASSERT(username != NULL);
	AERN_ASSERT(userlen != 0U);
	AERN_ASSERT(password != NULL);
	AERN_ASSERT(passlen != 0U);
	AERN_ASSERT(hash != NULL);
	AERN_ASSERT(hashlen != 0U);

	bool res;

	res = false;

	if (username != NULL && userlen != 0U && password != NULL && passlen != 0 && hash != NULL && hashlen != 0U)
	{
		uint8_t tmph[AERN_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		aern_crypto_hash_password(tmph, sizeof(tmph), (const uint8_t*)username, userlen, (const uint8_t*)password, passlen);
		res = qsc_memutils_are_equal(tmph, hash, hashlen);
	}

	return res;
}

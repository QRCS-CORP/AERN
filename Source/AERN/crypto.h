/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef AERN_CRYPTO_H
#define AERN_CRYPTO_H

#include "aerncommon.h"
#include "aern.h"

/**
 * \file crypto.h
 * \brief AERN Cryptographic Functions.
 *
 * \details
 * This header defines the cryptographic functions used by the Anonymous Encrypted Relay Network (AERN).
 * The crypto module encapsulates all operations required for secure data processing including:
 *
 * - Stream encryption and decryption using a symmetric cipher based on the RCS (Randomized Cipher Stream) algorithm.
 * - Generation of secure key chains by combining a user's password and username with a unique application salt.
 * - Generation of message hashes and message authentication codes (MACs) using SHA3-256 and KMAC256.
 * - Password handling including a minimum quality check, secure password hashing, and verification.
 * - Secure memory management functions to allocate and deallocate memory that is immediately cleared to protect sensitive data.
 *
 * Two configuration macros are provided to tune the passphrase hashing function:
 * - \ref AERN_CRYPTO_PHASH_CPU_COST sets the CPU cost in iterations.
 * - \ref AERN_CRYPTO_PHASH_MEMORY_COST sets the memory cost in megabytes.
 *
 * \note
 * These cryptographic operations build upon underlying primitives provided by the QSC library (e.g. SHA3, cSHAKE,
 * KMAC, and RCS). Correct operation of these functions is critical to the security of the AERN protocol.
 *
 * \test
 * The AERN crypto functions are rigorously tested to ensure that:
 *
 * - Data streams are properly encrypted and decrypted.
 * - The application key chain is securely generated from a user's password and username, using a salt derived from OS sources.
 * - Message hashes and MAC codes are computed accurately.
 * - Passwords are validated against a set minimum complexity and correctly verified against stored hashes.
 * - Secure memory is allocated and deallocated without leaving residual data.
 *
 * These tests help ensure that the cryptographic foundation of AERN is robust and reliable.
 */

/*! 
 * \def AERN_CRYPTO_PHASH_CPU_COST
 * \brief The passphrase hash CPU cost in iterations (acceptable range: 1-100000).
 */
#define AERN_CRYPTO_PHASH_CPU_COST 4U

/*! 
 * \def AERN_CRYPTO_PHASH_MEMORY_COST
 * \brief The passphrase hash memory cost in MB (acceptable range: 1-4096).
 */
#define AERN_CRYPTO_PHASH_MEMORY_COST 1U

/**
 * \brief Decrypt a stream of bytes.
 *
 * \param output [out] The output array receiving the plain-text.
 * \param seed [in, const] The secret seed array used as the decryption key (expected size: AERN_CRYPTO_SEED_SIZE).
 * \param input [in, const] The cipher-text input.
 * \param length The number of bytes to decrypt.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length);

/**
 * \brief Encrypt a stream of bytes.
 *
 * \param output [out] The output array receiving the cipher-text.
 * \param seed [in, const] The secret seed array used as the encryption key (expected size: AERN_CRYPTO_SEED_SIZE).
 * \param input [in, const] The plain-text input.
 * \param length The number of bytes to encrypt.
 */
AERN_EXPORT_API void aern_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length);

/**
 * \brief Generate a secure application key chain.
 *
 * Derives a secure key chain (seed) from the provided password and username combined with an
 * application salt generated from OS-specific sources.
 *
 * \param seed [out] The output secret seed array.
 * \param seedlen The length of the seed array.
 * \param password [in, const] The password.
 * \param passlen The byte length of the password.
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 */
AERN_EXPORT_API void aern_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen);

/**
 * \brief Generate a user-unique application salt from OS sources.
 *
 * The salt is generated by collecting system parameters such as the computer name, user name, and MAC address,
 * and then hashing these values using SHAKE256.
 *
 * \param output [out] The secret seed array to receive the salt.
 * \param outlen The length of the salt array.
 */
AERN_EXPORT_API void aern_crypto_generate_application_salt(uint8_t* output, size_t outlen);

/**
 * \brief Hash a message and write the resulting hash to an output array.
 *
 * Computes the SHA3-256 hash of the specified message.
 *
 * \param output [out] The output array receiving the hash.
 * \param message [in, const] A pointer to the message array.
 * \param msglen The length of the message.
 */
AERN_EXPORT_API void aern_crypto_generate_hash_code(uint8_t* output, const uint8_t* message, size_t msglen);

/**
 * \brief Compute a MAC (Message Authentication Code) for a message.
 *
 * Uses KMAC256 to compute a MAC from the provided message and key.
 *
 * \param output [out] The output array receiving the MAC.
 * \param outlen The byte length of the output array.
 * \param message [in, const] A pointer to the message array.
 * \param msglen The length of the message.
 * \param key [in, const] A pointer to the key array.
 * \param keylen The length of the key array.
 */
AERN_EXPORT_API void aern_crypto_generate_mac_code(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
 * \brief Hash a password and user name.
 *
 * Combines the username and password with an application salt to compute a secure hash via KMAC256.
 *
 * \param output [out] The output array receiving the hash.
 * \param outlen The length of the output array.
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 * \param password [in, const] The password.
 * \param passlen The length of the password.
 */
AERN_EXPORT_API void aern_crypto_hash_password(uint8_t* output, size_t outlen, const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen);

/**
 * \brief Check a password for a minimum secure threshold.
 *
 * Evaluates the password for minimum requirements (such as inclusion of uppercase, lowercase,
 * numeric, and special characters, and a minimum length).
 *
 * \param password [in, const] The password array.
 * \param passlen The byte length of the password.
 *
 * \return Returns true if the password meets the minimum requirements.
 */
AERN_EXPORT_API bool aern_crypto_password_minimum_check(const char* password, size_t passlen);

/**
 * \brief Verify a password against a stored hash.
 *
 * Computes the hash of the username and password and compares it with a stored hash.
 *
 * \param username [in, const] The computer's user name.
 * \param userlen The byte length of the user name.
 * \param password [in, const] The password.
 * \param passlen The byte length of the password.
 * \param hash The stored hash to compare.
 * \param hashlen The length of the stored hash.
 *
 * \return Returns true if the computed hash matches the stored value.
 */
AERN_EXPORT_API bool aern_crypto_password_verify(const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen, const uint8_t* hash, size_t hashlen);

/**
 * \brief Allocate a block of secure memory.
 *
 * Allocates memory using secure allocation routines to prevent sensitive data from being paged or left in memory.
 *
 * \param length The number of bytes to allocate.
 *
 * \return Returns a pointer to the allocated secure memory, or NULL on failure.
 */
AERN_EXPORT_API uint8_t* aern_crypto_secure_memory_allocate(size_t length);

/**
 * \brief Release an allocated block of secure memory.
 *
 * Securely erases the memory block and then frees it.
 *
 * \param block The pointer to the memory block.
 * \param length The length of the memory block.
 */
AERN_EXPORT_API void aern_crypto_secure_memory_deallocate(uint8_t* block, size_t length);

#endif

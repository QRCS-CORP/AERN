/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDAARS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef AERN_CERTIFICATE_H
#define AERN_CERTIFICATE_H

#include "aern.h"

/**
 * \file certificate.h
 * \brief AERN Certificate Handling Functions.
 *
 * \details
 * This header defines the functions for managing and processing certificates used by the
 * Anonymous Encrypted Relay Network (AERN). The certificate module is responsible for creating,
 * encoding, decoding, serializing, deserializing, signing, and verifying both child (device)
 * and root (trust anchor) certificates. These certificates carry critical information such as:
 *
 * - The issuer identity.
 * - Certificate validity periods.
 * - Public verification keys.
 * - Algorithm configuration identifiers.
 * - Digital signatures produced by the root certificate.
 *
 * The functions provided in this module allow conversion between protocol-set strings and their
 * enumerated representations, as well as conversion of network-designation values between string and
 * enumerated forms. They also perform cryptographic operations such as hashing and digital signing,
 * using the underlying QSC cryptographic primitives.
 *
 * \note
 * The certificate functions depend on the QSC library for routines including SHA3 (Keccak),
 * base64 encoding/decoding, file I/O, and memory utilities. The active AERN configuration (protocol-set)
 * is used to automatically populate certificate fields.
 *
 * \test
 * When the AERN_DEBUG_TESTS_RUN macro is defined, the function
 * \ref aern_certificate_functions_test() executes a series of self-tests that verify:
 *
 * - **Algorithm Conversion:** That protocol-set strings are correctly decoded into enumerated values
 *   (and vice versa) via aern_certificate_algorithm_decode() and aern_certificate_algorithm_encode().
 *
 * - **Child Certificate Operations:** The creation (aern_certificate_child_create()), signing
 *   (aern_certificate_root_sign()), encoding (aern_certificate_child_encode()),
 *   serialization/deserialization (aern_certificate_child_serialize()/aern_certificate_child_deserialize()),
 *   and validity testing (aern_certificate_child_is_valid()) of child certificates.
 *
 * - **Root Certificate Operations:** The creation (aern_certificate_root_create()), encoding
 *   (aern_certificate_root_encode()), serialization/deserialization (aern_certificate_root_serialize()/aern_certificate_root_deserialize()),
 *   and verification (aern_certificate_root_signature_verify()) of root certificates.
 *
 * - **Equality and Copy:** That child certificates can be compared (aern_certificate_child_are_equal())
 *   and copied (aern_certificate_child_copy()) correctly.
 *
 * - **Expiration and Signature Functions:** That certificate expiration is properly set and verified,
 *   and that messages can be hashed and signed/verified (aern_certificate_message_hash_sign() and
 *   aern_certificate_signature_verify_message()).
 *
 * These tests help ensure that the certificate operations function as expected in real-world use.
 */


/* Function Prototypes */

/**
 * \brief Decode the string algorithm-set number to the enumerated representation.
 *
 * \param name [in, const] The protocol-set string (for example, "dilithium-s1_kyber-s1_rcs-256_sha3-256").
 *
 * \return Returns the corresponding protocol-set enumerator.
 */
AERN_EXPORT_API aern_configuration_sets aern_certificate_algorithm_decode(const char* name);

/**
 * \brief Test if the specified protocol-set is enabled on this system.
 *
 * \param conf The protocol-set enumerator to test.
 *
 * \return Returns true if the given protocol-set is enabled; otherwise, false.
 */
AERN_EXPORT_API bool aern_certificate_algorithm_enabled(aern_configuration_sets conf);

/**
 * \brief Encode the protocol-set enumerator into its string form.
 *
 * \param name [out] The output buffer that will receive the protocol-set string.
 * \param conf The protocol-set enumerator to encode.
 */
AERN_EXPORT_API void aern_certificate_algorithm_encode(char* name, aern_configuration_sets conf);

/**
 * \brief Compare two child certificates for equivalence.
 *
 * This function compares all the significant fields of two child certificate structures
 * (including algorithm, version, designation, expiration, issuer, serial, signature, and public key).
 *
 * \param a [in, const] The first certificate.
 * \param b [in, const] The second certificate.
 *
 * \return Returns true if the two certificates are equal.
 */
AERN_EXPORT_API bool aern_certificate_child_are_equal(const aern_child_certificate* a, const aern_child_certificate* b);

/**
 * \brief Copy a child certificate structure.
 *
 * This function performs a deep copy of the child certificate from the \p input structure to the
 * \p output structure.
 *
 * \param output [out] The destination child certificate.
 * \param input [in, const] The source child certificate.
 */
AERN_EXPORT_API void aern_certificate_child_copy(aern_child_certificate* output, const aern_child_certificate* input);

/**
 * \brief Create a child certificate.
 *
 * This function initializes and populates a child certificate structure with the provided public key,
 * expiration information, issuer string, and designation.
 *
 * \param child [out] A pointer to the empty child certificate to populate.
 * \param pubkey [in] A pointer to the public signature key.
 * \param expiration [in, const] The certificate expiration time structure.
 * \param issuer [in, const] The certificate issuer string.
 * \param designation The certificate designation type (e.g. aps, client, etc.).
 */
AERN_EXPORT_API void aern_certificate_child_create(aern_child_certificate* child, const uint8_t* pubkey, const aern_certificate_expiration* expiration, const char* issuer, aern_network_designations designation);

/**
 * \brief Decode a child certificate string into a certificate structure.
 *
 * This function decodes an encoded child certificate string (with a fixed maximum size) into its
 * corresponding certificate structure.
 *
 * \param child [out] The pointer to the child certificate structure to populate.
 * \param enck [in] The encoded certificate string.
 *
 * \return Returns true if the certificate was successfully decoded.
 */
AERN_EXPORT_API bool aern_certificate_child_decode(aern_child_certificate* child, const char enck[AERN_CHILD_CERTIFICATE_STRING_SIZE]);

/**
 * \brief Deserialize a child certificate from a byte array.
 *
 * This function converts a serialized child certificate (stored as a byte stream) into a certificate structure.
 *
 * \param child [out] The pointer to the child certificate structure to populate.
 * \param input [in, const] The input byte array containing the serialized certificate.
 */
AERN_EXPORT_API void aern_certificate_child_deserialize(aern_child_certificate* child, const uint8_t* input);

/**
 * \brief Encode a public child certificate into a human-readable string.
 *
 * This function encodes the given child certificate into a formatted string representation.
 *
 * \param enck [out] The output buffer that will receive the encoded certificate string.
 * \param child [in, const] The child certificate to encode.
 *
 * \return Returns the size of the encoded certificate string.
 */
AERN_EXPORT_API size_t aern_certificate_child_encode(char enck[AERN_CHILD_CERTIFICATE_STRING_SIZE], const aern_child_certificate* child);

/**
 * \brief Delete (erase) a child certificate.
 *
 * This function securely erases all fields of a child certificate structure.
 *
 * \param child [in,out] A pointer to the child certificate to erase.
 */
AERN_EXPORT_API void aern_certificate_child_erase(aern_child_certificate* child);

/**
 * \brief Copy a serialized certificate from a file into a child certificate structure.
 *
 * This function reads a file containing a serialized child certificate, deserializes it, and populates
 * the provided certificate structure.
 *
 * \param fpath [in, const] The file path from which to load the certificate.
 * \param child [out] A pointer to the child certificate structure.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_certificate_child_file_to_struct(const char* fpath, aern_child_certificate* child);

/**
 * \brief Compute the cryptographic hash of a child certificate.
 *
 * The hash is computed over key fields such as algorithm, designation, version, expiration, issuer,
 * serial, and public verification key.
 *
 * \param output [out] The output hash array (size: AERN_CERTIFICATE_HASH_SIZE).
 * \param child [in, const] A pointer to the child certificate.
 */
AERN_EXPORT_API void aern_certificate_child_hash(uint8_t* output, const aern_child_certificate* child);

/**
 * \brief Test a child certificate for a valid format and expiration.
 *
 * This function checks that the certificate fields (including algorithm, designation, version,
 * signature, serial, and public key) are nonzero and that the current time is within the expiration period.
 *
 * \param child [in, const] A pointer to the child certificate.
 *
 * \return Returns true if the certificate is valid.
 */
AERN_EXPORT_API bool aern_certificate_child_is_valid(const aern_child_certificate* child);

/**
 * \brief Verify a message signature using a child certificate.
 *
 * This function uses the public verification key from the child certificate to verify that a given
 * signature correctly authenticates a message.
 *
 * \param message [out] The output buffer for the recovered message (if applicable).
 * \param msglen [in,out] A pointer to the length of the recovered message.
 * \param signature [in, const] A pointer to the signature.
 * \param siglen The length of the signature.
 * \param child [in, const] A pointer to the child certificate.
 *
 * \return Returns true if the message signature is verified.
 */
AERN_EXPORT_API bool aern_certificate_child_message_verify(uint8_t* message, size_t* msglen, const uint8_t* signature, size_t siglen, const aern_child_certificate* child);

/**
 * \brief Serialize a child certificate into a contiguous byte array.
 *
 * \param output [out] A pointer to the array receiving the serialized certificate (size: AERN_CERTIFICATE_CHILD_SIZE).
 * \param child [in, const] The child certificate to serialize.
 */
AERN_EXPORT_API void aern_certificate_child_serialize(uint8_t* output, const aern_child_certificate* child);

/**
 * \brief Verify that a signature hash matches a computed message hash using a child certificate.
 *
 * This function first verifies the signature using the child certificate's public key and then
 * compares the resulting hash to an independently computed hash of the message.
 *
 * \param signature [in, const] A pointer to the signed hash.
 * \param siglen The length of the signed hash.
 * \param message [in, const] A pointer to the message.
 * \param msglen The length of the message.
 * \param lcert [in, const] A pointer to the child certificate used for verification.
 *
 * \return Returns true if the signature hash verifies correctly.
 */
AERN_EXPORT_API bool aern_certificate_signature_hash_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const aern_child_certificate* lcert);

/**
 * \brief Write a child certificate structure to a file.
 *
 * \param fpath [in, const] The file path where the certificate will be stored.
 * \param child [in, const] A pointer to the child certificate structure.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_certificate_child_struct_to_file(const char* fpath, const aern_child_certificate* child);

/**
 * \brief Decode the network-designation string to its enumerated representation.
 *
 * \param sdsg [in, const] The network-designation string.
 *
 * \return Returns the corresponding network-designation enumerator.
 */
AERN_EXPORT_API aern_network_designations aern_certificate_designation_decode(const char* sdsg);

/**
 * \brief Encode the network-designation enumerator into a string.
 *
 * \param sdsg [out] The output buffer that will receive the encoded network-designation string.
 * \param designation The certificate designation type.
 *
 * \return Returns the size of the encoded string.
 */
AERN_EXPORT_API size_t aern_certificate_designation_encode(char* sdsg, aern_network_designations designation);

/**
 * \brief Set the expiration days on a certificate expiration structure.
 *
 * This function sets the \p from and \p to fields of the expiration structure using day intervals.
 *
 * \param expiration [in,out] A pointer to the expiration structure.
 * \param start The number of days until the certificate becomes valid.
 * \param duration The number of days the certificate remains valid.
 */
AERN_EXPORT_API void aern_certificate_expiration_set_days(aern_certificate_expiration* expiration, uint16_t start, uint16_t duration);

/**
 * \brief Set the expiration seconds on a certificate expiration structure.
 *
 * \param expiration [in,out] A pointer to the expiration structure.
 * \param start The number of seconds to delay before the certificate becomes valid.
 * \param period The number of seconds the certificate remains valid.
 */
AERN_EXPORT_API void aern_certificate_expiration_set_seconds(aern_certificate_expiration* expiration, uint64_t start, uint64_t period);

/**
 * \brief Verify the expiration time against the current UTC time.
 *
 * \param expiration [in, const] A pointer to the expiration time structure.
 *
 * \return Returns true if the current time is within the certificate's validity period.
 */
AERN_EXPORT_API bool aern_certificate_expiration_time_verify(const aern_certificate_expiration* expiration);

/**
 * \brief Hash a message and sign the hash.
 *
 * This function computes the SHA3-256 hash of the provided message and then signs that hash using
 * the given private signature key.
 *
 * \param signature [out] The array receiving the signature (size: AERN_ASYMMETRIC_SIGNATURE_SIZE).
 * \param sigkey [in, const] The private signature key.
 * \param message [in, const] The message to sign.
 * \param msglen The length of the message.
 *
 * \return Returns the size of the generated signature.
 */
AERN_EXPORT_API size_t aern_certificate_message_hash_sign(uint8_t* signature, const uint8_t* sigkey, const uint8_t* message, size_t msglen);

/**
 * \brief Compare two root certificates for equivalence.
 *
 * This function compares the key fields of two root certificates to determine if they are equal.
 *
 * \param a [in, const] The first root certificate.
 * \param b [in, const] The second root certificate.
 *
 * \return Returns true if the certificates are equivalent.
 */
AERN_EXPORT_API bool aern_certificate_root_compare(const aern_root_certificate* a, const aern_root_certificate* b);

/**
 * \brief Create a root certificate.
 *
 * This function creates a root certificate by populating its fields with the provided public key,
 * expiration structure, and issuer name. The generated certificate serves as the trust anchor.
 *
 * \param root [out] A pointer to the empty root certificate to populate.
 * \param pubkey [in] A pointer to the public signature key.
 * \param expiration [in, const] The certificate expiration time structure.
 * \param issuer [in, const] The issuer name string.
 */
AERN_EXPORT_API void aern_certificate_root_create(aern_root_certificate* root, const uint8_t* pubkey, const aern_certificate_expiration* expiration, const char* issuer);

/**
 * \brief Decode a root certificate string into a certificate structure.
 *
 * This function decodes an encoded root certificate string into its corresponding root certificate structure.
 *
 * \param root [out] The pointer to the root certificate structure to populate.
 * \param enck [in, const] The encoded certificate string.
 *
 * \return Returns true if the certificate was successfully decoded.
 */
AERN_EXPORT_API bool aern_certificate_root_decode(aern_root_certificate* root, const char* enck);

/**
 * \brief Deserialize a root certificate from a byte array.
 *
 * \param root [out] A pointer to the root certificate structure to populate.
 * \param input [in, const] A pointer to the input byte array (size: AERN_CERTIFICATE_ROOT_SIZE).
 */
AERN_EXPORT_API void aern_certificate_root_deserialize(aern_root_certificate* root, const uint8_t* input);

/**
 * \brief Encode a public root certificate into a human-readable string.
 *
 * This function encodes the given root certificate into a formatted string.
 *
 * \param enck [out] The output buffer that will receive the encoded certificate string.
 * \param root [in, const] The root certificate to encode.
 *
 * \return Returns the size of the encoded certificate string.
 */
AERN_EXPORT_API size_t aern_certificate_root_encode(char* enck, const aern_root_certificate* root);

/**
 * \brief Delete (erase) a root certificate.
 *
 * This function securely erases all fields of a root certificate structure.
 *
 * \param root [in,out] A pointer to the root certificate to erase.
 */
AERN_EXPORT_API void aern_certificate_root_erase(aern_root_certificate* root);

/**
 * \brief Copy a serialized root certificate from a file into a root certificate structure.
 *
 * \param fpath [in, const] The file path from which to read the certificate.
 * \param root [out] A pointer to the root certificate structure to populate.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_certificate_root_file_to_struct(const char* fpath, aern_root_certificate* root);

/**
 * \brief Compute the cryptographic hash of a root certificate.
 *
 * The hash is computed over key fields such as algorithm, version, expiration times,
 * issuer, serial, and public key.
 *
 * \param output [out] The output hash array.
 * \param root [in, const] A pointer to the root certificate.
 */
AERN_EXPORT_API void aern_certificate_root_hash(uint8_t* output, const aern_root_certificate* root);

/**
 * \brief Serialize a root certificate into a contiguous byte array.
 *
 * \param output [out] A pointer to the array receiving the serialized certificate (size: AERN_CERTIFICATE_ROOT_SIZE).
 * \param root [in, const] The root certificate to serialize.
 */
AERN_EXPORT_API void aern_certificate_root_serialize(uint8_t* output, const aern_root_certificate* root);

/**
 * \brief Sign a child certificate with the root certificate.
 *
 * This function hashes the child certificate, copies the root certificate serial number into the child,
 * and then produces a digital signature over the child certificate hash using the provided root signing key.
 *
 * \param child [in,out] A pointer to the child certificate to sign.
 * \param root [in, const] A pointer to the root certificate.
 * \param rsigkey [in, const] A pointer to the root private signing key.
 *
 * \return Returns the size of the generated signature.
 */
AERN_EXPORT_API size_t aern_certificate_root_sign(aern_child_certificate* child, const aern_root_certificate* root, const uint8_t* rsigkey);

/**
 * \brief Verify a child certificate against a root certificate.
 *
 * This function verifies that the digital signature on the child certificate (stored in its signed hash)
 * was produced by the given root certificate.
 *
 * \param child [in, const] A pointer to the child certificate.
 * \param root [in, const] A pointer to the root certificate.
 *
 * \return Returns true if the child certificate signature is valid.
 */
AERN_EXPORT_API bool aern_certificate_root_signature_verify(const aern_child_certificate* child, const aern_root_certificate* root);

/**
 * \brief Write a root certificate structure to a file.
 *
 * \param fpath [in, const] The file path where the certificate will be written.
 * \param root [in, const] A pointer to the root certificate structure.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_certificate_root_struct_to_file(const char* fpath, const aern_root_certificate* root);

/**
 * \brief Validate a root certificate.
 *
 * This function checks that the root certificate fields are nonzero and that the current time
 * is within its expiration period.
 *
 * \param root [in, const] A pointer to the root certificate.
 *
 * \return Returns true if the root certificate is valid.
 */
AERN_EXPORT_API bool aern_certificate_root_is_valid(const aern_root_certificate* root);

/**
 * \brief Generate and encode an asymmetric signature scheme keypair.
 *
 * This function generates a new keypair for the AERN asymmetric signature scheme and populates the
 * provided keypair container.
 *
 * \param keypair [out] A pointer to the keypair container.
 */
AERN_EXPORT_API void aern_certificate_signature_generate_keypair(aern_signature_keypair* keypair);

/**
 * \brief Sign a message using the asymmetric signature scheme.
 *
 * \param signature [out] The array that will receive the signature (size: AERN_ASYMMETRIC_SIGNATURE_SIZE).
 * \param message [in, const] The message to sign.
 * \param msglen The length of the message.
 * \param prikey [in] The private signature key.
 *
 * \return Returns the length of the generated signature.
 */
AERN_EXPORT_API size_t aern_certificate_signature_sign_message(uint8_t* signature, const uint8_t* message, size_t msglen, const uint8_t* prikey);

/**
 * \brief Verify a message signature using the asymmetric signature scheme.
 *
 * \param message [in, const] The original message.
 * \param msglen The length of the message.
 * \param signature [in, const] The signature to verify.
 * \param siglen The length of the signature.
 * \param pubkey [in] The public signature verification key.
 *
 * \return Returns true if the signature is verified.
 */
AERN_EXPORT_API bool aern_certificate_signature_verify_message(const uint8_t* message, size_t msglen, const uint8_t* signature, size_t siglen, const uint8_t* pubkey);

#if defined(AERN_DEBUG_TESTS_RUN)
/**
 * \brief Test the certificate functions.
 *
 * This function runs a suite of self-tests that verify:
 * - Correct conversion between protocol-set strings and enumerated configuration sets.
 * - Successful creation, signing, encoding, serialization, deserialization, and equality checking of both
 *   root and child certificates.
 * - Proper functioning of expiration, hashing, and signature verification routines.
 *
 * \return Returns true if all certificate function tests pass.
 */
AERN_EXPORT_API bool aern_certificate_functions_test(void);
#endif

#endif

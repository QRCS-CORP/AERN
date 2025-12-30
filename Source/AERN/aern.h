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


#ifndef AERN_AERN_H
#define AERN_AERN_H

#include "aerncommon.h"
#include "sha3.h"
#include "socketbase.h"

#if defined(AERN_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(AERN_CONFIG_SPHINCS_MCELIECE)
#	include "mceliece.h"
#	include "sphincsplus.h"
#else
#	error Invalid parameter set!
#endif

/**
 * \file aern.h
 * \brief AERN Common Definitions and Protocol Configuration.
 *
 * \details
 * This header defines the common constants, macros, enumerations, structures, and function prototypes
 * for the Anonymous Encrypted Relay Network (AERN). It provides configuration for the cryptographic parameter sets,
 * certificate handling, network protocol operations, and socket communication required to implement the AERN protocol.
 *
 * The AERN protocol leverages a combination of asymmetric cipher and signature schemes from the QSC library.
 * The parameter sets can be configured in the QSC library's common.h file. For maximum security, the McEliece/SPHINCS+
 * parameter set is recommended; for a balance of performance and security, the Dilithium/Kyber parameter set is advised.
 *
 * Key components defined in this header include:
 * - **Function Mapping Macros:** Aliases that map AERN high-level cryptographic operations (key generation,
 *   encapsulation/decapsulation, signing, and verification) to the corresponding functions in the QSC library,
 *   based on the selected configuration.
 * - **Modifiable Constants:** Preprocessor definitions that enable or disable protocol features (e.g., client-to-client
 *   encrypted tunneling, master fragment key cycling, IPv6 networking, and extended session security).
 * - **Parameter Macros:** Definitions for key sizes, certificate field sizes, network settings, and timing values that ensure
 *   consistency across the AERN protocol implementation.
 * - **Enumerations:** Enumerated types for AERN configuration sets, network designations, network and protocol error codes,
 *   and version sets.
 * - **Structures:** Data structures representing various certificates (ADC, APS, ROOT), connection and keep alive states,
 *   network packets, and cryptographic key pairs. These structures are central to protocol operations such as certificate
 *   management and secure message exchange.
 * - **Static Constants:** Predefined strings for certificate header/footer information and network designation labels.
 * - **Public API Functions:** Prototypes for functions handling connection management, packet encryption/decryption,
 *   packet serialization/deserialization, and error string conversion.
 *
 * \note
 * When using the McEliece/SPHINCS+ configuration in Visual Studio, it is recommended to increase the maximum stack size
 * (for example, to 200KB) to accommodate the larger key sizes.
 *
 * \test
 * Although this header does not directly implement test routines, it underpins multiple test modules that validate:
 * - The correct mapping of AERN high-level function calls to the underlying QSC library routines.
 * - The consistency and accuracy of defined constants (e.g., key sizes, certificate sizes, network parameters).
 * - The proper serialization/deserialization of packet headers and full packets (via aern_packet_header_serialize and
 *   aern_stream_to_packet).
 * - The correct conversion of error codes to descriptive strings (using aern_network_error_to_string and
 *   aern_protocol_error_to_string).
 *
 * These tests collectively ensure the robustness, consistency, and security of the AERN protocol configuration.
 */

/* --- Function Mapping Macros --- */

/*!
* \def AERN_USE_RCS_ENCRYPTION
* \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
* The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
*/
#define AERN_USE_RCS_ENCRYPTION

#if defined(AERN_USE_RCS_ENCRYPTION)
#	include "rcs.h"
#	define aern_cipher_state qsc_rcs_state
#	define aern_cipher_dispose qsc_rcs_dispose
#	define aern_cipher_initialize qsc_rcs_initialize
#	define aern_cipher_keyparams qsc_rcs_keyparams
#	define aern_cipher_set_associated qsc_rcs_set_associated
#	define aern_cipher_transform qsc_rcs_transform
#else
#	include "aes.h"
#	define aern_cipher_state qsc_aes_gcm256_state
#	define aern_cipher_dispose qsc_aes_gcm256_dispose
#	define aern_cipher_initialize qsc_aes_gcm256_initialize
#	define aern_cipher_keyparams qsc_aes_keyparams
#	define aern_cipher_set_associated qsc_aes_gcm256_set_associated
#	define aern_cipher_transform qsc_aes_gcm256_transform
#endif

/**
 * \brief AERN function mapping macros.
 *
 * These macros alias the high-level AERN cryptographic operations to the corresponding QSC library functions.
 * The mapping depends on the selected parameter set. For instance, if AERN_CONFIG_SPHINCS_MCELIECE is defined,
 * then the AERN cipher and signature functions map to the McEliece/SPHINCS+ routines. Alternatively, if
 * AERN_CONFIG_DILITHIUM_KYBER is defined, the corresponding Dilithium/Kyber routines are used.
 */
#if defined(AERN_CONFIG_SPHINCS_MCELIECE)
/*!
 * \def aern_cipher_generate_keypair
 * \brief Generate an asymmetric cipher key-pair
 */
#	define aern_cipher_generate_keypair qsc_mceliece_generate_keypair
/*!
 * \def aern_cipher_decapsulate
 * \brief Decapsulate a shared-secret with the asymmetric cipher
 */
#	define aern_cipher_decapsulate qsc_mceliece_decapsulate
/*!
 * \def aern_cipher_encapsulate
 * \brief Encapsulate a shared-secret with the asymmetric cipher
 */
#	define aern_cipher_encapsulate qsc_mceliece_encapsulate
/*!
 * \def aern_signature_generate_keypair
 * \brief Generate an asymmetric signature key-pair
 */
#	define aern_signature_generate_keypair qsc_sphincsplus_generate_keypair
/*!
 * \def aern_signature_sign
 * \brief Sign a message with the asymmetric signature scheme
 */
#	define aern_signature_sign qsc_sphincsplus_sign
/*!
 * \def aern_signature_verify
 * \brief Verify a message with the asymmetric signature scheme
 */
#	define aern_signature_verify qsc_sphincsplus_verify
#elif defined(AERN_CONFIG_DILITHIUM_KYBER)
/*!
 * \def aern_cipher_generate_keypair
 * \brief Generate an asymmetric cipher key-pair
 */
#	define aern_cipher_generate_keypair qsc_kyber_generate_keypair
/*!
 * \def aern_cipher_decapsulate
 * \brief Decapsulate a shared-secret with the asymmetric cipher
 */
#	define aern_cipher_decapsulate qsc_kyber_decapsulate
/*!
 * \def aern_cipher_encapsulate
 * \brief Encapsulate a shared-secret with the asymmetric cipher
 */
#	define aern_cipher_encapsulate qsc_kyber_encapsulate
/*!
 * \def aern_signature_generate_keypair
 * \brief Generate an asymmetric signature key-pair
 */
#	define aern_signature_generate_keypair qsc_dilithium_generate_keypair
/*!
 * \def aern_signature_sign
 * \brief Sign a message with the asymmetric signature scheme
 */
#	define aern_signature_sign qsc_dilithium_sign
/*!
 * \def aern_signature_verify
 * \brief Verify a message with the asymmetric signature scheme
 */
#	define aern_signature_verify qsc_dilithium_verify
#else
#	error Invalid parameter set!
#endif

/* ### Modifiable Constants: These constants can be enabled to turn on protocol features ### */

///*!
// * \def AERN_NETWORK_CLIENT_CONNECT
// * \brief Enable client to client encrypted tunnel.
// */
//#define AERN_NETWORK_CLIENT_CONNECT

///*!
// * \def AERN_NETWORK_MFK_HASH_CYCLED
// * \brief Enable mfk key cycling (default).
// */
//#define AERN_NETWORK_MFK_HASH_CYCLED

/*!
 * \def AERN_NETWORK_PROTOCOL_IPV6
 * \brief AERN is using the IPv6 networking stack.
 */
//#define AERN_NETWORK_PROTOCOL_IPV6

///*!
// * \def AERN_EXTENDED_SESSION_SECURITY
// * \brief Enable 512-bit security on session tunnels.
// */
//#define AERN_EXTENDED_SESSION_SECURITY

/* ### End of Modifiable Constants ### */


#if defined(AERN_CONFIG_DILITHIUM_KYBER)

/*!
 * \def AERN_ASYMMETRIC_CIPHERTEXT_SIZE
 * \brief The byte size of the asymmetric cipher-text array.
 */
#	define AERN_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
 * \def AERN_ASYMMETRIC_PRIVATE_KEY_SIZE
 * \brief The byte size of the asymmetric cipher private-key array.
 */
#	define AERN_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_PUBLIC_KEY_SIZE
 * \brief The byte size of the asymmetric cipher public-key array.
 */
#	define AERN_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_SIGNATURE_SIZE
 * \brief The byte size of the asymmetric signature array.
 */
#	define AERN_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
 * \def AERN_ASYMMETRIC_SIGNING_KEY_SIZE
 * \brief The byte size of the asymmetric signature signing-key array.
 */
#	define AERN_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE
 * \brief The byte size of the asymmetric signature verification-key array.
 */
#	define AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_KYBER_S1K2P512)
/*!
 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define AERN_CHILD_CERTIFICATE_STRING_SIZE 5612U
/*!
 * \def AERN_PARAMATERS_DILITHIUM_KYBER_D1K1
 * \brief The Dilithium D1K1 parameter set
 */
#		define AERN_PARAMATERS_DILITHIUM_KYBER_D1K1
/*!
 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define AERN_ROOT_CERTIFICATE_STRING_SIZE 2188U
/*!
 * \def AERN_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define AERN_SIGNATURE_ENCODING_SIZE 3312U
/*!
 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define AERN_VERIFICATION_KEY_ENCODING_SIZE 1752U
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_KYBER_S3K3P768)
/*!
 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define AERN_CHILD_CERTIFICATE_STRING_SIZE 7648U
/*!
 * \def AERN_PARAMATERS_DILITHIUM_KYBER_D3K3
 * \brief The Dilithium D1K1 parameter set
 */
#		define AERN_PARAMATERS_DILITHIUM_KYBER_D3K3
/*!
 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define AERN_ROOT_CERTIFICATE_STRING_SIZE 3053U
/*!
 * \def AERN_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define AERN_SIGNATURE_ENCODING_SIZE 4476U
/*!
 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define AERN_VERIFICATION_KEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S5K4P1024)
/*!
 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define AERN_CHILD_CERTIFICATE_STRING_SIZE 10311U
/*!
 * \def AERN_PARAMATERS_DILITHIUM_KYBER_D5K5
 * \brief The Dilithium D1K1 parameter set
 */
#		define AERN_PARAMATERS_DILITHIUM_KYBER_D5K5
/*!
 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define AERN_ROOT_CERTIFICATE_STRING_SIZE 3919U
/*!
 * \def AERN_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define AERN_SIGNATURE_ENCODING_SIZE 6212U
/*!
 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define AERN_VERIFICATION_KEY_ENCODING_SIZE 3456U
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S6K5P1280)
/*!
 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
 * \brief The encoded certificate string length
 */
#		define AERN_CHILD_CERTIFICATE_STRING_SIZE 10311U
/*!
 * \def AERN_PARAMATERS_DILITHIUM_KYBER_D5K6
 * \brief The Dilithium D1K1 parameter set
 */
#		define AERN_PARAMATERS_DILITHIUM_KYBER_D5K6
/*!
 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
 * \brief The root certificate encoded string size
 */
#		define AERN_ROOT_CERTIFICATE_STRING_SIZE 3919U
/*!
 * \def AERN_SIGNATURE_ENCODING_SIZE
 * \brief The encoded signature size
 */
#		define AERN_SIGNATURE_ENCODING_SIZE 6172U
/*!
 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
 * \brief The verification key size
 */
#		define AERN_VERIFICATION_KEY_ENCODING_SIZE 3456U
#	else
		/* The library signature scheme and asymmetric cipher parameter sets 
		must be synchronized to a common security level; s1, s3, s5, s5+ */
#		error the library parameter sets are mismatched!
#	endif

#elif defined(AERN_CONFIG_SPHINCS_MCELIECE)

/*!
 * \def AERN_ASYMMETRIC_CIPHERTEXT_SIZE
 * \brief The byte size of the cipher-text array.
 */
#	define AERN_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
 * \def AERN_ASYMMETRIC_PRIVATE_KEY_SIZE
 * \brief The byte size of the asymmetric cipher private-key array.
 */
#	define AERN_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_PUBLIC_KEY_SIZE
 * \brief The byte size of the asymmetric cipher public-key array.
 */
#	define AERN_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_SIGNATURE_SIZE
 * \brief The byte size of the asymmetric signature array.
 */
#	define AERN_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

/*!
 * \def AERN_ASYMMETRIC_SIGNING_KEY_SIZE
 * \brief The byte size of the asymmetric signature signing-key array.
 */
#	define AERN_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
 * \def AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE
 * \brief The byte size of the asymmetric signature verification-key array.
 */
#	define AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

#	if defined(QSC_MCELIECE_S1N3488T64)
#		if defined(QSC_SPHINCSPLUS_S1S128SHAKERF)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 23737U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SF1M1
			 * \brief The McEliece SF1M1 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSF_MCELIECE_SF1M1
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 455U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 22828U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 44U
#		elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 11237U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SS1M1
			 * \brief The McEliece SS1M1 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSS_MCELIECE_SS1M1
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 455U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 10520U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 44U
#		endif
#	elif defined(QSC_MCELIECE_S3N4608T96)
#		if defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 48912U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SF3M3
			 * \brief The McEliece SF3M3 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSF_MCELIECE_SF3M3
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 476U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 47596U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 64U
#		elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 22588U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SS3M3
			 * \brief The McEliece SS3M3 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSS_MCELIECE_SS3M3
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 476U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 21676U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 64U
#		endif
#	elif defined(QSC_MCELIECE_S5N6688T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 68158U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SF5M5
			 * \brief The McEliece SF5M5 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M5
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 40987U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SS5M5
			 * \brief The McEliece SS5M5 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSS_MCELIECE_SS5M5
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		endif
#	elif defined(QSC_MCELIECE_S6N6960T119)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 68157U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SF5M6
			 * \brief The McEliece SF5M6 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M6
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 40987U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SS5M6
			 * \brief The McEliece SS5M6 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSS_MCELIECE_SS5M6
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		endif
#	elif defined(QSC_MCELIECE_S7N8192T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 68157U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SF5M7
			 * \brief The McEliece SF5M7 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M7
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			 * \def AERN_CHILD_CERTIFICATE_STRING_SIZE
			 * \brief The encoded certificate string length
			 */
#			define AERN_CHILD_CERTIFICATE_STRING_SIZE 40987U
			/*!
			 * \def AERN_PARAMATERS_MCELIECE_SS5M7
			 * \brief The McEliece SS5M7 parameter set
			 */
#			define AERN_PARAMATERS_SPHINCSS_MCELIECE_SS5M7
			/*!
			 * \def AERN_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define AERN_ROOT_CERTIFICATE_STRING_SIZE 501U
			/*!
			 * \def AERN_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define AERN_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			 * \def AERN_VERIFICATION_KEY_ENCODING_SIZE
			 * \brief The verification key size
			 */
#			define AERN_VERIFICATION_KEY_ENCODING_SIZE 88U
#		else
#			error Invalid parameter sets, check the QSC library settings 
#		endif
#	else
	/* The library signature scheme and asymmetric cipher parameter sets 
	must be synchronized to a common security level; s1, s3, s5 or s6.
	Check the QSC library common.h file for cipher and signature security level alignment. */
#	error Invalid parameter sets, check the QSC library settings 
#	endif
#endif

/*!
 * \def AERN_ACTIVE_VERSION
 * \brief The AERN active version.
 */
#define AERN_ACTIVE_VERSION 1U

/*!
 * \def AERN_ACTIVE_VERSION_SIZE
 * \brief The AERN active version size.
 */
#define AERN_ACTIVE_VERSION_SIZE 2U

/*!
 * \def AERN_APS_FULL_TRUST
 * \brief The full trust designation number.
 */
#define AERN_APS_FULL_TRUST 1000001U

/*!
 * \def AERN_APS_MINIMUM_TRUST
 * \brief The minimum trust designation number.
 */
#define AERN_APS_MINIMUM_TRUST 1U

/*!
 * \def AERN_APS_NAME_MAX_SIZE
 * \brief The maximum aps name string length in characters.
 * The last character must be a string terminator.
 */
#define AERN_APS_NAME_MAX_SIZE 256U

/*!
 * \def AERN_APS_TWOWAY_TRUST
 * \brief The two-way trust designation number.
 */
#define AERN_APS_TWOWAY_TRUST 1000002U

/*!
 * \def AERN_APPLICATION_ADC_PORT
 * \brief The default ADC port number.
 */
#define AERN_APPLICATION_ADC_PORT 38762U

 /*!
  * \def AERN_APPLICATION_APS_PORT
  * \brief The default APS port number.
  */
#define AERN_APPLICATION_APS_PORT 38766U

/*!
 * \def AERN_APPLICATION_ARS_PORT
 * \brief The default ARS port number.
 */
#define AERN_APPLICATION_ARS_PORT 38764U

/*!
 * \def AERN_APPLICATION_CLIENT_PORT
 * \brief The default AERN Client port number.
 */
#define AERN_APPLICATION_CLIENT_PORT 37761U

/*!
 * \def AERN_APPLICATION_IDG_PORT
 * \brief The default AERN IDG port number.
 */
#define AERN_APPLICATION_IDG_PORT 38763U

/*!
 * \def AERN_CANONICAL_NAME_MINIMUM_SIZE
 * \brief The minimum canonical name size.
 */
#define AERN_CANONICAL_NAME_MINIMUM_SIZE 3U

/*!
 * \def AERN_CERTIFICATE_ADDRESS_SIZE
 * \brief The maximum IP address length.
 */
#define AERN_CERTIFICATE_ADDRESS_SIZE 22U

/*!
 * \def AERN_CERTIFICATE_ALGORITHM_SIZE
 * \brief The algorithm type.
 */
#define AERN_CERTIFICATE_ALGORITHM_SIZE 1U

/*!
 * \def AERN_CERTIFICATE_DEFAULT_PERIOD
 * \brief The default certificate validity period in milliseconds.
 */
#define AERN_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365U * 24U * 60U * 60U)

/*!
 * \def AERN_CERTIFICATE_DESIGNATION_SIZE
 * \brief The size of the child certificate designation field.
 */
#define AERN_CERTIFICATE_DESIGNATION_SIZE 1U

/*!
 * \def AERN_CERTIFICATE_EXPIRATION_SIZE
 * \brief The certificate expiration date length.
 */
#define AERN_CERTIFICATE_EXPIRATION_SIZE 16U

/*!
 * \def AERN_CERTIFICATE_HASH_SIZE
 * \brief The size of the certificate hash in bytes.
 */
#define AERN_CERTIFICATE_HASH_SIZE 32U

/*!
 * \def AERN_CERTIFICATE_ISSUER_SIZE
 * \brief The maximum certificate issuer string length.
 * The last character must be a string terminator.
 */
#define AERN_CERTIFICATE_ISSUER_SIZE 256U

/*!
 * \def AERN_CERTIFICATE_LINE_LENGTH
 * \brief The line length of the printed AERN certificate.
 */
#define AERN_CERTIFICATE_LINE_LENGTH 64U

/*!
 * \def AERN_CERTIFICATE_MAXIMUM_PERIOD
 * \brief The maximum certificate validity period in milliseconds.
 */
#define AERN_CERTIFICATE_MAXIMUM_PERIOD (AERN_CERTIFICATE_DEFAULT_PERIOD * 2U)

/*!
 * \def AERN_CERTIFICATE_MINIMUM_PERIOD
 * \brief The minimum certificate validity period in milliseconds.
 */
#define AERN_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1U * 24U * 60U * 60U)

/*!
 * \def AERN_CERTIFICATE_SERIAL_SIZE
 * \brief The certificate serial number field length.
 */
#define AERN_CERTIFICATE_SERIAL_SIZE 16U

/*!
 * \def AERN_CERTIFICATE_HINT_SIZE
 * \brief The topological hint.
 */
#define AERN_CERTIFICATE_HINT_SIZE (AERN_CERTIFICATE_HASH_SIZE + AERN_CERTIFICATE_SERIAL_SIZE)

/*!
 * \def AERN_CERTIFICATE_SIGNED_HASH_SIZE
 * \brief The size of the signature and hash field in a certificate.
 */
#define AERN_CERTIFICATE_SIGNED_HASH_SIZE (AERN_ASYMMETRIC_SIGNATURE_SIZE + AERN_CERTIFICATE_HASH_SIZE)

/*!
 * \def AERN_CERTIFICATE_VERSION_SIZE
 * \brief The version id.
 */
#define AERN_CERTIFICATE_VERSION_SIZE 1U

/*!
 * \def AERN_CERTIFICATE_CHILD_SIZE
 * \brief The length of a child certificate.
 */
#define AERN_CERTIFICATE_CHILD_SIZE (AERN_CERTIFICATE_SIGNED_HASH_SIZE + \
	AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	AERN_CERTIFICATE_ISSUER_SIZE + \
	AERN_CERTIFICATE_SERIAL_SIZE + \
	AERN_CERTIFICATE_SERIAL_SIZE + \
	AERN_CERTIFICATE_EXPIRATION_SIZE + \
	AERN_CERTIFICATE_DESIGNATION_SIZE + \
	AERN_CERTIFICATE_ALGORITHM_SIZE + \
	AERN_CERTIFICATE_VERSION_SIZE)

/*!
 * \def AERN_CERTIFICATE_IDG_SIZE
 * \brief The length of an IDG certificate.
 */
#define AERN_CERTIFICATE_IDG_SIZE (AERN_ASYMMETRIC_SIGNATURE_SIZE + \
	AERN_CERTIFICATE_HASH_SIZE + \
	AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	AERN_CERTIFICATE_ISSUER_SIZE + \
	AERN_CERTIFICATE_ADDRESS_SIZE + \
	AERN_CERTIFICATE_SERIAL_SIZE + \
	AERN_CERTIFICATE_SERIAL_SIZE + \
	AERN_CERTIFICATE_EXPIRATION_SIZE + \
	AERN_CERTIFICATE_DESIGNATION_SIZE + \
	AERN_CERTIFICATE_ALGORITHM_SIZE + \
	AERN_CERTIFICATE_VERSION_SIZE)

/*!
 * \def AERN_CERTIFICATE_ROOT_SIZE
 * \brief The length of the root certificate.
 */
#define AERN_CERTIFICATE_ROOT_SIZE (AERN_CERTIFICATE_HASH_SIZE + \
	AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	AERN_CERTIFICATE_ISSUER_SIZE + \
	AERN_CERTIFICATE_SERIAL_SIZE + \
	AERN_CERTIFICATE_EXPIRATION_SIZE + \
	AERN_CERTIFICATE_ALGORITHM_SIZE + \
	AERN_CERTIFICATE_VERSION_SIZE)

/*!
 * \def AERN_CRYPTO_SYMMETRIC_KEY_SIZE
 * \brief The byte length of the symmetric cipher key.
 */
#define AERN_CRYPTO_SYMMETRIC_KEY_SIZE 32U

/*!
 * \def AERN_CRYPTO_SYMMETRIC_NONCE_SIZE
 * \brief The byte length of the symmetric cipher nonce.
 */
#if defined(AERN_USE_RCS_ENCRYPTION)
#	define AERN_CRYPTO_SYMMETRIC_NONCE_SIZE 32U
#else
#	define AERN_CRYPTO_SYMMETRIC_NONCE_SIZE 16U
#endif

/*!
 * \def AERN_CRYPTO_SEED_SIZE
 * \brief The seed array byte size.
 */
#define AERN_CRYPTO_SEED_SIZE 64U

/*!
 * \def AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE
 * \brief The byte length of the symmetric token.
 */
#define AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE 32U

/*!
 * \def AERN_CRYPTO_SYMMETRIC_HASH_SIZE
 * \brief The hash function output byte size.
 */
#define AERN_CRYPTO_SYMMETRIC_HASH_SIZE 32U

/*!
 * \def AERN_CRYPTO_SYMMETRIC_MAC_SIZE
 * \brief The MAC function output byte size.
 */
#if defined(AERN_USE_RCS_ENCRYPTION)
#	if defined(AERN_EXTENDED_SESSION_SECURITY)
#		define AERN_CRYPTO_SYMMETRIC_MAC_SIZE 64U
#	else
#		define AERN_CRYPTO_SYMMETRIC_MAC_SIZE 32U
#	endif
#else
#	define AERN_CRYPTO_SYMMETRIC_MAC_SIZE 16U
#endif

/*!
 * \def AERN_CRYPTO_SYMMETRIC_SECRET_SIZE
 * \brief The shared secret byte size.
 */
#define AERN_CRYPTO_SYMMETRIC_SECRET_SIZE 32U

/*!
 * \def AERN_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE
 * \brief The session key security size.
 */
#if defined(AERN_EXTENDED_SESSION_SECURITY)
#	define AERN_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE 64U
#else
#	define AERN_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE 32U
#endif

/*!
 * \def AERN_ADC_CONVERGENCE_INTERVAL
 * \brief The interval between aps convergence checks (default is 24 hours).
 */
#define AERN_ADC_CONVERGENCE_INTERVAL (60U * 60U * 24U)

/*!
 * \def AERN_ADC_IP_MAX
 * \brief The maximum ip address length.
 */
#define AERN_ADC_IP_MAX 0x41U

/*!
 * \def AERN_ADC_PENALTY_MAX
 * \brief The maximum unreachable penalty before the ADC is deemed unreliable.
 */
#define AERN_ADC_PENALTY_MAX 0x100U

/*!
 * \def AERN_ADC_REDUCTION_INTERVAL
 * \brief The time before a penalty is reduced for a flapping ADC in milliseconds.
 */
#define AERN_ADC_REDUCTION_INTERVAL 1000000UL

/*!
 * \def AERN_ADC_UPDATE_WAIT_TIME
 * \brief The interval in milliseconds between topology full updates.
 *
 * Note: Default is 7 days.
 */
#define AERN_ADC_UPDATE_WAIT_TIME (7U * 24U * 60U * 60U)

/*!
 * \def AERN_ERROR_STRING_DEPTH
 * \brief The number of error strings.
 */
#define AERN_ERROR_STRING_DEPTH 26U

/*!
 * \def AERN_ERROR_STRING_WIDTH
 * \brief The maximum size in characters of an error string.
 */
#define AERN_ERROR_STRING_WIDTH 128U

/*!
 * \def AERN_MESSAGE_MAX_SIZE
 * \brief The maximum message size (max signature + max certificate sizes).
 */
#define AERN_MESSAGE_MAX_SIZE 1400000UL

/*!
 * \def AERN_MFK_EXPIRATION_PERIOD
 * \brief The MFK validity period in milliseconds.
 */
#define AERN_MFK_EXPIRATION_PERIOD ((uint64_t)60U * 24U * 60U * 60U)

/*!
 * \def AERN_MINIMUM_PATH_LENGTH
 * \brief The minimum file path length.
 */
#define AERN_MINIMUM_PATH_LENGTH 9U

/*!
 * \def AERN_NETWORK_CONNECTION_MTU
 * \brief The AERN packet buffer size.
 */
#define AERN_NETWORK_CONNECTION_MTU 1500U

/*!
 * \def AERN_NETWORK_DOMAIN_NAME_MAX_SIZE
 * \brief The maximum domain name length in characters.
 * The last character must be a string terminator.
 */
#define AERN_NETWORK_DOMAIN_NAME_MAX_SIZE 256U

/*!
 * \def AERN_NETWORK_MAX_APSS
 * \brief The maximum number of aps connections in a network.
 */
#define AERN_NETWORK_MAX_APSS 1000000UL

/*!
 * \def AERN_NETWORK_NODE_ID_SIZE
 * \brief The node identification string length.
 */
#define AERN_NETWORK_NODE_ID_SIZE 16

/*!
 * \def AERN_PERIOD_DAY_TO_SECONDS
 * \brief A period of one day in seconds.
 */
#define AERN_PERIOD_DAY_TO_SECONDS (24U * 60U * 60U)

/*!
 * \def AERN_SOCKET_TERMINATOR_SIZE
 * \brief The packet delimiter byte size.
 */
#define AERN_SOCKET_TERMINATOR_SIZE 1U

/*!
 * \def AERN_PACKET_ERROR_SIZE
 * \brief The packet error message byte size.
 */
#define AERN_PACKET_ERROR_SIZE 1U

/*!
 * \def AERN_PACKET_HEADER_SIZE
 * \brief The AERN packet header size.
 */
#define AERN_PACKET_HEADER_SIZE 22U

/*!
 * \def AERN_PACKET_SUBHEADER_SIZE
 * \brief The AERN packet sub-header size.
 */
#define AERN_PACKET_SUBHEADER_SIZE 16U

/*!
 * \def AERN_PACKET_SEQUENCE_TERMINATOR
 * \brief The sequence number of a packet that closes a connection.
 */
#define AERN_PACKET_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \def AERN_PACKET_TIME_SIZE
 * \brief The byte size of the serialized packet time parameter.
 */
#define AERN_PACKET_TIME_SIZE 8U

/*!
 * \def AERN_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is valid.
 */
#define AERN_PACKET_TIME_THRESHOLD 60U

/*!
 * \def AERN_NETWORK_TERMINATION_MESSAGE_SIZE
 * \brief The network termination message size.
 */
#define AERN_NETWORK_TERMINATION_MESSAGE_SIZE 1U

/*!
 * \def AERN_NETWORK_TERMINATION_PACKET_SIZE
 * \brief The network termination packet size.
 */
#define AERN_NETWORK_TERMINATION_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + AERN_NETWORK_TERMINATION_MESSAGE_SIZE)

/* enumerations */

/*!
 * \enum aern_configuration_sets
 * \brief The AERN algorithm configuration sets.
 */
AERN_EXPORT_API typedef enum aern_configuration_sets
{
	aern_configuration_set_none = 0x00U,										/*!< No algorithm identifier is set */
	aern_configuration_set_dilithium1_kyber1_rcs256_shake256 = 0x01U,			/*!< The Dilithium-S1/Kyber-S1/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_dilithium3_kyber3_rcs256_shake256 = 0x02U,			/*!< The Dilithium-S3/Kyber-S3/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_dilithium5_kyber5_rcs256_shake256 = 0x03U,			/*!< The Dilithium-S5/Kyber-S5/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_dilithium5_kyber6_rcs512_shake256 = 0x04U,			/*!< The Dilithium-S5/Kyber-S6/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256 = 0x05U,		/*!< The SPHINCS+-S1F/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256 = 0x06U,		/*!< The SPHINCS+-S1S/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256 = 0x07U,		/*!< The SPHINCS+-S3F/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256 = 0x08U,		/*!< The SPHINCS+-S3S/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256 = 0x09U,		/*!< The SPHINCS+-S5F/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256 = 0x0AU,		/*!< The SPHINCS+-S5S/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256 = 0x0BU,		/*!< The SPHINCS+-S5F/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256 = 0x0CU,		/*!< The SPHINCS+-S5S/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256 = 0x0DU,		/*!< The SPHINCS+-S5F/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
	aern_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256 = 0x0EU,		/*!< The SPHINCS+-S5S/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
} aern_configuration_sets;

/*!
 * \enum aern_network_designations
 * \brief The AERN device designation.
 */
AERN_EXPORT_API typedef enum aern_network_designations
{
	aern_network_designation_none = 0x00U,							/*!< No designation was selected */
	aern_network_designation_aps = 0x01U,							/*!< The device is an APS */
	aern_network_designation_client = 0x02U,						/*!< The device is a client */
	aern_network_designation_ads = 0x03U,							/*!< The device is the ADC */
	aern_network_designation_remote = 0x04U,						/*!< The device is a remote aps */
	aern_network_designation_ars = 0x05U,							/*!< The device is an ARS security server */
	aern_network_designation_revoked = 0x06U,						/*!< The device has been revoked */
	aern_network_designation_idg = 0x07U,							/*!< The device is the IDG */
	aern_network_designation_all = 0xFFU,							/*!< Every server and client device on the network */
} aern_network_designations;

/*!
 * \enum aern_network_errors
 * \brief The AERN network error values.
 */
AERN_EXPORT_API typedef enum aern_network_errors
{
	aern_network_error_none = 0x00U,								/*!< No error was detected */
	aern_network_error_accept_fail = 0x01U,							/*!< The socket accept function returned an error */
	aern_network_error_auth_failure = 0x02U,						/*!< The cipher authentication has failed */
	aern_network_error_bad_keep_alive = 0x03U,						/*!< The keep alive check failed */
	aern_network_error_channel_down = 0x04U,						/*!< The communications channel has failed */
	aern_network_error_connection_failure = 0x05U,					/*!< The device could not make a connection to the remote host */
	aern_network_error_decryption_failure = 0x06U,					/*!< The decryption authentication has failed */
	aern_network_error_establish_failure = 0x07U,					/*!< The transmission failed at the kex establish phase */
	aern_network_error_general_failure = 0x08U,						/*!< The connection experienced an unexpected error */
	aern_network_error_hosts_exceeded = 0x09U,						/*!< The server has run out of socket connections */
	aern_network_error_identity_unknown = 0x10U,					/*!< The random generator experienced a failure */
	aern_network_error_invalid_input = 0x1AU,						/*!< The input is invalid */
	aern_network_error_invalid_request = 0x1BU,						/*!< The request is invalid */
	aern_network_error_keep_alive_expired = 0x1CU,					/*!< The keep alive has expired with no response */
	aern_network_error_keep_alive_timeout = 0x1DU,					/*!< The keepalive failure counter has exceeded maximum  */
	aern_network_error_kex_auth_failure = 0x1EU,					/*!< The kex authentication has failed */
	aern_network_error_key_not_recognized = 0x1FU,					/*!< The key-id is not recognized */
	aern_network_error_key_has_expired = 0x20U,						/*!< The certificate has expired */
	aern_network_error_listener_fail = 0x21U,						/*!< The listener function failed to initialize */
	aern_network_error_memory_allocation = 0x22U,					/*!< The server has run out of memory */
	aern_network_error_packet_unsequenced = 0x23U,					/*!< The random generator experienced a failure */
	aern_network_error_random_failure = 0x24U,						/*!< The random generator experienced a failure */
	aern_network_error_ratchet_fail = 0x25U,						/*!< The ratchet operation has failed */
	aern_network_error_receive_failure = 0x26U,						/*!< The receiver failed at the network layer */
	aern_network_error_transmit_failure = 0x27U,					/*!< The transmitter failed at the network layer */
	aern_network_error_unknown_protocol = 0x28U,					/*!< The protocol version is unknown */
	aern_network_error_unsequenced = 0x29U,							/*!< The packet was received out of sequence */
	aern_network_error_verify_failure = 0x2AU,						/*!< The expected data could not be verified */
} aern_network_errors;

/*!
 * \enum aern_network_flags
 * \brief The AERN network flags.
 */
AERN_EXPORT_API typedef enum aern_network_flags
{
	aern_network_flag_none = 0x00U,									/*!< No flag was selected */
	aern_network_flag_connection_terminate_request = 0x01U,			/*!< The packet contains a connection termination message  */
	aern_network_flag_error_condition = 0x02U,						/*!< The connection experienced an error message*/
	aern_network_flag_fragment_collection_request = 0x03U,			/*!< The packet contains a server fragment collection request message */
	aern_network_flag_fragment_collection_response = 0x04U,			/*!< The packet contains an aps fragment collection response message */
	aern_network_flag_fragment_request = 0x05U,						/*!< The packet contains a server fragment key request message */
	aern_network_flag_fragment_response = 0x06U,					/*!< The packet contains an aps fragment key response message */
	aern_network_flag_fragment_query_request = 0x07U,				/*!< The packet contains a server fragment key request message */
	aern_network_flag_fragment_query_response = 0x08U,				/*!< The packet contains an aps fragment key response message */
	aern_network_flag_incremental_update_request = 0x09U,			/*!< The packet contains an incremental update request message */
	aern_network_flag_incremental_update_response = 0x0AU,			/*!< The packet contains an incremental update response message */
	aern_network_flag_register_request = 0x0BU,						/*!< The packet contains a join request message */
	aern_network_flag_register_response = 0x0CU,					/*!< The packet contains a join response message */
	aern_network_flag_register_update_request = 0x0DU,				/*!< The packet contains a join update request message */
	aern_network_flag_register_update_response = 0x0EU,				/*!< The packet contains a join update response message */
	aern_network_flag_keep_alive_request = 0x0FU,					/*!< The packet contains a keep alive request */
	aern_network_flag_keep_alive_response = 0x10U,					/*!< The packet contains a keep alive response */
	aern_network_flag_mfk_establish = 0x11U,						/*!< The packet contains a server master fragment key establish message */
	aern_network_flag_mfk_request = 0x12U,							/*!< The packet contains a server master fragment key request message */
	aern_network_flag_mfk_response = 0x13U,							/*!< The packet contains a client mfk exchange response message */
	aern_network_flag_mfk_verify = 0x14U,							/*!< The packet contains a server master fragment key verify message */
	aern_network_flag_network_announce_broadcast = 0x15U,			/*!< The packet contains a topology announce broadcast */
	aern_network_flag_network_converge_request = 0x16U,				/*!< The packet contains a network converge request message */
	aern_network_flag_network_converge_response = 0x17U,			/*!< The packet contains a network converge response message */
	aern_network_flag_network_converge_update = 0x18U,				/*!< The packet contains a network converge update message */
	aern_network_flag_network_resign_request = 0x19U,				/*!< The packet contains a network resignation request message */
	aern_network_flag_network_resign_response = 0x1AU,				/*!< The packet contains a network resignation response message */
	aern_network_flag_network_revocation_broadcast = 0x1BU,			/*!< The packet contains a certificate revocation broadcast */
	aern_network_flag_network_signature_request = 0x1CU,			/*!< The packet contains a certificate signing request */
	aern_network_flag_system_error_condition = 0x1DU,				/*!< The packet contains an error condition message */
	aern_network_flag_tunnel_connection_terminate = 0x1EU,			/*!< The packet contains a socket close message */
	aern_network_flag_tunnel_encrypted_message = 0x1FU,				/*!< The packet contains an encrypted message */
	aern_network_flag_tunnel_session_established = 0x20U,			/*!< The exchange is in the established state */
	aern_network_flag_tunnel_transfer_request = 0x21U,				/*!< Reserved - The host has received a transfer request */
	aern_network_flag_topology_query_request = 0x22U,				/*!< The packet contains a topology query request message */
	aern_network_flag_topology_query_response = 0x23U,				/*!< The packet contains a topology query response message */
	aern_network_flag_topology_status_request = 0x24U,				/*!< The packet contains a topology status request message */
	aern_network_flag_topology_status_response = 0x25U,				/*!< The packet contains a topology status response message */
	aern_network_flag_topology_status_available = 0x26U,			/*!< The packet contains a topology status available message */
	aern_network_flag_topology_status_synchronized = 0x27U,			/*!< The packet contains a topology status synchronized message */
	aern_network_flag_topology_status_unavailable = 0x28U,			/*!< The packet contains a topology status unavailable message */
	aern_network_flag_network_remote_signing_request = 0x29U,		/*!< The packet contains a remote signing request message */
	aern_network_flag_network_remote_signing_response = 0x2AU,		/*!< The packet contains a remote signing response message */
} aern_network_flags;

/*!
 * \enum aern_protocol_errors
 * \brief The AERN protocol error values.
 */
AERN_EXPORT_API typedef enum aern_protocol_errors
{
	aern_protocol_error_none = 0x00U,								/*!< No error was detected */
	aern_protocol_error_authentication_failure = 0x01U,				/*!< The symmetric cipher had an authentication failure */
	aern_protocol_error_certificate_not_found = 0x02U,				/*!< The node certificate could not be found */
	aern_protocol_error_channel_down = 0x03U,						/*!< The communications channel has failed */
	aern_protocol_error_connection_failure = 0x04U,					/*!< The device could not make a connection to the remote host */
	aern_protocol_error_connect_failure = 0x05U,					/*!< The transmission failed at the KEX connection phase */
	aern_protocol_error_convergence_failure = 0x06U,				/*!< The convergence call has returned an error */
	aern_protocol_error_convergence_synchronized = 0x07U,			/*!< The database is already synchronized */
	aern_protocol_error_decapsulation_failure = 0x08U,				/*!< The asymmetric cipher failed to decapsulate the shared secret */
	aern_protocol_error_decoding_failure = 0x09U,					/*!< The node or certificate decoding failed */
	aern_protocol_error_decryption_failure = 0x0AU,					/*!< The decryption authentication has failed */
	aern_protocol_error_establish_failure = 0x0BU,					/*!< The transmission failed at the KEX establish phase */
	aern_protocol_error_exchange_failure = 0x0CU,					/*!< The transmission failed at the KEX exchange phase */
	aern_protocol_error_file_not_deleted = 0x0DU,					/*!< The application could not delete a local file */
	aern_protocol_error_file_not_found = 0x0EU,						/*!< The file could not be found */
	aern_protocol_error_file_not_written = 0x0FU,					/*!< The file could not be written to storage */
	aern_protocol_error_hash_invalid = 0x10U,						/*!< The public-key hash is invalid */
	aern_protocol_error_hosts_exceeded = 0x11U,						/*!< The server has run out of socket connections */
	aern_protocol_error_invalid_request = 0x12U,					/*!< The packet flag was unexpected */
	aern_protocol_error_certificate_expired = 0x13U,				/*!< The certificate has expired */
	aern_protocol_error_key_expired = 0x14U,						/*!< The AERN public key has expired  */
	aern_protocol_error_key_unrecognized = 0x15U,					/*!< The key identity is unrecognized */
	aern_protocol_error_listener_fail = 0x16U,						/*!< The listener function failed to initialize */
	aern_protocol_error_memory_allocation = 0x17U,					/*!< The server has run out of memory */
	aern_protocol_error_message_time_invalid = 0x18U,				/*!< The network time is invalid or has substantial delay */
	aern_protocol_error_message_verification_failure = 0x19U,		/*!< The expected data could not be verified */
	aern_protocol_error_no_usable_address = 0x1AU,					/*!< The server has no usable IP address, assign in configuration */
	aern_protocol_error_node_not_available = 0x1BU,					/*!< The node is not available for a session */
	aern_protocol_error_node_not_found = 0x1CU,						/*!< The node could not be found in the database */
	aern_protocol_error_node_was_registered = 0x1DU,				/*!< The node was previously registered in the database */
	aern_protocol_error_operation_cancelled = 0x1EU,				/*!< The operation was cancelled by the user */
	aern_protocol_error_packet_header_invalid = 0x1FU,				/*!< The packet header received was invalid */
	aern_protocol_error_packet_unsequenced = 0x20U,					/*!< The packet was received out of sequence */
	aern_protocol_error_receive_failure = 0x21U,					/*!< The receiver failed at the network layer */
	aern_protocol_error_root_signature_invalid = 0x22U,				/*!< The root signature failed authentication */
	aern_protocol_error_serialization_failure = 0x23U,				/*!< The certificate could not be serialized */
	aern_protocol_error_signature_failure = 0x24U,					/*!< The signature scheme could not sign a message */
	aern_protocol_error_signing_failure = 0x25U,					/*!< The transmission failed to sign the data */
	aern_protocol_error_socket_binding = 0x26U,						/*!< The socket could not be bound to an IP address */
	aern_protocol_error_socket_creation = 0x27U,					/*!< The socket could not be created */
	aern_protocol_error_transmit_failure = 0x28U,					/*!< The transmitter failed at the network layer */
	aern_protocol_error_topology_no_aps = 0x29U,					/*!< The topological database has no aps entries */
	aern_protocol_error_unknown_protocol = 0x2AU,					/*!< The protocol string was not recognized */
	aern_protocol_error_verification_failure = 0x2BU,				/*!< The transmission failed at the KEX verify phase */
} aern_protocol_errors;

/*!
 * \enum aern_version_sets
 * \brief The AERN version sets.
 */
AERN_EXPORT_API typedef enum aern_version_sets
{
	aern_version_set_none = 0x00U,									/*!< No version identifier is set */
	aern_version_set_one_zero = 0x01U,								/*!< The 1.0 version identifier */
} aern_version_sets;

/* public structures */

/*!
 * \struct aern_certificate_expiration
 * \brief The certificate expiration time structure.
 */
AERN_EXPORT_API typedef struct aern_certificate_expiration
{
	uint64_t from;													/*!< The starting time in seconds */
	uint64_t to;													/*!< The expiration time in seconds */
} aern_certificate_expiration;

/*!
 * \struct aern_child_certificate
 * \brief The child certificate structure.
 */
AERN_EXPORT_API typedef struct aern_child_certificate
{
	uint8_t csig[AERN_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t verkey[AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	char issuer[AERN_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	aern_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	aern_network_designations designation;							/*!< The certificate type designation */
	aern_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
} aern_child_certificate;

/*!
 * \def AERN_X509_CERTIFICATE_SIZE
 * \brief x509 implementation where algorithm/signature output size is stored.
 */
#define AERN_X509_CERTIFICATE_SIZE 4096U

/*!
 * \def AERN_IDG_HINT_SIZE
 * \brief Hint query; certificate hash, root serial number hi=(H(cert) | rsn)
 * idg query asks if a peer knows of the root security server for a domain;
 * if the peer does know the root of the other domain, it sends back information
 * about that rds (address, certificate hash, root serial number, and trust metric).
 */
#define AERN_IDG_HINT_SIZE (AERN_CERTIFICATE_HASH_SIZE + AERN_CERTIFICATE_SERIAL_SIZE)

/*!
 * \struct aern_idg_hint
 * \brief The IDG hint structure.
 */
AERN_EXPORT_API typedef struct aern_idg_hint
{
	uint8_t chash[AERN_CERTIFICATE_HASH_SIZE];						/*!< The remote certificate's signed hash */
	uint8_t rootser[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The remote certificate's root serial number */
} aern_idg_hint;

/*!
 * \struct aern_idg_certificate
 * \brief The IDG certificate structure.
 *
 * The IDG certificate structure contains the necessary fields for identification and verification
 * of an inter-domain gateway. (Note: A field for a serialized x509 certificate may be added in future revisions.)
 */
AERN_EXPORT_API typedef struct aern_idg_certificate
{
	uint8_t csig[AERN_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t vkey[AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	uint8_t xcert[AERN_X509_CERTIFICATE_SIZE];						/*!< The serialized X509 certificate */
	uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	uint8_t hint[AERN_CERTIFICATE_HINT_SIZE];						/*!< The certificate's topological hint  */
	char issuer[AERN_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	aern_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	aern_network_designations designation;							/*!< The certificate type designation */
	aern_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
} aern_idg_certificate;

/*!
 * \struct aern_connection_state
 * \brief The AERN socket connection state structure.
 */
AERN_EXPORT_API typedef struct aern_connection_state
{
	qsc_socket target;												/*!< The target socket structure */
	aern_cipher_state rxcpr;											/*!< The receive channel cipher state */
	aern_cipher_state txcpr;											/*!< The transmit channel cipher state */
	uint64_t rxseq;													/*!< The receive channel's packet sequence number */
	uint64_t txseq;													/*!< The transmit channel's packet sequence number */
	uint32_t instance;												/*!< The connection's instance count */
	aern_network_flags exflag;										/*!< The network stage flag */
} aern_connection_state;

/*!
 * \struct aern_keep_alive_state
 * \brief The AERN keep alive state structure.
 */
AERN_EXPORT_API typedef struct aern_keep_alive_state
{
	qsc_socket target;												/*!< The target socket structure */
	uint64_t etime;													/*!< The keep alive epoch time  */
	uint64_t seqctr;												/*!< The keep alive packet sequence counter  */
	bool recd;														/*!< The keep alive response received status  */
} aern_keep_alive_state;

/*!
 * \struct aern_mfkey_state
 * \brief The AERN master fragment key structure.
 */
typedef struct aern_mfkey_state
{
	uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The mfk serial number  */
	uint8_t mfk[AERN_CRYPTO_SYMMETRIC_KEY_SIZE];					/*!< The master fragment key */
} aern_mfkey_state;

/*!
 * \struct aern_network_packet
 * \brief The AERN packet structure.
 */
AERN_EXPORT_API typedef struct aern_network_packet
{
	uint8_t flag;													/*!< The packet flag */
	uint32_t msglen;												/*!< The packet's message length */
	uint64_t sequence;												/*!< The packet sequence number */
	uint64_t utctime;												/*!< The UTC time the packet was created (in seconds) */
	uint8_t* pmessage;												/*!< A pointer to the packet's message buffer */
} aern_network_packet;

/*!
 * \struct aern_root_certificate
 * \brief The root certificate structure.
 *
 * The root certificate structure contains the fields for the AERN root (trust anchor)
 * including the public verification key, issuer information, certificate serial, validity times,
 * algorithm identifier, and version.
 */
AERN_EXPORT_API typedef struct aern_root_certificate
{
	uint8_t verkey[AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public key */
	char issuer[AERN_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer text name */
	uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	aern_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	aern_configuration_sets algorithm;								/*!< The signature algorithm identifier */
	aern_version_sets version;										/*!< The certificate version type */
} aern_root_certificate;

/*!
 * \struct aern_serialized_symmetric_key
 * \brief The structure for a serialized symmetric key.
 */
AERN_EXPORT_API typedef struct aern_serialized_symmetric_key
{
	uint64_t keyid;													/*!< The key identity */
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE];					/*!< The symmetric key */
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE];				/*!< The symmetric nonce */
} aern_serialized_symmetric_key;

/*!
 * \struct aern_signature_keypair
 * \brief The AERN asymmetric signature scheme key container.
 */
AERN_EXPORT_API typedef struct aern_signature_keypair
{
	uint8_t prikey[AERN_ASYMMETRIC_SIGNING_KEY_SIZE];				/*!< The secret signing key */
	uint8_t pubkey[AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The public signature verification key */
} aern_signature_keypair;

/*!
 * \struct aern_cipher_keypair
 * \brief The AERN asymmetric cipher key container.
 */
AERN_EXPORT_API typedef struct aern_cipher_keypair
{
	uint8_t prikey[AERN_ASYMMETRIC_PRIVATE_KEY_SIZE];				/*!< The asymmetric cipher private key */
	uint8_t pubkey[AERN_ASYMMETRIC_PUBLIC_KEY_SIZE];				/*!< The asymmetric cipher public key */
} aern_cipher_keypair;

/* public key encoding constants */

/** \cond */

#define AERN_CERTIFICATE_SEPERATOR_SIZE 1U
#define AERN_CHILD_CERTIFICATE_HEADER_SIZE 64U
#define AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE 30U
#define AERN_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE 23U
#define AERN_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE 9U
#define AERN_CHILD_CERTIFICATE_NAME_PREFIX_SIZE 7U
#define AERN_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define AERN_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE 14U
#define AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define AERN_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE 14U
#define AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE 10U
#define AERN_CHILD_CERTIFICATE_FOOTER_SIZE 64U
#define AERN_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE 19U

static const char AERN_CHILD_CERTIFICATE_HEADER[AERN_CHILD_CERTIFICATE_HEADER_SIZE] = "-----------BEGIN AERN CHILD PUBLIC CERTIFICATE BLOCK-----------";
static const char AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX[AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE] = "Root Signed Public Key Hash: ";
static const char AERN_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX[AERN_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE] = "Public Signature Key: ";
static const char AERN_CHILD_CERTIFICATE_ISSUER_PREFIX[AERN_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char AERN_CHILD_CERTIFICATE_NAME_PREFIX[AERN_CHILD_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char AERN_CHILD_CERTIFICATE_SERIAL_PREFIX[AERN_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char AERN_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX[AERN_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE] = "Root Serial: ";
static const char AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX[AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX[AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX[AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char AERN_CHILD_CERTIFICATE_VERSION_PREFIX[AERN_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX[AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE] = "Designation: ";
static const char AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX[AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE] = "Address: ";
static const char AERN_CHILD_CERTIFICATE_FOOTER[AERN_CHILD_CERTIFICATE_FOOTER_SIZE] = "------------END AERN CHILD PUBLIC CERTIFICATE BLOCK------------";
static const char AERN_CHILD_CERTIFICATE_DEFAULT_NAME[AERN_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE] = " Child Certificate";

#define AERN_NETWORK_DESIGNATION_SIZE 33
static const char AERN_NETWORK_DESIGNATION_NONE[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_none";
static const char AERN_NETWORK_DESIGNATION_APS[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_aps";
static const char AERN_NETWORK_DESIGNATION_CLIENT[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_client";
static const char AERN_NETWORK_DESIGNATION_ADS[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_ads";
static const char AERN_NETWORK_DESIGNATION_IDG[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_idg";
static const char AERN_NETWORK_DESIGNATION_REMOTE[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_remote";
static const char AERN_NETWORK_DESIGNATION_ROOT[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_ars";
static const char AERN_NETWORK_DESIGNATION_ALL[AERN_NETWORK_DESIGNATION_SIZE] = "aern_network_designation_all";

/** \endcond */

/*!
 * \def AERN_PROTOCOL_SET_SIZE
 * \brief The size of the protocol configuration string.
 */
#define AERN_PROTOCOL_SET_SIZE 41U

/* Valid parameter sets: 
Kyber-S1, Dilithium-S1
Kyber-S3, Dilithium-S3
Kyber-S5, Dilithium-S5
Kyber-S6, Dilithium-S5
McEliece-S1, Sphincs-S1(f,s)
McEliece-S3, Sphincs-S3(f,s)
McEliece-S5, Sphincs-S5(f,s)
McEliece-S6, Sphincs-S5(f,s)
McEliece-S7, Sphincs-S6(f,s) */

/** \cond */

#if defined(AERN_PARAMATERS_DILITHIUM_KYBER_D1K1)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "dilithium-s1_kyber-s1_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_dilithium1_kyber1_rcs256_shake256;
#elif defined(AERN_PARAMATERS_DILITHIUM_KYBER_D3K3)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "dilithium-s3_kyber-s3_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_dilithium3_kyber3_rcs256_shake256;
#elif defined(AERN_PARAMATERS_DILITHIUM_KYBER_D5K5)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s5_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_dilithium5_kyber5_rcs256_shake256;
#elif defined(AERN_PARAMATERS_DILITHIUM_KYBER_D5K6)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s6_rcs-512_sha3-512";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_dilithium5_kyber6_rcs512_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSF_MCELIECE_SF1M1) 
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-1f_mceliece-s1_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-1s_mceliece-s1_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSF_MCELIECE_SF3M3)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-3f_mceliece-s3_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-3s_mceliece-s3_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M5)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s5_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s5_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M6)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s6_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s6_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSF_MCELIECE_SF5M7)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s7_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
#elif defined(AERN_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char AERN_CONFIG_STRING[AERN_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s7_rcs-256_sha3-256";
static const aern_configuration_sets AERN_CONFIGURATION_SET = aern_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
#else
#	error Invalid parameter set!
#endif

/** \endcond */

/** \cond */

#define AERN_ROOT_CERTIFICATE_HEADER_SIZE 64U
#define AERN_ROOT_CERTIFICATE_HASH_PREFIX_SIZE 19U
#define AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13U
#define AERN_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE 9U
#define AERN_ROOT_CERTIFICATE_NAME_PREFIX_SIZE 7U
#define AERN_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define AERN_ROOT_CERTIFICATE_FOOTER_SIZE 64U
#define AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define AERN_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define AERN_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define AERN_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE 18U
#define AERN_ACTIVE_VERSION_STRING_SIZE 5U

/** \endcond */

/** \cond */

static const char AERN_ROOT_CERTIFICATE_HEADER[AERN_ROOT_CERTIFICATE_HEADER_SIZE] = "------------BEGIN AERN ROOT PUBLIC CERTIFICATE BLOCK-----------";
static const char AERN_ROOT_CERTIFICATE_ISSUER_PREFIX[AERN_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char AERN_ROOT_CERTIFICATE_NAME_PREFIX[AERN_ROOT_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char AERN_ROOT_CERTIFICATE_SERIAL_PREFIX[AERN_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX[AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char AERN_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX[AERN_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX[AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char AERN_ROOT_CERTIFICATE_VERSION_PREFIX[AERN_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char AERN_ROOT_CERTIFICATE_HASH_PREFIX[AERN_ROOT_CERTIFICATE_HASH_PREFIX_SIZE] = "Certificate Hash: ";
static const char AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX[AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE] = "Public Key: ";
static const char AERN_ROOT_CERTIFICATE_FOOTER[AERN_ROOT_CERTIFICATE_FOOTER_SIZE] = "------------END AERN ROOT PUBLIC CERTIFICATE BLOCK-------------";
static const char AERN_ROOT_CERTIFICATE_DEFAULT_NAME[AERN_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE] = " Root Certificate";

static const char AERN_ACTIVE_VERSION_STRING[AERN_ACTIVE_VERSION_STRING_SIZE] = "0x01";
static const char AERN_CERTIFICATE_CHILD_EXTENSION[] = ".ccert";
static const char AERN_CERTIFICATE_MFCOL_EXTENSION[] = ".mfcol";
static const char AERN_CERTIFICATE_ROOT_EXTENSION[] = ".rcert";
static const char AERN_CERTIFICATE_TOPOLOGY_EXTENSION[] = ".dtop";
static const char AERN_APPLICATION_ROOT_PATH[] = "\\AERN";
static const char AERN_CERTIFICATE_BACKUP_PATH[] = "\\Backup";
static const char AERN_CERTIFICATE_STORE_PATH[] = "\\Certificates";
static const char AERN_ROOT_CERTIFICATE_PATH[] = "\\Root";
static const char AERN_CERTIFICATE_TOPOLOGY_PATH[] = "\\Topology";

/** \endcond */

#define AERN_NETWORK_ERROR_STRING_DEPTH 28U
#define AERN_NETWORK_ERROR_STRING_SIZE 128U

/** \cond */

static const char AERN_NETWORK_ERROR_STRINGS[AERN_NETWORK_ERROR_STRING_DEPTH][AERN_NETWORK_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The cipher authentication has failed",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connnection to the remote host",
	"The decryption authentication has failed",
	"The transmission failed at the kex establish phase",
	"The connection experienced an unexpected error",
	"The server has run out of socket connections",
	"The random generator experienced a failure",
	"The input is invalid",
	"The request is invalid",
	"The keep alive has expired with no response",
	"The keepalive failure counter has exceeded maximum ",
	"The kex authentication has failed",
	"The key-id is not recognized",
	"The certificate has expired",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The random generator experienced a failure",
	"The random generator experienced a failure",
	"The ratchet operation has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol version is unknown",
	"The packet was received out of sequence",
	"The expected data could not be verified"
};

#define AERN_PROTOCOL_ERROR_STRING_DEPTH 44U
#define AERN_PROTOCOL_ERROR_STRING_SIZE 128U

static const char AERN_PROTOCOL_ERROR_STRINGS[AERN_PROTOCOL_ERROR_STRING_DEPTH][AERN_PROTOCOL_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The symmetric cipher had an authentication failure",
	"The node certificate could not be found",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The convergence call has returned an error",
	"The database is already synchronized",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The node or certificate decoding failed",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The application could not delete a local file",
	"The file could not be found",
	"The file could not be written to storage",
	"The public-key hash is invalid",
	"The server has run out of socket connections",
	"The packet flag was unexpected",
	"The certificate has expired and is invalid",
	"The AERN public key has expired ",
	"The key identity is unrecognized",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The network time is invalid or has substantial delay",
	"The expected data could not be verified",
	"The server has no usable IP address, assign in configuration",
	"The node is offline or not available for connection",
	"The node could not be found in the database",
	"The node was previously registered in the database",
	"The operation was cancelled by the user",
	"The packet header received was invalid",
	"The packet was received out of sequence",
	"The receiver failed at the network layer",
	"The root signature failed authentication",
	"The certificate could not be serialized",
	"The signature scheme could not sign a message",
	"The transmission failed to sign the data",
	"The socket could not be bound to an IP address",
	"The socket could not be created",
	"The transmitter failed at the network layer",
	"The topological database has no aps entries",
	"The protocol string was not recognized",
	"The transmission failed at the KEX verify phase"
};

/** \endcond */

/* API */

/**
 * \brief Close the network connection between hosts.
 *
 * \param rsock A pointer to the socket structure representing the connection.
 * \param err The network error code to report.
 * \param notify If true, notify the remote host that the connection is closing.
 */
AERN_EXPORT_API void aern_connection_close(qsc_socket* rsock, aern_network_errors err, bool notify);

/**
 * \brief Decrypt a message and copy it to the output buffer.
 *
 * \param cns A pointer to the connection state structure.
 * \param message The output array for the decrypted message.
 * \param msglen A pointer to a variable that will receive the length of the decrypted message.
 * \param packetin [const] A pointer to the input packet structure.
 *
 * \return Returns the network error state.
 */
AERN_EXPORT_API aern_protocol_errors aern_decrypt_packet(aern_connection_state* cns, uint8_t* message, size_t* msglen, const aern_network_packet* packetin);

/**
 * \brief Encrypt a message and build an output packet.
 *
 * \param cns A pointer to the connection state structure.
 * \param packetout A pointer to the output packet structure.
 * \param message [const] The input message array.
 * \param msglen The length of the input message.
 *
 * \return Returns the network error state.
 */
AERN_EXPORT_API aern_protocol_errors aern_encrypt_packet(aern_connection_state* cns, aern_network_packet* packetout, const uint8_t* message, size_t msglen);

/**
 * \brief Dispose of the tunnel connection state.
 *
 * \param cns A pointer to the connection state structure to dispose.
 */
AERN_EXPORT_API void aern_connection_state_dispose(aern_connection_state* cns);

/**
 * \brief Return a pointer to a string description of a network error code.
 *
 * \param error The network error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
AERN_EXPORT_API const char* aern_network_error_to_string(aern_network_errors error);

/**
 * \brief Return a pointer to a string description of a protocol error code.
 *
 * \param error The protocol error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
AERN_EXPORT_API const char* aern_protocol_error_to_string(aern_protocol_errors error);

/**
 * \brief Clear the state of a network packet.
 *
 * \param packet A pointer to the packet structure to clear.
 */
AERN_EXPORT_API void aern_packet_clear(aern_network_packet* packet);

/**
 * \brief Populate a packet structure with an error message.
 *
 * \param packet A pointer to the packet structure.
 * \param error The protocol error code to embed in the packet.
 */
AERN_EXPORT_API void aern_packet_error_message(aern_network_packet* packet, aern_protocol_errors error);

/**
 * \brief Deserialize a byte array into a packet header.
 *
 * \param header [const] The header byte array to deserialize.
 * \param packet A pointer to the packet structure that will be populated.
 */
AERN_EXPORT_API void aern_packet_header_deserialize(const uint8_t* header, aern_network_packet* packet);

/**
 * \brief Serialize a packet header into a byte array.
 *
 * \param packet [const] A pointer to the packet structure to serialize.
 * \param header The byte array that will receive the serialized header.
 */
AERN_EXPORT_API void aern_packet_header_serialize(const aern_network_packet* packet, uint8_t* header);

/**
 * \brief Set the local UTC time in the packet header.
 *
 * \param packet A pointer to the network packet.
 */
AERN_EXPORT_API void aern_packet_set_utc_time(aern_network_packet* packet);

/**
 * \brief Check if the packet's UTC time is within the valid time threshold.
 *
 * \param packet [const] A pointer to the network packet.
 *
 * \return Returns true if the packet was received within the valid time threshold.
 */
AERN_EXPORT_API bool aern_packet_time_valid(const aern_network_packet* packet);

/**
 * \brief Serialize a network packet to a byte stream.
 *
 * \param packet [const] A pointer to the packet.
 * \param pstream A pointer to the output byte stream.
 *
 * \return Returns the size of the serialized byte stream.
 */
AERN_EXPORT_API size_t aern_packet_to_stream(const aern_network_packet* packet, uint8_t* pstream);

/**
 * \brief Deserialize a byte stream into a network packet.
 *
 * \param pstream [const] The byte stream containing the packet data.
 * \param packet A pointer to the packet structure to populate.
 */
AERN_EXPORT_API void aern_stream_to_packet(const uint8_t* pstream, aern_network_packet* packet);

#endif

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

#ifndef AERN_TEST_ACCESS_H
#define AERN_TEST_ACCESS_H

#include "aerncommon.h"
#include "network.h"
#include "route.h"
#include "mek.h"

/**
 * \file access_test.h
 * \brief Private AERN implementation declarations used by AERNTest.
 *
 * \details
 * This header exposes selected internal AERN implementation symbols to the
 * AERNTest harness so protocol packet tests can be kept outside the production
 * implementation files. The constants mirror private packet-size definitions
 * used by the AERN network implementation. The function declarations mirror
 * internal route and network helpers exercised by negative-path and codec tests.
 *
 * \note These declarations are test-only. They must not be treated as public
 * AERN API declarations and must not be included by production consumers.
 */

/** \name Private network packet-size constants
 *
 * The following constants are test mirrors of the internal network packet layout
 * sizes used to validate packet construction, serialization, and malformed-input
 * rejection paths.
 */
/**@{*/
#define NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE)
#define NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE)
#define NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE (AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE)
#define NETWORK_JOIN_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_RESPONSE_MESSAGE_SIZE)
#define NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE)
#define NETWORK_MFK_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_REQUEST_MESSAGE_SIZE)
#define NETWORK_MFK_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_ASYMMETRIC_PUBLIC_KEY_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_RESPONSE_MESSAGE_SIZE)
#define NETWORK_MFK_ESTABLISH_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_ASYMMETRIC_CIPHERTEXT_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_ESTABLISH_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_ESTABLISH_MESSAGE_SIZE)
#define NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_QUERY_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_ISSUER_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + NETWORK_TOPOLOGY_QUERY_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE)

/**@}*/

/**
 * \brief Determine whether dummy traffic may be generated for a relay cache state.
 *
 * \param cache: A pointer to the relay cache state.
 * \param utilization: The current relay utilization value.
 * \param nowms: The current time in milliseconds.
 *
 * \return Returns true when dummy traffic is allowed by the route policy.
 */
bool route_dummy_traffic_allowed(aern_relay_cache_state* cache, uint32_t utilization, uint64_t nowms);

/**
 * \brief Derive a fragment encryption key from the MFK exchange inputs.
 *
 * \param ckey: A pointer to the derived cipher key output array.
 * \param mfk: A pointer to the master fragment key input.
 * \param lhash: A pointer to the local certificate hash input.
 * \param rhash: A pointer to the remote certificate hash input.
 * \param token: A pointer to the exchange token input.
 */
void network_derive_fkey(uint8_t* ckey, const uint8_t* mfk, const uint8_t* lhash, const uint8_t* rhash, const uint8_t* token);

/**
 * \brief Compute the network message authentication tag used by packet tests.
 *
 * \param mtag: A pointer to the authentication tag output array.
 * \param ckey: A pointer to the message authentication key.
 * \param ctxt: A pointer to the authenticated context buffer.
 * \param ctxlen: The length of the authenticated context buffer in bytes.
 * \param adata: A pointer to the associated data buffer.
 */
void network_mac_message(uint8_t* mtag, const uint8_t* ckey, const uint8_t* ctxt, size_t ctxlen, const uint8_t* adata);

/**
 * \brief Create an announce-broadcast packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the announce request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_announce_broadcast_packet(aern_network_packet* packetout, const aern_network_announce_request_state* state);

/**
 * \brief Create a converge-request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the converge request state.
 * \param snode: A pointer to the serialized sender node value.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_converge_request_packet(aern_network_packet* packetout, const aern_network_converge_request_state* state, const uint8_t* snode);

/**
 * \brief Verify a converge-response packet against the original request state.
 *
 * \param state: A pointer to the converge request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_converge_response_verify(const aern_network_converge_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a converge-response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the converge response state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_converge_response_packet(aern_network_packet* packetout, const aern_network_converge_response_state* state);

/**
 * \brief Verify a converge-request packet against the response-side state.
 *
 * \param state: A pointer to the converge response state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_converge_request_verify(const aern_network_converge_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Create an FKEY request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the FKEY request state.
 */
void network_fkey_request_packet(aern_network_packet* packetout, aern_network_fkey_request_state* state);

/**
 * \brief Verify an FKEY response packet against the request state.
 *
 * \param state: A pointer to the FKEY request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_fkey_response_verify(aern_network_fkey_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create an FKEY response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param packetin: A pointer to the input request packet.
 * \param state: A pointer to the FKEY response state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_fkey_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_fkey_response_state* state);

/**
 * \brief Create an incremental-update request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the incremental-update request state.
 */
void network_incremental_update_request_packet(aern_network_packet* packetout, const aern_network_incremental_update_request_state* state);

/**
 * \brief Verify an incremental-update request packet.
 *
 * \param state: A pointer to the incremental-update request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_incremental_update_verify(const aern_network_incremental_update_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create an incremental-update response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param packetin: A pointer to the input request packet.
 * \param state: A pointer to the incremental-update response state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_incremental_update_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, const aern_network_incremental_update_response_state* state);

/**
 * \brief Create an MFK request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the MFK request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_mfk_request_packet(aern_network_packet* packetout, const aern_network_mfk_request_state* state);

/**
 * \brief Create an MFK establish packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param packetin: A pointer to the input request packet.
 * \param state: A pointer to the MFK request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_mfk_establish_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_mfk_request_state* state);

/**
 * \brief Create an MFK response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param packetin: A pointer to the input establish packet.
 * \param state: A pointer to the MFK response state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_mfk_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_mfk_response_state* state);

/**
 * \brief Verify an MFK response packet.
 *
 * \param packetin: A pointer to the input network packet.
 * \param state: A pointer to the MFK response state.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_mfk_verify_packet(const aern_network_packet* packetin, aern_network_mfk_response_state* state);

/**
 * \brief Create a register-request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the register request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_register_request_packet(aern_network_packet* packetout, const aern_network_register_request_state* state);

/**
 * \brief Verify a register-request packet.
 *
 * \param state: A pointer to the register request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_register_verify(aern_network_register_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a register-response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the register response state.
 * \param packetin: A pointer to the input request packet.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_register_response_packet(aern_network_packet* packetout, aern_network_register_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a register-update request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the register-update request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_register_update_request_packet(aern_network_packet* packetout, const aern_network_register_update_request_state* state);

/**
 * \brief Verify a register-update request packet.
 *
 * \param state: A pointer to the register-update request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_register_update_verify(aern_network_register_update_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a register-update response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the register-update response state.
 * \param buffer: A pointer to the serialized certificate or topology buffer.
 * \param packetin: A pointer to the input request packet.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_register_update_response_packet(aern_network_packet* packetout, aern_network_register_update_response_state* state, uint8_t* buffer, const aern_network_packet* packetin);

/**
 * \brief Create a remote-signing request packet for network protocol tests.
 *
 * \param state: A pointer to the remote-signing request state.
 * \param packetout: A pointer to the output network packet.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_remote_signing_request_packet(aern_network_remote_signing_request_state* state, aern_network_packet* packetout);

/**
 * \brief Verify a remote-signing request packet.
 *
 * \param state: A pointer to the remote-signing request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_remote_signing_request_verify(const aern_network_remote_signing_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a remote-signing response packet for network protocol tests.
 *
 * \param state: A pointer to the remote-signing response state.
 * \param packetout: A pointer to the output network packet.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_remote_signing_response_packet(aern_network_remote_signing_response_state* state, aern_network_packet* packetout);

/**
 * \brief Verify a remote-signing response packet.
 *
 * \param state: A pointer to the remote-signing response state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_remote_signing_response_verify(const aern_network_remote_signing_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a topological-query request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the topological-query request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_topological_query_request_packet(aern_network_packet* packetout, const aern_network_topological_query_request_state* state);

/**
 * \brief Create a topological-query response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the topological-query response state.
 * \param packetin: A pointer to the input request packet.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_topological_query_response_packet(aern_network_packet* packetout, const aern_network_topological_query_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Verify a topological-query response packet for network protocol tests.
 *
 * \param state: A pointer to the topological-query request state.
 * \param packetin: A pointer to the input response packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_topological_query_request_verify(const aern_network_topological_query_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Verify a topological-query response packet.
 *
 * \param query: A pointer to the topology query buffer.
 * \param state: A pointer to the topological-query response state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_topological_query_response_verify(uint8_t* query, const aern_network_topological_query_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a topological-status request packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the topological-status request state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_topological_status_request_packet(aern_network_packet* packetout, const aern_network_topological_status_request_state* state);

/**
 * \brief Verify a topological-status request packet.
 *
 * \param state: A pointer to the topological-status request state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors aern_network_topological_status_request_verify(const aern_network_topological_status_request_state* state, const aern_network_packet* packetin);

/**
 * \brief Create a topological-status response packet for network protocol tests.
 *
 * \param packetout: A pointer to the output network packet.
 * \param state: A pointer to the topological-status response state.
 *
 * \return Returns the protocol status produced by packet construction.
 */
aern_protocol_errors network_topological_status_response_packet(aern_network_packet* packetout, const aern_network_topological_status_response_state* state);

/**
 * \brief Verify a topological-status response packet.
 *
 * \param state: A pointer to the topological-status response state.
 * \param packetin: A pointer to the input network packet.
 *
 * \return Returns the protocol verification status.
 */
aern_protocol_errors network_topological_status_response_verify(const aern_network_topological_status_response_state* state, const aern_network_packet* packetin);


/**
 * \brief Derive and initialize MEK connection ciphers for unit tests.
 *
 * \param cns: [aern_connection_state*] Output connection state.
 * \param secret: [uint8_t*] Shared secret buffer, cleared by the function.
 * \param initiator: [const uint8_t*] Initiator certificate serial.
 * \param responder: [const uint8_t*] Responder certificate serial.
 * \param initiatorrole: [bool] True when initializing initiator-local state.
 */
void mek_derive_and_init_ciphers(aern_connection_state* cns, uint8_t secret[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE],
	const uint8_t initiator[AERN_CERTIFICATE_SERIAL_SIZE], const uint8_t responder[AERN_CERTIFICATE_SERIAL_SIZE], bool initiatorrole);

#endif

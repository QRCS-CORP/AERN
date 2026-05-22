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

#ifndef AERN_LIFECYCLE_H
#define AERN_LIFECYCLE_H

#include "aern.h"
#include "mek.h"
#include "network.h"
#include "route.h"
#include "server.h"
#include "topology.h"

/**
 * \file lifecycle.h
 * \brief Phase-5: Session lifecycle and fault handling.
 */

#ifndef AERN_KEEP_ALIVE_INTERVAL_S
#  define AERN_KEEP_ALIVE_INTERVAL_S 30U    /*!< Seconds between keep-alive probes */
#endif

#ifndef AERN_KEEP_ALIVE_RETRY_MS
#  define AERN_KEEP_ALIVE_RETRY_MS 5000U    /*!< Retry interval if no response (ms) */
#endif

#ifndef AERN_SESSION_TIMEOUT_S
#  define AERN_SESSION_TIMEOUT_S 1800U      /*!< Session idle timeout (30 min) */
#endif

#ifndef AERN_NODE_ALIVE_POLL_S
#  define AERN_NODE_ALIVE_POLL_S 10U        /*!< ADC polls each APS every 10 s */
#endif

#ifndef AERN_NODE_ALIVE_TIMEOUT_S
#  define AERN_NODE_ALIVE_TIMEOUT_S 300U    /*!< Max silence before APS marked inactive */
#endif

#ifndef AERN_REVOKE_TIMEOUT_S
#  define AERN_REVOKE_TIMEOUT_S 60U         /*!< Revoke ack timeout per node */
#endif

/*!
 * \struct aern_resign_request_v2_state
 * \brief Phase-5 resign request state (augments network.h state with cipher teardown).
 */
AERN_EXPORT_API typedef struct aern_resign_request_v2_state
{
    const char* address;                            /*!< ADC address */
    const aern_child_certificate* lcert;            /*!< Device local certificate */
    const uint8_t* sigkey;                          /*!< Device ML-DSA signing key */
    const aern_root_certificate* root;              /*!< Root certificate (for ack verify) */
    aern_cipher_table* ctable;                      /*!< Cipher table (zeroed on success) */
} aern_resign_request_v2_state;

/*!
 * \struct aern_resign_response_v2_state
 * \brief Phase-5 resign response state (ADC side, spec-complete).
 */
AERN_EXPORT_API typedef struct aern_resign_response_v2_state
{
    const qsc_socket* csock;                        /*!< Connected socket */
    const aern_child_certificate* lcert;            /*!< ADC local certificate */
    const uint8_t* sigkey;                          /*!< ADC signing key */
    const aern_root_certificate* root;              /*!< Root certificate */
    aern_topology_list_state* vtopo;                /*!< Versioned topology */
} aern_resign_response_v2_state;

/*!
 * \struct aern_revoke_v2_state
 * \brief Phase-5 revoke response state (any receiving node).
 */
AERN_EXPORT_API typedef struct aern_revoke_v2_state
{
    const qsc_socket* csock;                        /*!< Socket (for tunnel teardown + ack) */
    const aern_child_certificate* lcert;            /*!< Local certificate (for ack sig) */
    const aern_child_certificate* dcert;            /*!< ADC cert (for broadcast sig verify) */
    const aern_root_certificate* root;              /*!< Root certificate */
    const uint8_t* sigkey;                          /*!< Local signing key (for ack) */
    aern_topology_list_state* vtopo;                /*!< Versioned topology (node removed) */
    aern_cipher_table* ctable;                      /*!< Cipher table (tunnel zeroed) */
} aern_revoke_v2_state;

/*!
 * \struct aern_adc_alive_poll_state
 * \brief State for the ADC background node-alive poller.
 */
AERN_EXPORT_API typedef struct aern_adc_alive_poll_state
{
    const aern_child_certificate* lcert;            /*!< ADC local certificate */
    const uint8_t* sigkey;                          /*!< ADC signing key */
    const aern_root_certificate* root;              /*!< Root certificate */
    aern_topology_list_state* vtopo;                /*!< Versioned topology */
    const aern_server_application_state* appstate;  /*!< App state for error log */
    volatile bool running;                          /*!< Set false to stop thread */
} aern_adc_alive_poll_state;

/*!
 * \struct aern_error_context
 * \brief Context for error dispatch and logging.
 */
AERN_EXPORT_API typedef struct aern_error_context
{
    const qsc_socket* csock;                        /*!< Socket for error packet send */
    const aern_child_certificate* lcert;            /*!< Local certificate (for log sig) */
    const uint8_t* sigkey;                          /*!< Local signing key */
    const aern_server_application_state* appstate;  /*!< App state for ADC log */
    aern_connection_state* cns;                     /*!< Cipher state (may be NULL) */
    aern_cipher_table* ctable;                      /*!< Cipher table (may be NULL) */
    const char* peer_addr;                          /*!< Peer IP string (may be NULL) */
} aern_error_context;

/**
 * \brief Send a resign request to the ADC and process the acknowledgement.
 *
 * \param state: [aern_resign_request_v2_state*] Resign state; cipher and session tables are cleared on success.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_resign_request_v2(aern_resign_request_v2_state* state);

/**
 * \brief ADC-side resign response handler
 *
 * \param state: [aern_resign_response_v2_state*] Resign response state.
 * \param packetin: [const aern_network_packet*] Incoming resign-request packet.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_resign_response_v2(aern_resign_response_v2_state* state, const aern_network_packet* packetin);

/**
 * \brief Node-side revoke broadcast handler
 *
 * \param state: [aern_revoke_v2_state*] Revoke response state.
 * \param packetin: [const aern_network_packet*] Incoming revoke-broadcast packet.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_revoke_response_v2(aern_revoke_v2_state* state, const aern_network_packet* packetin);

/**
 * \brief Background thread: ADC polls each APS every AERN_NODE_ALIVE_POLL_S seconds.
 *
 * - Sends { adc_cert || timestamp || adc_sig } to each APS.
 * - Expects a response within AERN_NODE_ALIVE_TIMEOUT_S seconds from last response.
 * - On timeout: marks inactive, calls aern_network_revoke_broadcast, logs.
 *
 * \param arg: [void*] Pointer to aern_adc_alive_poll_state.
 */
AERN_EXPORT_API void aern_adc_alive_poll_thread(void* arg);

/**
 * \brief Gracefully tear down a connection with ephemeral key erasure.
 *
 * \param cstate: [aern_connection_state*] Connection state to tear down.
 * \param csock: [qsc_socket*] Socket (may be NULL if already closed).
 * \param address: [const char*] Peer IP (used to remove from ctable; may be NULL).
 * \param ctable: [aern_cipher_table*] Cipher table (may be NULL).
 */
AERN_EXPORT_API void aern_teardown_connection(aern_connection_state* cstate, qsc_socket* csock, const char* address, aern_cipher_table* ctable);

/**
 * \brief Forward-path transmit failure: attempt hop bypass.
 *
 * \param fwd: [aern_forward_state*] Forward state.
 * \param plaintext: [uint8_t*] Decrypted plaintext (1446 bytes) to re-route.
 * \param rm: [aern_route_map*] Route map whose future-hop slots may be consumed.
 * \param failed_addr: [const char*] IP of the unresponsive hop.
 * \param entry_addr: [const char*] Entry node IP (for error report).
 * 
 * \return Returns aern_protocol_error_none if bypass succeeded.
 */
AERN_EXPORT_API aern_protocol_errors aern_forward_hop_bypass(aern_forward_state* fwd, uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], aern_route_map* rm, const char* failed_addr, const char* entry_addr);

/**
 * \brief Dispatch an error code: log to ADC and perform the correct action.
 *
 * \param ctx: [aern_error_context*] Error context.
 * \param error: [aern_protocol_errors] The error code to handle.
 */
AERN_EXPORT_API void aern_error_handle(aern_error_context*  ctx, aern_protocol_errors error);

/**
 * \brief Map a protocol error code to a human-readable string.
 *
 * Returns a static const string. Returns "(unknown error)" for out-of-range values.
 *
 * \param error: [aern_protocol_errors] The protocol error code.
 * 
 * \return A non-NULL string describing the error.
 */
AERN_EXPORT_API const char* aern_error_to_string(aern_protocol_errors error);

/**
 * \brief Map a network error code to a human-readable string.
 *
 * \param error: [aern_network_errors] The network error code.
 * 
 * \return A non-NULL string describing the error.
 */
AERN_EXPORT_API const char* aern_network_error_to_string_v2(aern_network_errors error);

#endif

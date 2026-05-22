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

#ifndef AERN_MEK_H
#define AERN_MEK_H

#include "aern.h"
#include "async.h"
#include "server.h"
#include "topology.h"

/**
 * \file mek.h
 * \brief Master Encryption Key (MEK) derivation, APS cipher-table management, and proxy mesh orchestration.
 *
 * The wire exchange is performed by the canonical MFK exchange functions in
 * network.c. This module converts the resulting shared secret into directional
 * RCS send and receive states, stores peer tunnel state, and tracks the MEK
 * rekey threshold for APS-to-APS tunnels.
 */

#define AERN_MEK_KDF_OUTPUT_SIZE (AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_NONCE_SIZE)
#define AERN_MEK_REKEY_PACKET_THRESHOLD 1200ULL
#define AERN_MEK_REKEY_SOFT_THRESHOLD 1000ULL
#define AERN_MEK_REKEY_GRACE_THRESHOLD 128ULL

#ifndef AERN_MAX_PEERS
#  define AERN_MAX_PEERS 256U
#endif

/*!
 * \enum aern_mesh_peer_status
 * \brief APS mesh synchronization status for a cached peer tunnel.
 */
typedef enum aern_mesh_peer_status
{
    aern_mesh_peer_status_none = 0x00U,             /*!< No peer synchronization state has been assigned */
    aern_mesh_peer_status_synchronizing = 0x01U,    /*!< The peer tunnel is in the process of synchronizing */
    aern_mesh_peer_status_synchronized = 0x02U,     /*!< The peer tunnel has completed synchronization and is ready for use */
    aern_mesh_peer_status_failed = 0x03U,           /*!< The peer tunnel has failed and must not be used for relay traffic */
    aern_mesh_peer_status_expired = 0x04U           /*!< The peer tunnel has expired and requires renewal before use */
} aern_mesh_peer_status;

/*!
 * \struct aern_mek_request_state
 * \brief State for the MEK exchange requestor (P_L / client).
 */
AERN_EXPORT_API typedef struct aern_mek_request_state
{
    const char* remote_address;                     /*!< Remote peer IP string */
    const aern_child_certificate* lcert;            /*!< Local certificate        */
    const aern_child_certificate* rcert;            /*!< Remote peer certificate  */
    const aern_root_certificate* root;              /*!< Root certificate         */
    const uint8_t* sigkey;                          /*!< Local ML-DSA signing key */
    aern_connection_state* cns_out;                 /*!< Output: initialised cipher state */
} aern_mek_request_state;

/*!
 * \struct aern_mek_response_state
 * \brief State for the MEK exchange responder (P_R / APS entry-node).
 */
AERN_EXPORT_API typedef struct aern_mek_response_state
{
    qsc_socket* csock;                              /*!< Connected socket (caller's) */
    const aern_child_certificate* lcert;            /*!< Local certificate */
    const aern_child_certificate* rcert;            /*!< Remote peer certificate */
    const aern_root_certificate* root;              /*!< Root certificate */
    const uint8_t* sigkey;                          /*!< Local ML-DSA signing key */
    aern_connection_state* cns_out;                 /*!< Output: initialised cipher state */
} aern_mek_response_state;

/*!
 * \struct aern_cipher_table_slot
 * \brief One slot in the cipher table.
 */
typedef struct aern_cipher_table_slot
{
    char address[AERN_CERTIFICATE_ADDRESS_SIZE];    /*!< Peer IP address. */
    uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE];   /*!< Peer certificate serial number. */
    aern_connection_state cns;                      /*!< Cipher state. */
    uint64_t created;                               /*!< UTC creation time for the current MEK. */
    uint64_t lastrekey;                             /*!< UTC time of the last successful MEK exchange. */
    bool rekeypending;                              /*!< Rekey has been requested but not completed. */
    aern_mesh_peer_status status;                   /*!< Peer synchronization status. */
    bool used;                                      /*!< Slot occupied. */
} aern_cipher_table_slot;

/*!
 * \struct aern_cipher_table
 * \brief Fixed-capacity, mutex-protected cipher-state table.
 *
 * Pre-allocated static array of AERN_MAX_PEERS slots.
 * No dynamic allocation; all state is inline.
 */
AERN_EXPORT_API typedef struct aern_cipher_table
{
    aern_cipher_table_slot slots[AERN_MAX_PEERS];   /*!< Cipher-state slots */
    uint32_t count;                                 /*!< Number of used slots */
    qsc_mutex gmtx;                                 /*!< The global table mutex */
} aern_cipher_table;

/*!
 * \struct aern_aps_state
 * \brief APS runtime state for mesh operations.
 */
AERN_EXPORT_API typedef struct aern_aps_state
{
    const aern_child_certificate* lcert;            /*!< Local APS certificate */
    const aern_root_certificate* root;              /*!< Root certificate */
    const uint8_t* sigkey;                          /*!< Local ML-DSA signing key */
    const aern_server_application_state* appstate;  /*!< Application state used for certificate-cache lookup. */
    aern_topology_list_state* vtopo;                /*!< Versioned topology */
    aern_cipher_table* ctable;                      /*!< Cipher state table */
} aern_aps_state;

/**
 * \brief MEK exchange - requestor side (P_L initiates).
 *
 * Calls the canonical network.c MFK exchange to obtain the shared secret, then
 * derives directional RCS TX and RX states for the APS tunnel. MEK is the tunnel
 * use of the exchanged secret; MFK exchange remains the wire protocol.
 *
 * \param state: [aern_mek_request_state*] MEK requestor state; cns_out is populated on success.
 * 
 * \return Returns aern_protocol_error_none on success.
 * \note Spec reference: AERN-2025 Rev. 1a 3a/3b.
 */
AERN_EXPORT_API aern_protocol_errors aern_mek_exchange_request(aern_mek_request_state* state);

/**
 * \brief MEK exchange - responder side (P_R / APS entry-node).
 *
 * Called when a packet with flag aern_network_flag_mfk_request arrives. The
 * response path delegates the wire exchange to network.c and then derives the
 * responder-side directional RCS states.
 *
 * \param state: [aern_mek_response_state*] MEK responder state; cns_out populated on success.
 * \param packetin: [const aern_network_packet*] The incoming MEK-request packet.
 * 
 * \return Returns aern_protocol_error_none on success.
 * \note Spec reference: AERN-2025 Rev. 1a 3a/3b.
 */
AERN_EXPORT_API aern_protocol_errors aern_mek_exchange_response(aern_mek_response_state* state, const aern_network_packet* packetin);

/**
 * \brief Initialise a cipher table (zero all slots, count = 0).
 *
 * \param table: [aern_cipher_table*] The table to initialise.
 */
AERN_EXPORT_API void aern_cipher_table_initialize(aern_cipher_table* table);

/**
 * \brief Add or replace a connection state, keyed by remote IP address.
 *
 * If a matching address already exists, the old cipher/socket state is disposed
 * before the new state is copied into the slot. This permits safe tunnel refresh
 * and deterministic handling of duplicate or concurrent APS MEK exchanges.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param address: [const char*] Remote peer IP string.
 * \param cns: [const aern_connection_state*] The cipher state to copy into the slot.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_cipher_table_add(aern_cipher_table* table, const char* address, const aern_connection_state* cns);

/**
 * \brief Add or replace a peer connection state with serial and status metadata.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param address: [const char*] Remote peer IP string.
 * \param serial: [const uint8_t*] Remote peer certificate serial number.
 * \param cns: [const aern_connection_state*] The cipher state to copy into the slot.
 * \param status: [aern_mesh_peer_status] The synchronization status to store.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_cipher_table_add_peer(aern_cipher_table* table, const char* address, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], const aern_connection_state* cns, aern_mesh_peer_status status);

/**
 * \brief Look up a connection state by remote IP address.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param address: [const char*] Remote peer IP string.
 * 
 * \return Pointer to the slot's connection state, or NULL if not found.
 */
AERN_EXPORT_API aern_connection_state* aern_cipher_table_get_by_ip(aern_cipher_table* table, const char* address);

/**
 * \brief Look up a connection state by remote certificate serial number.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param serial: [const uint8_t:] Remote peer certificate serial number.
 * 
 * \return Pointer to the slot's connection state, or NULL if not found.
 */
AERN_EXPORT_API aern_connection_state* aern_cipher_table_get_by_serial(aern_cipher_table* table, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE]);

/**
 * \brief Look up a connection state by instance number.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param instance: [uint32_t] The instance counter value to match.
 * 
 * \return Pointer to the matching slot's connection state, or NULL if not found.
 */
AERN_EXPORT_API aern_connection_state* aern_cipher_table_get_by_instance(aern_cipher_table* table, uint32_t instance);

/**
 * \brief Remove a connection state by remote IP address.
 *
 * Securely zeroes the slot before releasing it.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param address: [const char*] Remote peer IP string.
 * 
 * \return Returns aern_protocol_error_none if removed; aern_protocol_error_node_not_found if not present.
 */
AERN_EXPORT_API aern_protocol_errors aern_cipher_table_remove(aern_cipher_table* table, const char* address);

/**
 * \brief Zero all cipher states and mark all slots unused.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 */
AERN_EXPORT_API void aern_cipher_table_dispose(aern_cipher_table* table);

/**
 * \brief Test whether a connection state has reached the MEK soft rekey threshold.
 *
 * \param cns: [const aern_connection_state*] The connection state to inspect.
 * 
 * \return Returns true when transmit or receive use has reached the soft threshold.
 */
AERN_EXPORT_API bool aern_mek_rekey_required(const aern_connection_state* cns);

/**
 * \brief Test whether a connection state has reached the MEK hard packet limit.
 *
 * \param cns: [const aern_connection_state*] The connection state to inspect.
 * 
 * \return Returns true when transmit or receive use has reached the hard threshold.
 */
AERN_EXPORT_API bool aern_mek_rekey_limit_exceeded(const aern_connection_state* cns);

/**
 * \brief Mark a peer slot as having a pending MEK rekey operation.
 *
 * \param table: [aern_cipher_table*] The cipher table.
 * \param serial: [const uint8_t*] The peer certificate serial number.
 * \param pending: [bool] The pending state to store.
 * 
 * \return Returns aern_protocol_error_none if the peer is updated.
 */
AERN_EXPORT_API aern_protocol_errors aern_cipher_table_mark_rekey_pending(aern_cipher_table* table, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], bool pending);

/**
 * \brief Establish MEK tunnels to all peer APS nodes (spec task 3d).
 *
 * For each APS node in the topology (excluding self):
 *   a. If already in cipher table: skip.
 *   b. Load the peer APS certificate from the local certificate cache.
 *   c. Verify the peer certificate against the root and ADC topology node.
 *   d. Call aern_mek_exchange_request() to establish a tunnel.
 *   e. On success: add connection state to the cipher table.
 *   f. On failure: mark the peer unsynchronised and continue.
 *
 * \param state: [aern_aps_state*] APS runtime state.
 * 
 * \return Number of successfully established tunnels, or aern_protocol_error_channel_down (cast to size_t) if count < 1.
 */
AERN_EXPORT_API size_t aern_aps_mesh_synchronize(aern_aps_state* state);

/**
 * \brief Check whether this APS has MEK tunnels to all active peers (task 3e).
 *
 * \param state: [const aern_aps_state*] APS runtime state.
 * 
 * \return Returns true if fully synchronized.
 */
AERN_EXPORT_API bool aern_aps_is_synchronized(const aern_aps_state* state);

#endif

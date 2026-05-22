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

#ifndef AERN_CLIENT_H
#define AERN_CLIENT_H

#include "aerncommon.h"
#include "mek.h"
#include "route.h"

/**
 * \file client.h
 * \brief AERN Client Device application interface.
 *
 * \details
 * The AERN Client Device registers with the AERN Domain Controller, receives
 * the authenticated APS topology set, retrieves and verifies APS certificates,
 * prepares the local APS cache used for entry-node selection, selects an
 * APS entry node, and establishes the client-to-entry APS MEK tunnel and transmits
 * fixed-size relay packets to the selected APS entry node.
 */


/**
 * \brief Validate the client entry-node readiness context.
 *
 * The function verifies that a client has a valid root-signed client
 * certificate, an initialized topology, a selected APS topology node, a
 * matching cached APS certificate, and an established client-to-entry APS
 * tunnel in the cipher table.  This predicate is intended for production
 * readiness checks and for deterministic client-initialization tests.
 *
 * \param root: [const aern_root_certificate*] Accepted ARS root certificate.
 * \param lcert: [const aern_child_certificate*] Local client certificate.
 * \param topology: [const aern_topology_list_state*] Client APS topology.
 * \param entry: [const aern_topology_node_state*] Selected entry APS topology node.
 * \param entrycert: [const aern_child_certificate*] Cached entry APS certificate.
 * \param ctable: [const aern_cipher_table*] Client cipher table.
 *
 * \return Returns true only when the entry-node certificate, topology binding,
 * and tunnel state are coherent.
 */
AERN_EXPORT_API bool aern_client_entry_context_is_valid(const aern_root_certificate* root, const aern_child_certificate* lcert,
	const aern_topology_list_state* topology, const aern_topology_node_state* entry, const aern_child_certificate* entrycert,
	const aern_cipher_table* ctable);

/**
 * \typedef aern_client_transport_receive_callback
 * \brief Backend callback used to deliver authenticated return packets to the local client transport.
 *
 * The callback is invoked only after a return packet has been authenticated by
 * the client-to-entry tunnel, associated with the active client session, and
 * reassembled when fragmented. Implementations may bind this callback to a
 * local tunnel adapter, packet injector, socket shim, userspace transport, or
 * application callback.
 *
 * \param header: [const aern_relay_payload_header*] Authenticated return relay payload header.
 * \param packet: [const uint8_t*] Serialized TCP/UDP packet bytes.
 * \param pktlen: [size_t] Number of serialized packet bytes.
 * \param context [void*] Opaque backend context supplied during registration.
 * 
 * \return Returns aern_protocol_error_none only when the backend accepts delivery.
 */
typedef aern_protocol_errors (*aern_client_transport_receive_callback)(const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context);

/**
 * \brief Register the client local receive backend callback.
 *
 * Passing a NULL callback disables client local delivery and causes
 * authenticated return packets to return a controlled non-success status.
 * The callback is not invoked until tunnel authentication, session validation,
 * and fragment reassembly have succeeded.
 *
 * \param callback: [aern_client_transport_receive_callback] Client receive callback, or NULL to disable.
 * \param context: [void*] Opaque backend context passed to the callback.
 */
AERN_EXPORT_API void aern_client_transport_set_callback(aern_client_transport_receive_callback callback, void* context);

/**
 * \brief Start the AERN client application.
 *
 * The client initializes its local application state and enters the client
 * command loop.  The command loop supports client registration with the ADC,
 * APS topology synchronization, and client-to-entry APS tunnel establishment.
 *
 * \return Returns zero on normal termination.
 */
AERN_EXPORT_API int32_t aern_client_start(void);


/**
 * \brief Receive and process one encrypted return relay packet from the selected entry APS.
 *
 * The function reads one fixed-size AERN relay packet from the active
 * client-to-entry APS tunnel, authenticates and decrypts it using the tunnel
 * receive cipher state, parses the encrypted relay payload header, and either
 * delivers an unfragmented return packet to the client transport abstraction or
 * caches a return fragment until the complete serialized packet is available.
 *
 * \return Returns aern_protocol_error_none only when the packet is authenticated and accepted by the receive path.
 */
AERN_EXPORT_API aern_protocol_errors aern_client_receive_once(void);

/**
 * \brief Backend-neutral client-side serialized packet receive boundary.
 *
 * This function is called after an authenticated return packet has been
 * associated with the active client session and reassembled if fragmented.
 * Platform-specific delivery to a local tunnel, packet injector, socket shim,
 * or application callback is intentionally deferred behind this boundary.
 *
 * \param header: [const aern_relay_payload_header*] Authenticated relay payload header.
 * \param packet: [const uint8_t*] Serialized TCP/UDP packet bytes.
 * \param pktlen: [size_t] Number of packet bytes.
 * 
 * \return Returns aern_protocol_error_none only when a backend reports delivery.
 */
AERN_EXPORT_API aern_protocol_errors aern_client_transport_receive_serialized_packet(const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen);

/**
 * \brief Stop the AERN client application.
 *
 * The function stops the client command loop, clears the local client
 * certificate cache, and unloads the client application state.
 */
AERN_EXPORT_API void aern_client_stop(void);


#endif

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

#ifndef AERN_NETWORK_H
#define AERN_NETWORK_H

#include "aerncommon.h"
#include "topology.h"
#include "collection.h"
#include "sha3.h"
#include "socket.h"

/**
 * \file network.h
 * \brief The AERN network functions.
 *
 * This header defines the public network functions and data types used by AERN to
 * perform secure network operations. These operations include certificate announcement,
 * network convergence, registration and update of network nodes, key exchange, remote
 * signing, revocation, and topological queries.
 *
 * Each network message is encapsulated in a packet that includes a header (with a
 * time-stamp, sequence number, and flag), a payload, and a digital signature that
 * covers the payload and header. This ensures integrity, authenticity, and protection
 * against replay attacks.
 *
 * \note This header declares only the public API. Many internal functions (such as
 *       those for constructing and validating packet headers, hashing, signing, etc.)
 *       are defined as static in the implementation file.
 *
 * Example:
 * \code
 *   aern_network_announce_request_state req_state;
 *   req_state.list   = &global_topology_list;
 *   req_state.rnode  = &remote_node;
 *   req_state.sigkey = local_signing_key;
 *
 *   aern_protocol_errors err = aern_network_announce_broadcast(&req_state);
 *   if (err != aern_protocol_error_none)
 *   {
 *       // Handle error.
 *   }
 * \endcode
 */

/**
* \struct aern_network_announce_request_state
* \brief The certificate announce request function state
*/
AERN_EXPORT_API typedef struct aern_network_announce_request_state
{
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_announce_request_state;

/**
* \struct aern_network_announce_response_state
* \brief The certificate announce response function state
*/
AERN_EXPORT_API typedef struct aern_network_announce_response_state
{
	const aern_child_certificate* dcert;				/*!< A pointer to the ads certificate */
	aern_topology_node_state* rnode;					/*!< A pointer to the remote node */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
} aern_network_announce_response_state;

/**
* \struct aern_network_converge_request_state
* \brief The certificate converge request function state
*/
AERN_EXPORT_API typedef struct aern_network_converge_request_state
{
	const aern_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	aern_topology_node_state* rnode;					/*!< A pointer to the remote node */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_converge_request_state;

/**
* \struct aern_network_converge_response_state
* \brief The certificate converge response function state
*/
AERN_EXPORT_API typedef struct aern_network_converge_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_converge_response_state;

/**
* \struct aern_network_converge_response_verify_state
* \brief The certificate converge verify function state
*/
AERN_EXPORT_API typedef struct aern_network_converge_response_verify_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const aern_child_certificate* rcert;				/*!< A pointer to the remote certificate */
} aern_network_converge_response_verify_state;

/**
* \struct aern_network_converge_update_verify_state
* \brief The certificate converge update verify function state
*/
AERN_EXPORT_API typedef struct aern_network_converge_update_verify_state
{
	const qsc_socket* csock;									/*!< A pointer to the connected socket */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_converge_update_verify_state;

/**
* \struct aern_network_fkey_request_state
* \brief The fkey request function state
*/
AERN_EXPORT_API typedef struct aern_network_fkey_request_state
{
	uint8_t* frag;										/*!< A pointer to the key fragment */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node */
	const uint8_t* mfk;									/*!< A pointer to the master fragment key */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node */
	uint8_t* token;										/*!< A pointer to the exchange token */
} aern_network_fkey_request_state;

/**
* \struct aern_network_fkey_response_state
* \brief The fkey response function state
*/
AERN_EXPORT_API typedef struct aern_network_fkey_response_state
{
	qsc_socket* csock;									/*!< A pointer to the connected socket */
	uint8_t* frag;										/*!< A pointer to the key fragment */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node */
	const uint8_t* mfk;									/*!< A pointer to the master fragment key */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node */
} aern_network_fkey_response_state;

/**
* \struct aern_network_incremental_update_request_state
* \brief The incremental update request function state
*/
AERN_EXPORT_API typedef struct aern_network_incremental_update_request_state
{
	aern_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
} aern_network_incremental_update_request_state;

/**
* \struct aern_network_incremental_update_response_state
* \brief The incremental update response function state
*/
AERN_EXPORT_API typedef struct aern_network_incremental_update_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const aern_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_incremental_update_response_state;

/**
* \struct aern_network_register_request_state
* \brief The network join request function state
*/
AERN_EXPORT_API typedef struct aern_network_register_request_state
{
	const char* address;								/*!< The ads server address */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_register_request_state;

/**
* \struct aern_network_register_response_state
* \brief The network join response function state
*/
AERN_EXPORT_API typedef struct aern_network_register_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	aern_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_register_response_state;

/**
* \struct aern_network_register_update_request_state
* \brief The network join request function state
*/
AERN_EXPORT_API typedef struct aern_network_register_update_request_state
{
	const char* address;								/*!< The server address */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	aern_topology_list_state* list;						/*!< A pointer to the topology list */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_register_update_request_state;

/**
* \struct aern_network_register_update_response_state
* \brief The network join update response function state
*/
AERN_EXPORT_API typedef struct aern_network_register_update_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	aern_child_certificate* rcert;						/*!< A pointer to the output remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_register_update_response_state;

/**
* \struct aern_network_mfk_request_state
* \brief The mfk request function state
*/
AERN_EXPORT_API typedef struct aern_network_mfk_request_state
{
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	uint8_t* mfk;										/*!< A pointer to the master fragment key */
	const aern_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_mfk_request_state;

/**
* \struct aern_network_mfk_response_state
* \brief The mfk response function state
*/
AERN_EXPORT_API typedef struct aern_network_mfk_response_state
{
	const qsc_socket* csock;							/*!< A pointer to the connected socket */
	aern_cipher_keypair ckp;							/*!< The asymmetric encryption keypair */
	const aern_child_certificate* lcert;				/*!< A pointer to the local certificate */
	uint8_t* mfk;										/*!< A pointer to the master fragment key */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_mfk_response_state;

/**
* \struct aern_network_remote_signing_request_state
* \brief The certificate remote signing request function state
*/
AERN_EXPORT_API typedef struct aern_network_remote_signing_request_state
{
	const char* address;								/*!< The rds server address */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_remote_signing_request_state;

/**
* \struct aern_network_remote_signing_response_state
* \brief The certificate remote signing response function state
*/
AERN_EXPORT_API typedef struct aern_network_remote_signing_response_state
{
	qsc_socket* csock;									/*!< A pointer to the connected socket */
	aern_child_certificate* dcert;						/*!< A pointer to the ads certificate */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	const aern_root_certificate* root;					/*!< A pointer to the root certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_remote_signing_response_state;

/**
* \struct aern_network_resign_request_state
* \brief The certificate resign request function state
*/
AERN_EXPORT_API typedef struct aern_network_resign_request_state
{
	const char* address;								/*!< The server address */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_resign_request_state;

/**
* \struct aern_network_resign_response_state
* \brief The certificate resign request function state
*/
AERN_EXPORT_API typedef struct aern_network_resign_response_state
{
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	aern_child_certificate* rcert;						/*!< A pointer to the remote certificate */
	aern_topology_node_state* rnode;					/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_resign_response_state;

/**
* \struct aern_network_revoke_request_state
* \brief The certificate revoke request function state
*/
AERN_EXPORT_API typedef struct aern_network_revoke_request_state
{
	aern_network_designations designation;				/*!< The node type designation */
	const aern_topology_list_state* list;				/*!< A pointer to the node database */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_revoke_request_state;

/**
* \struct aern_network_revoke_response_state
* \brief The certificate revoke response function state
*/
AERN_EXPORT_API typedef struct aern_network_revoke_response_state
{
	const aern_topology_list_state* list;				/*!< A pointer to the node database */
	aern_topology_node_state* rnode;					/*!< A pointer to the remote node structure */
	const aern_child_certificate* dcert;				/*!< A pointer to the ads certificate */
} aern_network_revoke_response_state;

/**
* \struct aern_network_topological_query_request_state
* \brief The topological query request function state
*/
AERN_EXPORT_API typedef struct aern_network_topological_query_request_state
{
	const aern_child_certificate* dcert;				/*!< A pointer to the ads certificate */
	aern_topology_node_state* dnode;					/*!< A pointer to the ads node node structure */
	const char* issuer;									/*!< A pointer to the query issuer string */
	aern_topology_node_state* rnode;					/*!< A pointer to the return remote node structure */
	const uint8_t* serial;								/*!< A pointer to the local serial number */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_topological_query_request_state;

/**
* \struct aern_network_incremental_update_response_state
* \brief The topological query response function state
*/
AERN_EXPORT_API typedef struct aern_network_topological_query_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const aern_child_certificate* ccert;				/*!< A pointer to the remote clients certificate */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_topological_query_response_state;

/**
* \struct aern_network_topological_status_request_state
* \brief The topological status request function state
*/
AERN_EXPORT_API typedef struct aern_network_topological_status_request_state
{
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_child_certificate* rcert;				/*!< A pointer to the client responder certificate */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_topological_status_request_state;

/**
* \struct aern_network_topological_status_response_state
* \brief The topological status response function state
*/
AERN_EXPORT_API typedef struct aern_network_topological_status_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_child_certificate* rcert;				/*!< A pointer to the remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_topological_status_response_state;

/**
* \struct aern_network_fragment_collection_request_state
* \brief The fkey collection request function state
*/
AERN_EXPORT_API typedef struct aern_network_fragment_collection_request_state
{
	qsc_socket* csock;									/*!< The connected socket */
	uint8_t* hfkey;										/*!< A pointer to the fkeys hash */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const aern_topology_node_state* lnode;				/*!< A pointer to the remote node structure */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	uint8_t* token;										/*!< A pointer to the client token */
} aern_network_fragment_collection_request_state;

/**
* \struct aern_network_fragment_collection_response_state
* \brief The fkey collection response function state
*/
AERN_EXPORT_API typedef struct aern_network_fragment_collection_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	uint8_t* frag;										/*!< A pointer to the key fragment */
	uint8_t* hfkey;										/*!< A pointer to the fkeys hash */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
	uint8_t* ctok;										/*!< A pointer to the client token */
	uint8_t* mtok;										/*!< A pointer to the server token */
} aern_network_fragment_collection_response_state;

/**
* \struct aern_network_fragment_query_request_state
* \brief The fkey query request function state
*/
AERN_EXPORT_API typedef struct aern_network_fragment_query_request_state
{
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_topology_node_state* rnode;				/*!< A pointer to the client node structure */
	const uint8_t* token;								/*!< A pointer to the local token */
} aern_network_fragment_query_request_state;

/**
* \struct aern_network_fragment_query_response_state
* \brief The fkey query response function state
*/
AERN_EXPORT_API typedef struct aern_network_fragment_query_response_state
{
	const qsc_socket* csock;							/*!< The connected socket */
	const aern_topology_node_state* lnode;				/*!< A pointer to the local node structure */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	qsc_collection_state* lmfk;							/*!< A pointer to the mfk collection */
	const aern_topology_node_state* rnode;				/*!< A pointer to the remote node structure */
} aern_network_fragment_query_response_state;

/**
* \struct aern_network_key_exchange_request_state
* \brief The key exchange request function state
*/
AERN_EXPORT_API typedef struct aern_network_key_exchange_request_state
{
	const char* address;								/*!< The server address */
	aern_connection_state* cns;							/*!< The connection state */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	const aern_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* token;								/*!< A pointer to a token */
} aern_network_key_exchange_request_state;

/**
* \struct aern_network_key_exchange_response_state
* \brief The key exchange response function state
*/
AERN_EXPORT_API typedef struct aern_network_key_exchange_response_state
{
	aern_connection_state* cns;							/*!< The connection state */
	const qsc_socket* csock;							/*!< The connected socket */
	const aern_topology_list_state* list;				/*!< A pointer to the topology list */
	const aern_child_certificate* rcert;				/*!< A pointer to the output remote certificate */
	const uint8_t* sigkey;								/*!< A pointer to the secret signing key */
} aern_network_key_exchange_response_state;

/*---------------------------------------------------------------------------
  Public Function Prototypes
---------------------------------------------------------------------------*/

/**
* \brief Announce a certificate using the ads, and broadcast it to the network
*
* \param state: The announce state structure
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_announce_broadcast(aern_network_announce_request_state* state);

/**
* \brief Process a announce response message
*
* \param state: The announce response state structure
* \param packetin: [const] The input packet containing the announce request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_announce_response(aern_network_announce_response_state* state, const aern_network_packet* packetin);

/**
* \brief Gets the network designation from a port number
*
* \param tnode: The target network designation type
* \return Returns the port number, or zero if the node type is invalid
*/
AERN_EXPORT_API uint16_t aern_network_application_to_port(aern_network_designations tnode);

/**
* \brief Broadcast a message to a node type on the network
*
* \param list: [const] A pointer to the topology list
* \param message: The message to send
* \param msglen: The length of the message
* \param tnode: The target node-type designation
*/
AERN_EXPORT_API void aern_network_broadcast_message(const aern_topology_list_state* list, const uint8_t* message, size_t msglen, aern_network_designations tnode);

/**
* \brief Connect a socket to a remote address
*
* \param csock: A pointer to the socket
* \param address: [const] The remote hosts address
* \param designation: The remote hosts designation
* \return Returns the socket error
*/
AERN_EXPORT_API qsc_socket_exceptions aern_network_connect_to_device(qsc_socket* csock, const char* address, aern_network_designations designation);

/**
* \brief The ADC sends out a convergence request, and broadcast it to the network
*
* \param state: The converge request state structure
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_converge_request(const aern_network_converge_request_state* state);

/**
* \brief Respond to a ads network converge request
*
* \param state: The converge response state structure
* \param packetin: [const] The input packet containing the verify response
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_converge_response(const aern_network_converge_response_state* state, const aern_network_packet* packetin);

/**
* \brief Connect a socket to a remote address and port
*
* \param csock: A pointer to the socket
* \param address: [const] The remote hosts address
* \param port: The application port number
* \return Returns the socket error
*/
AERN_EXPORT_API qsc_socket_exceptions aern_network_connect_to_address(qsc_socket* csock, const char* address, uint16_t port);

/**
* \brief Request and execute a key exchange for a fragmentation key
*
* \param state: The fkey request state structure
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_fkey_request(aern_network_fkey_request_state* state);

/**
* \brief Respond and execute a key exchange for a fragmentation key
*
* \param state: The fkey response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_fkey_response(aern_network_fkey_response_state* state, const aern_network_packet* packetin);

/**
* \brief Get the local IP address
*
* \param address: The output address byte array
* \return Returns true if the address is retrieved
*/
AERN_EXPORT_API bool aern_network_get_local_address(char address[AERN_CERTIFICATE_ADDRESS_SIZE]);

/**
* \brief Send an error message
*
* \param csock: A pointer to the socket
* \param error: The error code
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_send_error(const qsc_socket* csock, aern_protocol_errors error);

/**
* \brief Shut down and dispose of a socket instance
*
* \param csock: A pointer to the socket
*/
AERN_EXPORT_API void aern_network_socket_dispose(qsc_socket* csock);

/**
* \brief Send an incremental update request
*
* \param state: The incremental update request function state
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_incremental_update_request(const aern_network_incremental_update_request_state* state);

/**
* \brief Send a copy of a certificate to a remote host
*
* \param state: The update response function state
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_incremental_update_response(const aern_network_incremental_update_response_state* state, const aern_network_packet* packetin);

/**
* \brief Send an APS join request to the ADC
*
* \param state: The join request function state
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_register_request(aern_network_register_request_state* state);

/**
* \brief Send a MAS or Client join update request to the ADC
*
* \param state: The join update request function state
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_register_update_request(aern_network_register_update_request_state* state);

/**
* \brief Send a join response to the aps
*
* \param state: The join response function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_register_response(aern_network_register_response_state* state, const aern_network_packet* packetin);

/**
* \brief Send a join update response to the server or client
*
* \param state: The join response function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_register_update_response(aern_network_register_update_response_state* state, const aern_network_packet* packetin);

/**
* \brief Send a certificate signing request from the ADC to the ARS
*
* \param state: The remote signing request state
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_remote_signing_request(aern_network_remote_signing_request_state* state);

/**
* \brief Send a signed certificate response from the ARS to the ADC
*
* \param state: The remote signing response state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_remote_signing_response(aern_network_remote_signing_response_state* state, const aern_network_packet* packetin);

/**
* \brief Request and execute a key exchange request for a master fragmentation key
*
* \param state: The mfk request state structure
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_mfk_exchange_request(aern_network_mfk_request_state* state);

/**
* \brief Request and execute a key exchange response for a master fragmentation key
*
* \param state: The mfk response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_mfk_exchange_response(aern_network_mfk_response_state* state, const aern_network_packet* packetin);

/**
* \brief Gets the network designation from a port number
*
* \param port: The network application port
* \return Returns the network designation type
*/
AERN_EXPORT_API aern_network_designations aern_network_port_to_application(uint16_t port);

/**
* \brief Verify a certificates format and root signature
*
* \param ccert: [const] The child certificate
* \param root: [const] The root certificate
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_certificate_verify(const aern_child_certificate* ccert, const aern_root_certificate* root);

/**
* \brief Send a resign request to the ads
*
* \param state: The resign request state structure
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_resign_request(const aern_network_resign_request_state* state);

/**
* \brief Send a resign response to the aps or server
*
* \param state: The resign response state structure
* \param packetin: [const] The input packet containing the request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_resign_response(aern_network_resign_response_state* state, const aern_network_packet* packetin);

/**
* \brief Send a revocation request from the ADC
*
* \param state: The revocation broadcast function state
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_revoke_broadcast(aern_network_revoke_request_state* state);

/**
* \brief Verify a revocation request sent from the ADC
*
* \param state: The revocation verify function state
* \param packetin: [const] The input packet containing the request
* \return Returns a protocol error flag
*/
AERN_EXPORT_API aern_protocol_errors aern_network_revoke_response(aern_network_revoke_response_state* state, const aern_network_packet* packetin);

/**
* \brief Query a device for its topological information
*
* \param state: The topological query request state
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_topological_query_request(const aern_network_topological_query_request_state* state);

/**
* \brief Respond to a topological query request
*
* \param state: topological query response state
* \param packetin: The packet containing the topological query request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_topological_query_response(const aern_network_topological_query_response_state* state, const aern_network_packet* packetin);

/**
* \brief Send a status request from the ADC to a client device
*
* \param state: The topological status request state
* \param query: The device query string
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_topological_status_request(const aern_network_topological_status_request_state* state);

/**
* \brief Process the status response from the client device and send a response
*
* \param state: The topological status response state
* \param packetin: The packet containing the topological status request
* \return Returns the error code
*/
AERN_EXPORT_API aern_protocol_errors aern_network_topological_status_response(const aern_network_topological_status_response_state* state, const aern_network_packet* packetin);

#if defined(AERN_DEBUG_MODE)
AERN_EXPORT_API bool aern_network_protocols_test(void);
#endif

#endif

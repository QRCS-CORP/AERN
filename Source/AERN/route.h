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

#ifndef AERN_ROUTE_H
#define AERN_ROUTE_H

#include "aern.h"
#include "mek.h"
#include "topology.h"
#include "relayqueue.h"

/**
 * \file route.h
 * \brief Phase-4: Route engine and packet forwarding.
 *
 * Spec: AERN-2025 Rev. 1a 5–6, Phase-4 tasks 4a–4i.
 */

/*!
 * \def AERN_RELAY_CACHE_KEY_SIZE
 * \brief The byte length of the deterministic relay cache lookup key.
 */
#ifndef AERN_RELAY_CACHE_KEY_SIZE
#  define AERN_RELAY_CACHE_KEY_SIZE 16U
#endif

/*!
 * \def AERN_ROUTE_MIN_HOPS
 * \brief The minimum number of APS nodes in a complete relay route.
 */
#ifndef AERN_ROUTE_MIN_HOPS
#  define AERN_ROUTE_MIN_HOPS 3U
#endif

/*!
 * \def AERN_ROUTE_MINIMUM_HOPS
 * \brief Compatibility macro for the minimum complete relay route length.
 */
#ifndef AERN_ROUTE_MINIMUM_HOPS
#  define AERN_ROUTE_MINIMUM_HOPS AERN_ROUTE_MIN_HOPS
#endif

/*!
 * \def AERN_ROUTE_MAX_HOPS
 * \brief The maximum number of APS nodes in a complete relay route.
 */
#ifndef AERN_ROUTE_MAX_HOPS
#  define AERN_ROUTE_MAX_HOPS 16U
#endif

/*!
 * \def AERN_ROUTE_MAXIMUM_HOPS
 * \brief Compatibility macro for the maximum complete relay route length.
 */
#ifndef AERN_ROUTE_MAXIMUM_HOPS
#  define AERN_ROUTE_MAXIMUM_HOPS    AERN_ROUTE_MAX_HOPS
#endif

#ifndef AERN_INGRESS_PENDING_QUEUE_DEPTH
/*!
 * \def AERN_INGRESS_PENDING_QUEUE_DEPTH
 * \brief The maximum number of relay packets queued while a session-open acknowledgement is pending.
 */
#  define AERN_INGRESS_PENDING_QUEUE_DEPTH 64U
#endif

#ifndef AERN_INGRESS_DELAY_QUEUE_DEPTH
/*!
 * \def AERN_INGRESS_DELAY_QUEUE_DEPTH
 * \brief The maximum number of relay packets held in the optional ingress randomized-delay queue.
 */
#  define AERN_INGRESS_DELAY_QUEUE_DEPTH 64U
#endif

#ifndef AERN_RELAY_SESSION_CONTEXT_INGRESS
/*!
 * \def AERN_RELAY_SESSION_CONTEXT_INGRESS
 * \brief Session-cache key context for ingress-side sessions.
 */
#  define AERN_RELAY_SESSION_CONTEXT_INGRESS 0x01U
#endif

#ifndef AERN_RELAY_SESSION_CONTEXT_EGRESS
/*!
 * \def AERN_RELAY_SESSION_CONTEXT_EGRESS
 * \brief Session-cache key context for egress-side sessions.
 */
#  define AERN_RELAY_SESSION_CONTEXT_EGRESS 0x02U
#endif

#ifndef AERN_RELAY_SESSION_TIMEOUT_SECONDS
/*!
 * \def AERN_RELAY_SESSION_TIMEOUT_SECONDS
 * \brief Default relay session cache lifetime in seconds.
 */
#  define AERN_RELAY_SESSION_TIMEOUT_SECONDS 300U
#endif

#ifndef AERN_RELAY_FRAGMENT_TIMEOUT_SECONDS
/*!
 * \def AERN_RELAY_FRAGMENT_TIMEOUT_SECONDS
 * \brief Default fragment reassembly cache lifetime in seconds.
 */
#  define AERN_RELAY_FRAGMENT_TIMEOUT_SECONDS 30U
#endif

#define AERN_ROUTE_PATH_SIZE 16U   /*!< Serialized consumed-next-hop route path size */

#define AERN_RELAY_MTU AERN_NETWORK_CONNECTION_MTU  /* 1500 */
#define AERN_RELAY_HEADER_SIZE AERN_PACKET_HEADER_SIZE      /* 22   */
#define AERN_RELAY_CIPHERTEXT_SIZE (AERN_RELAY_MTU - AERN_RELAY_HEADER_SIZE)  /* 1478 */
#define AERN_RELAY_MAC_SIZE AERN_CRYPTO_SYMMETRIC_MAC_SIZE  /* 32  */
#define AERN_RELAY_PLAINTEXT_SIZE (AERN_RELAY_CIPHERTEXT_SIZE - AERN_RELAY_MAC_SIZE) /* 1446 */

#define AERN_ROUTEMAP_SIZE AERN_ROUTE_PATH_SIZE   /*!< Route-map bytes in encrypted payload */
#define AERN_LEN_PREFIX_SIZE 2U    /*!< uint16_t actual_len prefix           */
#define AERN_MAX_USER_PAYLOAD (AERN_RELAY_PLAINTEXT_SIZE - AERN_LEN_PREFIX_SIZE - AERN_ROUTEMAP_SIZE)
                                         /* = 1446 - 2 - 16 = 1428 bytes          */
#ifndef AERN_RELAY_PAYLOAD_FLAG_RETURN
/*!
 * \def AERN_RELAY_PAYLOAD_FLAG_RETURN
 * \brief Relay payload flag indicating destination-to-client return traffic.
 */
#  define AERN_RELAY_PAYLOAD_FLAG_RETURN 0x0001U
#endif

#ifndef AERN_RELAY_PAYLOAD_FLAG_OUTBOUND
/*!
 * \def AERN_RELAY_PAYLOAD_FLAG_OUTBOUND
 * \brief Relay payload flag value for client-to-destination traffic.
 */
#  define AERN_RELAY_PAYLOAD_FLAG_OUTBOUND 0x0000U
#endif

#ifndef AERN_RELAY_DATA_PAYLOAD_SIZE
/*!
 * \def AERN_RELAY_DATA_PAYLOAD_SIZE
 * \brief Maximum opaque serialized packet bytes carried after the encrypted relay payload header.
 */
#  define AERN_RELAY_DATA_PAYLOAD_SIZE (AERN_MAX_USER_PAYLOAD - AERN_RELAY_PAYLOAD_HEADER_SIZE)
#endif

#ifndef AERN_FRAG_CHUNK_SIZE
/*!
 * \def AERN_FRAG_CHUNK_SIZE
 * \brief Maximum application bytes carried by one relay payload fragment.
 */
#  define AERN_FRAG_CHUNK_SIZE AERN_RELAY_DATA_PAYLOAD_SIZE
#endif

#ifndef AERN_EXIT_TIMEOUT_MS
#  define AERN_EXIT_TIMEOUT_MS 10000U /*!< Exit-node response timeout (ms)   */
#endif
#ifndef AERN_MAX_FRAGMENTS
#  define AERN_MAX_FRAGMENTS 4096U  /*!< Max fragments per dynamic reassembly cache */
#endif

#ifndef AERN_FRAGMENT_CACHE_MEMORY_MAX
#  define AERN_FRAGMENT_CACHE_MEMORY_MAX (16ULL * 1024ULL * 1024ULL)
#endif

/*!
 * \def AERN_MAX_RELAY_PACKET_SIZE
 * \brief Size of a single relay wire packet.
 */
#define AERN_MAX_RELAY_PACKET_SIZE AERN_RELAY_MTU  /* 1500 bytes */

/*!
 * \enum aern_relay_payload_type
 * \brief Encrypted relay payload message types.
 */
typedef enum aern_relay_payload_type
{
    aern_relay_payload_none = 0x00U,                /*!< No relay payload type was specified */
    aern_relay_payload_session_open = 0x01U,        /*!< Ingress-to-egress session establishment */
    aern_relay_payload_session_open_ack = 0x02U,    /*!< Egress-to-ingress session acknowledgement */
    aern_relay_payload_session_close = 0x03U,       /*!< Session close notification */
    aern_relay_payload_data = 0x04U,                /*!< Opaque serialized packet payload */
    aern_relay_payload_dummy = 0x05U,               /*!< Dummy relay packet payload */
    aern_relay_payload_error = 0xFFU                /*!< Relay error payload */
} aern_relay_payload_type;

/*!
 * \enum aern_relay_fragment_direction
 * \brief Fragment-cache traffic direction.
 */
typedef enum aern_relay_fragment_direction
{
    aern_relay_fragment_direction_none = 0x00U,     /*!< Direction is unspecified */
    aern_relay_fragment_direction_outbound = 0x01U, /*!< Client-to-destination direction */
    aern_relay_fragment_direction_inbound = 0x02U,  /*!< Destination-to-client direction */
    aern_relay_fragment_direction_return = 0x02U    /*!< Compatibility alias for return direction */
} aern_relay_fragment_direction;

/*!
 * \enum aern_relay_session_status
 * \brief Relay session cache state values.
 */
typedef enum aern_relay_session_status
{
    aern_relay_session_status_none = 0x00U,         /*!< Session entry is unused */
    aern_relay_session_status_pending = 0x01U,      /*!< Session-open has been sent but not acknowledged */
    aern_relay_session_status_active = 0x02U,       /*!< Session-open acknowledgement has been received */
    aern_relay_session_status_closing = 0x03U,      /*!< Session close has been requested */
    aern_relay_session_status_expired = 0x04U,      /*!< Session entry has expired */
    aern_relay_session_status_failed = 0x05U        /*!< Session transport or relay processing failed */
} aern_relay_session_status;

/*!
 * \enum aern_exit_transport_status
 * \brief Backend-neutral egress transport state values.
 */
typedef enum aern_exit_transport_status
{
    aern_exit_transport_status_none = 0x00U,        /*!< No transport state is assigned */
    aern_exit_transport_status_pending = 0x01U,     /*!< Transport state is being established */
    aern_exit_transport_status_active = 0x02U,      /*!< Transport state is active */
    aern_exit_transport_status_unimplemented = 0x03U, /*!< No platform transport backend is attached */
    aern_exit_transport_status_failed = 0x04U       /*!< Transport state failed */
} aern_exit_transport_status;

struct aern_relay_payload_header;
struct aern_relay_session_cache_entry;

/*!
 * \typedef aern_exit_transport_send_callback
 * \brief Backend callback used to transmit authenticated serialized packets from an egress APS.
 *
 * The callback is invoked only after the relay packet has been authenticated,
 * associated with an active egress session, and reassembled when fragmented.
 * Implementations may bind this callback to a TUN/TAP device, raw socket,
 * packet-filter backend, userspace transport stack, or application transport.
 * Destination responses are submitted back to AERN with
 * aern_exit_transport_return_serialized_packet(); no direct socket path is
 * used inside the relay layer.
 *
 * \param session [in] Backend-validated egress session metadata.
 * \param header [in] Authenticated relay payload header.
 * \param packet [in] Opaque serialized packet bytes.
 * \param pktlen [in] Number of serialized packet bytes.
 * \param context [in] Opaque backend context supplied during registration.
 * 
 * \return Returns aern_protocol_error_none only when the backend accepts delivery.
 */
typedef aern_protocol_errors(*aern_exit_transport_send_callback)(const struct aern_relay_session_cache_entry* session,
    const struct aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context);

/*!
 * \typedef aern_ingress_transport_send_callback
 * \brief Backend callback used to deliver authenticated return packets at an ingress APS.
 *
 * The callback is invoked only after return traffic has been authenticated,
 * associated with an active ingress session, and reassembled when fragmented.
 * A later platform backend can use this callback to forward the serialized
 * packet through the client tunnel, a local tunnel adapter, a packet injector,
 * or an application callback.
 *
 * \param session [in] Backend-validated ingress session metadata.
 * \param header [in] Authenticated return relay payload header.
 * \param packet [in] Opaque serialized packet bytes.
 * \param pktlen [in] Number of serialized packet bytes.
 * \param context [in] Opaque backend context supplied during registration.
 * 
 * \return Returns aern_protocol_error_none only when the backend accepts delivery.
 */
typedef aern_protocol_errors(*aern_ingress_transport_send_callback)(const struct aern_relay_session_cache_entry* session,
    const struct aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context);

/*!
 * \struct aern_route_map
 * \brief Parsed route-map (in-memory representation).
 */
AERN_EXPORT_API typedef struct aern_route_map
{
    uint8_t path[AERN_ROUTE_PATH_SIZE];             /*!< path[0] is origin; path[1..15] are future hops */
    uint8_t hopcount;                               /*!< Generation-only live route count */
} aern_route_map;

/*!
 * Brief Forward declaration for the relay cache state.
 */
typedef struct aern_relay_cache_state aern_relay_cache_state;

/*!
 * \struct aern_forward_state
 * \brief State passed to aern_packet_forward.
 */
AERN_EXPORT_API typedef struct aern_forward_state
{
    aern_cipher_table* conn_table;                  /*!< Cipher table (all peer connections) */
    aern_relay_cache_state* relay_cache;            /*!< Relay session, fragment, and queue cache */
    const aern_topology_list_state* topology;       /*!< APS topology list */
    uint8_t apscount;                               /*!< Number of APS entries */
    uint8_t ownhint;                                /*!< This node's one-based APS route hint */
    const char* own_address;                        /*!< This node's IP address */
} aern_forward_state;

/*!
 * \struct aern_exit_state
 * \brief State held at the exit node per active circuit.
 */
AERN_EXPORT_API typedef struct aern_exit_state
{
    aern_route_map return_route;                    /*!< Pre-computed return route */
    aern_cipher_table* conn_table;                  /*!< Cipher table */
    const aern_topology_list_state* topology;       /*!< APS topology list */
    uint8_t apscount;                               /*!< Number of APS entries */
    uint8_t ownhint;                                /*!< This exit node's one-based APS route hint */
    uint8_t entryhint;                              /*!< Entry node one-based APS route hint */
    uint32_t session_id;                            /*!< Session ID for logging */
} aern_exit_state;

/*!
 * \struct aern_relay_packet
 * \brief A pre-padded, fixed-1500-byte relay packet ready for transmission.
 */
AERN_EXPORT_API typedef struct aern_relay_packet
{
    uint8_t wire[AERN_RELAY_MTU];                   /*!< Raw on-wire bytes (exactly 1500) */
    uint32_t fragseq;                               /*!< Fragment sequence (UINT32_MAX = last) */
} aern_relay_packet;

/*!
 * \struct aern_relay_payload_header
 * \brief Encrypted relay payload header.
 *
 * This header is serialized inside the encrypted relay payload. Intermediate
 * APS nodes cannot read it unless they are processing the packet as the
 * current decrypting hop. The terminal egress uses this header to associate
 * opaque serialized packets and fragments with a previously established
 * session cache entry.
 */
typedef struct aern_relay_payload_header
{
    uint64_t sessionid;                             /*!< Logical ingress-to-egress session identifier */
    uint64_t packetid;                              /*!< Serialized packet identifier within the session */
    uint32_t fragseq;                               /*!< Fragment sequence: zero means unfragmented */
    uint32_t fragcount;                             /*!< Total fragment count: zero means unfragmented */
    uint32_t msglen;                                /*!< Valid payload bytes following this header */
    uint8_t payloadtype;                            /*!< One of aern_relay_payload_type */
    uint8_t reserved;                               /*!< Reserved; set to zero */
    uint16_t flags;                                 /*!< Payload-specific flags */
} aern_relay_payload_header;

/*!
 * \struct aern_relay_session_open
 * \brief Encrypted ingress-to-egress session-open message.
 */
AERN_EXPORT_API typedef struct aern_relay_session_open
{
    uint64_t sessionid;                             /*!< Session identifier chosen by ingress */
    uint8_t destination[AERN_CERTIFICATE_ADDRESS_SIZE]; /*!< Destination IP address bytes */
    uint8_t ingresshint;                            /*!< One-based ingress APS route hint */
    uint8_t egresshint;                             /*!< One-based egress APS route hint */
    uint16_t port;                                  /*!< Destination port */
    uint8_t reserved;                               /*!< Reserved; set to zero */
    uint8_t flags;                                  /*!< Session-open flags */
} aern_relay_session_open;

/*!
 * \struct aern_relay_session_open_ack
 * \brief Encrypted egress-to-ingress session-open acknowledgement.
 */
AERN_EXPORT_API typedef struct aern_relay_session_open_ack
{
    uint64_t sessionid;                             /*!< Session identifier being acknowledged */
    uint8_t status;                                 /*!< Zero on success, nonzero on failure */
    uint8_t flags;                                  /*!< Acknowledgement flags */
    uint16_t reserved;                              /*!< Reserved for future use; set to zero */
} aern_relay_session_open_ack;

/*!
 * \struct aern_relay_session_cache_entry
 * \brief Metadata stored in the fixed relay session table for an ingress or egress relay session.
 */
typedef struct aern_relay_session_cache_entry
{
    uint64_t sessionid;                             /*!< Logical session identifier */
    uint64_t created;                               /*!< UTC creation time in seconds */
    uint64_t activity;                              /*!< UTC last-activity time in seconds */
    uint64_t expiry;                                /*!< UTC expiry time in seconds */
    uint8_t ingresshint;                            /*!< One-based ingress APS route hint */
    uint8_t egresshint;                             /*!< One-based egress APS route hint */
    uint64_t txcount;                               /*!< Serialized packets transmitted to destination */
    uint64_t rxcount;                               /*!< Serialized packets received from destination */
    uint32_t txfail;                                /*!< Consecutive destination transmit failures */
    uint32_t rxfail;                                /*!< Consecutive client return delivery failures */
    uint16_t port;                                  /*!< Destination port */
    uint8_t destination[AERN_CERTIFICATE_ADDRESS_SIZE]; /*!< Destination address bytes */
    uint8_t status;                                 /*!< One of aern_relay_session_status */
    uint8_t context;                                /*!< Session-cache context value */
    uint8_t flags;                                  /*!< Session flags */
    uint8_t transport;                              /*!< One of aern_exit_transport_status */
    uint8_t reserved[4U];                           /*!< Reserved; set to zero */
} aern_relay_session_cache_entry;

/*!
 * \struct aern_relay_fragment_set_entry
 * \brief Metadata stored in the dynamic fragment cache for a fragmented relay packet.
 */
AERN_EXPORT_API typedef struct aern_relay_fragment_set_entry
{
    uint64_t sessionid;                             /*!< Logical session identifier */
    uint64_t packetid;                              /*!< Fragmented packet identifier */
    uint64_t created;                               /*!< UTC creation time in seconds */
    uint64_t expiry;                                /*!< UTC expiry time in seconds */
    uint32_t fragcount;                             /*!< Expected fragment count */
    uint32_t received;                              /*!< Number of fragments received */
    uint32_t totalsize;                             /*!< Total reassembled payload size */
    uint8_t direction;                              /*!< One of aern_relay_fragment_direction */
    uint8_t complete;                               /*!< Non-zero when all fragments have arrived */
    uint8_t reserved[2U];                           /*!< Reserved; set to zero */
} aern_relay_fragment_set_entry;

#ifndef AERN_RELAYSESSION_TABLE_DEPTH
#  define AERN_RELAYSESSION_TABLE_DEPTH 64U
#endif

/*!
 * \struct aern_relaysession_table
 * \brief Fixed relay-session metadata table.
 */
typedef struct aern_relaysession_table
{
    aern_relay_session_cache_entry entries[AERN_RELAYSESSION_TABLE_DEPTH];
    bool active[AERN_RELAYSESSION_TABLE_DEPTH];
    bool initialized;
} aern_relaysession_table;

/*!
 * \struct aern_fragment_part_state
 * \brief Heap-backed fragment part stored inside a dynamic fragment set.
 */
AERN_EXPORT_API typedef struct aern_fragment_part_state
{
    uint8_t* data;                                  /*!< Heap-backed fragment bytes */
    size_t datalen;                                 /*!< Number of valid fragment bytes */
    size_t capacity;                                /*!< Allocated fragment capacity in bytes */
    bool received;                                  /*!< True when this fragment index is present */
} aern_fragment_part_state;

/*!
 * \struct aern_fragment_cache
 * \brief Dynamic fragment set for one fragmented relay packet.
 */
AERN_EXPORT_API typedef struct aern_fragment_cache
{
    aern_fragment_part_state* parts;                /*!< Heap-backed part array */
    size_t partscap;                                /*!< Allocated number of part entries */
    size_t total_bytes;                             /*!< Running byte count of received fragments */
    size_t declared_length;                         /*!< Declared reassembled message length */
    uint64_t sessionid;                             /*!< Session identifier for this fragment set */
    uint64_t packetid;                              /*!< Packet identifier for this fragment set */
    uint64_t created;                               /*!< UTC creation time in seconds */
    uint64_t expiry;                                /*!< UTC expiration time in seconds */
    uint32_t total_frags;                           /*!< Expected fragment count; zero if unknown */
    uint32_t received_count;                        /*!< Number of distinct fragments received */
    uint16_t flags;                                 /*!< Bound relay payload flags */
    uint8_t payloadtype;                            /*!< Bound relay payload type */
    uint8_t reserved;                               /*!< Bound reserved header byte */
    bool metaset;                                   /*!< True when metadata has been bound */
    uint8_t direction;                              /*!< One of aern_relay_fragment_direction */
    bool complete;                                  /*!< True when all expected fragments are present */
} aern_fragment_cache;

/*!
 * \struct aern_fragment_table
 * \brief Dynamic fragment-set cache.
 */
AERN_EXPORT_API typedef struct aern_fragment_table
{
    aern_fragment_cache* sets;                      /*!< Heap-backed fragment-set array */
    size_t setscap;                                 /*!< Allocated number of set entries */
    size_t setscount;                               /*!< Number of active fragment sets */
    size_t memoryused;                              /*!< Approximate owned fragment payload bytes */
    size_t memorymax;                               /*!< Maximum owned fragment payload bytes */
    bool initialized;                               /*!< True when the set array is allocated */
} aern_fragment_table;

/*!
 * \struct aern_relay_cache_state
 * \brief Relay session, fragment, and ingress queue cache state.
 */
struct aern_relay_cache_state
{
    aern_relaysession_table sessions;               /*!< Fixed ingress/egress session metadata */
    aern_fragment_table fragments;                  /*!< Dynamic fragment-set cache */
    aern_relayqueue_state pendingqueue;             /*!< FIFO packets waiting for session-open acknowledgement */
    aern_relayqueue_state delayqueue;               /*!< FIFO packets held for optional randomized ingress delay */
    uint64_t relaytxbytes;                          /*!< Approximate relay bytes transmitted in the current window */
    uint64_t relayrxbytes;                          /*!< Approximate relay bytes received in the current window */
    uint64_t windowstartms;                         /*!< Traffic accounting window start time in milliseconds */
    uint64_t lastdummyms;                           /*!< Last dummy generation time in milliseconds */
    uint64_t nextdummyms;                           /*!< Next allowed dummy generation time in milliseconds */
    uint64_t dummywindowms;                         /*!< Dummy-packet accounting window start time in milliseconds */
    uint64_t dummysent;                             /*!< Number of dummy packets generated by this APS */
    uint64_t dummydropped;                          /*!< Number of terminal dummy packets discarded by this APS */
    uint64_t pendingreleased;                       /*!< Number of pending ingress packets released after acknowledgement */
    uint64_t pendingdropped;                        /*!< Number of expired or failed pending ingress packets discarded */
    uint64_t pendingoverflow;                       /*!< Number of pending or delay queue insertion failures */
    uint32_t dummywindowcount;                      /*!< Number of dummy packets generated in the current window */
    bool dummysuppressed;                           /*!< True when utilization hysteresis suppresses dummy generation */
    bool initialized;                               /*!< True when all backing containers were initialized */
};

/**
 * \brief Generate a random source-routed path through the topology.
 *
 * \param rm: [aern_route_map*] Output route map.
 * \param topocount: [uint16_t]  Number of APS nodes in the topology.
 * \param ownindex: [uint16_t]  Caller's zero-based APS topology ordinal.
 * 
 * \return Returns aern_protocol_error_none on success.
 * \note Spec reference: AERN-2025 Rev. 1a 4a.
 */
AERN_EXPORT_API aern_protocol_errors aern_route_generate(aern_route_map* rm, uint8_t apscount, uint8_t originhint, uint8_t targethint);

/**
 * \brief Serialise a route map into the 33-byte wire representation.
 *
 * Layout: path[0..15] = 16 one-byte route hints.
 * Route hints are serialized as one-based APS topology ordinals. Zero is reserved.
 *
 * \param dst: [uint8_t*] 16-byte output buffer.
 * \param rm: [aern_route_map*]  Route map to serialise.
 */
AERN_EXPORT_API void aern_route_map_serialize(uint8_t dst[AERN_ROUTEMAP_SIZE], const aern_route_map* rm);

/**
 * \brief Deserialise a 33-byte wire representation into a route map.
 *
 * \param rm: [aern_route_map*] Output route map.
 * \param src: [uint8_t*]  16-byte input buffer.
 */
AERN_EXPORT_API void aern_route_map_deserialize(aern_route_map* rm, const uint8_t src[AERN_ROUTEMAP_SIZE]);

/**
 * \brief Validate the minimum runtime prerequisites for relay forwarding.
 *
 * This function checks that the forward state contains a cipher table,
 * topology reference, valid APS topology count, and a valid local APS hint.
 * When requirecache is true, the relay cache must also be present and
 * initialized. The function performs no network action and does not mutate
 * state.
 *
 * \param fwd: [const aern_forward_state*] Forward state to validate.
 * \param requirecache: [bool] Require an initialized relay cache when true.
 * 
 * \return Returns true when the forward state is usable.
 */
AERN_EXPORT_API bool aern_relay_forward_state_is_valid(const aern_forward_state* fwd, bool requirecache);

/**
 * \brief Process one per-hop relay packet.
 *
 * Relay authentication failure discards the packet without advancing the
 * receive sequence number or parsing the encrypted route map. A single failed
 * relay packet does not invalidate the peer tunnel.
 *
 * \param fwd: [aern_forward_state*] Forward state.
 * \param wire: [uint8_t*] Raw 1500-byte wire buffer (decrypted in place).
 * \param srcip: [const char*] Source peer IP string.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_packet_forward(aern_forward_state* fwd, uint8_t wire[AERN_RELAY_MTU], const char* srcip);

/**
 * \brief Process a client-origin relay packet at the entry APS.
 *
 * The packet is decrypted using the synchronized client-to-entry APS tunnel,
 * a fresh route map is generated by the entry APS, the first hop is consumed,
 * and the packet is re-encrypted to the selected APS peer tunnel. The client
 * does not create the APS route map.
 *
 * \param fwd: [aern_forward_state*] Forward state.
 * \param wire: [uint8_t*] Raw 1500-byte wire buffer.
 * \param srcip: [const char*] Source client IP string.
 *
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_entry_packet_forward(aern_forward_state* fwd, uint8_t wire[AERN_RELAY_MTU], const char* srcip);

/**
 * \brief Serialize an encrypted relay payload header.
 *
 * \param output: [uint8_t*] AERN_RELAY_PAYLOAD_HEADER_SIZE-byte output buffer.
 * \param header: [const aern_relay_payload_header*]  Header to serialize.
 */
AERN_EXPORT_API void aern_relay_payload_header_serialize(uint8_t output[AERN_RELAY_PAYLOAD_HEADER_SIZE], const aern_relay_payload_header* header);

/**
 * \brief Deserialize an encrypted relay payload header.
 *
 * \param header: [aern_relay_payload_header*] Header receiving the decoded fields.
 * \param input: [uint8_t*] AERN_RELAY_PAYLOAD_HEADER_SIZE-byte input buffer.
 */
AERN_EXPORT_API void aern_relay_payload_header_deserialize(aern_relay_payload_header* header, const uint8_t input[AERN_RELAY_PAYLOAD_HEADER_SIZE]);

/**
 * \brief Serialize a session-open payload.
 *
 * \param output: [uint8_t*] AERN_RELAY_SESSION_OPEN_SIZE-byte output buffer.
 * \param state: [const aern_relay_session_open*]  Session-open structure to serialize.
 */
AERN_EXPORT_API void aern_relay_session_open_serialize(uint8_t output[AERN_RELAY_SESSION_OPEN_SIZE], const aern_relay_session_open* state);

/**
 * \brief Deserialize a session-open payload.
 *
 * \param state: [aern_relay_session_open*] Session-open structure receiving decoded fields.
 * \param input: [const uint8_t*] AERN_RELAY_SESSION_OPEN_SIZE-byte input buffer.
 */
AERN_EXPORT_API void aern_relay_session_open_deserialize(aern_relay_session_open* state, const uint8_t input[AERN_RELAY_SESSION_OPEN_SIZE]);

/**
 * \brief Serialize a session-open acknowledgement payload.
 *
 * \param output: [uint8_t*] AERN_RELAY_SESSION_OPEN_ACK_SIZE-byte output buffer.
 * \param state: [const aern_relay_session_open_ack*] Session-open acknowledgement structure to serialize.
 */
AERN_EXPORT_API void aern_relay_session_open_ack_serialize(uint8_t output[AERN_RELAY_SESSION_OPEN_ACK_SIZE], const aern_relay_session_open_ack* state);

/**
 * \brief Deserialize a session-open acknowledgement payload.
 *
 * \param state: [aern_relay_session_open_ack*] Session-open acknowledgement structure receiving decoded fields.
 * \param input: [const uint8_t*] AERN_RELAY_SESSION_OPEN_ACK_SIZE-byte input buffer.
 */
AERN_EXPORT_API void aern_relay_session_open_ack_deserialize(aern_relay_session_open_ack* state, const uint8_t input[AERN_RELAY_SESSION_OPEN_ACK_SIZE]);

/**
 * \brief Build a deterministic relay cache key for a relay fragment set.
 *
 * The key uses the selected Option-2 layout: bytes 0..7 contain sessionid,
 * bytes 8..14 contain the low 56 bits of packetid, and byte 15 contains the
 * direction value.
 *
 * \param key: [uint8_t*] AERN_RELAY_CACHE_KEY_SIZE-byte key buffer.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param packetid: [uint64_t] Packet identifier.
 * \param direction: [uint8_t] One of aern_relay_fragment_direction.
 */
AERN_EXPORT_API void aern_relay_fragment_key_create(uint8_t key[AERN_RELAY_CACHE_KEY_SIZE], uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Add or replace fragment-set metadata in the relay cache.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param entry: [const aern_relay_fragment_set_entry*] Fragment-set metadata to store.
 * 
 * \return Returns true if the entry is present after the operation.
 */
AERN_EXPORT_API bool aern_relay_fragment_set_add(aern_relay_cache_state* cache, const aern_relay_fragment_set_entry* entry);

/**
 * \brief Find fragment-set metadata in the relay cache.
 *
 * \param cache: [const aern_relay_cache_state*]  Relay cache state.
 * \param entry: [aern_relay_fragment_set_entry*] Fragment-set metadata receiving the result.
 * \param sessionid: [uint64_t]  Relay session identifier.
 * \param packetid: [uint64_t]  Packet identifier.
 * \param direction: [uint8_t]  One of aern_relay_fragment_direction.
 * 
 * \return Returns true if the entry was found.
 */
AERN_EXPORT_API bool aern_relay_fragment_set_find(const aern_relay_cache_state* cache, aern_relay_fragment_set_entry* entry, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Remove fragment-set metadata from the relay cache.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param packetid: [uint64_t] Packet identifier.
 * \param direction: [uint8_t] One of aern_relay_fragment_direction.
 */
AERN_EXPORT_API void aern_relay_fragment_set_remove(aern_relay_cache_state* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Dispose all relay cache containers and dynamic allocations.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state to dispose.
 */
AERN_EXPORT_API void aern_relay_cache_dispose(aern_relay_cache_state* cache);

/**
 * \brief Initialize all relay cache containers.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state to initialize.
 */
AERN_EXPORT_API void aern_relay_cache_initialize(aern_relay_cache_state* cache);

/**
 * \brief Expire stale relay sessions, fragment caches, pending packets, and delay-queue entries.
 *
 * This helper is the common lifecycle cleanup function for APS and client
 * relay caches. It removes expired pending session-open packets, stale ingress
 * delay entries, inactive relay sessions, and incomplete fragment reassembly
 * state whose timeout has elapsed. It also resets local relay traffic counters
 * when the configured accounting window has elapsed.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state to clean.
 */
AERN_EXPORT_API void aern_relay_cache_cleanup(aern_relay_cache_state* cache);

/**
 * \brief Pop a delayed ingress packet from the relay delay queue.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param item: [aern_ingress_pending_item*] Queue item receiving the packet.
 * 
 * \return Returns true if a packet was popped.
 */
AERN_EXPORT_API bool aern_relay_delay_pop(aern_relay_cache_state* cache, aern_ingress_pending_item* item);

/**
 * \brief Push a packet into the optional randomized ingress delay queue.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param item: [const aern_ingress_pending_item*] Queue item to enqueue.
 * 
 * \return Returns true if the item was queued.
 */
AERN_EXPORT_API bool aern_relay_delay_push(aern_relay_cache_state* cache, const aern_ingress_pending_item* item);

/**
 * \brief Flush due packets from the randomized ingress delay queue.
 *
 * This function releases packets whose delay timer has expired. Packets that
 * are not due remain queued. Expired packets are discarded. This queue is used
 * only for established ingress sessions; session-open and session-open-ack
 * messages are not delayed.
 *
 * \param fwd: [aern_forward_state*] Forwarding state containing the relay cache and APS mesh.
 * 
 * \return Returns aern_protocol_error_none when the flush completed.
 */
AERN_EXPORT_API aern_protocol_errors aern_ingress_delay_flush(aern_forward_state* fwd);

/**
 * \brief Pop an ingress packet waiting for session-open acknowledgement.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param item: [aern_ingress_pending_item*] Queue item receiving the packet.
 * 
 * \return Returns true if a packet was popped.
 */
AERN_EXPORT_API bool aern_relay_pending_pop(aern_relay_cache_state* cache, aern_ingress_pending_item* item);

/**
 * \brief Push an ingress packet while waiting for session-open acknowledgement.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param item: [const aern_ingress_pending_item*] Queue item to enqueue.
 * 
 * \return Returns true if the item was queued.
 */
AERN_EXPORT_API bool aern_relay_pending_push(aern_relay_cache_state* cache, const aern_ingress_pending_item* item);

/**
 * \brief Remove all pending and delayed ingress packets for a session.
 *
 * This function is used when a session-open acknowledgement fails or when a
 * pending ingress session is explicitly closed. It removes queued plaintext
 * relay packets for the specified session from both the session-open pending
 * queue and the randomized delay queue.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param sessionid: [uint64_t] Relay session identifier to purge.
 *
 * \return Returns the number of queued packets removed.
 */
AERN_EXPORT_API uint32_t aern_relay_pending_remove_session(aern_relay_cache_state* cache, uint64_t sessionid);

/**
 * \brief Build a deterministic relay cache key for a relay session.
 *
 * \param key: [uint8_t*] AERN_RELAY_CACHE_KEY_SIZE-byte key buffer.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param context: [uint8_t] Session context value.
 */
AERN_EXPORT_API void aern_relay_session_key_create(uint8_t key[AERN_RELAY_CACHE_KEY_SIZE], uint64_t sessionid, uint8_t context);

/**
 * \brief Add or replace relay session metadata in the relay cache.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param entry: [const aern_relay_session_cache_entry*] Session metadata to store.
 * 
 * \return Returns true if the entry is present after the operation.
 */
AERN_EXPORT_API bool aern_relay_session_add(aern_relay_cache_state* cache, const aern_relay_session_cache_entry* entry);

/**
 * \brief Test whether a relay session exists in the cache.
 *
 * \param cache: [const aern_relay_cache_state*] Relay cache state.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param context: [uint8_t] Session context value.
 * 
 * \return Returns true if the entry exists.
 */
AERN_EXPORT_API bool aern_relay_session_exists(const aern_relay_cache_state* cache, uint64_t sessionid, uint8_t context);

/**
 * \brief Find relay session metadata in the relay cache.
 *
 * \param cache: [const aern_relay_cache_state*] Relay cache state.
 * \param entry: [aern_relay_session_cache_entry*] Session metadata receiving the result.
 * \param sessionid: [uint64_t]  Relay session identifier.
 * \param context: [uint8_t] Session context value.
 * 
 * \return Returns true if the entry was found.
 */
AERN_EXPORT_API bool aern_relay_session_find(const aern_relay_cache_state* cache, aern_relay_session_cache_entry* entry, uint64_t sessionid, uint8_t context);

/**
 * \brief Remove relay session metadata from the relay cache.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param context: [uint8_t] Session context value.
 */
AERN_EXPORT_API void aern_relay_session_remove(aern_relay_cache_state* cache, uint64_t sessionid, uint8_t context);

/**
 * \brief Record observed relay traffic volume in the relay cache.
 *
 * This helper records approximate per-APS relay traffic volume for the dummy
 * traffic policy. It does not log addresses, payloads, sessions, or packet
 * contents. The values are only local counters used to decide whether dummy
 * traffic may be generated by the APS.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param pktlen: [size_t] Number of relay bytes observed.
 * \param inbound: [bool] True for received bytes, false for transmitted bytes.
 */
AERN_EXPORT_API void aern_relay_traffic_observe(aern_relay_cache_state* cache, size_t pktlen, bool inbound);

/**
 * \brief Estimate relay utilization for the current local traffic window.
 *
 * The returned value is a local percentage derived from the relay byte counters
 * and AERN_DUMMY_TRAFFIC_WINDOW_TARGET_BYTES. It is used only by APS dummy
 * traffic policy and does not expose packet contents, addresses, sessions, or
 * route metadata.
 *
 * \param cache: [const aern_relay_cache_state*] Relay cache state.
 *
 * \return Returns a utilization value in the inclusive range 0..100.
 */
AERN_EXPORT_API uint32_t aern_relay_traffic_utilization(const aern_relay_cache_state* cache);

/**
 * \brief Generate one APS dummy relay packet when policy allows.
 *
 * The dummy packet is a normal fixed-size authenticated relay packet. It is
 * routed through the APS mesh with a randomized route map, contains an
 * encrypted relay payload header with payload type aern_relay_payload_dummy,
 * and carries random encrypted payload bytes. Intermediate APS nodes forward
 * the packet identically to ordinary traffic. The terminal APS discards the
 * dummy payload without creating session state.
 *
 * \param fwd: [aern_forward_state*] Forwarding state containing APS topology, relay cache, and synchronized APS tunnel table.
 * \param utilization: [uint32_t] Approximate current utilization percentage.
 * 
 * \return Returns aern_protocol_error_none when the policy check completed.
 */
AERN_EXPORT_API aern_protocol_errors aern_dummy_traffic_generate(aern_forward_state* fwd, uint32_t utilization);

/**
 * \brief Register the backend callback used for egress destination delivery.
 *
 * Passing a NULL callback disables backend delivery and causes authenticated
 * egress packets to return a controlled non-success status. The callback is
 * not invoked until all relay authentication and session validation checks
 * have succeeded.
 *
 * \param callback: [aern_exit_transport_send_callback] Backend transmit callback, or NULL to disable.
 * \param context: [void*] Opaque backend context passed to the callback.
 */
AERN_EXPORT_API void aern_exit_transport_set_callback(aern_exit_transport_send_callback callback, void* context);

/**
 * \brief Register the backend callback used for ingress-side return delivery.
 *
 * Passing a NULL callback disables ingress delivery and causes authenticated
 * return packets to return a controlled non-success status. The callback is
 * not invoked until all relay authentication and ingress-session validation
 * checks have succeeded.
 *
 * \param callback: [aern_ingress_transport_send_callback] Backend return-delivery callback, or NULL to disable.
 * \param context: [void*] Opaque backend context passed to the callback.
 */
AERN_EXPORT_API void aern_ingress_transport_set_callback(aern_ingress_transport_send_callback callback, void* context);

/**
 * \brief Send an authenticated serialized packet through the egress transport abstraction.
 *
 * This function is the backend-neutral boundary between AERN relay processing
 * and the platform-specific destination transport. It validates the established
 * egress session metadata and opaque serialized packet length, then returns a
 * controlled status. Until a platform backend is attached, the function returns
 * a non-success status without pretending that destination delivery occurred.
 *
 * \param session: [const aern_relay_session_cache_entry*] Established egress session metadata.
 * \param header: [const aern_relay_payload_header*] Authenticated relay payload header.
 * \param packet: [const uint8_t*] Opaque serialized packet bytes.
 * \param pktlen: [size_t] Number of serialized packet bytes.
 * 
 * \return Returns aern_protocol_error_none only when a backend reports delivery.
 */
AERN_EXPORT_API aern_protocol_errors aern_exit_transport_send_serialized_packet(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen);

/**
 * \brief Submit a serialized destination response to the AERN return path.
 *
 * This helper is the backend-neutral response boundary for egress transport
 * implementations. A platform backend calls this function after it receives a
 * opaque serialized response from the destination. The function validates the
 * active egress session, copies the immutable callback session metadata, and
 * delegates to aern_return_packet_send() so response traffic is fragmented,
 * encrypted, and routed back to the ingress APS.
 *
 * \param fwd: [aern_forward_state*] Forwarding state for the egress APS.
 * \param session: [const aern_relay_session_cache_entry*] Active egress session metadata received by the backend callback.
 * \param packet: [const uint8_t*] Opaque serialized response packet bytes.
 * \param pktlen: [size_t] Number of serialized packet bytes.
 *
 * \return Returns aern_protocol_error_none on successful return relay submission.
 */
AERN_EXPORT_API aern_protocol_errors aern_exit_transport_return_serialized_packet(aern_forward_state* fwd, const aern_relay_session_cache_entry* session, const uint8_t* packet, size_t pktlen);

/**
 * \brief Send an authenticated return packet through the ingress client-transport abstraction.
 *
 * This function is the backend-neutral boundary between AERN ingress relay
 * processing and the local client delivery backend. It is called only after a
 * return relay payload has reached the ingress APS, the relay packet has been
 * authenticated, and the ingress session cache entry has been validated. Until
 * a platform client-delivery backend is attached, the function returns a
 * controlled non-success status without pretending delivery occurred.
 *
 * \param session: [const aern_relay_session_cache_entry*] Established ingress session metadata.
 * \param header: [const aern_relay_payload_header*] Authenticated relay payload header.
 * \param packet: [const uint8_t*] Opaque serialized packet bytes.
 * \param pktlen: [size_t] Number of serialized packet bytes.
 * 
 * \return Returns aern_protocol_error_none only when a backend reports delivery.
 */
AERN_EXPORT_API aern_protocol_errors aern_ingress_transport_send_serialized_packet(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen);

/**
 * \brief Build and send destination-to-client return relay packets.
 *
 * This helper is the return-path substrate used by a future destination
 * transport backend. The egress APS supplies the active egress session and a
 * opaque serialized response packet. The helper wraps the response in the
 * encrypted relay payload format, fragments it when required, marks the payload
 * as return traffic, and routes it back toward the ingress APS using a fresh
 * randomized route terminating at the ingress route hint.
 *
 * \param fwd: [aern_forward_state*] Forwarding state.
 * \param session: [aern_relay_session_cache_entry*] Active egress session metadata. The helper updates return counters and activity.
 * \param packet: [const uint8_t*] Opaque serialized response packet bytes.
 * \param pktlen: [size_t] Number of serialized packet bytes.
 * 
 * \return Returns aern_protocol_error_none on successful relay submission.
 */
AERN_EXPORT_API aern_protocol_errors aern_return_packet_send(aern_forward_state* fwd, aern_relay_session_cache_entry* session, const uint8_t* packet, size_t pktlen);

/**
 * \brief Initialise a fragment cache.
 * 
 * \param cache: [aern_fragment_cache*] Cache to initialise.
 */
AERN_EXPORT_API void aern_fragment_cache_initialize(aern_fragment_cache* cache);

/**
 * \brief Add a fragment packet to the reassembly cache.
 *
 * \param cache: [aern_fragment_cache*] Fragment cache.
 * \param data: [const uint8_t*] Fragment payload (user bytes only, no route header).
 * \param dlen: [size_t] Length of data.
 * \param seq: [uint32_t] Fragment sequence (1-indexed; UINT32_MAX = last for legacy callers).
 * 
 * \return Returns true if the message is now complete (all fragments received).
 */
AERN_EXPORT_API bool aern_fragment_cache_add(aern_fragment_cache* cache, const uint8_t* data, size_t dlen, uint32_t seq);

/**
 * \brief Add an out-of-order fragment with an explicit fragment count.
 *
 * This helper is the preferred relay-fragment API for AERN session-aware payloads. 
 * Fragments are cached by sequence number and the cache is marked
 * complete only when all fragments from one through \p fragcount are present. Non-final fragments in a multi-fragment packet must be exactly AERN_FRAG_CHUNK_SIZE bytes.
 *
 * \param cache: [aern_fragment_cache*] Fragment cache.
 * \param data: [const uint8_t*] Fragment payload bytes.
 * \param dlen: [size_t] Fragment payload length.
 * \param fragseq: [uint32_t] Fragment sequence. Zero means unfragmented.
 * \param fragcount: [uint32_t] Total fragment count. Zero means unfragmented.
 * 
 * \return Returns true when the full packet has been received.
 */
AERN_EXPORT_API bool aern_fragment_cache_add_fragment(aern_fragment_cache* cache, const aern_relay_payload_header* header, const uint8_t* data, size_t dlen, uint8_t direction, bool* complete);

/**
 * \brief Set the session key fields for a fragment cache entry.
 *
 * \param cache: [aern_fragment_cache*] Fragment cache.
 * \param sessionid: [uint64_t] Session identifier.
 * \param packetid: [uint64_t] Packet identifier.
 * \param direction: [uint8_t] Fragment direction.
 * \param expiry: [uint64_t] UTC expiration time in seconds.
 */
AERN_EXPORT_API void aern_fragment_cache_set_key(aern_fragment_cache* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction, uint64_t expiry);

/**
 * \brief Assemble all received fragments into a contiguous buffer.
 *
 * \param cache: [const aern_fragment_cache*] Fragment cache (must have complete == true).
 * \param output: [uint8_t*] Output buffer (must be >= cache->total_bytes).
 * \param outlen: [size_t*] Receives the assembled length.
 */
AERN_EXPORT_API void aern_fragment_cache_assemble(const aern_fragment_cache* cache, uint8_t* output, size_t* outlen);

/**
 * \brief Zero and reset the fragment cache.
 * 
 * \param cache: [aern_fragment_cache*] Cache to clear.
 */
AERN_EXPORT_API void aern_fragment_cache_clear(aern_fragment_cache* cache);

/**
 * \brief Add or replace a complete fragment reassembly cache entry.
 *
 * The entry is keyed using the same Option-2 key layout as the fragment-set
 * metadata: sessionid, low 56 bits of packetid, and direction. This helper
 * stores the full out-of-order reassembly state, including received flags and
 * fragment payload bytes.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param entry: [const aern_fragment_cache*] Fragment cache entry to store.
 * 
 * \return Returns true if the entry is present after the operation.
 */
AERN_EXPORT_API bool aern_relay_fragment_cache_add(aern_relay_cache_state* cache, const aern_fragment_cache* entry);

/**
 * \brief Find a complete fragment reassembly cache entry.
 *
 * \param cache: [const aern_relay_cache_state*] Relay cache state.
 * \param entry: [aern_fragment_cache*] Fragment cache entry receiving the result.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param packetid: [uint64_t] Packet identifier.
 * \param direction: [uint8_t] One of aern_relay_fragment_direction.
 * 
 * \return Returns true if the entry was found.
 */
AERN_EXPORT_API bool aern_relay_fragment_cache_find(const aern_relay_cache_state* cache, aern_fragment_cache* entry, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Remove a complete fragment reassembly cache entry.
 *
 * \param cache: [aern_relay_cache_state*] Relay cache state.
 * \param sessionid: [uint64_t] Relay session identifier.
 * \param packetid: [uint64_t] Packet identifier.
 * \param direction: [uint8_t] One of aern_relay_fragment_direction.
 */
AERN_EXPORT_API void aern_relay_fragment_cache_remove(aern_relay_cache_state* cache,  uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Pad a plaintext buffer to AERN_RELAY_PLAINTEXT_SIZE bytes.
 *
 * Writes a 2-byte LE actual_len prefix at position 0, then fills bytes
 * (2 + actual_len)..(AERN_RELAY_PLAINTEXT_SIZE - 1) with CSPRNG bytes.
 * The routemap at bytes [2..34] is written by the caller before this call
 * (or after — the padding does not touch the routemap region unless actual_len
 * extends into it, which it does not by construction).
 *
 * \param plaintext: [uint8_t*] Buffer of AERN_RELAY_PLAINTEXT_SIZE bytes.
 * \param textlen: [uint16_t] Real content length (0..AERN_MAX_USER_PAYLOAD).
 */
AERN_EXPORT_API void aern_packet_pad(uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint16_t textlen);

/**
 * \brief Recover the actual payload length from a padded plaintext buffer.
 *
 * Reads the 2-byte LE prefix written by aern_packet_pad.
 *
 * \param plaintext: [const uint8_t*] Buffer of AERN_RELAY_PLAINTEXT_SIZE bytes.
 * 
 * \return The actual content length, or 0 if the value is out of range.
 */
AERN_EXPORT_API uint16_t aern_packet_unpad(const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE]);

#endif

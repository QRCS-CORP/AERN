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

#ifndef AERN_DOXYMAIN_H
#define AERN_DOXYMAIN_H

/**
 * \mainpage Authenticated Encrypted Relay Network (AERN)
 *
 * \section intro_sec Introduction
 *
 * The Authenticated Encrypted Relay Network (AERN) is a certificate-anchored,
 * post-quantum relay protocol for controlled anonymity and authenticated private
 * transport domains. AERN is designed for managed infrastructures in which relay
 * nodes are admitted by certificate, topology membership is administered by a
 * domain controller, and data-plane packets traverse pre-established symmetric
 * tunnels between authenticated proxy servers. The protocol is intended to
 * provide authenticated participation, encrypted relay metadata, fixed-size
 * packet transport, strict replay rejection, bounded traffic shaping, and a
 * backend-neutral transport boundary.
 *
 * AERN is not a public volunteer relay system. It is a controlled-domain relay
 * fabric that can be deployed as a private anonymous VPN substrate, institutional
 * relay network, sovereign communications fabric, or regulated post-quantum
 * transport domain. Its anonymity properties are conditional on the controlled
 * deployment model, honest topology distribution, and the absence of simultaneous
 * compromise or precise observation of the relevant ingress and egress
 * correlation points.
 *
 * \section role_sec Protocol Entities
 *
 * \subsection ars_sec AERN Root Security (ARS)
 *
 * The ARS is the root trust anchor for an AERN domain. It generates and stores
 * the root signing key, creates the root certificate, and signs child
 * certificates. The ARS signing key is retained only by the ARS. A deployment may
 * isolate the ARS and expose only a restricted remote-signing path through the
 * ADC. ARS compromise affects future identity trust, but does not by itself
 * reveal completed tunnel keys after exchange material and active symmetric
 * state have been erased.
 *
 * \subsection adc_sec AERN Domain Controller (ADC)
 *
 * The ADC is the certified administrative authority for the domain. It validates
 * root-signed device certificates, manages registration and revocation,
 * maintains the versioned topology list, signs topology and control messages,
 * distributes APS topology state to clients and proxies, and coordinates
 * convergence and administrative updates. ADC compromise affects topology
 * integrity, revocation, availability, and route-set bias.
 *
 * \subsection aps_sec AERN Proxy Server (APS)
 *
 * APS nodes are authenticated relay servers. A synchronized APS maintains local
 * topology state, certificate caches, peer tunnel state, relay-session state,
 * fragment reassembly state, pending queues, optional ingress-delay queues,
 * dummy-traffic accounting, and backend callback context. APS nodes may act as
 * ingress, forwarding relay, egress, or return-path terminal for a relay session.
 *
 * \subsection acd_sec AERN Client Device (ACD)
 *
 * A client registers or joins through the ADC, receives an authenticated APS
 * topology, selects an entry APS, and establishes an encrypted tunnel to that
 * entry node. Client traffic is serialized and treated as opaque backend data by
 * the relay core.
 *
 * \section init_sec Network Initialization
 *
 * A conforming AERN domain is initialized in the following order:
 *
 * 1. Initialize the ARS, generate the ARS signing key pair, create the root
 *    certificate, and verify the serialized root-certificate self-hash.\n
 * 2. Initialize the ADC, generate the ADC signing key pair and child
 *    certificate, have the ARS sign the ADC certificate, and initialize ADC
 *    topology, certificate-cache, and administrative state.\n
 * 3. Initialize APS nodes. Each APS generates its signing key pair and
 *    certificate, obtains a root signature directly or through the remote-signing
 *    path, registers with the ADC, obtains ADC-authenticated topology, exchanges
 *    certificates with peers, and establishes APS-to-APS symmetric tunnel state.\n
 * 4. Initialize clients. Each client obtains a signed certificate, registers or
 *    joins through the ADC, receives the current APS topology, selects an entry
 *    APS, and establishes a client-to-entry tunnel.
 *
 * Once APS nodes have synchronized topology, cached peer certificates, and
 * established directional tunnel state with their peers, the AERN relay fabric is
 * ready to carry serialized backend traffic.
 *
 * \section relay_sec Relay Packet Model
 *
 * AERN relay transport uses fixed-size 1500-byte wire packets. The active relay
 * packet is composed of a visible authenticated outer tunnel header and an
 * authenticated encrypted ciphertext region. The outer header is adjacent-peer
 * metadata only; it carries the packet flag, ciphertext length, sequence number,
 * UTC creation timestamp, and reserved alignment byte. The header is serialized
 * and authenticated as associated data by the tunnel cipher.
 *
 * The encrypted relay plaintext contains the relay-layer state:
 *
 * - a two-byte used-length prefix;
 * - a sixteen-byte consumed-path route array;
 * - a thirty-two-byte relay payload header;
 * - a relay body and padding.
 *
 * Route hints, session identifiers, packet identifiers, fragment metadata,
 * payload type, reserved relay byte, return flag, and backend payload bytes are
 * all inside the encrypted relay plaintext. They are not transmitted as clear
 * relay metadata.
 *
 * \section route_sec Route Maps and Forwarding
 *
 * AERN uses compact route hints rather than clear addresses in relay packets.
 * Each route hint is a one-byte, one-based ordinal into the synchronized APS
 * topology list. The value zero is reserved as an empty or consumed route value.
 * This encoding limits a single active route-addressable domain to 255 APS
 * ordinals. Larger deployments require topology partitioning, route-domain
 * sharding, or a future extended-hint profile.
 *
 * The serialized route map is a sixteen-byte consumed-path array. The first byte
 * identifies the route origin. The remaining bytes contain ordered future-hop
 * hints. A forwarding APS authenticates and decrypts the tunnel packet, parses
 * the encrypted route path, resolves the first nonzero future-hop hint, clears
 * that consumed entry, reserializes the route path, and forwards the packet under
 * the tunnel shared with the next APS. If no future-hop entry remains, the packet
 * is terminal for the current traversal direction.
 *
 * \section session_sec Relay Sessions and Backend Boundary
 *
 * AERN uses explicit ingress-to-egress relay sessions. On the first outbound
 * serialized payload for a destination, the ingress APS creates a pending session
 * entry and sends a session-open payload to the selected egress APS. Non-dummy
 * data is held in a pending queue until a valid session-open acknowledgement is
 * accepted for the same session identifier and egress context. The egress creates
 * an active session only after accepting the authenticated session-open payload.
 *
 * Backend transport is deliberately outside the cryptographic relay core. The
 * relay core authenticates, decrypts, validates route and session state,
 * reassembles fragments when required, classifies direction, and invokes the
 * configured egress or ingress callback. The callback may bind to a TUN or TAP
 * interface, raw socket path, userspace network stack, application adapter, or
 * test backend. Backend implementations shall not expose relay metadata through
 * logs or external interfaces.
 *
 * \section frag_sec Fragmentation and Reassembly
 *
 * Fragmentation is performed at the encrypted relay payload layer. Fragment
 * metadata is carried in the encrypted relay payload header and is accepted only
 * after the enclosing tunnel packet has authenticated and decrypted. Reassembly
 * is bound to the session identifier, packet identifier, direction flag, payload
 * type, reserved byte, fragment count, fragment sequence, and reconstructed
 * length. Incomplete or inconsistent fragment sets are discarded and must not
 * invoke backend delivery.
 *
 * \section dummy_sec Dummy Traffic and Ingress Delay
 *
 * AERN supports bounded dummy relay traffic and optional randomized ingress
 * delay. Dummy packets use ordinary fixed-size relay packets, tunnel
 * authentication, route processing, and terminal discard. They do not invoke
 * backend callbacks. Dummy generation is controlled by local utilization policy
 * with floor, ceiling, interval, accounting-window, and per-window emission
 * limits. Ingress delay adds bounded local timing uncertainty before outbound
 * packets enter the APS mesh. These mechanisms mitigate sparse-flow timing and
 * traffic-volume observation but do not provide mixnet-grade anonymity against a
 * fully global timing adversary.
 *
 * \section crypto_sec Cryptographic Components
 *
 * AERN uses post-quantum asymmetric primitives for certificate authentication
 * and tunnel establishment, and symmetric authenticated encryption for the data
 * plane. Supported configurations include ML-KEM/Kyber or McEliece for key
 * encapsulation and ML-DSA/Dilithium or SPHINCS+ for signatures. SHA3, SHAKE,
 * and KMAC are used for hashing, derivation, and authentication support. RCS is
 * used as the authenticated symmetric tunnel cipher in the current AERN profile.
 *
 * Tunnel receive authentication is transactional. On packet authentication
 * failure, the receive-side RCS authentication state is restored, the receive
 * sequence is not advanced, the plaintext buffer is cleared, and the authentication
 * failure counter is incremented. Repeated authentication failures reach the
 * configured channel-down threshold.
 *
 * \section admin_sec Administrative Message Families
 *
 * AERN defines signed administrative and control-message families for announce,
 * convergence, topology update, incremental certificate retrieval, fragment-key
 * exchange, MFK/MEK exchange, registration, register update, remote signing,
 * resignation, revocation, join, topological query, and topological status. Each
 * accepted control message is bound to certificate state, role authorization,
 * freshness, sequence policy where applicable, and the relevant topology or
 * certificate constraints.
 *
 * \section file_sec Primary Modules
 *
 * - aern.h: public constants, enumerations, structures, and core API types.\n
 * - admin.h: administrative utility and command support.\n
 * - ars.h: root trust-anchor initialization and certificate-signing support.\n
 * - adc.h: domain-controller state, registration, topology, and control logic.\n
 * - aps.h: proxy-server state, synchronization, and peer tunnel support.\n
 * - client.h: client registration, join, and entry-tunnel support.\n
 * - certificate.h: root and child certificate encoding, decoding, signing, and validation.\n
 * - network.h: administrative/control-message serialization and processing.\n
 * - topology.h: topology-node and topology-list management.\n
 * - mek.h: tunnel key exchange, key derivation, and rekey policy support.\n
 * - route.h: relay packet construction, forwarding, route handling, and backend delivery.\n
 * - relaysession.h: relay session cache and session lifecycle state.\n
 * - relayqueue.h: pending and delay queue support.\n
 * - fragment.h: relay fragmentation and reassembly support.\n
 * - backend.h: backend callback interface for egress and ingress delivery.
 *
 * \section validation_sec Validation Status
 *
 * The current virtual-network validation campaign builds and runs under GCC and
 * Clang, exercises ARS, ADC, APS, client, control-message, tunnel, relay-session,
 * fragmentation, dummy-traffic, ingress-delay, backend, replay, timestamp,
 * sequence, and 4-APS encrypted multi-hop profiles, and completes the Address
 * Sanitizer profile. Extended sanitizer review of QSC Kyber-derived modular
 * arithmetic is tracked separately from AERN functional validation.
 *
 * \section usage_sec Operational Outline
 *
 * 1. Generate and protect the ARS root signing key and root certificate.\n
 * 2. Generate the ADC certificate and have the ARS sign it.\n
 * 3. Start the ADC and initialize versioned topology and certificate-cache state.\n
 * 4. Generate and sign APS certificates, register APS nodes, synchronize topology,
 *    exchange peer certificates, and establish APS-to-APS tunnels.\n
 * 5. Register or join clients through the ADC and establish the client-to-entry
 *    tunnel.\n
 * 6. Configure egress and ingress backend callbacks and begin fixed-size relay
 *    packet transport.
 *
 * \author QRCS Corporation
 * \date 2026-05-21
 */

#endif

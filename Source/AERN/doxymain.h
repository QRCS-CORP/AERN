#ifndef AERN_DOXYMAIN_H
#define AERN_DOXYMAIN_H

/**
 * \mainpage Authenticated Encrypted Relay Network (AERN)
 *
 * \section intro_sec Introduction
 *
 * AERN is an authenticated, encrypted proxy-chaining protocol that forms a fully
 * meshed “cloud” of proxy servers to provide secure, anonymous communications.
 * Proxies perform asymmetric key exchange to derive shared secrets, then operate
 * bi-directional symmetric tunnels for data forwarding. Clients enter the mesh
 * by selecting an entry node at random from a controller-provided list and
 * establishing an encrypted tunnel to it. Routes are built as randomized proxy
 * circuits, enabling strong metadata resistance. \n
 * (See: Introduction and network overview.)
 *
 * \section arch_sec Architecture and Roles
 *
 * \subsection ars_sec AERN Root Security (ARS)
 * Trust anchor that signs device certificates used for authentication across the mesh.
 *
 * \subsection adc_sec AERN Domain Controller (ADC)
 * Manages device registration, certificate validation, topology distribution,
 * and revocation; returns the authenticated proxy list to clients.
 *
 * \subsection aps_sec AERN Proxy Server (APS)
 * Authenticated server participating in a full-mesh; maintains per-peer tunnels,
 * forwards encrypted traffic, and can serve as entry, intermediate, or exit node.
 *
 * \subsection acd_sec AERN Client Device (ACD)
 * Authenticated endpoint that registers to obtain the proxy list, selects an
 * entry node, performs key exchange, and transmits via the proxy mesh.
 *
 * \section proto_sec Protocol Overview
 *
 * \subsection join_sec Registration and Entry
 * Clients register with the ADC, which verifies certificates and returns a
 * signed, hashed proxy list. The client chooses an entry proxy at random and
 * performs an asymmetric key exchange to derive a shared secret. The shared
 * secret is expanded (SHAKE) into RCS keys/nonces for a duplex symmetric tunnel.
 *
 * \subsection routing_sec Route Maps and Forwarding
 * For each message flow, the entry node composes a route map: a randomized
 * sequence of proxy “hints” (16-bit indices into the shared topology list).
 * The map and packet are encrypted; at each hop the next destination is looked
 * up and the payload (including header fields) is re-encrypted and forwarded.
 * Entry/exit nodes remain fixed for the session; intermediate hops are varied.
 *
 * \subsection pkt_sec Framing and Header
 * AERN uses a fixed 1500-byte MTU frame. The inter-proxy packet format (54-byte
 * header + payload) includes: message/flag type, sequence number, fragment
 * sequence, encrypted route map, and UTC timestamp used for anti-replay. Larger
 * messages are fragmented and reassembled at exit/client as required.
 *
 * \section crypto_sec Cryptographic Primitives
 *
 * Asymmetric: Kyber/ML-KEM and McEliece for KEM; Dilithium or SPHINCS+ for
 * signatures. \n
 * Symmetric: RCS AEAD stream cipher for tunnels. \n
 * Hash/KDF/MAC: SHA3-512, SHAKE, and KMAC for hashing, expansion, and
 * authentication. Asymmetric operations are limited to registration and
 * session setup; the data plane is symmetric for efficiency.
 *
 * \section filesec_sec Files and Modules
 *
 * - aern.h        : Public API, constants, enums, and structures.
 * - aern_client.h : Client initialization and tunnel establishment.
 * - aern_proxy.h  : Proxy synchronization, per-peer tunnels, forwarding.
 * - aern_ctrl.h   : Domain controller functions (registration, topology).
 * - aern_crypto.h : KEM, signatures, KDF/MAC wrappers (QSC primitives).
 * - aern_net.h    : Packet structure, route-map handling, fragmentation.
 *
 * \section usage_sec Getting Started
 *
 * 1) Deploy ARS (root) and ADC (domain controller); provision certificates. \n
 * 2) Start proxies; synchronize topology and derive per-peer symmetric tunnels. \n
 * 3) Register clients through ADC; obtain the signed proxy list. \n
 * 4) Client selects entry node at random, performs KEX, and sends traffic via
 *    randomized multi-hop route maps.
 *
 * \author QRCS Corporation
 * \date 2025-11-06
 */

#endif

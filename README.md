# AERN: Authenticated Encrypted Relay Network

## Introduction 

[![Build](https://github.com/QRCS-CORP/AERN/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/AERN/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/AERN/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/AERN/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/aern/badge)](https://www.codefactor.io/repository/github/qrcs-corp/aern)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/AERN/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/AERN/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/AERN/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/AERN)](https://github.com/QRCS-CORP/AERN/releases)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/AERN.svg)](https://github.com/QRCS-CORP/AERN/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**AERN** is an authenticated encrypted relay protocol for controlled anonymity domains. It provides certificate-anchored node admission, a managed proxy topology, post-quantum-capable tunnel establishment, fixed-size encrypted relay packets, encrypted route metadata, explicit ingress-to-egress relay sessions, encrypted fragmentation metadata, optional dummy traffic, randomized ingress delay, and backend-neutral transport callbacks.

AERN is designed for private, administered relay domains rather than open volunteer-node operation. The network is composed of a root trust anchor, a domain controller, authenticated proxy servers, authenticated clients, and local backend adapters. Regular relay traffic is carried by symmetric authenticated tunnel states derived from authenticated asymmetric key exchanges.

[AERN Help Documentation](https://qrcs-corp.github.io/AERN/)  
[AERN Protocol Specification](https://qrcs-corp.github.io/AERN/pdf/aern_specification.pdf)  
[AERN Summary Document](https://qrcs-corp.github.io/AERN/pdf/aern_summary.pdf)  
[AERN Formal Analysis](https://qrcs-corp.github.io/AERN/pdf/aern_formal.pdf)  
[RCS Formal Analysis](https://qrcscorp.ca/documents/rcs_formal.pdf)  

> This repository provides the C-language reference implementation of the AERN protocol, developed by QRCS – Quantum Resistant Cryptographic Solutions Corporation.

## Protocol Summary

AERN uses a controlled proxy mesh. Each APS proxy server is certified by the ARS root trust anchor and registered through the ADC domain controller. APS nodes synchronize topology state, exchange certificates, and establish authenticated peer tunnels with other APS nodes in the relay domain. Each peer tunnel maintains independent transmit and receive RCS cipher states and strict per-direction sequence counters.

A client obtains the authenticated APS topology from the ADC, selects an entry APS, and establishes an authenticated encrypted client-to-entry tunnel. The ingress APS creates a logical relay session to an egress APS and sends an encrypted session-open payload before releasing queued non-dummy data. The egress APS validates the session-open payload and returns an encrypted acknowledgement. Backend delivery occurs only after authenticated relay processing, session validation, and fragment reassembly where required.

Relay routes are expressed as compact one-byte APS route hints into the topology-sorted APS list. Route hints are serialized inside the encrypted relay plaintext and are not transmitted as clear relay header fields. Each relay packet uses a consumed-next-hop route path. An intermediate APS decrypts and authenticates the per-hop tunnel packet, consumes the next future-hop entry inside the encrypted relay state, reserializes the relay plaintext, and forwards the packet to the next APS through the corresponding authenticated tunnel.

## Architecture Overview

| Component | Role | Primary Responsibility |
|----------|------|------------------------|
| **ARS** | AERN Root Security server | Root trust anchor; generates and protects the root signing key; signs child certificates directly or through a controlled remote-signing path. |
| **ADC** | AERN Domain Controller | Domain control authority; manages registration, topology, revocation, convergence, topology queries, remote signing requests, and administrative control messages. |
| **APS** | AERN Proxy Server | Authenticated relay node; maintains APS peer tunnels, relay session state, fragment cache state, pending and delay queues, dummy traffic policy, and backend callback bindings. |
| **ACD** | AERN Client Device | Authenticated client endpoint; registers or joins the domain, obtains APS topology, selects an entry APS, and submits serialized traffic into the relay domain. |
| **Backend Adapter** | Local integration boundary | Receives authenticated, session-valid, reassembled serialized packets and connects AERN to a TUN/TAP device, raw socket path, userspace transport stack, or application adapter. |

## Security Model

AERN is built around authenticated membership and controlled topology. Device identities are represented by root-signed certificates. Administrative messages are authenticated by role-specific certificates and freshness metadata. Relay packets are protected by symmetric authenticated encryption, strict sequencing, and timestamp validation.

The protocol security goals include:

- certificate-anchored node admission;
- authenticated topology and revocation control;
- post-quantum-capable tunnel establishment;
- per-hop tunnel confidentiality and integrity;
- encrypted route-path and relay-session metadata;
- strict replay rejection for APS tunnel packets;
- explicit relay-session establishment before backend delivery;
- encrypted fragmentation metadata and bounded reassembly;
- backend-boundary separation;
- traffic-analysis mitigation by fixed-size packets, per-packet route variation, optional dummy traffic, and randomized ingress delay.

AERN is a low-latency controlled relay system. Dummy traffic and randomized ingress delay reduce deterministic timing linkage but are not represented as a complete defense against a fully global timing adversary.

## Cryptographic Dependencies

AERN uses the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC) for cryptographic primitives, encoding utilities, networking support, and low-level platform services.

| Primitive or Service | AERN Use |
|---------------------|----------|
| **SHA-3 / SHAKE** | Hashing, extendable-output derivation, certificate and message hashing, and key derivation support. |
| **KMAC** | SHA-3-derived message authentication where required by protocol components and supporting infrastructure. |
| **RCS** | Authenticated symmetric stream cipher used for APS-to-APS and client-to-entry tunnel packet encryption. |
| **Kyber / ML-KEM** | Post-quantum KEM option for authenticated tunnel establishment. |
| **Classic McEliece** | Code-based post-quantum KEM option for tunnel establishment profiles. |
| **Dilithium / ML-DSA** | Post-quantum signature option for certificates and signed protocol messages. |
| **SPHINCS+ / SLH-DSA family** | Hash-based signature option for certificate and message authentication profiles. |
| **CSP / DRBG support** | Random serials, route selection, session identifiers, packet identifiers, dummy payloads, and key material generation. |

## Relay Packet Model

AERN relay traffic uses a fixed 1500-byte wire packet. The visible outer tunnel header is authenticated as associated data. Route state, relay-session state, fragment metadata, payload type, return flag, and backend payload bytes are encrypted inside the relay plaintext.

| Field | Size | Visibility | Description |
|------|------|------------|-------------|
| Relay wire packet | 1500 bytes | Wire-visible length | Fixed MTU relay transmission unit. |
| Outer tunnel header | 22 bytes | Visible but authenticated | Contains packet flag, ciphertext length, sequence number, UTC timestamp, and reserved header byte. |
| Ciphertext region | 1478 bytes | Opaque | Authenticated encrypted tunnel payload and authentication material. |
| Relay plaintext | 1446 bytes | Visible only after successful tunnel authentication | Contains length prefix, route path, relay payload header, body, and padding. |
| Length prefix | 2 bytes | Encrypted | Used relay payload length after the route path. |
| Route path | 16 bytes | Encrypted | Consumed-next-hop route path using one-byte APS hints. |
| Relay payload header | 32 bytes | Encrypted | Session identifier, packet identifier, fragment metadata, payload type, reserved byte, and flags. |
| Data payload per fragment | 1396 bytes | Encrypted | Maximum opaque serialized packet bytes carried in one relay fragment. |

The compact route profile uses one-byte route hints. Hint value zero is reserved as the route terminator and unused-slot value. A single compact route-addressable APS domain therefore supports up to 255 APS ordinals.

## Relay Sessions, Fragmentation, and Backend Delivery

AERN uses explicit ingress-to-egress relay sessions. The ingress creates a pending session, sends a 36-byte encrypted session-open payload, and queues non-dummy data until a 12-byte encrypted session-open acknowledgement is accepted. If the acknowledgement is not accepted before the session-open timeout, pending data is discarded and the session-open attempt fails.

Fragmentation is performed inside the encrypted relay payload layer. Each fragment carries the same session identifier and packet identifier, while the fragment sequence, fragment count, length, payload type, reserved byte, and direction flag remain encrypted. A terminal APS inserts fragments into the reassembly cache only after successful tunnel authentication and relay-header validation. Backend delivery occurs once, after the fragment set is complete, consistent, and bound to the active relay session.

The backend interface is a callback boundary. The relay core authenticates, decrypts, validates, reassembles, and classifies serialized packets. The backend adapter performs external transport integration and must not expose route paths, session identifiers, packet identifiers, fragment identifiers, or payload contents through ordinary operational logs.

## Traffic Shaping and Replay Policy

AERN uses strict next-sequence processing for ordered APS tunnels. The replay window size is zero. A packet is accepted only if the authenticated sequence number equals the next expected receive sequence, the timestamp is within the configured threshold, and tunnel authentication succeeds.

AERN also defines local traffic-analysis controls:

| Control | Default Policy |
|---------|----------------|
| Dummy traffic | Enabled. Dummy relay packets are fixed-size, encrypted, route-processed, and discarded at the terminal APS without backend delivery. |
| Dummy bandwidth floor | 10 percent local utilization. |
| Dummy bandwidth ceiling | 25 percent local utilization. |
| Dummy interval | Randomized generation attempts between 50 and 250 milliseconds. |
| Dummy accounting window | 1000 milliseconds, with a target based on 128 MTU-sized packets. |
| Dummy cap | Maximum of 8 dummy packets per accounting window. |
| Ingress delay | Enabled. Outbound packets may be delayed by 0 to 25 milliseconds before mesh injection. |
| Packet freshness threshold | 60 seconds by default. |
| Relay authentication failure limit | 8 failures per peer tunnel policy threshold. |

## Source Layout

| File or Module | Description |
|---------------|-------------|
| `aern.h` | Primary constants, public protocol types, role identifiers, packet sizes, certificate sizes, policy constants, and exported API declarations. |
| `certificate.c` / `certificate.h` | Root and child certificate generation, serialization, decoding, signing, verification, hash binding, and text encoding. |
| `topology.c` / `topology.h` | Topology node/list management, sorted topology state, versioned topology handling, topology hashing, stale-version checks, and topology queries. |
| `network.c` / `network.h` | Administrative network message families, message serialization, signing, verification, freshness checking, and role-to-role control exchanges. |
| `mek.c` / `mek.h` | Master encryption key exchange, peer tunnel synchronization state, key derivation, cipher-state installation, and peer tunnel renewal policy. |
| `route.c` / `route.h` | Route generation, relay packet construction, packet forwarding, session-open handling, return-path processing, dummy packet generation, and backend callback delivery. |
| `relaysession.c` / `relaysession.h` | Relay session cache state, session status transitions, ingress and egress session lookup, timeout handling, and session teardown. |
| `relayqueue.c` / `relayqueue.h` | Pending session queue and randomized ingress delay queue management. |
| `fragment.c` / `fragment.h` | Encrypted relay-payload fragmentation, fragment-cache insertion, out-of-order reassembly, timeout cleanup, and fragment integrity checks. |
| `ars.c` / `ars.h` | ARS role processing and root-security server operations. |
| `adc.c` / `adc.h` | ADC role processing, topology control, registration handling, revocation, convergence, and remote signing support. |
| `aps.c` / `aps.h` | APS role processing, proxy service behavior, relay ingress/egress handling, and peer tunnel operation. |
| `client.c` / `client.h` | Client registration, join, entry-node connection, and client tunnel processing. |
| `server.c` / `server.h` | Shared service runtime and network service coordination. |
| `admin.c` / `admin.h` | Administrative helpers, command support, address utilities, jittered transmission, and console-facing support functions. |
| `logger.c` / `logger.h` | Encrypted logging and operational log utilities. |
| `lifecycle.c` / `lifecycle.h` | Runtime lifecycle, cleanup, teardown, and service-state support. |
| `menu.c`, `help.c`, `commands.h` | Interactive console command interface and help text. |
| `AERNTest` | Companion validation project for certificates, topology, administrative messages, relay routing, queues, fragmentation, replay handling, dummy traffic, backend delivery, and virtual-network execution. |

## Operational Deployment Model

A typical AERN domain is initialized in the following order:

1. Initialize the ARS and generate the root certificate.
2. Generate and sign the ADC certificate.
3. Start the ADC and configure domain, topology, registration, revocation, and remote signing policy.
4. Generate APS certificates and register APS nodes with the ADC.
5. Synchronize APS topology state and exchange APS peer certificates.
6. Establish authenticated APS-to-APS tunnel states.
7. Register clients and distribute authenticated APS topology.
8. Establish client-to-entry tunnels.
9. Bind ingress and egress backend callbacks.
10. Enable relay traffic, dummy traffic, ingress delay, replay policy, logging policy, and operational monitoring.

A production topology should contain at least three route-addressable APS nodes. The compact route format requires an ingress APS, at least one forwarding APS, and an egress APS for the full relay path model.

## Associated QRCS Projects

| Project | Repository or Document | Relationship to AERN |
|---------|------------------------|----------------------|
| **QSC** | [https://github.com/QRCS-CORP/QSC](https://github.com/QRCS-CORP/QSC) | Core cryptographic and systems library used by AERN. |
| **RCS** | [https://qrcscorp.ca/documents/rcs_formal.pdf](https://qrcscorp.ca/documents/rcs_formal.pdf) | Authenticated symmetric stream cipher used for tunnel packet encryption. |
| **AERN Specification** | [https://qrcscorp.ca/documents/aern_specification.pdf](https://qrcscorp.ca/documents/aern_specification.pdf) | Normative protocol specification for AERN structure, message processing, routing, security policy, and conformance behavior. |
| **AERN Codebase** | [https://github.com/QRCS-CORP/AERN](https://github.com/QRCS-CORP/AERN) | C-language reference implementation and validation target. |
| **AERN Documentation** | [https://qrcs-corp.github.io/AERN/](https://qrcs-corp.github.io/AERN/) | Generated public help documentation and API reference. |

## Build and Validation

AERN is built together with the QSC library and the AERNTest validation project. Build QSC first, then AERN, then AERNTest. The complete validation sequence should be run before operational deployment or parameter-set changes.

Example source layout:

```text
workspace/
  QSC/
  AERN/
  AERNTest/
```

Visual Studio build order:

```text
1. QSC
2. AERN
3. AERNTest
```

Portable build outline:

```sh
cc -I./QSC -c QSC/*.c
cc -I./QSC -I./AERN -c AERN/*.c
cc -I./QSC -I./AERN -I./AERNTest -c AERNTest/*.c
cc -o AERNTest *.o
```

The command-line outline is intentionally generic. Select platform files, compiler flags, cryptographic parameter sets, and architecture-specific options according to the deployment target.

## License

INVESTMENT INQUIRIES:  
QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact: contact@qrcscorp.ca  
Visit https://www.qrcscorp.ca for a full inventory of QRCS products and services.

PATENT NOTICE:  
One or more patent applications, provisional and/or non-provisional, covering aspects of this software have been filed with the United States Patent and Trademark Office. Unauthorized use may result in patent infringement liability.

License and Use Notice (2025-2026)  
This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation for public review, cryptographic analysis, interoperability testing, and evaluation.

All source code and materials in this repository are provided under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026, unless explicitly stated otherwise.

This license permits public access and non-commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.

For licensing inquiries, supported implementations, or commercial use, contact: licensing@qrcscorp.ca

Quantum Resistant Cryptographic Solutions Corporation, 2026.  
_All rights reserved by QRCS Corp. 2026._

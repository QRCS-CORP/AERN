# AERN – Authenticated Encrypted Relay Network

**AERN** is a cryptographic protocol for secure, anonymous, and authenticated communication across a mesh of fully verified proxy servers. Built as a successor to TOR, AERN avoids the vulnerabilities of public volunteer nodes and introduces post-quantum secure tunneling, dynamic route randomization, and fixed-size encrypted packets. Designed for deployment as a private, domain-based anonymity network, AERN delivers military-grade privacy with real-time performance.

> This repository provides the official C-language reference implementation of the AERN protocol, developed by QRCS – Quantum Resistant Cryptographic Solutions.

## Introduction

AERN (Authenticated Encrypted Relay Network) is a proxy chaining protocol, one that uses a fully meshed ‘cloud’ of proxy servers, that provides message authentication and encryption, and a network system that also provides a strong guarantee of anonymity to the users.   
Each proxy node on the network undergoes an asymmetric key exchange with every other proxy, exchanging a shared secret that is expanded and used to key two symmetric cipher instances; one for the send channel the other for the receive channel, creating a bi-directional encrypted tunnel. These tunnels are used to encrypt and decrypt packet flows as they travel between proxy servers. These proxy server routes are randomly assembled circuits; proxy servers selected at random, and a random ranged number of nodes in the path.  
The network is administrated over by a domain controller which handles device registrations and control messages, and a root server which acts as the authentication trust anchor. 
An entry node is chosen at random by the client from a list of proxy servers it receives during network registration. The device performs an asymmetric key exchange with the entry node and establishes an encrypted tunnel to access the proxy network.  
Once a network of proxy nodes is ‘synchronized’, and they all share encrypted tunnels with each other, all data traversing these nodes is encrypted using symmetric encryption, which is computationally cheap, and allows for a long proxy chain without incurring delay or jitter associated with video or voice messaging. 
Exit nodes can either perform a client-to-server function; in which the message packet is decrypted and sent to a server that is not part of the network (ex. HTTP server), or client-to-client function in which an underlying encrypted tunnel between remote clients is established which operates underneath the proxy circuit.  
Every packet sent through the proxy circuit is the same size; 1500 bytes, the standard network MTU, and so packets remain size-indistinguishable as they traverse the proxy circuit. 
Packets are encrypted using different encrypted tunnel interfaces between proxies, the symmetric cipher (RCS) is a CTR based authenticated stream cipher, so the same packet travelling through the same circuit at different times will still be a unique and indistinguishable ciphertext. The entire message packet is encrypted by the encrypted tunnels between proxy nodes, so that nothing is identifiable or trackable in that message. Given the number of nodes is random; between three (entry node – forwarding node – exit node) and a tunable maximum hops value (default of sixteen), timing variances are difficult to establish, and on a network under load, almost impossible to calculate.  
Packets that exceed the MTU size are fragmented and reassembled at the destination. The path changes every time a packet is sent from source to destination, whether from client to server or server to client; a new random path, that maintains the source and destination nodes in the path but changes intermediate nodes is calculated, randomizing the route for every packet that traverses the network. There can be any number of proxy nodes in the network up to a theoretical maximum, but in practical terms, a 100 or more nodes is reasonable, with more nodes representing more path possibilities and increased resistance to path calculation or correlating clients with exit traffic.  
AERN operates more like a modern VPN service than a TOR network, in that AERN is not a single global-scale network, but domain based, where multiple AERN domains can be added to a federation of proxy networks. Different AERN domains can be listed in the VPN applications choice window, selected at random from a list of domain options, and even switched and rotated during a client session. AERN is a truly anonymous form of VPN, one which not only hides address information from the destination server, but strongly mitigates traffic flow observations by an outside observer, providing anonymity in the broader sense, against attempts to profile individuals and monitor their internet traffic.  


## Protocol Overview

- **Key Exchange:** Quantum-secure asymmetric key exchange (Kyber, McEliece) is used once per session; all subsequent communication is encrypted with symmetric RCS cipher instances.
- **Proxy Mesh:** All APS nodes form a full mesh of symmetric tunnels; any node can be an entry, forward, or exit node.
- **Client Access:** Clients receive a list of authenticated proxies and connect through a randomly selected entry node.
- **Dynamic Routing:** Every packet receives a new randomized path through 3–16 proxies; only the entry and exit nodes are stable per session.
- **Packet Format:** Fixed 1500-byte MTU packets, constant across all transfers to eliminate size-based traffic analysis.
- **Replay Defense:** Packet headers include signed timestamps and sequence numbers; late or duplicated packets are discarded.

## Architecture Overview

| Component | Description |
|----------|-------------|
| **ARS (Root Security Server)** | Trust anchor that signs all certificates. |
| **ADC (Domain Controller)** | Manages registration, revocation, and topology updates. |
| **APS (Proxy Server)** | Authenticated relays forming a full symmetric tunnel mesh. |
| **ACD (Client Device)** | Authenticated client that tunnels anonymously via the proxy cloud. |

Each component plays a fixed cryptographic role, and all device interactions are validated using signed certificates and SHAKE-based MACs.

### Cryptographic Dependencies

MPDC-I uses the QSC cryptographic library: [The QSC Library](https://github.com/QRCS-CORP/QSC).  
*QRCS-PL private License. See license file for details. All rights reserved by QRCS Corporation, copyrighted and patents pending.*

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

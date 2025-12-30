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

#ifndef AERN_ADC_H
#define AERN_ADC_H

#include "aerncommon.h"

/**
 * \file adc.h
 * \brief AERN Domain Controller (ADC) Server.
 *
 * \details
 * The AERN Domain Controller (ADC) is a central component of the Anonymous Encrypted Relay Network (AERN)
 * responsible for managing the network's device list (topology), certificate distribution, and
 * convergence. The ADC server acts as an intermediary between remote devices (APS
 * and clients) and the root certificate authority. It handles operations such as:
 *
 * - Processing registration requests from devices seeking to join the network.
 * - Issuing incremental updates and convergence responses to synchronize device topology.
 * - Broadcasting revocation and announcement messages to update the network state.
 *
 * The ADC server is implemented as a dedicated network server that listens for incoming TCP
 * connections (supporting both IPv4 and IPv6). It uses a console-based command loop to accept
 * administrator commands for configuration, certificate management, and topology control. An idle
 * timeout mechanism automatically logs out inactive sessions.
 *
 * The implementation includes rigorous internal tests of its convergence, certificate verification,
 * and topology update routines. These tests ensure that the ADC server reliably maintains an accurate
 * network view and securely processes certificate-related transactions.
 *
 * \note
 * The public API provided in this header comprises functions to start, pause, and stop the ADC server.
 * Internal operations (such as certificate generation, topology convergence, and node queries) are
 * encapsulated within the ADC server's implementation.
 */

/**
 * \brief Pause the ADC server.
 *
 * Temporarily suspends the ADC server's processing of incoming network requests and command loop.
 */
AERN_EXPORT_API void aern_adc_pause_server(void);

/**
 * \brief Start the ADC server.
 *
 * Initializes and starts the AERN ADC server. This function configures the network listening socket,
 * loads the local ADC certificate (importing the root certificate if necessary), initializes the topology
 * database, and begins the interactive command loop.
 *
 * \return Returns zero on success; a non-zero value indicates an error during initialization.
 */
AERN_EXPORT_API int32_t aern_adc_start_server(void);

/**
 * \brief Stop the ADC server.
 *
 * Terminates the ADC server by shutting down the network socket, stopping the command loop, and releasing
 * all allocated resources.
 */
AERN_EXPORT_API void aern_adc_stop_server(void);

#endif

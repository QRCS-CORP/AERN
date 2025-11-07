/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDAARS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
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

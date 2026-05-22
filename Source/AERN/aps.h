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

#ifndef AERN_APS_H
#define AERN_APS_H

#include "aerncommon.h"

/**
 * \file aps.h
 * \brief AERN Anonymous Proxy Server (APS).
 *
 * \details
 * The APS is the workhorse of the AERN network.  Each APS holds a child
 * certificate signed by the domain's ARS and registered with the ADC.  APS
 * nodes relay encrypted client traffic, participate in topology convergence,
 * exchange master fragment keys with peers, and forward registration requests
 * from clients to the ADC.
 *
 * Public API:
 * aern_aps_pause_server: temporarily suspend processing
 * aern_aps_start_server: initialise and start the APS
 * aern_aps_stop_server: terminate and release resources
 */

/**
 * \brief Pause the APS server.
 *
 * Temporarily suspends the APS server's processing of incoming connections
 * and the command loop.
 */
AERN_EXPORT_API void aern_aps_pause_server(void);

/**
 * \brief Start the APS server.
 *
 * Initialises the server state, loads or imports the APS child certificate
 * (requesting ARS signing if necessary), registers with the ADC, and begins
 * the command/receive loop.
 *
 * \return Returns 0 on success; a non-zero error code on failure.
 */
AERN_EXPORT_API int32_t aern_aps_start_server(void);

/**
 * \brief Stop the APS server.
 *
 * Sends a resignation request to the ADC, closes all sockets, and releases
 * all allocated resources.
 */
AERN_EXPORT_API void aern_aps_stop_server(void);


#endif

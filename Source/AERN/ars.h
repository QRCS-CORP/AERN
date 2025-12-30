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

#ifndef AERN_ARS_H
#define AERN_ARS_H

#include "aerncommon.h"

/**
 * \file ars.h
 * \brief The AERN Root Domain Security server.
 *
 * Detailed File Description:
 * This header file defines the public interface for the AERN Root Domain Security (ARS)
 * server. The ARS server is responsible for managing the root domain security functions within
 * the AERN system. This includes handling operations related to the creation, storage, signing,
 * and verification of the root certificate as well as coordinating secure communications with
 * other nodes in the network. The public functions declared here allow the ARS server to be started,
 * paused, and stopped. In addition, when the macro AERN_DEBUG_TESTS_RUN is defined, a test function
 * is provided to run self-diagnostic tests on the ARS server functionality.
 *
 * Every function declared in this header file is documented with its purpose, parameters, and return
 * value (if any).
 */

/**
 * \brief Pause the ARS server.
 *
 * This function pauses the operation of the ARS server. When called, the server will temporarily
 * suspend processing of incoming network messages and connections until it is resumed.
 */
AERN_EXPORT_API void aern_ars_pause_server(void);

/**
 * \brief Start the ARS server.
 *
 * This function initializes and starts the ARS server. It sets up all necessary resources,
 * initializes the application state, and begins accepting network connections.
 */
AERN_EXPORT_API void aern_ars_start_server(void);

/**
 * \brief Stop the ARS server.
 *
 * This function stops the ARS server by terminating its main command loop and releasing all allocated
 * resources. After calling this function, the server will no longer process incoming network messages.
 */
AERN_EXPORT_API void aern_ars_stop_server(void);

#if defined(AERN_DEBUG_TESTS_RUN)
/**
 * \brief Test the ARS server's functions.
 *
 * This function runs a suite of tests on the ARS server functions to verify proper operation of the
 * server's core features, such as certificate management and network communication.
 *
 * \return Returns true if all tests pass successfully, otherwise returns false.
 */
AERN_EXPORT_API bool aern_ars_appserv_test(void);
#endif

#endif

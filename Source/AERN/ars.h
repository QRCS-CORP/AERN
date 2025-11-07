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

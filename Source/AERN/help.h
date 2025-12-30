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

#ifndef AERN_HELP_H
#define AERN_HELP_H

#include "aerncommon.h"
#include "commands.h"
#include "resources.h"

/**
 * \file help.h
 * \brief AERN Help and Guidance Functions.
 *
 * \details
 * This header declares functions that provide context-sensitive help messages for the AERN
 * console interface. These functions print help strings that explain available command actions
 * and options based on the current console mode (e.g., configuration, enable, or user mode) and
 * the device's network designation (e.g., APS, Client, ADC, ARS). The help functions make
 * use of pre-defined help text strings (stored in the AERN_APPLICATION_HELP_STRINGS array) and
 * output them using the QSC console utilities.
 *
 * The primary functions provided in this module are:
 *
 * - \ref aern_help_print_context(): Prints a single help message associated with a specific
 *   command action.
 * - \ref aern_help_print_mode(): Prints a set of help messages tailored to the current console mode
 *   and network designation.
 *
 * These functions are essential for providing users with guidance on how to interact with the AERN
 * system.
 */

/**
 * \brief Print a help string associated with a command action.
 *
 * This function prints a context-specific help message corresponding to the given command action.
 * The help string is printed using the provided console prompt.
 *
 * \param prompt [in] The console prompt string.
 * \param command The command action (from the aern_command_actions enumeration) for which to display help.
 */
AERN_EXPORT_API void aern_help_print_context(const char* prompt, aern_command_actions command);

/**
 * \brief Print a console prompt with help text for the current mode.
 *
 * This function prints a set of help messages that are appropriate for the current console mode and
 * the server type designation. It guides the user by displaying available commands and their context
 * based on whether the console is in configuration, enable, or user mode.
 *
 * \param prompt [in] The console prompt string.
 * \param mode The current console mode (from the aern_console_modes enumeration).
 * \param designation The network designation (from the aern_network_designations enumeration) for which
 * the help messages should be tailored.
 */
AERN_EXPORT_API void aern_help_print_mode(const char* prompt, aern_console_modes mode, aern_network_designations designation);

#endif

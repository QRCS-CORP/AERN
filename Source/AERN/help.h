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

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

#ifndef AERN_MENU_H
#define AERN_MENU_H

#include "aerncommon.h"
#include "commands.h"

/**
 * \file menu.h
 * \brief The AERN console menu functions.
 *
 * This module provides functions for printing prompts, messages, and errors to the
 * AERN console. These functions are used to interact with the user by displaying
 * status messages, predefined texts, and user confirmations.
 *
 * The functions include:
 *  - Retrieving the prompt string for a given console mode.
 *  - Printing error messages derived from protocol error codes.
 *  - Printing plain text messages and predefined messages.
 *  - Printing prompts (with or without text) to the console.
 *
 * All messages are printed in plain ASCII. No Unicode characters are used.
 *
 * Example usage:
 * \code
 *     // Get and print the console prompt for configuration mode.
 *     const char* prompt = aern_menu_get_prompt(aern_console_mode_config);
 *     qsc_consoleutils_print_safe(prompt);
 *
 *     // Print an error message based on a protocol error.
 *     aern_menu_print_error(aern_protocol_error_invalid_request, aern_console_mode_config, "Host1");
 *
 *     // Print a predefined message and wait for confirmation.
 *     if (aern_menu_print_predefined_message_confirm(aern_application_log_backup, aern_console_mode_config, "Host1"))
 *     {
 *         // Proceed with backup...
 *     }
 * \endcode
 */

/**
 * \brief Returns the console prompt string.
 *
 * This function returns the appropriate prompt string based on the specified
 * console mode. The prompt is selected from an internal array of mode strings.
 *
 * \param mode The current console mode.
 * \return A pointer to the prompt string.
 */
AERN_EXPORT_API const char* aern_menu_get_prompt(aern_console_modes mode);

/**
 * \brief Print an error message to the console.
 *
 * This function converts a protocol error code into a descriptive string and
 * prints it to the console. It prints the prompt first (based on the mode and
 * host) and then the error message.
 *
 * \param error The protocol error enumerator.
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_error(aern_protocol_errors error, aern_console_modes mode, const char* host);

/**
 * \brief Print a message to the console.
 *
 * This function prints the given message string to the console. It first prints
 * the prompt (using the current mode and host) and then the message on a new line.
 *
 * \param message The message string to print.
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_message(const char* message, aern_console_modes mode, const char* host);

/**
 * \brief Print a message to the console and wait for confirmation.
 *
 * This function prints a message and then waits for the user to input a single
 * character. If the user enters 'y' or 'Y', the function returns true.
 *
 * \param message The message string.
 * \param mode The current console mode.
 * \param host The host name.
 * \return True if the user confirms (answers 'y' or 'Y'); false otherwise.
 */
AERN_EXPORT_API bool aern_menu_print_message_confirm(const char* message, aern_console_modes mode, const char* host);

/**
 * \brief Print a predefined message to the console.
 *
 * This function prints a message that is predefined in the AERN application. The
 * message is chosen based on the msgnum parameter.
 *
 * \param msgnum The predefined message enumerator.
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_predefined_message(aern_application_messages msgnum, aern_console_modes mode, const char* host);

/**
 * \brief Print a predefined message to the console and wait for confirmation.
 *
 * This function prints a predefined message and then waits for the user to provide
 * confirmation. A response of 'y' or 'Y' returns true.
 *
 * \param msgnum The predefined message enumerator.
 * \param mode The current console mode.
 * \param host The host name.
 * \return True if the user confirms; false otherwise.
 */
AERN_EXPORT_API bool aern_menu_print_predefined_message_confirm(aern_application_messages msgnum, aern_console_modes mode, const char* host);

/**
 * \brief Print the application prompt.
 *
 * This function prints the application prompt string to the console using the
 * current console mode and host name.
 *
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_prompt(aern_console_modes mode, const char* host);

/**
 * \brief Print a prompt and text with no line terminator.
 *
 * This function prints a prompt followed by a message string. The message is
 * printed without appending a newline character.
 *
 * \param message The message string to print.
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_prompt_text(const char* message, aern_console_modes mode, const char* host);

/**
 * \brief Print a predefined message with no line terminator.
 *
 * This function prints a predefined message (as defined in the AERN application
 * messages) without a newline at the end.
 *
 * \param msgnum The predefined message enumerator.
 * \param mode The current console mode.
 * \param host The host name.
 */
AERN_EXPORT_API void aern_menu_print_predefined_text(aern_application_messages msgnum, aern_console_modes mode, const char* host);

/**
 * \brief Print a text string to the console without a newline.
 *
 * This function prints the specified text string using a safe console print,
 * without appending a newline.
 *
 * \param message The message string to print.
 */
AERN_EXPORT_API void aern_menu_print_text(const char* message);

/**
 * \brief Print a text string to the console with a newline.
 *
 * This function prints the specified text string and then appends a newline.
 *
 * \param message The message string to print.
 */
AERN_EXPORT_API void aern_menu_print_text_line(const char* message);

/**
 * \brief Print the application prompt on an empty line.
 *
 * This function prints the default application prompt on a new line.
 */
AERN_EXPORT_API void aern_menu_print_prompt_empty(void);

#endif

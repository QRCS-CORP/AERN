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

#ifndef AERN_UTILS_H
#define AERN_UTILS_H

#include "aerncommon.h"

/**
 * \file aern_utils.h
 * \brief Common test harness utilities for AERNTest.
 *
 * \details
 * This header defines the shared output, conversion, and case-dispatch helpers
 * used by the AERN deterministic test harness. The declarations are test-only
 * utilities and are not part of the AERN protocol API.
 */

/**
 * \typedef aerntest_function
 * \brief The AERNTest case callback type.
 *
 * \details
 * A test callback returns \c true when the case succeeds and \c false when the
 * case fails.
 */
typedef bool (*aerntest_function)(void);

/**
 * \struct aerntest_case
 * \brief A named AERNTest case descriptor.
 *
 * \details
 * This structure binds a printable test name to the callback used by the common
 * test dispatcher.
 */
typedef struct aerntest_case
{
	const char* name;          /*!< The printable test case name. */
	aerntest_function test;    /*!< The test case callback. */
} aerntest_case;

/**
 * \brief Read one character from the console.
 *
 * \return Returns the character read from standard input.
 */
char aerntest_get_char(void);

/**
 * \brief Wait for and read one character from the console.
 *
 * \return Returns the character read from standard input.
 */
char aerntest_get_wait(void);

/**
 * \brief Convert a hexadecimal string to a binary array.
 *
 * \param hexstr: A pointer to the null-terminated hexadecimal string.
 * \param output: A pointer to the output binary array.
 * \param length: The number of bytes to write to the output array.
 */
void aerntest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
 * \brief Print a binary array as hexadecimal text.
 *
 * \param input: A pointer to the input byte array.
 * \param inputlen: The number of bytes in the input array.
 * \param linelen: The maximum number of bytes printed per output line.
 */
void aerntest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
 * \brief Print a null-terminated string without appending a newline.
 *
 * \param input: A pointer to the null-terminated string to print.
 */
void aerntest_print_safe(const char* input);

/**
 * \brief Print a null-terminated string followed by a newline.
 *
 * \param input: A pointer to the null-terminated string to print.
 */
void aerntest_print_line(const char* input);

/**
 * \brief Print an unsigned 64-bit integer value.
 *
 * \param digit: The integer value to print.
 */
void aerntest_print_ulong(uint64_t digit);

/**
 * \brief Print a double-precision floating-point value.
 *
 * \param digit: The floating-point value to print.
 */
void aerntest_print_double(double digit);

/**
 * \brief Request interactive confirmation from the test operator.
 *
 * \param message: A pointer to the confirmation message.
 *
 * \return Returns true when the operator confirms the prompt.
 */
bool aerntest_test_confirm(const char* message);

/**
 * \brief Print the result of a named test case.
 *
 * \param name: A pointer to the printable test case name.
 * \param passed: The test result flag.
 */
void aerntest_print_result(const char* name, bool passed);

/**
 * \brief Run a single named test case through the common dispatcher.
 *
 * \param tcase: A pointer to the test case descriptor.
 *
 * \return Returns true when the test case succeeds.
 */
bool aerntest_run_case(const aerntest_case* tcase);

#endif

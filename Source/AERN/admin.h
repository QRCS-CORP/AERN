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

#ifndef AERN_ADMIN_H
#define AERN_ADMIN_H

#include "aern.h"
#include "certificate.h"
#include "lifecycle.h"
#include "mek.h"
#include "network.h"
#include "route.h"
#include "server.h"
#include "topology.h"

/**
 * \file admin.h
 * \brief Phase-6: Administrative controls and security hardening.
 */

/*!
 * \struct aern_log_state
 * \brief State for the ADC encrypted log.
 *
 * The log file is encrypted at rest with RCS using a 64-byte seed derived
 * from the admin password: seed = SHAKE-256(password || salt)[0..63]
 *
 * The salt (AERN_LOG_SALT_SIZE = 32 bytes) is stored as a plaintext file
 * alongside the log.  The key is never stored; it is re-derived on every
 * aern_log_open() call.
 *
 * Each log entry is fixed-width (AERN_LOG_ENTRY_SIZE bytes) in plaintext,
 * formatted as: <ISO-8601 UTC timestamp 32B> <device_name 32B> <hex_error 10B> <error_str 64B>\n
 *
 * No client IP addresses, session IDs, or traffic metadata are written.
 */
AERN_EXPORT_API typedef struct aern_log_state
{
    char log_path[AERN_STORAGE_PATH_MAX];       /*!< Full path to the encrypted log file   */
    char salt_path[AERN_STORAGE_PATH_MAX];      /*!< Full path to the plaintext salt file   */
    uint8_t seed[AERN_LOG_SEED_SIZE];           /*!< Derived encryption seed (zeroed on close) */
    bool open;                                  /*!< True when log is ready for writes     */
} aern_log_state;

/*!
 * \struct aern_console_state
 * \brief Runtime state for the ADC administrative console.
 */
AERN_EXPORT_API typedef struct aern_console_state
{
    aern_server_application_state* appstate;    /*!< ADC application state */
    aern_topology_list_state* vtopo;       /*!< ADC versioned topology */
    const aern_child_certificate* lcert;        /*!< ADC local certificate */
    const uint8_t* sigkey;                      /*!< ADC signing key */
    const aern_root_certificate* root;          /*!< Root certificate */
    aern_log_state* log;                        /*!< Encrypted log state */
    bool authenticated;                         /*!< True after password verified */
    bool running;                               /*!< Set false to exit loop */
    uint64_t start_time;                        /*!< UTC seconds at startup */
} aern_console_state;

/*!
 * \struct aern_background_state
 * \brief State for the APS background cover-traffic thread.
 */
AERN_EXPORT_API typedef struct aern_background_state
{
    aern_cipher_table* ctable;                  /*!< Cipher table (one packet per active tunnel) */
    volatile bool running;                      /*!< Set false to stop the thread */
    volatile bool synchronized;                 /*!< Only run when APS is synchronized */
} aern_background_state;

/**
 * \brief Open the ADC encrypted log and derive the encryption key.
 *
 * If the salt file does not exist it is created with a freshly generated
 * AERN_LOG_SALT_SIZE-byte random salt.
 *
 * \param ls: [aern_log_state*] Log state to populate.
 * \param logpath: [const char*] Path to the encrypted log file.
 * \param password: [const uint8_t*] Admin password string (not stored; used only for KDF).
 * \param pwlen: [size_t] Password length in bytes.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_log_open(aern_log_state* ls, const char* logpath, const uint8_t* password, size_t pwlen);

/**
 * \brief Append one entry to the encrypted ADC log.
 *
 * The entry is formatted, appended to the plaintext, and the entire file is re-encrypted.
 * This is consistent with the pattern in server.c.
 *
 * \param ls: [aern_log_state*] Open log state.
 * \param devname: [const char*] Device name string (up to AERN_LOG_DEVICE_NAME_SIZE bytes).
 * \param error: [aern_protocol_errors] Protocol error code.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_log_write(aern_log_state* ls, const char* devname, aern_protocol_errors error);

/**
 * \brief Close the log and zero the derived key material.
 *
 * \param ls: [aern_log_state*] Log state to close.
 */
AERN_EXPORT_API void aern_log_close(aern_log_state* ls);

/**
 * \brief Decrypt and read all log entries into a caller-provided buffer.
 *
 * \param ls: [const aern_log_state*]  Open log state.
 * \param out: [char*] Output buffer for formatted log text.
 * \param outsize: [size_t]  Size of the output buffer in bytes.
 * \param entrycount: [size_t*] Number of complete entries read.
 * 
 * \return Returns aern_protocol_error_none on success.
 */
AERN_EXPORT_API aern_protocol_errors aern_log_read_all(const aern_log_state* ls, char* out, size_t outsize, size_t* entrycount);

/**
 * \brief Run the ADC administrative console (blocking loop).
 *
 * \param cs: [aern_console_state*] Console state.
 */
AERN_EXPORT_API void aern_console_run(aern_console_state* cs);

/**
 * \brief Test whether a child certificate has expired.
 *
 * \param cert: [const aern_child_certificate*] The certificate to check.
 * \param now: [uint64_t] Current UTC epoch seconds.
 * 
 * \return Returns true if cert.expiration.to < now OR now < cert.expiration.from.
 */
AERN_EXPORT_API bool aern_certificate_is_expired(const aern_child_certificate* cert, uint64_t now);

/**
 * \brief Return the seconds remaining until the certificate expires.
 *
 * \param cert: [const aern_child_certificate*] The certificate to check.
 * \param now: [uint64_t] Current UTC epoch seconds.
 * 
 * \return Positive seconds remaining, zero or negative.
 */
AERN_EXPORT_API int64_t aern_certificate_time_remaining(const aern_child_certificate* cert, uint64_t now);

/**
 * \brief Enforce certificate expiration on an incoming certificate.
 *
 * Calls aern_certificate_is_expired; on expiry logs to ADC and returns aern_protocol_error_certificate_expired.
 *
 * \param cert: [const aern_child_certificate*] Certificate to enforce.
 * \param appstate: [aern_server_application_state*] ADC app state (for logging).
 * 
 * \return Returns aern_protocol_error_none if valid.
 */
AERN_EXPORT_API aern_protocol_errors aern_certificate_enforce_expiry(const aern_child_certificate* cert, aern_server_application_state* appstate);

/**
 * \brief Add a CSPRNG-derived random delay then transmit a packet.
 *
 * \param csock: [qsc_socket*] Socket to transmit on.
 * \param wire: [const uint8_t*] Packet buffer (exactly AERN_RELAY_MTU bytes).
 * \param basedelayms: [uint32_t] Maximum jitter in milliseconds.
 * 
 * \return Bytes sent, or 0 on failure.
 */
AERN_EXPORT_API size_t aern_jitter_send(qsc_socket* csock, const uint8_t wire[AERN_RELAY_MTU], uint32_t basedelayms);

/**
 * \brief Start the background cover-traffic thread.
 *
 * Spawns a thread that calls the background traffic loop.
 * Must call aern_background_stop() before process exit.
 *
 * \param bg: [aern_background_state*] Background state; running is set to true.
 */
AERN_EXPORT_API void aern_background_start(aern_background_state* bg);

/**
 * \brief Stop the background cover-traffic thread.
 *
 * Sets running to false and waits for the thread to exit.
 *
 * \param bg: [aern_background_state*] Background state.
 */
AERN_EXPORT_API void aern_background_stop(aern_background_state* bg);

/**
 * \brief Background cover-traffic thread function.
 *
 * Every AERN_BACKGROUND_INTERVAL_MS, sends one random-padded 1500-byte
 * encrypted packet on each active cipher-table entry.
 * Thread exits when bg->running == false.
 *
 * \param arg: [void*] Pointer to aern_background_state.
 */
AERN_EXPORT_API void aern_background_thread(void* arg);

#endif

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

#ifndef AERN_LOG_H
#define AERN_LOG_H

#include "aerncommon.h"
#include "commands.h"

/**
 * \file logger.h
 * \brief AERN Logging Functions.
 *
 * \details
 * This header defines the logging functions used throughout the AERN system. The logger provides
 * a standard mechanism for writing diagnostic and operational messages to a log file. The logging
 * module supports basic operations such as:
 *
 * - Obtaining the default logging file path.
 * - Initializing the logger.
 * - Checking for the existence and retrieving the size of the log file.
 * - Writing plain, decorated, and time-stamped log messages.
 * - Reading the complete log or individual log lines.
 * - Resetting (erasing) and disposing (deleting) the log file.
 *
 * The following macros are defined to specify the maximum message length and the dimensions of the
 * log string storage:
 *   - \ref AERN_LOGGING_MESSAGE_MAX defines the maximum number of characters for a log message.
 *   - \ref AERN_LOG_STRING_DEPTH and \ref AERN_LOG_STRING_SIZE specify the dimensions used for storing
 *     pre-defined log strings.
 *
 * Additionally, static constants provide the default logger path, file name, and header string.
 *
 * These logging routines utilize underlying QSC file and console utilities to ensure thread-safe
 * access to the log file and provide formatted, timestamped output.
 */

/*! \def AERN_LOGGING_MESSAGE_MAX
 *  \brief The maximum length (in characters) for a logging message.
 */
#define AERN_LOGGING_MESSAGE_MAX 256U

/*! \def AERN_LOG_STRING_DEPTH
 *  \brief The number of predefined log strings.
 */
#define AERN_LOG_STRING_DEPTH 69U

/*! \def AERN_LOG_STRING_SIZE
 *  \brief The maximum size (in characters) for a single log string.
 */
#define AERN_LOG_STRING_SIZE 64U

/*! \var static const char AERN_LOGGER_PATH[]
 *  \brief The default directory name for AERN logs.
 */
static const char AERN_LOGGER_PATH[] = "AERN";

/*! \var static const char AERN_LOGGER_FILE[]
 *  \brief The default log file name.
 */
static const char AERN_LOGGER_FILE[] = "aern.log";

/*! \var static const char AERN_LOGGER_HEAD[]
 *  \brief A header string to identify the AERN log file.
 */
static const char AERN_LOGGER_HEAD[] = "AERN Version 1.0";

/**
 * \brief Get the default logging path.
 *
 * This function retrieves the default log file path by obtaining the user's documents directory,
 * appending the AERN logger directory name, and finally the log file name.
 *
 * \param path [out] The output buffer that will receive the full log file path.
 * \param pathlen The length of the output buffer.
 */
AERN_EXPORT_API void logger_default_path(char* path, size_t pathlen);

/**
 * \brief Erase and delete the log file.
 *
 * This function deletes the log file at the specified path.
 *
 * \param path [in] The log file path.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_logger_dispose(const char* path);

/**
 * \brief Erase the log file.
 *
 * This function clears the contents of the log file without deleting the file itself.
 *
 * \param path [in] The log file path.
 *
 * \return Returns true on success.
 */
AERN_EXPORT_API bool aern_logger_erase_all(const char* path);

/**
 * \brief Check if the log file exists.
 *
 * \param path [in] The log file path.
 *
 * \return Returns true if the log file exists.
 */
AERN_EXPORT_API bool aern_logger_exists(const char* path);

/**
 * \brief Initialize the logger.
 *
 * This function creates or resets the log file at the specified path if it does not already exist.
 *
 * \param path [in] The log file path.
 */
AERN_EXPORT_API void aern_logger_initialize(const char* path);

/**
 * \brief Get the size of the log file.
 *
 * This function returns the size (in characters) of the log file.
 *
 * \param path [in] The log file path.
 *
 * \return Returns the character size of the log file.
 */
AERN_EXPORT_API size_t aern_logger_get_size(const char* path);

/**
 * \brief Reset the logger.
 *
 * Erases the log file (or creates a new empty log file if it does not exist).
 *
 * \param path [in] The log file path.
 */
AERN_EXPORT_API void aern_logger_reset(const char* path);

/**
 * \brief Write a message to the log file.
 *
 * This function appends a terminated line (with a newline) to the log file.
 *
 * \param path [in] The log file path.
 * \param line [in, const] The null-terminated string to write.
 * \param linelen The length of the line.
 *
 * \return Returns the number of characters written.
 */
AERN_EXPORT_API size_t aern_logger_write_message(const char* path, const char* line, size_t linelen);

/**
 * \brief Write a decorated message to the log file.
 *
 * This function prepends a predefined message (based on the provided message type) to the given
 * message text and writes the result to the log.
 *
 * \param path [in] The log file path.
 * \param msgtype The predefined message type (from aern_application_messages).
 * \param message [in, const] The message to write.
 * \param msglen The length of the message.
 *
 * \return Returns the number of characters written.
 */
AERN_EXPORT_API size_t aern_logger_write_decorated_message(const char* path, aern_application_messages msgtype, const char* message, size_t msglen);

/**
 * \brief Write a time-stamped message to the log file.
 *
 * This function writes a log entry that begins with a current timestamp.
 *
 * \param path [in] The log file path.
 * \param message [in, const] The message to log.
 * \param msglen The length of the message.
 *
 * \return Returns the number of characters written.
 */
AERN_EXPORT_API size_t aern_logger_write_time_stamped_message(const char* path, const char* message, size_t msglen);

/**
 * \brief Write a decorated, time-stamped message to the log file.
 *
 * This function first obtains a current timestamp, then prepends a predefined message based on the
 * given message type, and finally writes the complete entry to the log file.
 *
 * \param path [in] The full log file path.
 * \param msgtype The predefined message type.
 * \param message [in, const] The message to write.
 * \param msglen The length of the message.
 *
 * \return Returns the number of characters written.
 */
AERN_EXPORT_API size_t aern_logger_write_decorated_time_stamped_message(const char* path, aern_application_messages msgtype, const char* message, size_t msglen);

/**
 * \brief Read the entire log into a character array.
 *
 * \param path [in] The full path to the log file.
 * \param output [out] The output string receiving the log contents.
 * \param outlen The length of the output array.
 *
 * \return Returns the number of characters read.
 */
AERN_EXPORT_API size_t aern_logger_read_all(const char* path, char* output, size_t outlen);

/**
 * \brief Read a single line from the log file.
 *
 * \param path [in] The full path to the log file.
 * \param output [out] The output string receiving the line.
 * \param outlen The length of the output string.
 * \param linenum The 0-based line number to read.
 *
 * \return Returns the number of characters read.
 */
AERN_EXPORT_API int64_t aern_logger_read_line(const char* path, char* output, size_t outlen, size_t linenum);

/**
 * \brief Write a timestamp to a string.
 *
 * This function retrieves the current date and time in a formatted string.
 *
 * \param output [out] The output string receiving the timestamp.
 * \param outlen The length of the output array.
 *
 * \return Returns the number of characters in the timestamp string.
 */
AERN_EXPORT_API size_t aern_logger_time_stamp(char* output, size_t outlen);

#endif

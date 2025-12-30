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


/**
* \file commands.h
* \brief The AERN command enumerations
*/

#ifndef AERN_COMMANDS_H
#define AERN_COMMANDS_H

#include "aern.h"

/*!
* \enum aern_console_commands
* \brief The common console functions
*/
typedef enum aern_console_commands
{
	aern_commands_none = 0x00U,									/*!< No command is recognized */
	aern_commands_certificate_create = 0x01U,					/*!< Create a new root certificate */
	aern_commands_certificate_change = 0x02U,					/*!< Broadcast a root certificate change */
	aern_commands_certificate_sign = 0x03U,						/*!< Sign a device certificate */
	aern_commands_certificate_revoke = 0x04U,					/*!< Broadcast a certificate revocation */
	aern_commands_certificate_format = 0x05U,					/*!< Convert a certificate to a readable string */
	aern_commands_device_add = 0x06U,							/*!< Add a device to the AERN network */
	aern_commands_network_converge = 0x07U,						/*!< Broadcast a network reconvergence event */
	aern_commands_adc_election = 0x08U,							/*!< Broadcast a ADC election */
} aern_console_commands;

/*!
* \enum aern_application_messages
* \brief The ARS application messages
*/
typedef enum aern_application_messages
{
	aern_application_not_recognized = 0x00U,					/*!< The command was not recognized. */
	aern_application_erase_erase_all = 0x01U,					/*!< The system will be erased, including configuration and log files, do you want to proceed Y|N */
	aern_application_erase_config = 0x02U,						/*!< The user configuration will be erased, do you want to proceed Y|N" */
	aern_application_erase_log = 0x03U,							/*!< The log files will be erased, do you want to proceed Y|N */
	aern_application_authorization_failure = 0x04U,				/*!< The user is not authorized. Press any key to terminate the application. */
	aern_application_retries_exceeded = 0x05U,					/*!< Login has exceeded maximum retries. Press any key to terminate the application. */
	aern_application_application_quit = 0x06U,					/*!< The quit command has been entered. Press any key to terminate the application. */
	aern_application_logging_disabled = 0x07U,					/*!< Activity logging has been disabled. */
	aern_application_logging_enabled = 0x08U,					/*!< Activity logging has been enabled. */
	aern_application_authentication_failure = 0x09U,			/*!< User authentication has failed. Press any key to terminate the application. */
	aern_application_operation_aborted = 0x0AU,					/*!< The operation was aborted by the user. */
	aern_application_system_erased = 0x0BU,						/*!< System reset: The application log and configuration have been erased. */
	aern_application_configuration_erased = 0x0CU,				/*!< System reset: The application log and configuration have been erased. */
	aern_application_log_erased = 0x0DU,						/*!< The log file has been erased.*/
	aern_application_retry_invalid = 0x0EU,						/*!< The retry setting is invaid; valid retry range is between one and five [1-5] login attempts. */
	aern_application_timeout_invalid = 0x0FU,					/*!< The timeout setting is invalid; valid timeout setting is between one and sixty [1-60] minutes. */
	aern_application_domain_invalid = 0x10U,					/*!< The domain name setting is invalid; valid domain name length is between two and thirty [2-32] characters. */
	aern_application_hostname_invalid = 0x11U,					/*!< The hostname setting is invalid; valid hostname length is between two and thirty [2-32] characters.*/
	aern_application_configuration = 0x12U,						/*!< Printing configuration details: */
	aern_application_connection = 0x13U,						/*!< Printing connection details: */
	aern_application_connection_details = 0x14U,				/*!<  minutes */
	aern_application_log_empty = 0x15U,							/*!< The log file is empty.*/
	aern_application_first_login = 0x16U,						/*!< Running for the first time; please set the applications device name, username and password. */
	aern_application_choose_name = 0x17U,						/*!< Please choose a user name, minimum 6 characters, to a maximum 128 characters. */
	aern_application_choose_password = 0x18U,					/*!< Password must be 8-128 characters long [a-z, A-Z], at least 1 number, and 1 symbol [0-9][!#$&'()*+,_./]. */
	aern_application_password_set = 0x19U,						/*!< The user name and password have been set. */
	aern_application_challenge_user = 0x1AU,					/*!< Please enter the user name: */
	aern_application_challenge_user_failure = 0x1BU,			/*!< The user name entered is not recognized. */
	aern_application_challenge_password = 0x1CU,				/*!< Please enter the password: */
	aern_application_challenge_password_failure = 0x1DU,		/*!< The password entered is invalid. */
	aern_application_challenge_device_name = 0x1EU,				/*!< Please enter the device name, minimum 2 characters, to a maximum of 16 characters */
	aern_application_challenge_device_name_success = 0x1FU,		/*!< The device name has been set. */
	aern_application_challenge_device_name_failure = 0x20U,		/*!< The device name is invalid. */
	aern_application_remote_connect = 0x21U,					/*!< Enter the IPv4 or IPv6 address of the host name. */
	aern_application_remote_connect_key = 0x22U,				/*!< No public key is associated with that address. Enter the encoded public key. */
	aern_application_remote_connect_success = 0x23U,			/*!< Connecting to the server... */
	aern_application_remote_connect_failure = 0x24U,			/*!< Connection attempt failed. The server is unreachable. */
	aern_application_socket_listen = 0x25U,						/*!< The host has entered server mode. Type quit to exit server mode. */
	aern_application_socket_listen_failure = 0x26U,				/*!< The listener failed to initialize. The host could not enter the listening state. */
	aern_application_socket_listen_success = 0x27U,				/*!< The listener has initialized: The server is now in the listening state. */
	aern_application_generate_key = 0x28U,						/*!< Generating the public/private signature key-pair. */
	aern_application_generate_key_failure = 0x29U,				/*!< The certificate could not be generated. */
	aern_application_generate_key_success = 0x2AU,				/*!< The public key was saved to: */
	aern_application_generate_key_overwrite = 0x2BU,			/*!< The signature key-pair already exists, do you want to overwite it? Y|N */
	aern_application_operation_cancelled = 0x2CU,				/*!< The operation was cancelled by the user. */
	aern_application_client_enter_pubkey_path = 0x2DU,			/*!< Enter the path to the remote hosts public key. */
	aern_application_client_pubkey_path_invalid = 0x2EU,		/*!< Invalid path, could not find the hosts public key. */
	aern_application_client_connection_success = 0x2FU,			/*!< Client connected to the remote host successfully. */
	aern_application_client_connection_failure = 0x30U,			/*!< Connection attempt failed! Could not connect to the remote server. */
	aern_application_address_invalid_format = 0x31U,			/*!< The IP address format was invalid! Enter a valid address format, ex. n.n.n.n */
	aern_application_certificate_exists = 0x32U,				/*!< Warning! The root certificate exists, do you want to overwite it? Y|N */
	aern_application_certificate_not_revoked = 0x33U,			/*!< Cannot delete an active certificate; revoke the certificate before deleting the file. */
	aern_application_console_timeout_expired = 0x34U,			/*!< The console timeout period has expired, set to user mode. */
	aern_application_challenge_root_path = 0x35U,				/*!< Enter the full path to the ARS root certificate. */
	aern_application_challenge_root_path_success = 0x36U,		/*!< The root certificate has been stored successfully. */
	aern_application_challenge_root_path_failure = 0x37U,		/*!< Could not find the certificate, or the file is invalid, please enter the path again. */
	aern_application_root_copy_success = 0x38U,					/*!< The root certificate has been copied successfully.*/
	aern_application_root_copy_failure = 0x39U,					/*!< The root certificate could not be copied, check the path and permissions. */
	aern_application_root_sign_failure = 0x3AU,					/*!< The certificate signing failed. The certificate was invalid or has incompatible parameters. */
	aern_application_root_sign_success = 0x3BU,					/*!< The certificate was signed successfully. */
	aern_application_invalid_input = 0x3CU,						/*!< The command input was invalid, operation failed. */
	aern_application_register_failure = 0x3DU,					/*!< The network join request has failed, check the address. */
	aern_application_register_success = 0x3EU,					/*!< The network join request has succeeded. */
	aern_application_register_existing = 0x3FU,					/*!< The node is joined to an existing network, rejoin the ads? Y|N */
	aern_application_announce_failure = 0x40U,					/*!< The certificate has been announced to the network. */
	aern_application_announce_success = 0x41U,					/*!< The certificate announce operation has failed, check the path. */
	aern_application_converge_failure = 0x42U,					/*!< The topology update has failed, memory or signing failure. */
	aern_application_converge_success = 0x43U,					/*!< The topology update has been announced to the network. */
	aern_application_message_time_invalid = 0x44U,				/*!< The network time is invalid or has substantial delay. */
	aern_application_certificate_not_found = 0x45U,				/*!< The root, ads, or aps certificate could not be found. */
	aern_application_signature_failure = 0x46U,					/*!< The signature could not be generated for a message. */
	aern_application_network_resign_failure = 0x47U,			/*!< The network resign has failed, check the address. */
	aern_application_network_resign_success = 0x48U,			/*!< This node has resigned from the network. */
	aern_application_certificate_revoke_failure = 0x49U,		/*!< The certificate revocation has failed, check the path. */
	aern_application_certificate_revoke_success = 0x4AU,		/*!< The certificate revocation has been broadcast to the network. */
	aern_application_address_change_failure = 0x4BU,			/*!< The address is not routable, or not properly formed. */
	aern_application_address_change_success = 0x4CU,			/*!< The server ip address has been changed, restart the server for changes to take effect. */
	aern_application_address_change_challenge = 0x4DU,			/*!< Do you want to change the ip address? Y|N */
	aern_application_address_change_current = 0x4EU,			/*!< The auto-detected ip address is:  */
	aern_application_address_change_message = 0x4FU,			/*!< Enter a routable IPv4 or IPv6 address. */
	aern_application_server_service_start_failure = 0x50U,		/*!< The server service could not be started, check for a valid signed certificate and network membership. */
	aern_application_server_service_start_success = 0x51U,		/*!< The server service was started successfully. */
	aern_application_server_service_stopped = 0x52U,			/*!< The server service has been stopped, use the command 'service start' to run. */
	aern_application_server_service_paused = 0x53U,				/*!< The server service has been paused, use the command 'service resume' to restart. */
	aern_application_server_service_resume_failure = 0x54U,		/*!< The server service could not be resumed, use the command 'service start' to run. */
	aern_application_server_service_resume_success = 0x55U,		/*!< The server service has resumed successfully. */
	aern_application_import_certificate_exists = 0x56U,			/*!< The server certificate already exists, do you want to replace it? Y|N */
	aern_application_import_certificate_changed = 0x57U,		/*!< Changing the server name or the domain name requires recreating the certificate, do you want to proceed? Y|N */
	aern_application_import_certificate_failure = 0x58U,		/*!< The server certificate could not be updated, check the path and root signature */
	aern_application_import_certificate_success = 0x59U,		/*!< The server certificate was updated successfully */
	aern_application_export_certificate_failure = 0x5AU,		/*!< The server certificate could not be exported, check the path */
	aern_application_export_certificate_success = 0x5BU,		/*!< The server certificate was exported successfully */
	aern_application_server_domain_change_challenge = 0x5CU,	/*!< Do you want to change the servers domain name? Y|N */
	aern_application_server_domain_change_current = 0x5DU,		/*!< The current domain name string:  */
	aern_application_server_domain_change_failure = 0x5EU,		/*!< The server could not update the domain name. */
	aern_application_server_domain_change_success = 0x5FU,		/*!< The domain name has been updated successfully. */
	aern_application_certificate_period_update = 0x60U,			/*!< The days entered exceeds the root expiration period; days reduced to: */
	aern_application_certificate_root_validate = 0x61U,			/*!< The certificate must be signed by the ARS server before joining the network. */
	aern_application_command_not_supported = 0x62U,				/*!< The command is not supported on this server or version. */
	aern_application_network_ip_address_not_set = 0x63U,		/*!< The network address is invalid or not set. */
	aern_application_network_local_error = 0x64U,				/*!< received a network error from remote host:  */
	aern_application_network_remote_error = 0x65U,				/*!< a network error occured with remote host:  */
	aern_application_topological_query_unknown = 0x66U,			/*!< The query name format is invalid, valid format is domain.client */
	aern_application_topological_query_failure = 0x67U,			/*!< The device is offline or unknown to the ADC */
	aern_application_topological_query_success = 0x68U,			/*!< The device is online and available for connection */
	aern_application_adc_certificate_path_failure = 0x69U,		/*!< The certificate was not found or is not signed */
	aern_application_adc_certificate_path_success = 0x6AU,		/*!< Provide the full path to the signed ADC certificate */
	aern_application_adc_certificate_address_challenge = 0x6BU,	/*!< Provide the IP address of the ADC server */
	aern_application_adc_certificate_address_failure = 0x6CU,	/*!< The ADC IP address format is invalid */
	aern_application_server_backup_restore_challenge = 0x6DU,	/*!< Restore the configuration files from the last backup? */
	aern_application_server_backup_save_confirmation = 0x6EU,	/*!< The configuration files have been backed up. */
	aern_application_certificate_remote_sign_failure = 0x6FU,	/*!< The proxy service could not sign the certificate. */
	aern_application_certificate_remote_sign_success = 0x70U,	/*!< The certificate was signed by the proxy service. */
	aern_application_log_address_change = 0x71U,				/*!< The server address has been changed by the administrator */
	aern_application_log_domain_change = 0x72U,					/*!< The domain name was changed to */
	aern_application_log_hostname_change = 0x73U,				/*!< The host name was changed to */
	aern_application_log_user_logged_in = 0x74U,				/*!< Local user logged in: */
	aern_application_log_log_created = 0x75U,					/*!< Log file created: */
	aern_application_log_log_disabled = 0x76U,					/*!< Logging has been disabled on */
	aern_application_log_log_enabled = 0x77U,					/*!< Logging has been enabled on */
	aern_application_log_log_header = 0x78U,					/*!< AERN version 1.0a, created September 2022. */
	aern_application_log_retries_change = 0x79U,				/*!< The login retries setting was changed to */
	aern_application_log_timeout_change = 0x7AU,				/*!< The session timeout was changed to */
	aern_application_log_user_added = 0x7BU,					/*!< Added user configuration: */
	aern_application_log_state_restore = 0x7CU,					/*!< The server state has been restored */
	aern_application_log_state_backup = 0x7DU,					/*!< The server state has been backed up */
	aern_application_log_service_paused = 0x7EU,				/*!< The server service was paused */
	aern_application_log_service_resumed = 0x7FU,				/*!< The server service was resumed */
	aern_application_log_service_started = 0x80U,				/*!< The server service was started */
	aern_application_log_service_stopped = 0x81U,				/*!< The server service was stopped */
	aern_application_log_mfk_exchange_failure = 0x82U,			/*!< The network mfk exchange has failed */
	aern_application_log_mfk_exchange_success = 0x83U,			/*!< The network mfk exchange has succeeded */
	aern_application_log_generate_delete = 0x84U,				/*!< The server generated a replacement certificate: */
	aern_application_log_generate_failure = 0x85U,				/*!< The certificate generation has failed. */
	aern_application_log_generate_success = 0x86U,				/*!< The certificate generation has succeeded: */
	aern_application_log_revocation_failure = 0x87U,			/*!< The certificate announcement has succeeded */
	aern_application_log_revocation_success = 0x88U,			/*!< The certificate revocation has failed */
	aern_application_log_convergence_failure = 0x89U,			/*!< The converce call has returned a failure */
	aern_application_log_convergence_success = 0x8AU,			/*!< The remote host has converged and updated its certificate */
	aern_application_log_incremental_failure = 0x8BU,			/*!< The topological update request failed or was denied */
	aern_application_log_incremental_success = 0x8CU,			/*!< The topological update request was sent */
	aern_application_log_allocation_failure = 0x8DU,			/*!< Memory allocation failure, connection aborted to host */
	aern_application_log_connection_terminated = 0x8EU,			/*!< Connection terminated by remote host */
	aern_application_log_configuration_erased = 0x8FU,			/*!< The configuration was erased by user: */
	aern_application_log_receive_failure = 0x90U,				/*!< The network session has timed out */
	aern_application_log_register_failure = 0x91U,				/*!< The network ads join request was denied */
	aern_application_log_register_success = 0x92U,				/*!< The network ads join request has succeeded */
	aern_application_log_fragment_exchange_failure = 0x93U,		/*!< The key fragment exchange has failed */
	aern_application_log_fragment_exchange_success = 0x94U,		/*!< The key fragment exchange has succeeded */
	aern_application_log_local_resign_failure = 0x95U,			/*!< The host resignation from the network failed */
	aern_application_log_local_resign_success = 0x96U,			/*!< The host has resigned from the network */
	aern_application_log_remote_invalid_request = 0x97U,		/*!< The remote device sent an invalid or unknown request */
	aern_application_log_remote_reported_error = 0x98U,			/*!< The remote device responded with an error code */
	aern_application_log_connect_failure = 0x99U,				/*!< Remote connection failed at */
	aern_application_log_connect_success = 0x9AU,				/*!< Connected to remote host: */
	aern_application_log_topology_node_query_failure = 0x9BU,	/*!< The node query failed */
	aern_application_log_topology_node_query_success = 0x9CU,	/*!< The device answered a node query successfully */
	aern_application_log_announce_failure = 0x9DU,				/*!< The node was not found in the topological database */
	aern_application_log_announce_success = 0x9EU,				/*!< The certificate announcement has failed */
	aern_application_log_remote_signing_failure = 0x9FU,		/*!< The remote certificate could not be signed */
	aern_application_log_remote_signing_success = 0xA0U,		/*!< The remote certificate was signed successfully */
	aern_application_log_remote_resign_failure = 0xA1U,			/*!< The remote host resignation from the network failed */
	aern_application_log_remote_resign_success = 0xA2U,			/*!< The remote host has resigned from the network */
	aern_application_log_converge_node_remove_challenge = 0xA3U,/*!< Do you want to revoke this device and remove it from the database? */
	aern_application_ars_certificate_address_challenge = 0xA4U,	/*!< Provide the IP address of the ARS server */
	aern_application_ars_certificate_address_failure = 0xA5U,	/*!< The ARS IP address format is invalid */
	aern_application_server_service_not_started = 0xA6U,		/*!< The server service must be started before issuing this command */
} aern_application_messages;

/*!
* \enum aern_command_actions
* \brief The ARS command actions
*/
typedef enum aern_command_actions
{
	aern_command_action_none = 0x00U,							/*!< unknown command */
	  
	/* configuration commands */
	aern_command_action_config_address = 0x01U,					/*!< address [ip address] -Assign the server's network interface address; requires a restart.*/
	aern_command_action_config_certificate = 0x02U,				/*!< crypto -enter the cryptographic command interface */
	aern_command_action_config_clear_all = 0x03U,				/*!< clear all -requires auth challenge, deletes everything */
	aern_command_action_config_clear_config = 0x04U,			/*!< clear config -requires auth challenge, deletes public key cache */
	aern_command_action_config_clear_log = 0x05U,				/*!< clear log -requires auth challenge, clears the logs */
	aern_command_action_config_exit = 0x06U,					/*!< exit -exits to enable mode */
	aern_command_action_config_help = 0x07U,					/*!< help for config mode */
	aern_command_action_config_log_host = 0x08U,				/*!< log [enable | disable] -log command and connection activity */
	aern_command_action_config_name_domain = 0x09U,				/*!< name domain [domain-name] -fully qualified domain-name */
	aern_command_action_config_name_host = 0x0AU,				/*!< name host [host-name] */
	aern_command_action_config_retries = 0x0BU,					/*!< retries [count] -authentication retries, default is 2 */
	aern_command_action_config_server = 0x0CU,					/*!< server -enter server configuration mode */
	aern_command_action_config_timeout = 0x0DU,					/*!< timeout [seconds] -session default 120 */

	/* enable commands */
	aern_command_action_enable_clear_screen = 0x0EU,			/*!< clear the screen */
	aern_command_action_enable_config = 0x0FU,					/*!< config -enter configuration mode */
	aern_command_action_enable_exit = 0x10U,					/*!< exit -exits to user mode */
	aern_command_action_enable_help = 0x11U,					/*!< help for enable mode */
	aern_command_action_enable_quit = 0x12U,					/*!< quit -closes the application */
	aern_command_action_enable_show_config = 0x13U,				/*!< show config -show configuration */
	aern_command_action_enable_show_log = 0x14U,				/*!< show user log -show the user activity log */

	/* user commands */
	aern_command_action_user_enable = 0x15U,					/*!< enable -triggers authentication challenge */
	aern_command_action_user_help = 0x16U,						/*!< help -lists the help for user commands */
	aern_command_action_user_quit = 0x17U,						/*!< quit -closes the application */

	/* config-certificate commands */
	aern_command_action_certificate_exit = 0x18U,				/*!< exit -exits to config mode */
	aern_command_action_certificate_export = 0x19U,				/*!< export [path] -exports the local certificate to a file */
	aern_command_action_certificate_generate = 0x1AU,			/*!< generate [period] -generate the public certificate */
	aern_command_action_certificate_help = 0x1BU,				/*!< help -command help for certificate mode */
	aern_command_action_certificate_import = 0x1CU,				/*!< import [path] -imports a certificate from a file */
	aern_command_action_certificate_print = 0x1DU,				/*!< print -print a certificate */

	/* config-server commands */
	aern_command_action_server_backup = 0x1EU,					/*!< backup -save a backup of the aps state */
	aern_command_action_server_connect = 0x1FU,					/*!< connect [ip address] -connects to an application server or client */
	aern_command_action_server_exit = 0x20U,					/*!< exit -exits to config mode */
	aern_command_action_server_help = 0x21U,					/*!< help -command help for server mode */
	aern_command_action_server_list = 0x22U,					/*!< list -display the topological database */
	aern_command_action_server_register = 0x23U,				/*!< register [address] -register aps with the ADC */
	aern_command_action_server_resign = 0x24U,					/*!< resign [address] -resign from the ADC */
	aern_command_action_server_restore = 0x25U,					/*!< restore -restore the device state from backup */
	aern_command_action_server_service = 0x26U,					/*!< service -[start | stop | pause | resume] the server service */

	/* client config-connect commands */
	aern_command_action_server_query = 0x27U,					/*!< query [canonical-name] -Request node information for a device from the ADC */
	aern_command_action_client_connect_help = 0x28U,			/*!< help -command help for connect mode */
	aern_command_action_client_connect_quit = 0x29U,			/*!< quit -quits the remote server connection */

	/* ads config-certificate commands */
	aern_command_action_adc_certificate_revoke = 0x2AU,			/*!< revoke [certificate path] -revoke the local device certificate */

	/* ads config-server commands */
	aern_command_action_adc_server_announce = 0x2BU,			/*!< announce [certificate-path, ip-address] -announce an aps to servers in the network */
	aern_command_action_adc_server_converge = 0x2CU,			/*!< converge -announce a topology update to the network */
	aern_command_action_adc_server_revoke = 0x2DU,				/*!< revoke [certificate path] -revoke an aps's credentials by announcing it to the network */
	aern_command_action_adc_server_sproxy = 0x2EU,				/*!< sproxy [certificate path] -send a remote certificate signing request to the ARS server */

	/* rds config-certificate commands */
	aern_command_action_certificate_sign = 0x2FU,				/*!< sign [certificate path] -sign a child certificate */

	/* config sub commands */
	aern_command_action_config_clear = 0x30U,					/*!< clear the configuration */
	aern_command_action_config_log = 0x31U,						/*!< print the configuration log */
	aern_command_action_config_name = 0x32U,					/*!< get the configuration name */
	aern_command_action_help_enable_all = 0x33U,				/*!< enable all mode help */
	aern_command_action_help_enable_show = 0x34U,				/*!< enable show mode help */
	aern_command_action_help_enable_user = 0x35U,				/*!< enable user mode help */
	aern_command_action_command_unrecognized = 0x36U,			/*!< the command was unrecognized */
} aern_command_actions;

/*!
* \enum aern_console_modes
* \brief The ARS console modes
*/
typedef enum aern_console_modes
{
	aern_console_mode_name = 0x00U,								/*!< The name prompt */
	aern_console_mode_user = 0x01U,								/*!< The user mode prompt */
	aern_console_mode_enable = 0x02U,							/*!< The enable mode prompt */
	aern_console_mode_config = 0x03U,							/*!< The config mode prompt */
	aern_console_mode_certificate = 0x04U,						/*!< The certificate mode prompt */
	aern_console_mode_server = 0x05U,							/*!< The server mode prompt */
	aern_console_mode_login_message = 0x06U,					/*!< The login message */
	aern_console_mode_login_password = 0x07U,					/*!< The login password message */
	aern_console_mode_login_user = 0x08U,						/*!< The login user name message */
	aern_console_mode_login_hostname = 0x09U,					/*!< The login host name message */
	aern_console_mode_login_address = 0x0AU,					/*!< The login address message */
	aern_console_mode_login_domain = 0x0BU,						/*!< The login domain name message */
	aern_console_mode_login_rootpath = 0x0CU,					/*!< The login root path message */
	aern_console_mode_client_connected = 0x0DU,					/*!< The client is connected to a remore server */
} aern_console_modes;

#endif

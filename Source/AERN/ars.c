#include "ars.h"
#include "server.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "aern.h"
#include "network.h"
#include "resources.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct ars_receive_state
{
	qsc_socket csock;
} ars_receive_state;
/** \endcond */

static aern_server_application_state m_ars_application_state = { 0 };
static aern_server_server_loop_status m_ars_command_loop_status;
static aern_server_server_loop_status m_ars_server_loop_status;
static uint64_t m_ars_idle_timer;

/* rds functions */

static bool ars_certificate_export(const char* dpath)
{
	AERN_ASSERT(dpath != NULL);

	bool res;

	res = aern_server_root_certificate_export(&m_ars_application_state, dpath);

	return res;
}

static bool ars_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (aern_server_topology_root_fetch(&m_ars_application_state, &m_ars_application_state.root) == true)
	{
		res = aern_topology_node_verify_root(&m_ars_application_state.tlist, &m_ars_application_state.root);
	}

	return res;
}

static bool ars_certificate_generate_root(const char* sprd)
{
	AERN_ASSERT(sprd != NULL); 

	uint64_t period;
	bool res;

	res = false;

	/* generate a certificate and write to file */
	if (qsc_stringutils_is_numeric(sprd, qsc_stringutils_string_size(sprd)) == true)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_server_certificate_path(&m_ars_application_state, fpath, sizeof(fpath), m_ars_application_state.issuer);
		period = qsc_stringutils_string_to_int(sprd);
		period *= AERN_PERIOD_DAY_TO_SECONDS;

		if (period >= AERN_CERTIFICATE_MINIMUM_PERIOD || period <= AERN_CERTIFICATE_MAXIMUM_PERIOD)
		{
			if (qsc_fileutils_exists(fpath) == true)
			{
				/* file exists, overwrite challenge */
				if (aern_menu_print_predefined_message_confirm(aern_application_generate_key_overwrite, m_ars_application_state.mode, m_ars_application_state.hostname) == true)
				{
					/* remove the node entry */
					aern_topology_node_remove(&m_ars_application_state.tlist, m_ars_application_state.root.serial);
					/* delete the original */
					qsc_fileutils_delete(fpath);
					/* create the certificate and copy the signing key to state */
					aern_server_root_certificate_generate(&m_ars_application_state, &m_ars_application_state.root, period);
					/* write the certificate to file */
					aern_server_root_certificate_store(&m_ars_application_state, &m_ars_application_state.root);
					/* store the state */
					res = aern_server_state_store(&m_ars_application_state);
					res = ars_server_load_root();
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_operation_aborted, m_ars_application_state.mode, m_ars_application_state.hostname);
					res = false;
				}
			}
			else
			{
				aern_server_root_certificate_generate(&m_ars_application_state, &m_ars_application_state.root, period);
				aern_server_root_certificate_store(&m_ars_application_state, &m_ars_application_state.root);
				res = aern_server_state_store(&m_ars_application_state);
				res = ars_server_load_root();
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_invalid_input, m_ars_application_state.mode, m_ars_application_state.hostname);
		}
	}

	return res;
}

static bool ars_certificate_sign(const char* fpath)
{
	AERN_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (qsc_fileutils_exists(fpath) == true && 
		qsc_stringutils_string_contains(fpath, AERN_CERTIFICATE_CHILD_EXTENSION) == true)
	{
		aern_child_certificate child = { 0 };

		if (aern_certificate_child_file_to_struct(fpath, &child) == true)
		{
			if (aern_certificate_root_sign(&child, &m_ars_application_state.root, m_ars_application_state.sigkey) == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
			{
				res = aern_certificate_child_struct_to_file(fpath, &child);
			}
		}
	}

	return res;
}

static aern_protocol_errors ads_remote_signing_response(qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_topology_node_state dnode = { 0 };
	aern_protocol_errors merr;

	if (m_ars_application_state.joined == true)
	{
		if (aern_topology_node_find(&m_ars_application_state.tlist, &dnode, m_ars_application_state.ads.serial) == true)
		{
			if (qsc_memutils_are_equal((const uint8_t*)dnode.address, (const uint8_t*)csock->address, AERN_CERTIFICATE_ADDRESS_SIZE) == true)
			{
				aern_child_certificate rcert = { 0 };

				aern_network_remote_signing_response_state rsr = {
					.csock = csock,
					.dcert = &m_ars_application_state.ads,
					.rcert = &rcert,
					.root = &m_ars_application_state.root,
					.sigkey = m_ars_application_state.sigkey
				};

				merr = aern_network_remote_signing_response(&rsr, packetin);
			}
			else
			{
				merr = aern_protocol_error_invalid_request;
			}
		}
		else
		{
			merr = aern_protocol_error_node_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_certificate_not_found;
	}

	return merr;
}

static void ars_server_dispose(void)
{
	aern_server_state_initialize(&m_ars_application_state, aern_network_designation_ars);
	m_ars_command_loop_status = aern_server_loop_status_stopped;
	m_ars_server_loop_status = aern_server_loop_status_stopped;
	m_ars_idle_timer = 0U;
}

static bool ars_server_load_ads(void)
{
	bool res;

	res = false;

	/* load the ads certificate */
	if (aern_server_topology_adc_fetch(&m_ars_application_state, &m_ars_application_state.ads) == true)
	{
		/* check the ads certificate structure */
		if (aern_certificate_child_is_valid(&m_ars_application_state.ads) == true)
		{
			/* verify the root signature */
			if (aern_certificate_root_signature_verify(&m_ars_application_state.ads, &m_ars_application_state.root) == true)
			{
				/* verify a hash of the certificate against the hash stored on the topological node */
				res = aern_topology_node_verify_ads(&m_ars_application_state.tlist, &m_ars_application_state.ads);
			}
		}
	}

	return res;
}

static bool ars_server_adc_dialogue(void)
{
	char cmsg[AERN_STORAGE_PATH_MAX] = { 0 };
	char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
	size_t slen;
	uint8_t rctr;
	bool res;

	res = false;
	rctr = 0U;

	while (res == false)
	{
		++rctr;

		if (rctr > 3U)
		{
			break;
		}

		aern_menu_print_predefined_message(aern_application_adc_certificate_path_success, aern_console_mode_server, m_ars_application_state.hostname);
		aern_menu_print_prompt(aern_console_mode_server, m_ars_application_state.hostname);
		slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

		if (slen >= AERN_STORAGE_FILEPATH_MIN && 
			slen <= AERN_STORAGE_FILEPATH_MAX &&
			qsc_fileutils_exists(cmsg) == true &&
			qsc_stringutils_string_contains(cmsg, AERN_CERTIFICATE_CHILD_EXTENSION))
		{
			aern_child_certificate ccert = { 0 };

			if (aern_certificate_child_file_to_struct(cmsg, &ccert) == true)
			{
				if (aern_certificate_child_is_valid(&ccert) == true && 
					aern_certificate_root_signature_verify(&ccert, &m_ars_application_state.root) == true)
				{
					/* get the ADC ip address */
					qsc_memutils_clear(cmsg, sizeof(cmsg));
					aern_menu_print_predefined_message(aern_application_adc_certificate_address_challenge, aern_console_mode_server, m_ars_application_state.hostname);
					aern_menu_print_prompt(aern_console_mode_server, m_ars_application_state.hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= QSC_IPINFO_IPV4_MINLEN)
					{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
						qsc_ipinfo_ipv6_address tadd;

						tadd = qsc_ipinfo_ipv6_address_from_string(cmsg);

						if (qsc_ipinfo_ipv6_address_is_valid(&tadd) == true)
						{
#else
						qsc_ipinfo_ipv4_address tadd;

						tadd = qsc_ipinfo_ipv4_address_from_string(cmsg);

						if (qsc_ipinfo_ipv4_address_is_valid(&tadd) == true)
						{
#endif
							aern_topology_node_state rnode = { 0 };

							/* add the node to the topology */
							aern_topology_child_register(&m_ars_application_state.tlist, &ccert, cmsg);
							aern_server_topology_to_file(&m_ars_application_state);

							if (aern_topology_node_find(&m_ars_application_state.tlist, &rnode, ccert.serial) == true)
							{
								/* copy the certificate to file */
								aern_server_certificate_path(&m_ars_application_state, fpath, sizeof(fpath), rnode.issuer);

								if (aern_certificate_child_struct_to_file(fpath, &ccert) == true)
								{
									/* copy certificate to state */
									aern_certificate_child_copy(&m_ars_application_state.ads, &ccert);
									m_ars_application_state.joined = true;
									/* store the state */
									res = aern_server_state_store(&m_ars_application_state);
									break;
								}
							}
						}
					}
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_adc_certificate_path_failure, aern_console_mode_server, m_ars_application_state.hostname);
				}
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_certificate_not_found, aern_console_mode_server, m_ars_application_state.hostname);
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_certificate_not_found, aern_console_mode_server, m_ars_application_state.hostname);
		}
	}

	return res;
}

static void ars_receive_loop(void* ras)
{
	AERN_ASSERT(ras != NULL);

	aern_network_packet pkt = { 0 };
	uint8_t* buff;
	ars_receive_state* pras;
	const char* cmsg;
	size_t mlen;
	size_t plen;
	aern_protocol_errors merr;

	merr = aern_protocol_error_none;

	if (ras != NULL)
	{
		pras = (ars_receive_state*)ras;
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			uint8_t hdr[AERN_PACKET_HEADER_SIZE] = { 0U };

			mlen = 0U;
			plen = qsc_socket_peek(&pras->csock, hdr, AERN_PACKET_HEADER_SIZE);

			if (plen == AERN_PACKET_HEADER_SIZE)
			{
				aern_packet_header_deserialize(hdr, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= AERN_MESSAGE_MAX_SIZE)
				{
					plen = pkt.msglen + AERN_PACKET_HEADER_SIZE;
					buff = (uint8_t*)qsc_memutils_realloc(buff, plen);

					if (buff != NULL)
					{
						qsc_memutils_clear(buff, plen);
						mlen = qsc_socket_receive(&pras->csock, buff, plen, qsc_socket_receive_flag_wait_all);
					}
					else
					{
						merr = aern_protocol_error_memory_allocation;
						aern_server_log_write_message(&m_ars_application_state, aern_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
				}
				else
				{
					merr = aern_protocol_error_invalid_request;
					aern_server_log_write_message(&m_ars_application_state, aern_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
				}

				if (mlen > 0U)
				{
					pkt.pmessage = buff + AERN_PACKET_HEADER_SIZE;

					if (pkt.flag == aern_network_flag_network_remote_signing_request)
					{
						merr = ads_remote_signing_response(&pras->csock, &pkt);

						if (merr == aern_protocol_error_none)
						{
							aern_server_log_write_message(&m_ars_application_state, aern_application_log_remote_signing_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
						else
						{
							cmsg = aern_protocol_error_to_string(merr);

							if (cmsg != NULL)
							{
								aern_logger_write_time_stamped_message(m_ars_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							aern_server_log_write_message(&m_ars_application_state, aern_application_log_remote_signing_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else if (pkt.flag == aern_network_flag_system_error_condition)
					{
						/* log the error condition */
						cmsg = aern_protocol_error_to_string((aern_protocol_errors)pkt.pmessage[0U]);

						if (cmsg != NULL)
						{
							aern_logger_write_time_stamped_message(m_ars_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
						}

						aern_server_log_write_message(&m_ars_application_state, aern_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
					else
					{
						qsc_socket_exceptions err = qsc_socket_get_last_error();

						if (err != qsc_socket_exception_success)
						{
							/* fatal socket errors */
							if (err == qsc_socket_exception_circuit_reset ||
								err == qsc_socket_exception_circuit_terminated ||
								err == qsc_socket_exception_circuit_timeout ||
								err == qsc_socket_exception_dropped_connection ||
								err == qsc_socket_exception_network_failure ||
								err == qsc_socket_exception_shut_down)
							{
								aern_server_log_write_message(&m_ars_application_state, aern_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							aern_network_send_error(&pras->csock, aern_protocol_error_invalid_request);
							aern_server_log_write_message(&m_ars_application_state, aern_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
				}
			}

			qsc_memutils_alloc_free(buff);
		}

		/* close the connection and dispose of the socket */
		aern_network_socket_dispose(&pras->csock);

		/* free the socket from memory */
		qsc_memutils_alloc_free(pras);
		pras = NULL;
	}
}

#if defined(AERN_NETWORK_PROTOCOL_IPV6)

static void ars_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv6_address_from_string(m_ars_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, AERN_APPLICATION_ARS_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						ars_receive_state* ras;

						ras = (ars_receive_state*)qsc_memutils_malloc(sizeof(ars_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								aern_server_log_write_message(&m_ars_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&ars_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								aern_server_log_write_message(&m_ars_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							break;
						}
					};
				}
			}
		}
	}
}

#else

static void ars_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv4_address_from_string(m_ars_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, AERN_APPLICATION_ARS_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						ars_receive_state* ras;

						ras = (ars_receive_state*)qsc_memutils_malloc(sizeof(ars_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&ars_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								aern_server_log_write_message(&m_ars_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							aern_server_log_write_message(&m_ars_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
			}
		}
	}
}

#endif

static bool ars_server_service_start(void)
{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&ars_ipv6_server_start))
#else
	if (qsc_async_thread_create_noargs(&ars_ipv4_server_start))
#endif
	{
		m_ars_server_loop_status = aern_server_loop_status_started;
	}

	return (m_ars_server_loop_status == aern_server_loop_status_started);
}

/* application functions */

static void ars_get_command_mode(const char* command)
{
	AERN_ASSERT(command != NULL);

	aern_console_modes nmode;

	nmode = m_ars_application_state.mode;

	switch (m_ars_application_state.mode)
	{
		case aern_console_mode_config:
		{
			if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				nmode = aern_console_mode_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				nmode = aern_console_mode_server;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = aern_console_mode_enable;
			}

			break;
		}
		case aern_console_mode_certificate:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = aern_console_mode_config;
			}

			break;
		}
		case aern_console_mode_server:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = aern_console_mode_config;
			}

			break;
		}
		case aern_console_mode_enable:
		{
			if (qsc_consoleutils_line_equals(command, "config"))
			{
				nmode = aern_console_mode_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = aern_console_mode_user;
			}

			break;
		}
		case aern_console_mode_user:
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				nmode = aern_console_mode_enable;
			}
			else if (qsc_stringutils_string_size(command) > 0U)
			{
				nmode = aern_console_mode_user;
			}

			break;
		}
		default:
		{
		}
	}

	m_ars_application_state.mode = nmode;
}

static void ars_set_command_action(const char* command)
{
	AERN_ASSERT(command != NULL);

	aern_command_actions res;
	size_t clen;

	res = aern_command_action_command_unrecognized;
	clen = qsc_stringutils_string_size(command);

	if (clen == 0U || clen > QSC_CONSOLE_MAX_LINE)
	{
		res = aern_command_action_none;
	}
	else
	{
		if (m_ars_application_state.mode == aern_console_mode_config)
		{
			if (qsc_consoleutils_line_equals(command, "clear all"))
			{
				res = aern_command_action_config_clear_all;
			}
			else if (qsc_consoleutils_line_equals(command, "clear config"))
			{
				res = aern_command_action_config_clear_config;
			}
			else if (qsc_consoleutils_line_equals(command, "clear log"))
			{
				res = aern_command_action_config_clear_log;
			}
			else if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				res = aern_command_action_config_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_config_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_config_help;
			}
			else if (qsc_consoleutils_line_contains(command, "log "))
			{
				res = aern_command_action_config_log_host;
			}
			else if (qsc_consoleutils_line_contains(command, "address "))
			{
				res = aern_command_action_config_address;
			}
			else if (qsc_consoleutils_line_contains(command, "name domain "))
			{
				res = aern_command_action_config_name_domain;
			}
			else if (qsc_consoleutils_line_contains(command, "name host "))
			{
				res = aern_command_action_config_name_host;
			}
			else if (qsc_consoleutils_line_contains(command, "retries "))
			{
				res = aern_command_action_config_retries;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				res = aern_command_action_config_server;
			}
			else if (qsc_consoleutils_line_contains(command, "timeout "))
			{
				res = aern_command_action_config_timeout;
			}
		}
		else if (m_ars_application_state.mode == aern_console_mode_certificate)
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_certificate_exit;
			}
			else if (qsc_consoleutils_line_contains(command, "export "))
			{
				res = aern_command_action_certificate_export;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_certificate_help;
			}
			else if (qsc_consoleutils_line_contains(command, "generate "))
			{
				res = aern_command_action_certificate_generate;
			}
			else if (qsc_consoleutils_line_equals(command, "print"))
			{
				res = aern_command_action_certificate_import;
			}
			else if (qsc_consoleutils_line_contains(command, "sign "))
			{
				res = aern_command_action_certificate_sign;
			}
		}
		else if (m_ars_application_state.mode == aern_console_mode_server)
		{
			if (qsc_consoleutils_line_equals(command, "backup"))
			{
				res = aern_command_action_server_backup;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_server_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_server_help;
			}
			else if (qsc_consoleutils_line_equals(command, "restore"))
			{
				res = aern_command_action_server_restore;
			}
			else if (qsc_consoleutils_line_contains(command, "service "))
			{
				res = aern_command_action_server_service;
			}
		}
		else if (m_ars_application_state.mode == aern_console_mode_enable)
		{
			if (qsc_consoleutils_line_equals(command, "clear"))
			{
				res = aern_command_action_enable_clear_screen;
			}
			else if (qsc_consoleutils_line_equals(command, "show config"))
			{
				res = aern_command_action_enable_show_config;
			}
			else if (qsc_consoleutils_line_equals(command, "show log"))
			{
				res = aern_command_action_enable_show_log;
			}
			else if (qsc_consoleutils_line_equals(command, "config"))
			{
				res = aern_command_action_enable_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_enable_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_enable_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = aern_command_action_enable_quit;
			}
		}
		else if (m_ars_application_state.mode == aern_console_mode_user)
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				res = aern_command_action_user_enable;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_user_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = aern_command_action_user_quit;
			}
		}
	}

	m_ars_application_state.action = res;
}

static void ars_command_execute(const char* command)
{
	AERN_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	bool res;

	switch (m_ars_application_state.action)
	{
	case aern_command_action_certificate_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_certificate_export:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = ars_certificate_export(cmsg);

			if (res == true)
			{
				aern_menu_print_predefined_message(aern_application_root_copy_success, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_root_copy_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(m_ars_application_state.username);

		if (cmsg != NULL)
		{
			res = ars_certificate_generate_root(cmsg);

			if (res == true)
			{
				char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

				aern_server_certificate_path(&m_ars_application_state, fpath, sizeof(fpath), m_ars_application_state.issuer);
				aern_menu_print_predefined_message(aern_application_generate_key_success, m_ars_application_state.mode, m_ars_application_state.hostname);
				aern_menu_print_message(fpath, m_ars_application_state.mode, m_ars_application_state.hostname);
				aern_server_log_write_message(&m_ars_application_state, aern_application_log_generate_success, m_ars_application_state.username, slen);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_generate_key_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
				aern_server_log_write_message(&m_ars_application_state, aern_application_log_generate_failure, m_ars_application_state.username, slen);
			}
		}

		break;
	}
	case aern_command_action_certificate_help:
	{
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_certificate, m_ars_application_state.srvtype);
		break;
	}
	case aern_command_action_certificate_import:
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		res = false;
		aern_server_certificate_path(&m_ars_application_state, fpath, sizeof(fpath), m_ars_application_state.issuer);

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = aern_server_root_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			aern_menu_print_predefined_message(aern_application_client_pubkey_path_invalid, m_ars_application_state.mode, m_ars_application_state.hostname);
		}

		break;
	}
	case aern_command_action_certificate_sign:
	{
		res = false;
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = ars_certificate_sign(cmsg);
			slen = qsc_stringutils_string_size(m_ars_application_state.username);

			if (res == true)
			{
				aern_server_log_write_message(&m_ars_application_state, aern_application_root_sign_success, m_ars_application_state.username, slen);
				aern_menu_print_predefined_message(aern_application_root_sign_success, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
			else
			{
				aern_server_log_write_message(&m_ars_application_state, aern_application_root_sign_failure, m_ars_application_state.username, slen);
				aern_menu_print_predefined_message(aern_application_root_sign_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);
			res = aern_server_set_ip_address(&m_ars_application_state, cmsg, slen);

			if (res == true)
			{
				aern_menu_print_predefined_message(aern_application_address_change_success, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_address_change_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_clear:
	{
		/* show clear help */
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_clear_all);
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_clear_config);
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_clear_log);

		break;
	}
	case aern_command_action_config_log:
	{
		/* show log help */
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_log_host);

		break;
	}
	case aern_command_action_config_name:
	{
		/* show name help */
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_name_domain);
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_name_host);

		break;
	}
	case aern_command_action_config_clear_all:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_erase_all, m_ars_application_state.mode, m_ars_application_state.hostname) == true)
		{
			aern_server_erase_all(&m_ars_application_state);
			aern_menu_print_predefined_message(aern_application_system_erased, m_ars_application_state.mode, m_ars_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_ars_application_state.mode, m_ars_application_state.hostname);
		}

		break;
	}
	case aern_command_action_config_clear_config:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_config, aern_console_mode_config, m_ars_application_state.hostname) == true)
		{
			aern_server_log_write_message(&m_ars_application_state, aern_application_log_configuration_erased, m_ars_application_state.username, qsc_stringutils_string_size(m_ars_application_state.username));
			aern_server_clear_config(&m_ars_application_state);
			aern_menu_print_predefined_message(aern_application_configuration_erased, m_ars_application_state.mode, m_ars_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_ars_application_state.mode, m_ars_application_state.hostname);
		}

		break;
	}
	case aern_command_action_config_clear_log:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_log, aern_console_mode_config, m_ars_application_state.hostname) == true)
		{
			aern_server_clear_log(&m_ars_application_state);
			aern_menu_print_predefined_message(aern_application_log_erased, m_ars_application_state.mode, m_ars_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_ars_application_state.mode, m_ars_application_state.hostname);
		}

		break;
	}
	case aern_command_action_config_certificate:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_config_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_config_help:
	{
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_config, m_ars_application_state.srvtype);
		break;
	}
	case aern_command_action_config_log_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			if (qsc_stringutils_string_contains(cmsg, "enable"))
			{
				/* enable logging */
				m_ars_application_state.loghost = true;
				aern_server_log_host(&m_ars_application_state);
				aern_menu_print_predefined_message(aern_application_logging_enabled, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_ars_application_state.loghost = false;
				aern_server_log_host(&m_ars_application_state);
				aern_menu_print_predefined_message(aern_application_logging_disabled, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_not_recognized, m_ars_application_state.mode, m_ars_application_state.hostname);
				aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_log_host);
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_not_recognized, m_ars_application_state.mode, m_ars_application_state.hostname);
			aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_config_log_host);
		}

		break;
	}
	case aern_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_domain_name(&m_ars_application_state, cmsg, slen) == false)
			{
				aern_menu_print_predefined_message(aern_application_domain_invalid, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_name_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_host_name(&m_ars_application_state, cmsg, slen) == false)
			{
				aern_menu_print_predefined_message(aern_application_hostname_invalid, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_retries:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(cmsg);

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_password_retries(&m_ars_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				aern_menu_print_predefined_message(aern_application_retry_invalid, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_server:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_config_timeout:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_console_timeout(&m_ars_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				aern_menu_print_predefined_message(aern_application_timeout_invalid, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_enable_clear_screen:
	{
		/* clear the screen */
		qsc_consoleutils_set_window_clear();
		break;
	}
	case aern_command_action_enable_config:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_enable_exit:
	{
		aern_server_user_logout(&m_ars_application_state);

		break;
	}
	case aern_command_action_enable_help:
	{
		/* show enable help */
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_enable, m_ars_application_state.srvtype);

		break;
	}
	case aern_command_action_enable_quit:
	{
		/* quit the application */
		m_ars_command_loop_status = aern_server_loop_status_stopped;
		aern_server_state_unload(&m_ars_application_state);
		aern_menu_print_predefined_message(aern_application_application_quit, m_ars_application_state.mode, m_ars_application_state.hostname);
		aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case aern_command_action_enable_show_config:
	{
		/* show config */
		aern_server_print_configuration(&m_ars_application_state);
		break;
	}
	case aern_command_action_enable_show_log:
	{
		/* read the user log */
		aern_server_log_print(&m_ars_application_state);
		break;
	}
	case aern_command_action_help_enable_all:
	{
		/* show enable help */
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_enable, m_ars_application_state.srvtype);

		break;
	}
	case aern_command_action_help_enable_show:
	{
		/* show help */
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_enable_show_config);
		aern_help_print_context(m_ars_application_state.cmdprompt, aern_command_action_enable_show_log);

		break;
	}
	case aern_command_action_help_enable_user:
	{
		/* show enable user help */
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_user, m_ars_application_state.srvtype);

		break;
	}
	case aern_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_ars_application_state.hostname);
		aern_server_state_backup_save(&m_ars_application_state);
		aern_server_log_write_message(&m_ars_application_state, aern_application_log_state_backup, m_ars_application_state.hostname, slen);
		aern_menu_print_predefined_message(aern_application_server_backup_save_confirmation, m_ars_application_state.mode, m_ars_application_state.hostname);

		break;
	}
	case aern_command_action_server_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case aern_command_action_server_help:
	{
		/* show config-server help */
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_server, m_ars_application_state.srvtype);
		break;
	}
	case aern_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = aern_menu_print_predefined_message_confirm(aern_application_server_backup_restore_challenge, m_ars_application_state.mode, m_ars_application_state.hostname);
			
		if (dres == true)
		{
			aern_server_state_backup_restore(&m_ars_application_state);
			slen = qsc_stringutils_string_size(m_ars_application_state.hostname);
			aern_server_log_write_message(&m_ars_application_state, aern_application_log_state_restore, m_ars_application_state.hostname, slen);
		}

		break;
	}
	case aern_command_action_server_service:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_ars_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_ars_server_loop_status != aern_server_loop_status_started)
				{
					if (m_ars_application_state.joined == false)
					{
						ars_server_adc_dialogue();
					}

					if (ars_server_service_start() == true &&
						m_ars_server_loop_status == aern_server_loop_status_started)
					{
						aern_menu_print_predefined_message(aern_application_server_service_start_success, m_ars_application_state.mode, m_ars_application_state.hostname);
						aern_server_log_write_message(&m_ars_application_state, aern_application_log_service_started, m_ars_application_state.hostname, slen);
					}
					else
					{
						aern_menu_print_predefined_message(aern_application_server_service_start_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_ars_server_loop_status == aern_server_loop_status_started)
				{
					m_ars_server_loop_status = aern_server_loop_status_stopped;
					aern_menu_print_predefined_message(aern_application_server_service_stopped, m_ars_application_state.mode, m_ars_application_state.hostname);
					aern_server_log_write_message(&m_ars_application_state, aern_application_log_service_stopped, m_ars_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_ars_server_loop_status != aern_server_loop_status_paused)
				{
					m_ars_server_loop_status = aern_server_loop_status_paused;
					aern_menu_print_predefined_message(aern_application_server_service_paused, m_ars_application_state.mode, m_ars_application_state.hostname);
					aern_server_log_write_message(&m_ars_application_state, aern_application_log_service_paused, m_ars_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_ars_server_loop_status == aern_server_loop_status_paused)
				{
					m_ars_server_loop_status = aern_server_loop_status_started;
					aern_menu_print_predefined_message(aern_application_server_service_resume_success, m_ars_application_state.mode, m_ars_application_state.hostname);
					aern_server_log_write_message(&m_ars_application_state, aern_application_log_service_resumed, m_ars_application_state.hostname, slen);
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_server_service_resume_failure, m_ars_application_state.mode, m_ars_application_state.hostname);
				}
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_not_recognized, m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_user_enable:
	{
		/* user login */
		if (aern_server_user_login(&m_ars_application_state) == true)
		{
			if (ars_server_load_root() == true)
			{
				m_ars_application_state.joined = ars_server_load_ads();
			}
		}
		else
		{
			aern_ars_stop_server();
			aern_menu_print_predefined_message(aern_application_retries_exceeded, m_ars_application_state.mode, m_ars_application_state.hostname);
			aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case aern_command_action_user_help:
	{
		/* show user help */
		aern_help_print_mode(m_ars_application_state.cmdprompt, aern_console_mode_user, m_ars_application_state.srvtype);

		break;
	}
	case aern_command_action_user_quit:
	{
		m_ars_command_loop_status = aern_server_loop_status_stopped;
		aern_server_state_unload(&m_ars_application_state);
		aern_menu_print_predefined_message(aern_application_application_quit, m_ars_application_state.mode, m_ars_application_state.hostname);
		aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case aern_command_action_none:
	{
		/* empty return, do nothing */
		break;
	}
	case aern_command_action_command_unrecognized:
	{
		/* partial command */
		aern_menu_print_predefined_message(aern_application_not_recognized, m_ars_application_state.mode, m_ars_application_state.hostname);
		aern_help_print_mode(m_ars_application_state.cmdprompt, m_ars_application_state.mode, m_ars_application_state.srvtype);
		break;
	}
	default:
	{
		aern_help_print_mode(m_ars_application_state.cmdprompt, m_ars_application_state.mode, m_ars_application_state.srvtype);
	}
	}
}

static void ars_idle_timer(void)
{
	const uint32_t MMSEC = 60U * 1000U;

	while (true)
	{
		qsc_async_thread_sleep(MMSEC);
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		if (m_ars_application_state.mode != aern_console_mode_user)
		{
			++m_ars_idle_timer;

			if (m_ars_idle_timer >= m_ars_application_state.timeout)
			{
				aern_server_user_logout(&m_ars_application_state);
				m_ars_idle_timer = 0;
				qsc_consoleutils_print_line("");
				aern_menu_print_predefined_message(aern_application_console_timeout_expired, m_ars_application_state.mode, m_ars_application_state.hostname);
				aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void ars_command_loop(char* command)
{
	AERN_ASSERT(command != NULL);

	m_ars_command_loop_status = aern_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_ars_idle_timer = 0U;
		qsc_async_mutex_unlock_ex(mtx);

		ars_set_command_action(command);
		ars_command_execute(command);
		ars_get_command_mode(command);

		aern_server_set_command_prompt(&m_ars_application_state);
		aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);
		qsc_stringutils_clear_string(command);

		if (m_ars_command_loop_status == aern_server_loop_status_paused)
		{
			qsc_async_thread_sleep(AERN_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_ars_command_loop_status == aern_server_loop_status_stopped)
		{
			break;
		}
	}

	ars_server_dispose();
}

void aern_ars_pause_server(void)
{
	m_ars_command_loop_status = aern_server_loop_status_paused;
}

void aern_ars_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;

	/* initialize the server */
	aern_server_state_initialize(&m_ars_application_state, aern_network_designation_ars);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000, 600);
	qsc_consoleutils_set_window_title(m_ars_application_state.wtitle);

	/* application banner */
	aern_server_print_banner(&m_ars_application_state);

	/* load the command prompt */
	ars_get_command_mode(command);
	aern_menu_print_prompt(m_ars_application_state.mode, m_ars_application_state.hostname);

	/* start the idle timer */
	m_ars_idle_timer = 0U;
	idle = qsc_async_thread_create_noargs(&ars_idle_timer);

	if(idle)
	{
		/* command loop */
		ars_command_loop(command);
	}
}

void aern_ars_stop_server(void)
{
	m_ars_command_loop_status = aern_server_loop_status_stopped;
}

#if defined(AERN_DEBUG_TESTS_RUN)
bool aern_ars_appserv_test(void)
{
	return false;
}
#endif

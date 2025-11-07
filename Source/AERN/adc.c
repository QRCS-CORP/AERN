#include "adc.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "aern.h"
#include "network.h"
#include "resources.h"
#include "server.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct adc_receive_state
{
	qsc_socket csock;
} adc_receive_state;
/** \endcond */

static aern_server_application_state m_adc_application_state = { 0 };
static aern_server_server_loop_status m_adc_command_loop_status;
static aern_server_server_loop_status m_adc_server_loop_status;
static uint64_t m_adc_idle_timer;

/* ads network functions */

static bool adc_certificate_generate(const char* cmsg)
{
	AERN_ASSERT(cmsg != NULL);

	uint64_t period;
	size_t nlen;
	bool res;

	res = false;
	nlen = qsc_stringutils_string_size(cmsg);

	/* generate a certificate and write to file */
	if (qsc_stringutils_is_numeric(cmsg, nlen) == true)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_server_child_certificate_path(&m_adc_application_state, fpath, sizeof(fpath));
		/* extract the days */
		period = qsc_stringutils_string_to_int(cmsg);
		/* convert to seconds */
		period *= AERN_PERIOD_DAY_TO_SECONDS;

		/* check that the root is installed */
		res = aern_server_topology_root_exists(&m_adc_application_state);

		if (res == false)
		{
			res = aern_server_root_import_dialogue(&m_adc_application_state);
		}

		if (res == true && (period >= AERN_CERTIFICATE_MINIMUM_PERIOD || period <= AERN_CERTIFICATE_MAXIMUM_PERIOD))
		{
			char sadd[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };

			aern_network_get_local_address(sadd);

			/* the child certificate is invalid once the root certificate expires,
				if the period is longer than the root, change to the root expiration time */
			if (m_adc_application_state.root.expiration.to < period + qsc_timestamp_epochtime_seconds())
			{
				char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
				int32_t rtme;

				period = m_adc_application_state.root.expiration.to - qsc_timestamp_epochtime_seconds();
				rtme = (int32_t)period / AERN_PERIOD_DAY_TO_SECONDS;
				qsc_stringutils_int_to_string(rtme, tsc, sizeof(tsc));

				/* notify user of change in duration */
				aern_menu_print_predefined_text(aern_application_certificate_period_update, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_menu_print_text_line(tsc);
			}

			if (qsc_fileutils_exists(fpath) == true)
			{
				/* file exists, overwrite challenge */
				if (aern_menu_print_predefined_message_confirm(aern_application_generate_key_overwrite, m_adc_application_state.mode, m_adc_application_state.hostname) == true)
				{
					nlen = qsc_stringutils_string_size(fpath);
					/* create the certificate and copy the signing key to state */
					aern_server_child_certificate_generate(&m_adc_application_state, &m_adc_application_state.ads, period);
					/* write the certificate to file */
					aern_server_local_certificate_store(&m_adc_application_state, &m_adc_application_state.ads, sadd);
					/* store the state */
					res = aern_server_state_store(&m_adc_application_state);
					/* log the key overwrite */
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_generate_delete, fpath, nlen);
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_operation_aborted, m_adc_application_state.mode, m_adc_application_state.hostname);
					res = false;
				}
			}
			else
			{
				aern_server_child_certificate_generate(&m_adc_application_state, &m_adc_application_state.ads, period);
				aern_server_local_certificate_store(&m_adc_application_state, &m_adc_application_state.ads, sadd);
				res = aern_server_state_store(&m_adc_application_state);
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_invalid_input, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
	}
	else
	{
		aern_menu_print_predefined_message(aern_application_invalid_input, m_adc_application_state.mode, m_adc_application_state.hostname);
	}

	return res;
}

static aern_protocol_errors adc_announce_broadcast(const char* fpath, const char* address)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(address != NULL);

	qsc_mutex mtx;
	aern_protocol_errors merr;

	if (qsc_fileutils_exists(fpath) == true)
	{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
		qsc_ipinfo_ipv6_address addt = { 0 };

		addt = qsc_ipinfo_ipv6_address_from_string(address);

		if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
		{
#else
		qsc_ipinfo_ipv4_address addt = { 0 };

		addt = qsc_ipinfo_ipv4_address_from_string(address);

		if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
		{
#endif
			aern_child_certificate rcert = { 0 };

			if (aern_certificate_child_file_to_struct(fpath, &rcert) == true)
			{
				merr = aern_network_certificate_verify(&rcert, &m_adc_application_state.root);

				if (merr == aern_protocol_error_none)
				{
					/* validate the certificate type */
					if (rcert.designation == aern_network_designation_aps)
					{
						aern_topology_node_state rnode = { 0 };

						/* remove the old entry */
						aern_topology_node_remove(&m_adc_application_state.tlist, rcert.serial);

						mtx = qsc_async_mutex_lock_ex();

						/* register the node and save the database */
						aern_topology_child_register(&m_adc_application_state.tlist, &rcert, address);
						aern_server_topology_to_file(&m_adc_application_state);

						qsc_async_mutex_unlock_ex(mtx);

						if (aern_topology_node_find_issuer(&m_adc_application_state.tlist, &rnode, rcert.issuer) == true)
						{
							aern_network_announce_request_state ars = {
								.list = &m_adc_application_state.tlist,
								.rnode = &rnode,
								.sigkey = m_adc_application_state.sigkey
							};

							/* create and send the announce broadcast */
							merr = aern_network_announce_broadcast(&ars);
						}
						else
						{
							merr = aern_protocol_error_node_not_found;
						}
					}
					else
					{
						merr = aern_protocol_error_invalid_request;
					}
				}
			}
			else
			{
				merr = aern_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_no_usable_address;
		}
	}
	else
	{
		merr = aern_protocol_error_file_not_found;
	}

	return merr;
}

#if defined(AERN_FUTURE_FEATURE)
static void adc_converge_reset(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	aern_topology_list_state clst = { 0 };

	aern_topology_list_initialize(&clst);

	for (size_t i = 0U; i < list->count; ++i)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_list_item(list, &node, i) == true)
		{
			if (node.designation != aern_network_designation_aps &&
				node.designation != aern_network_designation_idg &&
				node.designation != aern_network_designation_mas)
			{
				aern_topology_child_add_item(&clst, &node);
			}
		}
	}

	if (list->count != clst.count)
	{
		aern_topology_list_dispose(list);

		for (size_t i = 0U; i < clst.count; ++i)
		{
			aern_topology_node_state node = { 0 };

			if (aern_topology_list_item(&clst, &node, i) == true)
			{
				aern_topology_child_add_item(list, &node);
			}
		}
	}

	aern_topology_list_dispose(&clst);
}
#endif

static void adc_converge_broadcast(void)
{
	aern_topology_list_state clst = { 0 };
	qsc_mutex mtx;
	aern_protocol_errors merr;
	
	if (m_adc_application_state.tlist.count > 0U)
	{
		aern_topology_node_state rnode = { 0 };

		aern_topology_list_initialize(&clst);

		/* iterate through nodes in the topology list, copying their signed node to the message */
		for (size_t i = 0U; i < m_adc_application_state.tlist.count; ++i)
		{
			if (aern_topology_list_item(&m_adc_application_state.tlist, &rnode, i) == true)
			{
				if (rnode.designation == aern_network_designation_aps ||
					rnode.designation == aern_network_designation_idg)
				{
					aern_child_certificate rcert = { 0 };

					if (aern_server_child_certificate_from_issuer(&rcert, &m_adc_application_state, rnode.issuer) == true)
					{
						aern_network_converge_request_state crs = {
							.rcert = &rcert,
							.rnode = &rnode,
							.sigkey = m_adc_application_state.sigkey
						};

						/* process the convergence update */
						merr = aern_network_converge_request(&crs);

						if (merr == aern_protocol_error_none)
						{
							aern_topology_child_add_item(&clst, &rnode);
						}
					}
				}
			}
		}

		for (size_t i = 0; i < m_adc_application_state.tlist.count; ++i)
		{
			aern_topology_node_state fnode = { 0 };

			aern_topology_list_item(&m_adc_application_state.tlist, &rnode, i);

			if (rnode.designation == aern_network_designation_aps ||
				rnode.designation == aern_network_designation_idg)
			{
				if (aern_topology_node_find(&clst, &fnode, rnode.serial) == false)
				{
					aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
					qsc_consoleutils_print_safe("The remote node: ");
					qsc_consoleutils_print_safe(rnode.issuer);
					qsc_consoleutils_print_line(" did not respond.");

					if (aern_menu_print_predefined_message_confirm(aern_application_log_converge_node_remove_challenge, m_adc_application_state.mode, m_adc_application_state.hostname) == true)
					{
						aern_network_revoke_request_state rrs = {
							.designation = rnode.designation,
							.list = &m_adc_application_state.tlist,
							.rnode = &rnode,
							.sigkey = m_adc_application_state.sigkey
						};

						/* create and send the revocation broadcast */
						merr = aern_network_revoke_broadcast(&rrs);

						if (merr == aern_protocol_error_none)
						{
							mtx = qsc_async_mutex_lock_ex();

							aern_server_topology_remove_certificate(&m_adc_application_state, rnode.issuer);
							aern_server_topology_remove_node(&m_adc_application_state, rnode.issuer);
							aern_server_topology_to_file(&m_adc_application_state);

							qsc_async_mutex_unlock_ex(mtx);
						}
					}
				}
			}
		}
	}

	aern_topology_list_dispose(&clst);
}

static aern_protocol_errors adc_incremental_update_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_topology_node_state rnode = { 0 };
	aern_protocol_errors merr;

	if (aern_topology_node_find(&m_adc_application_state.tlist, &rnode, packetin->pmessage) == true)
	{
		aern_child_certificate rcert = { 0 };

		if (aern_server_child_certificate_from_issuer(&rcert, &m_adc_application_state, rnode.issuer) == true)
		{
			aern_network_incremental_update_response_state urs = { 
				.csock = csock, 
				.rcert = &rcert, 
				.sigkey = m_adc_application_state.sigkey
			};

			/* create and send the incremental update */
			merr = aern_network_incremental_update_response(&urs, packetin);
		}
		else
		{
			merr = aern_protocol_error_certificate_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static aern_protocol_errors adc_register_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_child_certificate rcert = { 0 };
	qsc_mutex mtx;
	aern_protocol_errors merr;

	merr = aern_protocol_error_invalid_request;

	aern_network_register_response_state jrs = {
		.csock = csock,
		.lcert = &m_adc_application_state.ads, 
		.rcert = &rcert,
		.root = &m_adc_application_state.root, 
		.sigkey = m_adc_application_state.sigkey
	};

	/* create and send the join response */
	merr = aern_network_register_response(&jrs, packetin);

	if (merr == aern_protocol_error_none)
	{
		char rpath[AERN_STORAGE_PATH_MAX] = { 0 };
		
		if (aern_topology_node_exists(&m_adc_application_state.tlist, rcert.serial) == true)
		{
			aern_topology_node_remove(&m_adc_application_state.tlist, rcert.serial);
		}

		mtx = qsc_async_mutex_lock_ex();

		/* register the remote device in the topology */
		aern_topology_child_register(&m_adc_application_state.tlist, &rcert, csock->address);
		aern_server_topology_to_file(&m_adc_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		/* get the certificate path and overwrite existing */
		aern_server_child_certificate_path_from_issuer(&m_adc_application_state, rpath, sizeof(rpath), rcert.issuer);

		if (qsc_fileutils_exists(rpath) == true)
		{
			qsc_fileutils_delete(rpath);
		}

		/* save the certificate to file */
		if (aern_certificate_child_struct_to_file(rpath, &rcert) == false)
		{
			merr = aern_protocol_error_file_not_written;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static aern_protocol_errors adc_register_update_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_child_certificate rcert = { 0 };
	qsc_mutex mtx;
	aern_protocol_errors merr;

	merr = aern_protocol_error_invalid_request;

	aern_network_register_update_response_state rst = {
		.csock = csock,
		.lcert = &m_adc_application_state.ads,
		.list = &m_adc_application_state.tlist,
		.rcert = &rcert,
		.root = &m_adc_application_state.root, 
		.sigkey = m_adc_application_state.sigkey
	};

	/* create and send the join-update response */
	merr = aern_network_register_update_response(&rst, packetin);

	if (merr == aern_protocol_error_none)
	{
		char rpath[AERN_STORAGE_PATH_MAX] = { 0 };

		mtx = qsc_async_mutex_lock_ex();

		/* register the remote certificate in the topology */
		aern_topology_child_register(&m_adc_application_state.tlist, &rcert, csock->address);
		aern_server_topology_to_file(&m_adc_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		/* get the remote certificate path */
		aern_server_child_certificate_path_from_issuer(&m_adc_application_state, rpath, sizeof(rpath), rcert.issuer);

		/* save the certificate to file */
		if (aern_certificate_child_struct_to_file(rpath, &rcert) == false)
		{
			merr = aern_protocol_error_file_not_written;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static bool adc_remote_certificate_verify(aern_child_certificate* child)
{
	AERN_ASSERT(child != NULL);

	bool res;

	res = false;

	if (child != NULL)
	{
		if (child->algorithm == AERN_CONFIGURATION_SET &&
			child->designation != aern_network_designation_none &&
			child->version == AERN_ACTIVE_VERSION &&
			qsc_memutils_zeroed(child->serial, sizeof(child->serial)) == false &&
			qsc_memutils_zeroed(child->verkey, sizeof(child->verkey)) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= child->expiration.from && nsec <= child->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

static aern_protocol_errors adc_remote_signing_request(const char* fpath)
{
	AERN_ASSERT(fpath != NULL);
	
	aern_topology_node_state root = { 0 };
	aern_protocol_errors merr;
	
	if (aern_topology_node_find_root(&m_adc_application_state.tlist, &root) == true)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			aern_child_certificate rcert = { 0 };

			if (aern_certificate_child_file_to_struct(fpath, &rcert) == true)
			{
				if (adc_remote_certificate_verify(&rcert) == true)
				{
					aern_network_remote_signing_request_state rsr = {
						.address = root.address,
						.rcert = &rcert,
						.root = &m_adc_application_state.root,
						.sigkey = m_adc_application_state.sigkey
					};

					merr = aern_network_remote_signing_request(&rsr);

					if (merr == aern_protocol_error_none)
					{
						if (aern_certificate_child_struct_to_file(fpath, &rcert) == false)
						{
							merr = aern_protocol_error_file_not_written;
						}
					}
				}
				else
				{
					merr = aern_protocol_error_root_signature_invalid;
				}
			}
			else
			{
				merr = aern_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_file_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static void adc_resign_command(void)
{
	/* reset topology, certificates, and signing key */
	aern_server_topology_reset(&m_adc_application_state);
	aern_server_erase_signature_key(&m_adc_application_state);
	aern_server_topology_remove_certificate(&m_adc_application_state, m_adc_application_state.ads.issuer);
	aern_server_topology_remove_certificate(&m_adc_application_state, m_adc_application_state.root.issuer);
	qsc_memutils_clear(&m_adc_application_state.ads, sizeof(aern_child_certificate));
	qsc_memutils_clear(&m_adc_application_state.root, sizeof(aern_root_certificate));
}

static aern_protocol_errors adc_resign_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_topology_node_state rnode = { 0 };
	qsc_mutex mtx;
	const uint8_t* rser;
	aern_protocol_errors merr;

	(void)csock;
	rser = packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE;

	if (aern_topology_node_find(&m_adc_application_state.tlist, &rnode, rser) == true)
	{
		aern_child_certificate rcert = { 0 };

		if (aern_server_child_certificate_from_issuer(&rcert, &m_adc_application_state, rnode.issuer) == true)
		{
			if (aern_certificate_child_is_valid(&rcert) == true)
			{
				aern_network_resign_response_state rrs = {
					.list = &m_adc_application_state.tlist,
					.rcert = &rcert,
					.rnode = &rnode,
					.sigkey = m_adc_application_state.sigkey
				};

				/* process the resign update */
				merr = aern_network_resign_response(&rrs, packetin);

				if (merr == aern_protocol_error_none)
				{
					mtx = qsc_async_mutex_lock_ex();

					aern_server_topology_remove_certificate(&m_adc_application_state, rnode.issuer);
					aern_server_topology_remove_node(&m_adc_application_state, rnode.issuer);
					aern_server_topology_to_file(&m_adc_application_state);

					qsc_async_mutex_unlock_ex(mtx);
				}
			}
			else
			{
				merr = aern_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_certificate_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static aern_protocol_errors adc_revoke_broadcast(const char* cmsg)
{
	AERN_ASSERT(cmsg != NULL);
	
	qsc_mutex mtx;
	size_t mlen;
	aern_protocol_errors merr;

	mlen = qsc_stringutils_string_size(cmsg);

	if (mlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		if (qsc_fileutils_exists(cmsg) == true)
		{
			aern_child_certificate rcert = { 0 };

			if (aern_certificate_child_file_to_struct(cmsg, &rcert) == true)
			{
				aern_topology_node_state rnode = { 0 };

				/* find the node in the topological list */
				if (aern_topology_node_find(&m_adc_application_state.tlist, &rnode, rcert.serial) == true)
				{
					aern_network_revoke_request_state rrs = {
						.designation = rcert.designation,
						.list = &m_adc_application_state.tlist,
						.rnode = &rnode,
						.sigkey = m_adc_application_state.sigkey
					};

					/* create and send the revocation broadcast */
					merr = aern_network_revoke_broadcast(&rrs);

					if (merr == aern_protocol_error_none)
					{
						mtx = qsc_async_mutex_lock_ex();

						aern_server_topology_remove_certificate(&m_adc_application_state, rnode.issuer);
						aern_server_topology_remove_node(&m_adc_application_state, rnode.issuer);
						aern_server_topology_to_file(&m_adc_application_state);

						qsc_async_mutex_unlock_ex(mtx);
					}
				}
				else
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
			else
			{
				merr = aern_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_file_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

static aern_protocol_errors adc_topological_status_request(const aern_topology_node_state* rnode)
{
	AERN_ASSERT(rnode != NULL);

	aern_topology_node_state lnode = { 0 };
	aern_child_certificate rcert = { 0 };
	aern_protocol_errors merr;

	if (aern_topology_node_find(&m_adc_application_state.tlist, &lnode, m_adc_application_state.ads.serial) == true)
	{
		if (aern_server_child_certificate_from_issuer(&rcert, &m_adc_application_state, rnode->issuer) == true)
		{
			const aern_network_topological_status_request_state tsr = {
				.lnode = &lnode,
				.rcert = &rcert,
				.rnode = rnode,
				.sigkey = m_adc_application_state.sigkey
			};

			/* request the remote devices node information */
			merr = aern_network_topological_status_request(&tsr);
		}
		else
		{
			merr = aern_protocol_error_certificate_not_found;
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static aern_protocol_errors adc_topological_query_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_topology_node_state cnode = { 0 };
	aern_topology_node_state rnode = { 0 };
	const uint8_t* cser;
	const char* riss;
	aern_protocol_errors merr;

	cser = packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE;
	riss = (const char*)packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE;

	if (aern_topology_node_find_issuer(&m_adc_application_state.tlist, &rnode, riss) == true)
	{
		merr = adc_topological_status_request(&rnode);

		if (merr == aern_protocol_error_none)
		{
			if (aern_topology_node_find(&m_adc_application_state.tlist, &cnode, cser) == true)
			{
				aern_child_certificate ccert = { 0 };

				if (aern_server_child_certificate_from_issuer(&ccert, &m_adc_application_state, cnode.issuer) == true)
				{
					aern_network_topological_query_response_state tqr = {
						.csock = csock,
						.ccert = &ccert,
						.rnode = &rnode,
						.sigkey = m_adc_application_state.sigkey
					};

					merr = aern_network_topological_query_response(&tqr, packetin);
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
			/* if status request fails or is refused send the error */
			aern_network_send_error(csock, merr);
		}
	}
	else
	{
		merr = aern_protocol_error_node_not_found;
	}

	return merr;
}

static void adc_receive_loop(void* ras)
{
	AERN_ASSERT(ras != NULL);

	aern_network_packet pkt = { 0 };
	uint8_t* buff;
	adc_receive_state* pras;
	const char* cmsg;
	size_t mlen;
	size_t plen;
	aern_protocol_errors merr;

	merr = aern_protocol_error_none;

	if (ras != NULL)
	{
		pras = (adc_receive_state*)ras;
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			if (pras->csock.connection_status == qsc_socket_state_connected)
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
							aern_server_log_write_message(&m_adc_application_state, aern_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else
					{
						merr = aern_protocol_error_invalid_request;
						aern_server_log_write_message(&m_adc_application_state, aern_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
			
					if (mlen > 0U)
					{
						pkt.pmessage = buff + AERN_PACKET_HEADER_SIZE;

						if (pkt.flag == aern_network_flag_tunnel_connection_terminate)
						{
							aern_server_log_write_message(&m_adc_application_state, aern_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							aern_connection_close(&pras->csock, aern_network_error_none, true);
						}
						else if (pkt.flag == aern_network_flag_incremental_update_request)
						{
							/* sent by a client or server, requesting an apss topological info */
							merr = adc_incremental_update_response(&pras->csock, &pkt);

							if (merr == aern_protocol_error_none)
							{
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_incremental_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = aern_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								aern_server_log_write_message(&m_adc_application_state, aern_application_log_incremental_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == aern_network_flag_register_request)
						{
							/* sent to the ads requesting to join the network */
							merr = adc_register_response(&pras->csock, &pkt);

							if (merr == aern_protocol_error_none)
							{
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_register_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = aern_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								aern_server_log_write_message(&m_adc_application_state, aern_application_log_register_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == aern_network_flag_register_update_request)
						{
							/* sent to the ads from a MAS requesting to register on the network */
							merr = adc_register_update_response(&pras->csock, &pkt);

							if (merr == aern_protocol_error_none)
							{
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_register_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = aern_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								aern_server_log_write_message(&m_adc_application_state, aern_application_log_register_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == aern_network_flag_network_resign_request)
						{
							/* sent to the ads from a server or aps requesting a network resignation */
							
							merr = adc_resign_response(&pras->csock, &pkt);

							if (merr == aern_protocol_error_none)
							{
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_resign_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = aern_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_resign_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == aern_network_flag_topology_query_request)
						{
							/* sent to the ads from a server or aps querying for a node */
							
							merr = adc_topological_query_response(&pras->csock, &pkt);

							if (merr == aern_protocol_error_none)
							{
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_topology_node_query_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = aern_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								aern_server_log_write_message(&m_adc_application_state, aern_application_log_topology_node_query_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == aern_network_flag_system_error_condition)
						{
							/* log the error condition */
							merr = (aern_protocol_errors)pkt.pmessage[0U];
							cmsg = aern_protocol_error_to_string(merr);

							if (cmsg != NULL)
							{
								aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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
									aern_server_log_write_message(&m_adc_application_state, aern_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
								}
							}
							else
							{
								aern_network_send_error(&pras->csock, aern_protocol_error_invalid_request);
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
					}
				}
			}

			qsc_memutils_alloc_free(buff);
		}

		/* close the connection */
		aern_network_socket_dispose(&pras->csock);

		/* free the socket from memory */
		qsc_memutils_alloc_free(pras);
		pras = NULL;
	}
}

#if defined(AERN_NETWORK_PROTOCOL_IPV6)

static void adc_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv6_address_from_string(m_adc_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, AERN_APPLICATION_ADC_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						adc_receive_state* ras;

						ras = (adc_receive_state*)qsc_memutils_malloc(sizeof(adc_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
							serr = qsc_socket_accept(&lsock, &ras->csock);

							if (serr == qsc_socket_exception_success)
							{
								ras->csock.connection_status = qsc_socket_state_connected;
								qsc_async_thread_create(&adc_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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

static void adc_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv4_address_from_string(m_adc_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, AERN_APPLICATION_ADC_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						adc_receive_state* ras;

						ras = (adc_receive_state*)qsc_memutils_malloc(sizeof(adc_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
							serr = qsc_socket_accept(&lsock, &ras->csock);

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&adc_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								aern_server_log_write_message(&m_adc_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							aern_server_log_write_message(&m_adc_application_state, aern_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
			}
		}
	}
}

#endif

static void adc_server_dispose(void)
{
	m_adc_command_loop_status = aern_server_loop_status_stopped;
	aern_server_state_unload(&m_adc_application_state);
	aern_server_state_initialize(&m_adc_application_state, aern_network_designation_ads);
	qsc_memutils_clear(&m_adc_application_state.ads, sizeof(aern_child_certificate));
	m_adc_command_loop_status = aern_server_loop_status_stopped;
	m_adc_server_loop_status = aern_server_loop_status_stopped;
	m_adc_idle_timer = 0U;
}

static bool adc_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (aern_server_topology_root_fetch(&m_adc_application_state, &m_adc_application_state.root) == true)
	{
		res = aern_topology_node_verify_root(&m_adc_application_state.tlist, &m_adc_application_state.root);
	}

	return res;
}

static bool adc_server_load_local(void)
{
	bool res;

	res = false;

	/* load the local aps certificate */
	if (aern_server_topology_local_fetch(&m_adc_application_state, &m_adc_application_state.ads) == true)
	{
		/* verify the aps certificate */
		if (aern_certificate_child_is_valid(&m_adc_application_state.ads) == true &&
			aern_certificate_root_signature_verify(&m_adc_application_state.ads, &m_adc_application_state.root) == true)
		{
			res = aern_topology_node_verify_issuer(&m_adc_application_state.tlist, &m_adc_application_state.ads, m_adc_application_state.issuer);
		}
	}

	return res;
}

static bool adc_server_start(void)
{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&adc_ipv6_server_start))
#else
	if (qsc_async_thread_create_noargs(&adc_ipv4_server_start))
#endif
	{
		m_adc_server_loop_status = aern_server_loop_status_started;
	}

	return (m_adc_server_loop_status == aern_server_loop_status_started);
}

static bool adc_certificate_export(const char* cmsg)
{
	AERN_ASSERT(cmsg != NULL);

	bool res;

	res = aern_server_child_certificate_export(&m_adc_application_state, cmsg);

	return res;
}

static bool adc_certificate_import(const char* cmsg)
{
	AERN_ASSERT(cmsg != NULL);

	qsc_mutex mtx;
	bool res;

	if (m_adc_server_loop_status == aern_server_loop_status_started)
	{
		m_adc_server_loop_status = aern_server_loop_status_paused;
	}

	res = aern_server_child_certificate_import(&m_adc_application_state.ads, &m_adc_application_state, cmsg);

	if (res == true)
	{
		mtx = qsc_async_mutex_lock_ex();

		res = aern_certificate_child_file_to_struct(cmsg, &m_adc_application_state.ads);

		/* register the node and save the database */
		aern_topology_child_register(&m_adc_application_state.tlist, &m_adc_application_state.ads, m_adc_application_state.localip);
		aern_server_topology_to_file(&m_adc_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		if (m_adc_server_loop_status == aern_server_loop_status_paused)
		{
			res = adc_server_start();
		}
	}

	return res;
}

/* application functions */

static void adc_get_command_mode(const char* command)
{
	AERN_ASSERT(command != NULL);

	aern_console_modes nmode;

	nmode = m_adc_application_state.mode;

	switch (m_adc_application_state.mode)
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
				if (qsc_consoleutils_line_equals(command, "show") == false)
				{
					nmode = aern_console_mode_config;
				}
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

	m_adc_application_state.mode = nmode;
}

static void adc_set_command_action(const char* command)
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
		if (m_adc_application_state.mode == aern_console_mode_config)
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
		else if (m_adc_application_state.mode == aern_console_mode_certificate)
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_certificate_exit;
			}
			else if (qsc_consoleutils_line_contains(command, "export "))
			{
				res = aern_command_action_certificate_export;
			}
			else if (qsc_consoleutils_line_contains(command, "generate "))
			{
				res = aern_command_action_certificate_generate;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_certificate_help;
			}
			else if (qsc_consoleutils_line_contains(command, "import "))
			{
				res = aern_command_action_certificate_import;
			}
			else if (qsc_consoleutils_line_equals(command, "print"))
			{
				res = aern_command_action_certificate_print;
			}
			else if (qsc_consoleutils_line_contains(command, "revoke "))
			{
				res = aern_command_action_adc_certificate_revoke;
			}
		}
		else if (m_adc_application_state.mode == aern_console_mode_server)
		{
			if (qsc_consoleutils_line_contains(command, "announce "))
			{
				res = aern_command_action_adc_server_announce;
			}
			else if (qsc_consoleutils_line_equals(command, "backup"))
			{
				res = aern_command_action_server_backup;
			}
			else if (qsc_consoleutils_line_equals(command, "converge"))
			{
				res = aern_command_action_adc_server_converge;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = aern_command_action_server_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = aern_command_action_server_help;
			}
			else if (qsc_consoleutils_line_equals(command, "list"))
			{
				res = aern_command_action_server_list;
			}
			else if (qsc_consoleutils_line_equals(command, "resign"))
			{
				res = aern_command_action_server_resign;
			}
			else if (qsc_consoleutils_line_equals(command, "restore"))
			{
				res = aern_command_action_server_restore;
			}
			else if (qsc_consoleutils_line_contains(command, "revoke "))
			{
				res = aern_command_action_adc_server_revoke;
			}
			else if (qsc_consoleutils_line_contains(command, "service "))
			{
				res = aern_command_action_server_service;
			}
			else if (qsc_consoleutils_line_contains(command, "sproxy "))
			{
				res = aern_command_action_adc_server_sproxy;
			}
		}
		else if (m_adc_application_state.mode == aern_console_mode_enable)
		{
			if (qsc_consoleutils_line_equals(command, "clear screen"))
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
		else if (m_adc_application_state.mode == aern_console_mode_user)
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

	m_adc_application_state.action = res;
}

static void adc_command_execute(const char* command)
{
	AERN_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	aern_protocol_errors merr;
	bool res;

	res = true;

	switch (m_adc_application_state.action)
	{
	case aern_command_action_config_clear_all:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_erase_all, m_adc_application_state.mode, m_adc_application_state.hostname) == true)
		{
			aern_server_erase_all(&m_adc_application_state);
			aern_menu_print_predefined_message(aern_application_system_erased, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_config_clear_config:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_config, aern_console_mode_config, m_adc_application_state.hostname) == true)
		{
			slen = qsc_stringutils_string_size(m_adc_application_state.username);
			aern_server_log_write_message(&m_adc_application_state, aern_application_log_configuration_erased, m_adc_application_state.username, slen);
			aern_server_clear_config(&m_adc_application_state);
			aern_menu_print_predefined_message(aern_application_configuration_erased, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_config_clear_log:
	{
		if (aern_menu_print_predefined_message_confirm(aern_application_erase_log, aern_console_mode_config, m_adc_application_state.hostname) == true)
		{
			aern_server_clear_log(&m_adc_application_state);
			aern_menu_print_predefined_message(aern_application_log_erased, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_operation_aborted, m_adc_application_state.mode, m_adc_application_state.hostname);
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
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_config, m_adc_application_state.srvtype);
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
				m_adc_application_state.loghost = true;
				aern_server_log_host(&m_adc_application_state);
				aern_menu_print_predefined_message(aern_application_logging_enabled, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_adc_application_state.loghost = false;
				aern_server_log_host(&m_adc_application_state);
				aern_menu_print_predefined_message(aern_application_logging_disabled, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_not_recognized, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_log_host);
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_not_recognized, m_adc_application_state.mode, m_adc_application_state.hostname);
			aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_log_host);
		}

		break;
	}
	case aern_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_domain_name(&m_adc_application_state, cmsg, slen) == false)
			{
				aern_menu_print_predefined_message(aern_application_domain_invalid, m_adc_application_state.mode, m_adc_application_state.hostname);
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

			if (aern_server_set_host_name(&m_adc_application_state, cmsg, slen) == false)
			{
				aern_menu_print_predefined_message(aern_application_hostname_invalid, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_retries:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (aern_server_set_password_retries(&m_adc_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				aern_menu_print_predefined_message(aern_application_retry_invalid, m_adc_application_state.mode, m_adc_application_state.hostname);
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

			if (aern_server_set_console_timeout(&m_adc_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				aern_menu_print_predefined_message(aern_application_timeout_invalid, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
		}

		break;
	}
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
			res = adc_certificate_export(cmsg);
		}

		if (res == true)
		{
			aern_menu_print_predefined_message(aern_application_export_certificate_success, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_export_certificate_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_certificate_import:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = adc_certificate_import(cmsg);
		}

		if (res == true)
		{
			aern_menu_print_predefined_message(aern_application_import_certificate_success, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_import_certificate_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = adc_certificate_generate(cmsg);

			if (res == true)
			{
				char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

				aern_server_child_certificate_path(&m_adc_application_state, fpath, sizeof(fpath));
				slen = qsc_stringutils_string_size(fpath);

				aern_menu_print_predefined_message(aern_application_generate_key_success, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_menu_print_message(fpath, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_server_log_write_message(&m_adc_application_state, aern_application_log_generate_success, fpath, slen);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_generate_key_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_server_log_write_message(&m_adc_application_state, aern_application_log_generate_failure, NULL, 0U);
			}
		}

		break;
	}
	case aern_command_action_certificate_help:
	{
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_certificate, m_adc_application_state.srvtype);
		break;
	}
	case aern_command_action_certificate_print:
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		res = false;
		aern_server_child_certificate_path(&m_adc_application_state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = aern_server_child_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			aern_menu_print_predefined_message(aern_application_client_pubkey_path_invalid, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_adc_server_announce:
	{
		if (m_adc_server_loop_status == aern_server_loop_status_started)
		{
			char sadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			cmsg = qsc_stringutils_sub_string(command, " ");
			qsc_stringutils_split_strings(fpath, sadd, sizeof(fpath), cmsg + 1, ", ");
			slen = qsc_stringutils_string_size(fpath);

			merr = adc_announce_broadcast(fpath, sadd);

			if (merr == aern_protocol_error_none)
			{
				aern_menu_print_predefined_message(aern_application_announce_success, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_server_log_write_message(&m_adc_application_state, aern_application_announce_success, cmsg, slen);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_announce_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_server_log_write_message(&m_adc_application_state, aern_application_announce_failure, cmsg, slen);
				cmsg = aern_protocol_error_to_string(merr);

				if (cmsg != NULL)
				{
					aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
				}
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_server_service_not_started, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_adc_application_state.hostname);
		aern_server_state_backup_save(&m_adc_application_state);
		aern_server_log_write_message(&m_adc_application_state, aern_application_log_state_backup, m_adc_application_state.hostname, slen);
		aern_menu_print_predefined_message(aern_application_server_backup_save_confirmation, m_adc_application_state.mode, m_adc_application_state.hostname);

		break;
	}
	case aern_command_action_adc_server_converge:
	{
		if (m_adc_server_loop_status == aern_server_loop_status_started)
		{
			adc_converge_broadcast();
			aern_menu_print_predefined_message(aern_application_converge_success, m_adc_application_state.mode, m_adc_application_state.hostname);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_server_service_not_started, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

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
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_server, m_adc_application_state.srvtype);
		break;
	}
	case aern_command_action_server_list:
	{
		aern_server_topology_print_list(&m_adc_application_state);

		break;
	}
	case aern_command_action_server_resign:
	{
		if (m_adc_server_loop_status == aern_server_loop_status_started)
		{
			adc_resign_command();
			slen = qsc_stringutils_string_size(m_adc_application_state.hostname);
			m_adc_application_state.joined = false;
			slen = qsc_stringutils_string_size(m_adc_application_state.hostname);
			aern_menu_print_predefined_message(aern_application_network_resign_success, m_adc_application_state.mode, m_adc_application_state.hostname);
			aern_server_log_write_message(&m_adc_application_state, aern_application_log_local_resign_success, m_adc_application_state.hostname, slen);
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_server_service_not_started, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = aern_menu_print_predefined_message_confirm(aern_application_server_backup_restore_challenge, m_adc_application_state.mode, m_adc_application_state.hostname);
			
		if (dres == true)
		{
			aern_server_state_backup_restore(&m_adc_application_state);
			slen = qsc_stringutils_string_size(m_adc_application_state.hostname);
			aern_server_log_write_message(&m_adc_application_state, aern_application_log_state_restore, m_adc_application_state.hostname, slen);
		}

		break;
	}
	case aern_command_action_adc_server_revoke:
	{
		if (m_adc_server_loop_status == aern_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				slen = qsc_stringutils_string_size(cmsg);
				merr = adc_revoke_broadcast(cmsg);

				if (merr == aern_protocol_error_none)
				{
					aern_menu_print_predefined_message(aern_application_certificate_revoke_success, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_certificate_revoke_success, cmsg, slen);
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_certificate_revoke_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_certificate_revoke_failure, cmsg, slen);
					cmsg = aern_protocol_error_to_string(merr);

					if (cmsg != NULL)
					{
						aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
					}
				}
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_server_service_not_started, m_adc_application_state.mode, m_adc_application_state.hostname);
		}

		break;
	}
	case aern_command_action_server_service:
	{
		res = false;
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_adc_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_adc_server_loop_status != aern_server_loop_status_started)
				{
					res = adc_server_start();

					if (res == true)
					{
						aern_menu_print_predefined_message(aern_application_server_service_start_success, m_adc_application_state.mode, m_adc_application_state.hostname);
						aern_server_log_write_message(&m_adc_application_state, aern_application_log_service_started, m_adc_application_state.hostname, slen);
					}
					else
					{
						aern_menu_print_predefined_message(aern_application_server_service_start_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_adc_server_loop_status == aern_server_loop_status_started)
				{
					m_adc_server_loop_status = aern_server_loop_status_stopped;
					aern_menu_print_predefined_message(aern_application_server_service_stopped, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_service_stopped, m_adc_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_adc_server_loop_status != aern_server_loop_status_paused)
				{
					m_adc_server_loop_status = aern_server_loop_status_paused;
					aern_menu_print_predefined_message(aern_application_server_service_paused, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_service_paused, m_adc_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_adc_server_loop_status == aern_server_loop_status_paused)
				{
					m_adc_server_loop_status = aern_server_loop_status_started;
					aern_menu_print_predefined_message(aern_application_server_service_resume_success, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_service_resumed, m_adc_application_state.hostname, slen);
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_server_service_resume_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
				}
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_not_recognized, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_adc_server_sproxy:
	{
		if (m_adc_server_loop_status == aern_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				merr = adc_remote_signing_request(cmsg);

				slen = qsc_stringutils_string_size(cmsg);
				if (res == true)
				{
					aern_menu_print_predefined_message(aern_application_certificate_remote_sign_success, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_signing_success, cmsg, slen);
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_certificate_remote_sign_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
					aern_server_log_write_message(&m_adc_application_state, aern_application_log_remote_signing_failure, cmsg, slen);
					cmsg = aern_protocol_error_to_string(merr);

					if (cmsg != NULL)
					{
						aern_logger_write_time_stamped_message(m_adc_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
					}
				}
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_server_service_not_started, m_adc_application_state.mode, m_adc_application_state.hostname);
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
		aern_server_user_logout(&m_adc_application_state);

		break;
	}
	case aern_command_action_enable_help:
	{
		/* show enable help */
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_enable, m_adc_application_state.srvtype);

		break;
	}
	case aern_command_action_enable_quit:
	case aern_command_action_user_quit:
	{
		adc_server_dispose();
		aern_menu_print_predefined_message(aern_application_application_quit, m_adc_application_state.mode, m_adc_application_state.hostname);
		aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case aern_command_action_enable_show_config:
	{
		/* show config */
		aern_server_print_configuration(&m_adc_application_state);

		break;
	}
	case aern_command_action_enable_show_log:
	{
		/* read the user log */
		aern_server_log_print(&m_adc_application_state);
		break;
	}
	case aern_command_action_user_enable:
	{
		/* user login */
		if (aern_server_user_login(&m_adc_application_state) == true)
		{
			/* load certificates */
			if (adc_server_load_root() == true)
			{
				adc_server_load_local();
			}
		}
		else
		{
			aern_adc_stop_server();
			aern_menu_print_predefined_message(aern_application_retries_exceeded, m_adc_application_state.mode, m_adc_application_state.hostname);
			aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case aern_command_action_user_help:
	{
		/* show user help */
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_user, m_adc_application_state.srvtype);

		break;
	}
	case aern_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			res = aern_server_set_ip_address(&m_adc_application_state, cmsg, slen);

			if (res == true)
			{
				aern_menu_print_predefined_message(aern_application_address_change_success, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_address_change_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
			}
		}

		break;
	}
	case aern_command_action_config_clear:
	{
		/* show clear help */
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_clear_all);
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_clear_config);
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_clear_log);

		break;
	}
	case aern_command_action_config_log:
	{
		/* show log help */
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_log_host);

		break;
	}
	case aern_command_action_config_name:
	{
		/* show name help */
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_name_domain);
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_config_name_host);

		break;
	}
	case aern_command_action_help_enable_all:
	{
		/* show enable help */
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_enable, m_adc_application_state.srvtype);

		break;
	}
	case aern_command_action_help_enable_show:
	{
		/* show help */
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_enable_show_config);
		aern_help_print_context(m_adc_application_state.cmdprompt, aern_command_action_enable_show_log);

		break;
	}
	case aern_command_action_help_enable_user:
	{
		/* show enable user help */
		aern_help_print_mode(m_adc_application_state.cmdprompt, aern_console_mode_user, m_adc_application_state.srvtype);

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
		aern_menu_print_predefined_message(aern_application_not_recognized, m_adc_application_state.mode, m_adc_application_state.hostname);
		aern_help_print_mode(m_adc_application_state.cmdprompt, m_adc_application_state.mode, m_adc_application_state.srvtype);
		break;
	}
	default:
	{
		aern_help_print_mode(m_adc_application_state.cmdprompt, m_adc_application_state.mode, m_adc_application_state.srvtype);
	}
	}
}

static void adc_idle_timer(void)
{
	const uint32_t MMSEC = 60U * 1000U;

	while (true)
	{
		qsc_async_thread_sleep(MMSEC);
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		if (m_adc_application_state.mode != aern_console_mode_user)
		{
			++m_adc_idle_timer;

			if (m_adc_idle_timer >= m_adc_application_state.timeout)
			{
				aern_server_user_logout(&m_adc_application_state);
				m_adc_idle_timer = 0;
				qsc_consoleutils_print_line("");
				aern_menu_print_predefined_message(aern_application_console_timeout_expired, m_adc_application_state.mode, m_adc_application_state.hostname);
				aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void adc_command_loop(char* command)
{
	AERN_ASSERT(command != NULL);

	m_adc_command_loop_status = aern_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_adc_idle_timer = 0U;
		qsc_async_mutex_unlock_ex(mtx);

		adc_set_command_action(command);
		adc_command_execute(command);

		adc_get_command_mode(command);
		aern_server_set_command_prompt(&m_adc_application_state);
		aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
		qsc_stringutils_clear_string(command);

		if (m_adc_command_loop_status == aern_server_loop_status_paused)
		{
			qsc_async_thread_sleep(AERN_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_adc_command_loop_status == aern_server_loop_status_stopped)
		{
			break;
		}
	}
}

/* ads functions */

void aern_adc_pause_server(void)
{
	m_adc_command_loop_status = aern_server_loop_status_paused;
}

int32_t aern_adc_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;
	int32_t ret;

	/* initialize the server */
	aern_server_state_initialize(&m_adc_application_state, aern_network_designation_ads);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000U, 600U);
	qsc_consoleutils_set_window_title(m_adc_application_state.wtitle);

	/* application banner */
	aern_server_print_banner(&m_adc_application_state);

	/* load the command prompt */
	adc_get_command_mode(command);
	aern_menu_print_prompt(m_adc_application_state.mode, m_adc_application_state.hostname);
	m_adc_command_loop_status = aern_server_loop_status_started;

	/* start the idle timer */
	m_adc_idle_timer = 0U;
	idle = qsc_async_thread_create_noargs(&adc_idle_timer);
	
	if (idle)
	{
		/* command loop */
		adc_command_loop(command);
		ret = 0;
	}
	else
	{
		aern_menu_print_predefined_message(aern_application_authentication_failure, m_adc_application_state.mode, m_adc_application_state.hostname);
		ret = -1;
	}

	return (ret == 0);
}

void aern_adc_stop_server(void)
{
	m_adc_command_loop_status = aern_server_loop_status_stopped;
}

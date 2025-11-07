#include "server.h"
#include "crypto.h"
#include "help.h"
#include "logger.h"
#include "menu.h"
#include "aern.h"
#include "network.h"
#include "resources.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "collection.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "list.h"
#include "memutils.h"
#include "netutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

#define SERVER_KEYCHAIN_DEPTH 4U
#define SERVER_KEYCHAIN_WIDTH 64U
#define SERVER_KEYCHAIN_STATE_INDEX 0U
#define SERVER_KEYCHAIN_LOG_INDEX 1U
#define SERVER_KEYCHAIN_TOPOLOGY_INDEX 2U
#define SERVER_KEYCHAIN_MFKCOL_INDEX 3U

static const char ADS_APPLICATION_BANNER[] = "ADC v1.0 \n"
"QRCS Corp. 2025, All rights reserved. \n"
"A quantum safe Domain List APS server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char ADS_APPLICATION_NAME[] = "ADC";
static const char ADS_APPLICATION_PATH[] = "\\ADC";
static const char ADS_FILENAME_CONFIG[] = "\\userconfig.adscfg";
static const char ADS_PUBKEY_NAME[] = "ads_public_key.dcpkey";
static const char ADS_PRIKEY_NAME[] = "ads_secret_key.dcskey";
static const char ADS_PROMPT_DEFAULT[] = "ADC> ";
static const char ADS_TOPOLOGY_NAME[] = "\\ads_topology";
static const char ADS_WINDOW_TITLE[] = "Domain List APS v1.0a";

static const char APS_APPLICATION_BANNER[] = "APS v1.0 \n"
"QRCS Corp. 2025, All rights reserved. \n"
"A quantum safe APS list server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char APS_APPLICATION_NAME[] = "APS";
static const char APS_APPLICATION_PATH[] = "\\APS";
static const char APS_FILENAME_CONFIG[] = "\\userconfig.agtcfg";
static const char APS_TOPOLOGY_NAME[] = "\\aps_topology";
static const char APS_PUBKEY_NAME[] = "aps_public_key.acpkey";
static const char APS_PRIKEY_NAME[] = "aps_secret_key.acskey";
static const char APS_PROMPT_DEFAULT[] = "APS> ";
static const char APS_WINDOW_TITLE[] = "APS v1.0a";

static const char ARS_APPLICATION_BANNER[] = "ARS v1.0 \n"
"QRCS Corp. 2025, All rights reserved. \n"
"A quantum safe Root Domain Security server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char ARS_APPLICATION_NAME[] = "ARS";
static const char ARS_APPLICATION_PATH[] = "\\ARS";
static const char ARS_FILENAME_CONFIG[] = "\\userconfig.rdscfg";
static const char ARS_PUBKEY_NAME[] = "ars_public_key.rcpkey";
static const char ARS_PRIKEY_NAME[] = "ars_secret_key.rcskey";
static const char ARS_PROMPT_DEFAULT[] = "ARS> ";
static const char ARS_TOPOLOGY_NAME[] = "\\ars_topology";
static const char ARS_WINDOW_TITLE[] = "AERN Root Domain Security Server v1.0a";

static const char CLIENT_APPLICATION_BANNER[] = "Client v1.0 \n"
"QRCS Corp. 2025, All rights reserved. \n"
"A quantum safe AERN Network Client. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char CLIENT_APPLICATION_NAME[] = "Client";
static const char CLIENT_APPLICATION_PATH[] = "\\Client";
static const char CLIENT_FILENAME_CONFIG[] = "\\userconfig.cntcfg";
static const char CLIENT_PROMPT_DEFAULT[] = "Client> ";
static const char CLIENT_PUBKEY_NAME[] = "client_public_key.ccpkey";
static const char CLIENT_PRIKEY_NAME[] = "client_secret_key.ccskey";
static const char CLIENT_TOPOLOGY_NAME[] = "\\client_topology";
static const char CLIENT_WINDOW_TITLE[] = "Client v1.0a";

static const char IDG_APPLICATION_BANNER[] = "IDG v1.0 \n"
"QRCS Corp. 2025, All rights reserved. \n"
"A quantum safe Inter-Domain Gateway server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char IDG_APPLICATION_NAME[] = "IDG";
static const char IDG_APPLICATION_PATH[] = "\\IDG";
static const char IDG_FILENAME_CONFIG[] = "\\userconfig.idgcfg";
static const char IDG_PUBKEY_NAME[] = "idg_public_key.icpkey";
static const char IDG_PRIKEY_NAME[] = "idg_secret_key.icskey";
static const char IDG_PROMPT_DEFAULT[] = "IDG> ";
static const char IDG_TOPOLOGY_NAME[] = "\\idg_topology";
static const char IDG_WINDOW_TITLE[] = "AERN Inter-Domain Gateway v1.0a";

static void server_child_certificate_issuer(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, state->domain);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, "_");
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, state->hostname);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, AERN_CERTIFICATE_CHILD_EXTENSION);
	}
}

static void server_storage_directory(const aern_server_application_state* state, char* dpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dpath);

		if (qsc_folderutils_directory_exists(dpath) == true)
		{
			qsc_stringutils_concat_strings(dpath, pathlen, AERN_APPLICATION_ROOT_PATH);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}

			qsc_stringutils_concat_strings(dpath, pathlen, state->aplpath);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}
		}
	}
}

static void server_backup_directory(const aern_server_application_state* state, char* dpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);

		if (qsc_folderutils_directory_exists(dpath) == true)
		{
			qsc_stringutils_concat_strings(dpath, pathlen, AERN_CERTIFICATE_BACKUP_PATH);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}
		}
	}
}

static void server_config_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->cfgname);
	}
}

static void server_logging_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, AERN_LOG_FILENAME);
	}
}

static void server_topology_directory(const aern_server_application_state* state, char* dpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);
		qsc_stringutils_concat_strings(dpath, pathlen, AERN_CERTIFICATE_TOPOLOGY_PATH);

		if (qsc_folderutils_directory_exists(dpath) == false)
		{
			qsc_folderutils_create_directory(dpath);
		}
	}
}

static void server_topology_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_topology_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->topname);
		qsc_stringutils_concat_strings(fpath, pathlen, AERN_CERTIFICATE_TOPOLOGY_EXTENSION);
	}
}

static void server_initialize_key_chain(aern_server_application_state* state, const char* password, size_t passlen, const char* username, size_t userlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(password != NULL);
	AERN_ASSERT(username != NULL);
	AERN_ASSERT(passlen != 0U);
	AERN_ASSERT(userlen != 0U);

	if (state != NULL && password != NULL && username != NULL && passlen != 0 && userlen != 0U)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		aern_crypto_generate_application_keychain(state->kchain, klen, password, passlen, username, userlen);
	}
}

static void server_load_key_chain(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH) + AERN_ASYMMETRIC_SIGNING_KEY_SIZE;

		state->kchain = qsc_memutils_malloc(klen);

		if (state->kchain != NULL)
		{
			state->sigkey = state->kchain + (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		}
	}
}

static bool server_log_decrypt(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(state->logpath);

			if (flen > 0U)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - AERN_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(state->logpath, (char*)penc, flen);

					if (mlen > 0)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_LOG_INDEX * SERVER_KEYCHAIN_WIDTH);

						AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = aern_crypto_decrypt_stream(pdec, pkey, penc, mlen - AERN_STORAGE_MAC_SIZE);

						if (res == true)
						{
							qsc_fileutils_erase(state->logpath);
							qsc_fileutils_copy_stream_to_file(state->logpath, (const char*)pdec, flen - AERN_STORAGE_MAC_SIZE);
						}
						else
						{
							/* log is corrupted, delete and create */
							qsc_fileutils_delete(state->logpath);
							aern_server_log_host(state);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

static void server_log_encrypt(const aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(state->logpath);

			if (flen > 0U)
			{
				uint8_t* ptxt;
				uint8_t* penc;

				ptxt = (uint8_t*)qsc_memutils_malloc(flen);
				penc = (uint8_t*)qsc_memutils_malloc(flen + AERN_STORAGE_MAC_SIZE);

				if (penc != NULL && ptxt != NULL)
				{
					flen = qsc_fileutils_copy_file_to_stream(state->logpath, (char*)ptxt, flen);

					if (flen > 0U)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_LOG_INDEX * SERVER_KEYCHAIN_WIDTH);

						AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						aern_crypto_encrypt_stream(penc, pkey, ptxt, flen);
						qsc_fileutils_erase(state->logpath);
						qsc_fileutils_copy_stream_to_file(state->logpath, (const char*)penc, flen + AERN_STORAGE_MAC_SIZE);
					}
				}

				if (ptxt != NULL)
				{
					qsc_memutils_alloc_free(ptxt);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}
}

static void server_log_initialize(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == false ||
			qsc_fileutils_get_size(state->logpath) == 0U)
		{
			size_t slen;

			aern_logger_reset(state->logpath);
			slen = qsc_stringutils_string_size(state->hostname);
			aern_logger_write_decorated_message(state->logpath, aern_application_log_log_header, NULL, 0U);
			aern_logger_write_decorated_time_stamped_message(state->logpath, aern_application_log_log_created, state->hostname, slen);
			server_log_encrypt(state);
		}
	}
}

static void server_root_certificate_issuer(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, state->domain);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, "_");
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, state->hostname);
		qsc_stringutils_concat_strings(state->issuer, AERN_CERTIFICATE_ISSUER_SIZE, AERN_CERTIFICATE_ROOT_EXTENSION);
	}
}

static void server_state_deserialize(aern_server_application_state* state, const uint8_t* input, size_t inlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(input != NULL);
	AERN_ASSERT(inlen >= AERN_SERVER_APPLICATION_STATE_SIZE);

	size_t pos;

	if (state != NULL && input != NULL && inlen >= AERN_SERVER_APPLICATION_STATE_SIZE)
	{
		qsc_memutils_clear(state->cmdprompt, sizeof(state->cmdprompt));
		qsc_memutils_clear(state->domain, sizeof(state->domain));
		qsc_memutils_clear(state->hostname, sizeof(state->hostname));
		qsc_memutils_clear(state->localip, sizeof(state->localip));
		qsc_memutils_clear(state->logpath, sizeof(state->logpath));
		qsc_memutils_clear(&state->tlist, sizeof(state->tlist));
		qsc_memutils_clear(state->username, sizeof(state->username));

		qsc_memutils_copy(state->domain, input, sizeof(state->domain));
		pos = sizeof(state->domain);
		qsc_memutils_copy(state->hostname, ((const char*)input + pos), sizeof(state->hostname));
		pos += sizeof(state->hostname);
		qsc_memutils_copy(state->localip, ((const char*)input + pos), sizeof(state->localip));
		pos += sizeof(state->localip);
		qsc_memutils_copy(state->logpath, ((const char*)input + pos), sizeof(state->logpath));
		pos += sizeof(state->logpath);
		qsc_memutils_copy(state->username, ((const char*)input + pos), sizeof(state->username));
		pos += sizeof(state->username);
		qsc_memutils_copy(state->issuer, ((const char*)input + pos), sizeof(state->issuer));
		pos += sizeof(state->issuer);
		qsc_memutils_copy(&state->port, ((const char*)input + pos), sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(&state->srvtype, ((const char*)input + pos), sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&state->retries, ((const char*)input + pos), sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&state->timeout, ((const char*)input + pos), sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(&state->joined, ((const char*)input + pos), sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(&state->loghost, ((const char*)input + pos), sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(state->sigkey, ((const char*)input + pos), AERN_ASYMMETRIC_SIGNING_KEY_SIZE);

		state->mode = aern_console_mode_user;
		state->action = aern_command_action_none;
	}
}

static bool aern_server_configuration_load(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);

		if (res == true)
		{
			uint8_t encs[AERN_SERVER_APPLICATION_STATE_SIZE + AERN_STORAGE_MAC_SIZE] = { 0U };
			const uint8_t* pkey;

			res = (qsc_fileutils_copy_file_to_stream(fpath, (char*)encs, sizeof(encs)) == sizeof(encs));

			if (res == true)
			{
				uint8_t decs[AERN_SERVER_APPLICATION_STATE_SIZE] = { 0U };

				pkey = state->kchain + (SERVER_KEYCHAIN_STATE_INDEX * SERVER_KEYCHAIN_WIDTH);

				AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				res = aern_crypto_decrypt_stream(decs, pkey, encs, sizeof(decs));

				if (res == true)
				{
					/* deserialize the state */
					server_state_deserialize(state, decs, sizeof(decs));
				}
			}
		}
	}

	return res;
}

static bool server_state_load(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	/* initialize the log */
	server_log_initialize(state);

	res = aern_server_configuration_load(state);

	if (res == true)
	{
		res = aern_server_topology_load(state);

		/* load the topology */
		if (res == true)
		{
			/* change the prompt status */
			aern_server_set_command_prompt(state);
		}
	}

	return res;
}

static bool server_state_reset(const aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);

		if (res == true)
		{
			qsc_fileutils_erase(fpath);
			res = qsc_fileutils_delete(fpath);
		}
	}

	return res;
}

static size_t server_state_serialize(const aern_server_application_state* state, uint8_t* output)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(output != NULL);

	size_t pos;

	pos = 0;

	if (state != NULL && output != NULL)
	{
		qsc_memutils_copy(output, state->domain, sizeof(state->domain));
		pos = sizeof(state->domain);
		qsc_memutils_copy(((char*)output + pos), state->hostname, sizeof(state->hostname));
		pos += sizeof(state->hostname);
		qsc_memutils_copy(((char*)output + pos), state->localip, sizeof(state->localip));
		pos += sizeof(state->localip);
		qsc_memutils_copy(((char*)output + pos), state->logpath, sizeof(state->logpath));
		pos += sizeof(state->logpath);
		qsc_memutils_copy(((char*)output + pos), state->username, sizeof(state->username));
		pos += sizeof(state->username);
		qsc_memutils_copy(((char*)output + pos), state->issuer, sizeof(state->issuer));
		pos += sizeof(state->issuer);
		qsc_memutils_copy(((char*)output + pos), &state->port, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(((char*)output + pos), &state->srvtype, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(((char*)output + pos), &state->retries, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(((char*)output + pos), &state->timeout, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(((char*)output + pos), &state->joined, sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(((char*)output + pos), &state->loghost, sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(((char*)output + pos), state->sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += AERN_ASYMMETRIC_SIGNING_KEY_SIZE;
	}

	return pos;
}

static void server_unload_key_chain(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		qsc_memutils_clear(state->kchain, klen);
	}
}

static void server_unload_signature_key(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH) + AERN_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_clear(state->kchain, klen);
		qsc_memutils_alloc_free(state->kchain);
	}
}

void aern_server_certificate_directory(const aern_server_application_state* state, char* dpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);
		qsc_stringutils_concat_strings(dpath, pathlen, AERN_CERTIFICATE_STORE_PATH);

		if (qsc_folderutils_directory_exists(dpath) == false)
		{
			qsc_folderutils_create_directory(dpath);
		}

		qsc_folderutils_append_delimiter(dpath);
	}
}

void aern_server_certificate_path(const aern_server_application_state* state, char* fpath, size_t pathlen, const char* issuer)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);
	AERN_ASSERT(issuer != NULL);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH && issuer != NULL)
	{
		aern_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, issuer);
	}
}

bool aern_server_child_certificate_export(const aern_server_application_state* state, const char* dpath)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);

	bool res;

	res = false;

	if (state != NULL && dpath != NULL)
	{
		if (qsc_folderutils_directory_exists(dpath) == true &&
			qsc_stringutils_string_size(state->issuer) > 0U)
		{
			char cpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_child_certificate_path(state, cpath, sizeof(cpath));

			if (qsc_fileutils_exists(cpath) == true)
			{
				char opath[AERN_STORAGE_PATH_MAX] = { 0 };

				qsc_stringutils_copy_string(opath, sizeof(opath), dpath);

				if (qsc_folderutils_directory_has_delimiter(opath) == false)
				{
					qsc_folderutils_append_delimiter(opath);
				}

				qsc_stringutils_concat_strings(opath, sizeof(opath), state->issuer);
				res = qsc_fileutils_file_copy(cpath, opath);
			}
		}
	}

	return res;
}

bool aern_server_child_certificate_from_issuer(aern_child_certificate* ccert, const aern_server_application_state* state, const char* issuer)
{
	char rpath[AERN_STORAGE_PATH_MAX] = { 0 };
	bool res;

	res = false;

	aern_server_child_certificate_path_from_issuer(state, rpath, sizeof(rpath), issuer);

	if (qsc_fileutils_exists(rpath) == true)
	{
		res = aern_certificate_child_file_to_struct(rpath, ccert);
	}

	return res;
}

bool aern_server_child_certificate_from_serial(aern_child_certificate* ccert, const aern_server_application_state* state, const uint8_t* serial)
{
	aern_topology_node_state cnode = { 0 };
	bool res;

	res = false;

	if (aern_topology_node_find(&state->tlist, &cnode, serial) == true)
	{
		char rpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_server_child_certificate_path_from_issuer(state, rpath, sizeof(rpath), cnode.issuer);

		if (qsc_fileutils_exists(rpath) == true)
		{
			res = aern_certificate_child_file_to_struct(rpath, ccert);
		}
	}

	return res;
}

void aern_server_child_certificate_generate(aern_server_application_state* state, aern_child_certificate* ccert, uint64_t period)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(period != 0U);

	if (state != NULL && ccert != NULL && period != 0U)
	{
		aern_certificate_expiration exp = { 0 };
		aern_signature_keypair akp = { 0 };

		/* generate the key-pair */
		aern_certificate_signature_generate_keypair(&akp);
		exp.from = qsc_timestamp_epochtime_seconds();
		exp.to = exp.from + period;

		/* extrapolate a unique issuer name and store in state; domain_host.ccert */
		server_child_certificate_issuer(state);

		/* create the certificate */
		aern_certificate_child_create(ccert, akp.pubkey, &exp, state->issuer, state->srvtype);

		/* write the private key to state */
		qsc_memutils_copy(state->sigkey, akp.prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
	}
}

bool aern_server_child_certificate_import(aern_child_certificate* lcert, aern_server_application_state* state, const char* fpath)
{
	AERN_ASSERT(lcert != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (lcert != NULL && state != NULL && fpath != NULL)
	{
		char cpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_server_child_certificate_path(state, cpath, sizeof(cpath));

		if (aern_certificate_child_file_to_struct(fpath, lcert) == true)
		{
			if (aern_certificate_child_is_valid(lcert) == true)
			{
				if (aern_certificate_root_is_valid(&state->root) == true)
				{
					if (aern_certificate_root_signature_verify(lcert, &state->root) == true)
					{
						if (qsc_fileutils_exists(cpath) == true)
						{
							/* overwrite dialogue */
							if (aern_menu_print_predefined_message_confirm(aern_application_certificate_exists, state->mode, state->hostname) == true)
							{
								aern_topology_node_state rnode = { 0 };

								qsc_fileutils_delete(cpath);

								if (aern_topology_node_find_issuer(&state->tlist, &rnode, lcert->issuer) == true)
								{
									/* remove the old node and add the update */
									aern_topology_node_remove(&state->tlist, rnode.serial);
									aern_topology_child_register(&state->tlist, lcert, state->localip);
								}

								res = qsc_fileutils_file_copy(fpath, cpath);
							}
						}
						else
						{
							res = qsc_fileutils_file_copy(fpath, cpath);
						}
					}
				}
			}
		}
	}

	return res;
}

void aern_server_child_certificate_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		aern_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->issuer);
	}
}

void aern_server_child_certificate_path_from_issuer(const aern_server_application_state* state, char* fpath, size_t pathlen, const char* issuer)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);
	AERN_ASSERT(issuer != NULL);

	if (state != NULL && fpath != NULL && issuer != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		aern_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, issuer);
	}
}

bool aern_server_child_certificate_print(const char* fpath, size_t pathlen)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	bool res;

	res = false;

	if (fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		if (pathlen > 0U &&
			qsc_fileutils_exists(fpath) &&
			qsc_stringutils_string_contains(fpath, AERN_CERTIFICATE_CHILD_EXTENSION) == true)
		{
			aern_child_certificate ccert = { 0 };

			if (aern_certificate_child_file_to_struct(fpath, &ccert) == true)
			{
				char enck[AERN_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };
				const size_t SLEN = aern_certificate_child_encode(enck, &ccert);

				if (SLEN <= AERN_CHILD_CERTIFICATE_STRING_SIZE)
				{
					qsc_consoleutils_print_safe(enck);
					qsc_consoleutils_print_line("");
					res = true;
				}
			}
		}
	}

	return res;
}

void aern_server_local_certificate_store(aern_server_application_state* state, const aern_child_certificate* ccert, const char* address)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(address != NULL);

	if (state != NULL && ccert != NULL && address != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		/* copy the certificate to file */
		aern_server_child_certificate_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		aern_certificate_child_struct_to_file(fpath, ccert);

		if (aern_topology_node_exists(&state->tlist, ccert->serial) == true)
		{
			/* delete the old node entry */
			aern_topology_node_remove(&state->tlist, ccert->serial);
		}

		/* get the node address and register in the topology */
		aern_topology_child_register(&state->tlist, ccert, address);
		aern_server_topology_to_file(state);
	}
}

void aern_server_clear_config(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		server_state_reset(state);
		aern_server_state_initialize(state, state->srvtype);
	}
}

void aern_server_clear_log(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		/* erase contents */
		aern_logger_erase_all(state->logpath);
		/* reset the log file */
		qsc_fileutils_delete(state->logpath);
		aern_server_log_host(state);
	}
}

void aern_server_erase_all(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		aern_server_clear_log(state);
		server_state_reset(state);
		aern_server_state_initialize(state, state->srvtype);
	}
}

void aern_server_log_host(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	size_t slen;

	if (state != NULL)
	{
		slen = qsc_stringutils_string_size(state->hostname);

		/* initialize the log file */
		server_log_initialize(state);

		if (state->loghost == true)
		{
			/* first log entry */
			aern_server_log_write_message(state, aern_application_log_log_enabled, state->hostname, slen);
		}
		else
		{
			/* disable and warn */
			aern_server_log_write_message(state, aern_application_log_log_disabled, state->hostname, slen);
		}

		aern_server_state_store(state);
	}
}

void aern_server_log_print(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		if (aern_logger_exists(state->logpath))
		{
			if (server_log_decrypt(state) == true)
			{
				char buf[AERN_STORAGE_MESSAGE_MAX] = { 0 };
				int64_t len;
				size_t ctr;

				ctr = 0U;

				while (true)
				{
					len = aern_logger_read_line(state->logpath, buf, sizeof(buf), ctr);

					if (len > 0)
					{
						aern_menu_print_prompt(aern_console_mode_enable, state->hostname);
						qsc_consoleutils_print_line(buf);
						qsc_stringutils_clear_string(buf);
					}
					else if (len < 0)
					{
						break;
					}

					++ctr;
				}

				server_log_encrypt(state);
			}
		}
		else
		{
			aern_menu_print_predefined_message(aern_application_log_empty, aern_console_mode_enable, state->hostname);
		}
	}
}

bool aern_server_log_write_message(aern_server_application_state* state, aern_application_messages msgtype, const char* message, size_t msglen)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		res = aern_logger_exists(state->logpath);

		if (res == true)
		{
			if (qsc_fileutils_get_size(state->logpath) > 0U)
			{
				res = server_log_decrypt(state);
			}

			if (res == true)
			{
				aern_logger_write_decorated_time_stamped_message(state->logpath, msgtype, message, msglen);
				server_log_encrypt(state);
			}
		}
	}

	return res;
}

void aern_server_mfkcol_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		server_topology_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->topname);
		qsc_stringutils_concat_strings(fpath, pathlen, AERN_CERTIFICATE_MFCOL_EXTENSION);
	}
}

bool aern_server_mfkcol_from_file(qsc_collection_state* mfkcol, const aern_server_application_state* state)
{
	AERN_ASSERT(mfkcol != NULL);
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (mfkcol != NULL && state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_server_mfkcol_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0U)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - AERN_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(fpath, (char*)penc, flen);

					if (mlen > 0U)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_MFKCOL_INDEX * SERVER_KEYCHAIN_WIDTH);

						AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = aern_crypto_decrypt_stream(pdec, pkey, penc, mlen - AERN_STORAGE_MAC_SIZE);

						if (res == true)
						{
							qsc_collection_deserialize(mfkcol, pdec);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

void aern_server_mfkcol_to_file(const qsc_collection_state* mfkcol, const aern_server_application_state* state)
{
	AERN_ASSERT(mfkcol != NULL);
	AERN_ASSERT(state != NULL);

	size_t clen;

	if (mfkcol != NULL && state != NULL)
	{
		clen = qsc_collection_size(mfkcol);

		if (clen > 0U)
		{
			uint8_t* ptxt;
			uint8_t* penc;

			ptxt = (uint8_t*)qsc_memutils_malloc(clen);
			penc = (uint8_t*)qsc_memutils_malloc(clen + AERN_STORAGE_MAC_SIZE);

			if (penc != NULL && ptxt != NULL)
			{
				char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
				const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_MFKCOL_INDEX * SERVER_KEYCHAIN_WIDTH);

				AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				aern_server_mfkcol_path(state, fpath, sizeof(fpath));

				if (qsc_fileutils_exists(fpath) == true)
				{
					qsc_fileutils_delete(fpath);
				}

				qsc_collection_serialize(ptxt, mfkcol);
				aern_crypto_encrypt_stream(penc, pkey, ptxt, clen);
				qsc_fileutils_copy_stream_to_file(fpath, (const char*)penc, clen + AERN_STORAGE_MAC_SIZE);

				qsc_memutils_alloc_free(penc);
				qsc_memutils_alloc_free(ptxt);
			}
		}
	}
}

void aern_server_print_banner(const aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_consoleutils_print_line(state->banner);
		qsc_consoleutils_print_line("");
	}
}

void aern_server_print_error(const aern_server_application_state* state, aern_application_messages appmsg, const char* message, aern_protocol_errors error)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(message != NULL);

	if (state != NULL && message != NULL)
	{
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		aern_menu_print_predefined_text(appmsg, state->mode, state->hostname);
		aern_menu_print_text_line(message);
		aern_menu_print_error(error, state->mode, state->hostname);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void aern_server_print_configuration(const aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	const char DEFVAL[] = "NOT-SET";
	char ib[6U] = { 0 };

	if (state != NULL)
	{
		aern_menu_print_predefined_message(aern_application_configuration, aern_console_mode_enable, state->hostname);

		const char* sdom[3U] = {
			state->cmdprompt,
			"Domain string: ",
			qsc_stringutils_string_size(state->domain) > 0U ? state->domain : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(sdom, 3U);

		const char* shost[3U] = {
			state->cmdprompt,
			"Host name: ",
			qsc_stringutils_string_size(state->hostname) > 0U ? state->hostname : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(shost, 3U);

		const char* slip[3U] = {
			state->cmdprompt,
			"IP address: ",
			qsc_stringutils_string_size(state->localip) > 0U ? state->localip : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(slip, 3U);

		const char* slog[3U] = {
			state->cmdprompt,
			"Host Logging: ",
			state->loghost == true ? "true" : "false",
		};
		qsc_consoleutils_print_concatenated_line(slog, 3U);

		qsc_stringutils_int_to_string(state->port, ib, sizeof(ib));
		const char* tmpport[3U] = {
			state->cmdprompt,
			"Port number: ",
			ib,
		};
		qsc_consoleutils_print_concatenated_line(tmpport, 3U);

		qsc_memutils_clear(ib, sizeof(ib));
		qsc_stringutils_int_to_string(state->retries, ib, sizeof(ib));
		const char* sretr[3U] = {
			state->cmdprompt,
			"Authentication retries: ",
			ib,
		};

		qsc_consoleutils_print_concatenated_line(sretr, 3U);
		qsc_stringutils_int_to_string(state->timeout, ib, sizeof(ib));

		const char* stout[3U] = {
			state->cmdprompt,
			"Console timeout: ",
			ib,
		};

		qsc_consoleutils_print_concatenated_line(stout, 3U);
	}
}

bool aern_server_root_certificate_export(const aern_server_application_state* state, const char* dpath)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dpath != NULL);

	bool res;

	res = false;

	if (state != NULL && dpath != NULL)
	{
		if (qsc_folderutils_directory_exists(dpath) == true &&
			qsc_stringutils_string_size(state->issuer) > 0U)
		{
			char cpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_certificate_path(state, cpath, sizeof(cpath), state->issuer);

			if (qsc_fileutils_exists(cpath) == true)
			{
				char opath[AERN_STORAGE_PATH_MAX] = { 0 };

				qsc_stringutils_copy_string(opath, sizeof(opath), dpath);

				if (qsc_folderutils_directory_has_delimiter(opath) == false)
				{
					qsc_folderutils_append_delimiter(opath);
				}

				qsc_stringutils_concat_strings(opath, sizeof(opath), state->issuer);
				res = qsc_fileutils_file_copy(cpath, opath);
			}
		}
	}

	return res;
}

bool aern_server_root_import_dialogue(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	size_t slen;
	bool res;

	res = false;

	if (state != NULL)
	{
		char cmsg[AERN_STORAGE_PASSWORD_MAX] = { 0 };

		while (true)
		{
			aern_menu_print_predefined_message(aern_application_challenge_root_path, aern_console_mode_certificate, state->hostname);
			aern_menu_print_prompt(aern_console_mode_certificate, state->hostname);
			slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

			if (slen >= AERN_STORAGE_FILEPATH_MIN &&
				slen <= AERN_STORAGE_FILEPATH_MAX &&
				qsc_fileutils_exists(cmsg) == true &&
				qsc_stringutils_string_contains(cmsg, AERN_CERTIFICATE_ROOT_EXTENSION))
			{
				if (aern_certificate_root_file_to_struct(cmsg, &state->root) == true)
				{
					aern_server_root_certificate_store(state, &state->root);
					aern_menu_print_predefined_message(aern_application_challenge_root_path_success, aern_console_mode_certificate, state->hostname);
					res = true;
					break;
				}
				else
				{
					aern_menu_print_predefined_message(aern_application_challenge_root_path_failure, aern_console_mode_certificate, state->hostname);
				}
			}
			else
			{
				aern_menu_print_predefined_message(aern_application_challenge_root_path_failure, aern_console_mode_certificate, state->hostname);
			}
		}
	}

	return res;
}

void aern_server_root_certificate_generate(aern_server_application_state* state, aern_root_certificate* rcert, uint64_t period)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(rcert != NULL);
	AERN_ASSERT(period != 0U);

	if (state != NULL && rcert != NULL && period != 0U)
	{
		aern_certificate_expiration exp = { 0 };
		aern_signature_keypair akp = { 0 };

		/* generate the key-pair*/
		aern_certificate_signature_generate_keypair(&akp);
		exp.from = qsc_timestamp_epochtime_seconds();
		exp.to = exp.from + period;

		/* Note: ex. mydomain_ars1.rcert */
		server_root_certificate_issuer(state);

		/* create the certificate */
		aern_certificate_root_create(rcert, akp.pubkey, &exp, state->issuer);

		/* write the private key to state */
		qsc_memutils_copy(state->sigkey, akp.prikey, sizeof(akp.prikey));
	}
}

bool aern_server_root_certificate_load(const aern_server_application_state* state, aern_root_certificate* root, const aern_topology_list_state* tlist)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(tlist != NULL);

	bool res;

	res = false;

	if (state != NULL && root != NULL && tlist != NULL)
	{
		aern_topology_node_state rnode = { 0 };

		if (aern_topology_node_find_root(tlist, &rnode) == true)
		{
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_certificate_path(state, fpath, sizeof(fpath), rnode.issuer);

			if (qsc_fileutils_exists(fpath) &&
				qsc_stringutils_string_contains(fpath, AERN_CERTIFICATE_ROOT_EXTENSION) == true)
			{
				if (aern_certificate_root_is_valid(root) == true)
				{
					if (aern_certificate_root_file_to_struct(fpath, root) == true)
					{
						uint8_t chash[AERN_CRYPTO_SYMMETRIC_HASH_SIZE];

						aern_certificate_root_hash(chash, root);
						res = qsc_memutils_are_equal(chash, rnode.chash, sizeof(chash));

						if (res == false)
						{
							qsc_memutils_clear(root, sizeof(aern_root_certificate));
						}
					}
				}
			}
		}
	}

	return res;
}

void aern_server_root_certificate_path(const aern_server_application_state* state, char* fpath, size_t pathlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		aern_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->issuer);
	}
}

bool aern_server_root_certificate_print(const char* fpath, size_t pathlen)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(pathlen >= AERN_MINIMUM_PATH_LENGTH);

	bool res;

	res = false;

	if (fpath != NULL && pathlen >= AERN_MINIMUM_PATH_LENGTH)
	{
		if (pathlen > 0 &&
			qsc_fileutils_exists(fpath) &&
			qsc_stringutils_string_contains(fpath, AERN_CERTIFICATE_ROOT_EXTENSION) == true)
		{
			aern_root_certificate rcert = { 0 };

			if (aern_certificate_root_file_to_struct(fpath, &rcert) == true)
			{
				char enck[AERN_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };
				const size_t SLEN = aern_certificate_root_encode(enck, &rcert);

				if (SLEN <= AERN_ROOT_CERTIFICATE_STRING_SIZE)
				{
					qsc_consoleutils_print_safe(enck);
					qsc_consoleutils_print_line("");
					res = true;
				}
			}
		}
	}

	return res;
}

void aern_server_root_certificate_store(aern_server_application_state* state, const aern_root_certificate* rcert)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(rcert != NULL);

	bool res;
	
	if (state != NULL && rcert != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
		size_t slen;

		aern_server_certificate_path(state, fpath, sizeof(fpath), rcert->issuer);
		res = aern_certificate_root_struct_to_file(fpath, rcert);

		if (res == true)
		{
			if (state->srvtype == aern_network_designation_ads)
			{
				res = false;

				while (res == false)
				{
					char cmsg[AERN_STORAGE_PATH_MAX] = { 0 };

					/* get the root address and register in the topology */
					aern_menu_print_predefined_message(aern_application_ars_certificate_address_challenge, aern_console_mode_server, state->hostname);
					aern_menu_print_prompt(aern_console_mode_server, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= QSC_IPINFO_IPV4_MINLEN)
					{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
						if (qsc_ipinfo_ipv6_address_string_is_valid(cmsg) == true)
						{
#else
						if (qsc_ipinfo_ipv4_address_string_is_valid(cmsg) == true)
						{
#endif
							aern_topology_root_register(&state->tlist, rcert, cmsg);
							aern_server_topology_to_file(state);
							res = true;
						}
					}

					if (res == false)
					{
						aern_menu_print_predefined_message(aern_application_ars_certificate_address_failure, aern_console_mode_server, state->hostname);
					}
				}
			}
			else
			{
				char sadd[AERN_CERTIFICATE_ADDRESS_SIZE] = "0.0.0.0";

				aern_topology_root_register(&state->tlist, rcert, sadd);
				aern_server_topology_to_file(state);
			}
		}
	}
}

void aern_server_set_command_prompt(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		/* erase the prompt string */
		qsc_stringutils_clear_string(state->cmdprompt);
		/* copy the local host name */
		qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->hostname);

		/* copy the matching mode name to prompt string */
		switch (state->mode)
		{
			case aern_console_mode_config:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_config));
				break;
			}
			case aern_console_mode_certificate:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_certificate));
				break;
			}
			case aern_console_mode_server:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_server));
				break;
			}
			case aern_console_mode_client_connected:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_client_connected));
				break;
			}
			case aern_console_mode_enable:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_enable));
				break;
			}
			case aern_console_mode_user:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_user));
				break;
			}
			default:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), aern_menu_get_prompt(aern_console_mode_user));
			}
		}
	}
}

bool aern_server_set_console_timeout(aern_server_application_state* state, const char* snum, size_t numlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(snum != NULL);
	AERN_ASSERT(numlen != 0U);

	bool res;

	res = false;

	if (state != NULL && snum != NULL && numlen != 0U)
	{
		if (numlen > 0U)
		{
			uint16_t val;

			if (qsc_stringutils_is_numeric(snum, numlen) == true)
			{
				val = (uint16_t)qsc_stringutils_string_to_int(snum);

				if (val >= (uint16_t)AERN_STORAGE_TIMEOUT_MIN && val <= (uint16_t)AERN_STORAGE_TIMEOUT_MAX)
				{
					state->timeout = val;
					res = aern_server_state_store(state);

					if (res == true)
					{
						aern_server_log_write_message(state, aern_application_log_timeout_change, snum, numlen);
					}
				}
			}
		}
	}

	return res;
}

bool aern_server_set_domain_name(aern_server_application_state* state, const char* name, size_t namelen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(name != NULL);
	AERN_ASSERT(namelen != 0U);

	bool res;

	res = true;
	
	if (state != NULL && name != NULL && namelen != 0U)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		if (state->srvtype == aern_network_designation_ars)
		{
			aern_server_root_certificate_path(state, fpath, sizeof(fpath));
		}
		else
		{
			aern_server_child_certificate_path(state, fpath, sizeof(fpath));
		}

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		if (namelen >= AERN_STORAGE_DOMAINNAME_MIN && namelen <= AERN_STORAGE_DOMAINNAME_MAX)
		{
			qsc_stringutils_clear_string(state->domain);
			qsc_stringutils_copy_substring(state->domain, sizeof(state->domain), name, namelen);

			res = aern_server_state_store(state);

			if (res == true)
			{
				size_t slen;

				slen = qsc_stringutils_string_size(state->domain);

				if (state->srvtype == aern_network_designation_ars)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}

				aern_server_log_write_message(state, aern_application_log_domain_change, state->domain, slen);
			}
		}
	}

	return res;
}

bool aern_server_set_host_name(aern_server_application_state* state, const char* name, size_t namelen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(name != NULL);
	AERN_ASSERT(namelen != 0U);

	bool res;

	res = true;

	if (state != NULL && name != NULL && namelen != 0U)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		if (state->srvtype == aern_network_designation_ars)
		{
			aern_server_root_certificate_path(state, fpath, sizeof(fpath));
		}
		else
		{
			aern_server_child_certificate_path(state, fpath, sizeof(fpath));
		}

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		if (namelen >= AERN_STORAGE_HOSTNAME_MIN && namelen <= AERN_STORAGE_HOSTNAME_MAX)
		{
			qsc_stringutils_clear_string(state->hostname);
			qsc_stringutils_copy_substring(state->hostname, sizeof(state->hostname), name, namelen);

			res = aern_server_state_store(state);

			if (res == true)
			{
				size_t slen;

				if (state->srvtype == aern_network_designation_ars)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}

				slen = qsc_stringutils_string_size(state->hostname);
				aern_server_log_write_message(state, aern_application_log_hostname_change, state->hostname, slen);
			}
		}
	}

	return res;
}

bool aern_server_set_ip_address(aern_server_application_state* state, const char* address, size_t addlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(address != NULL);
	AERN_ASSERT(addlen != 0U);

	bool res;

	res = false;

	if (state != NULL && address != NULL && addlen != 0U)
	{
		if (addlen >= AERN_STORAGE_ADDRESS_MIN && addlen <= AERN_STORAGE_ADDRESS_MAX)
		{
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
			qsc_ipinfo_ipv6_address add = { 0 };
			add = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&add) == true && qsc_ipinfo_ipv6_address_is_zeroed(&add) == false)
#else
			qsc_ipinfo_ipv4_address add = { 0 };
			add = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&add) == true)
#endif
			{
				qsc_stringutils_clear_string(state->localip);
				qsc_stringutils_copy_substring(state->localip, sizeof(state->localip), address, addlen);
				res = aern_server_state_store(state);

				if (res == true)
				{
					aern_server_log_write_message(state, aern_application_log_address_change, address, addlen);
				}
			}
		}
	}

	return res;
}

bool aern_server_set_password_retries(aern_server_application_state* state, const char* snum, size_t numlen)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(snum != NULL);
	AERN_ASSERT(numlen != 0U);

	uint8_t val;
	bool res;

	res = false;

	if (state != NULL && snum != NULL && numlen != 0U)
	{
		if (qsc_stringutils_is_numeric(snum, numlen) == true)
		{
			if (numlen != 0U)
			{
				val = (uint8_t)qsc_stringutils_string_to_int(snum);

				if (val >= (uint8_t)AERN_STORAGE_RETRIES_MIN && val <= (uint8_t)AERN_STORAGE_RETRIES_MAX)
				{
					state->retries = val;
					res = aern_server_state_store(state);

					if (res == true)
					{
						aern_server_log_write_message(state, aern_application_log_retries_change, snum, numlen);
					}
				}
			}
		}
	}

	return res;
}

void aern_server_erase_signature_key(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		qsc_memutils_clear(state->kchain + (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH), AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
	}
}

void aern_server_state_backup_restore(const aern_server_application_state* state)
{
	if (state != NULL)
	{
		char bcdir[AERN_STORAGE_PATH_MAX] = { 0 };
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
		char spath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		server_backup_directory(state, bcdir, sizeof(bcdir));

		/* restore the configuration file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->cfgname);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
				qsc_stringutils_clear_string(fpath);
				qsc_stringutils_clear_string(spath);
			}
		}

		server_topology_path(state, fpath, sizeof(fpath));

		/* restore the topology file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->topname);
			qsc_stringutils_concat_strings(spath, sizeof(spath), AERN_CERTIFICATE_TOPOLOGY_EXTENSION);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
				qsc_stringutils_clear_string(fpath);
				qsc_stringutils_clear_string(spath);
			}
		}

		server_logging_path(state, fpath, sizeof(fpath));

		/* restore the log file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), AERN_LOG_FILENAME);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
			}
		}
	}
}

void aern_server_state_backup_save(const aern_server_application_state* state)
{
	if (state != NULL)
	{
		char bcdir[AERN_STORAGE_PATH_MAX] = { 0 };
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
		char spath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		server_backup_directory(state, bcdir, sizeof(bcdir));

		/* backup the configuration file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->cfgname);
			qsc_fileutils_file_copy(fpath, spath);
			qsc_stringutils_clear_string(fpath);
			qsc_stringutils_clear_string(spath);
		}

		server_topology_path(state, fpath, sizeof(fpath));

		/* backup the topology file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->topname);
			qsc_stringutils_concat_strings(spath, sizeof(spath), AERN_CERTIFICATE_TOPOLOGY_EXTENSION);
			qsc_fileutils_file_copy(fpath, spath);
			qsc_stringutils_clear_string(fpath);
			qsc_stringutils_clear_string(spath);
		}

		server_logging_path(state, fpath, sizeof(fpath));

		/* backup the log file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), AERN_LOG_FILENAME);
			qsc_fileutils_file_copy(fpath, spath);
		}
	}
}

void aern_server_state_initialize(aern_server_application_state* state, aern_network_designations srvtype)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(srvtype != aern_network_designation_none);

	if (state != NULL && srvtype != aern_network_designation_none)
	{
		qsc_memutils_clear(state->cmdprompt, sizeof(state->cmdprompt));
		qsc_memutils_clear(state->domain, sizeof(state->domain));
		qsc_memutils_clear(state->hostname, sizeof(state->hostname));
		qsc_memutils_clear(state->localip, sizeof(state->localip));
		qsc_memutils_clear(state->logpath, sizeof(state->logpath));
		qsc_memutils_clear(state->issuer, sizeof(state->issuer));
		qsc_memutils_clear(&state->tlist, sizeof(state->tlist));
		qsc_memutils_clear(state->username, sizeof(state->username));

		if (srvtype == aern_network_designation_aps)
		{
			state->aplpath = APS_APPLICATION_PATH;
			state->banner = APS_APPLICATION_BANNER;
			state->cfgname = APS_FILENAME_CONFIG;
			state->srvname = APS_APPLICATION_NAME;
			state->prikeyname = APS_PRIKEY_NAME;
			state->promptdef = APS_PROMPT_DEFAULT;
			state->pubkeyname = APS_PUBKEY_NAME;
			state->topname = APS_TOPOLOGY_NAME;
			state->wtitle = APS_WINDOW_TITLE;
			state->port = AERN_APPLICATION_APS_PORT;
		}
		else if (srvtype == aern_network_designation_client)
		{
			state->aplpath = CLIENT_APPLICATION_PATH;
			state->banner = CLIENT_APPLICATION_BANNER;
			state->cfgname = CLIENT_FILENAME_CONFIG;
			state->srvname = CLIENT_APPLICATION_NAME;
			state->prikeyname = CLIENT_PRIKEY_NAME;
			state->promptdef = CLIENT_PROMPT_DEFAULT;
			state->pubkeyname = CLIENT_PUBKEY_NAME;
			state->topname = CLIENT_TOPOLOGY_NAME;
			state->wtitle = CLIENT_WINDOW_TITLE;
			state->port = AERN_APPLICATION_CLIENT_PORT;
		}
		else if (srvtype == aern_network_designation_ads)
		{
			state->aplpath = ADS_APPLICATION_PATH;
			state->banner = ADS_APPLICATION_BANNER;
			state->cfgname = ADS_FILENAME_CONFIG;
			state->srvname = ADS_APPLICATION_NAME;
			state->prikeyname = ADS_PRIKEY_NAME;
			state->promptdef = ADS_PROMPT_DEFAULT;
			state->pubkeyname = ADS_PUBKEY_NAME;
			state->topname = ADS_TOPOLOGY_NAME;
			state->wtitle = ADS_WINDOW_TITLE;
			state->port = AERN_APPLICATION_ADC_PORT;
		}
		else if (srvtype == aern_network_designation_idg)
		{
			state->aplpath = IDG_APPLICATION_PATH;
			state->banner = IDG_APPLICATION_BANNER;
			state->cfgname = IDG_FILENAME_CONFIG;
			state->srvname = IDG_APPLICATION_NAME;
			state->prikeyname = IDG_PRIKEY_NAME;
			state->promptdef = IDG_PROMPT_DEFAULT;
			state->pubkeyname = IDG_PUBKEY_NAME;
			state->topname = IDG_TOPOLOGY_NAME;
			state->wtitle = IDG_WINDOW_TITLE;
			state->port = AERN_APPLICATION_IDG_PORT;
		}
		else if (srvtype == aern_network_designation_ars)
		{
			state->aplpath = ARS_APPLICATION_PATH;
			state->banner = ARS_APPLICATION_BANNER;
			state->cfgname = ARS_FILENAME_CONFIG;
			state->srvname = ARS_APPLICATION_NAME;
			state->prikeyname = ARS_PRIKEY_NAME;
			state->promptdef = ARS_PROMPT_DEFAULT;
			state->pubkeyname = ARS_PUBKEY_NAME;
			state->topname = ARS_TOPOLOGY_NAME;
			state->wtitle = ARS_WINDOW_TITLE;
			state->port = AERN_APPLICATION_ARS_PORT;
		}

		server_logging_path(state, state->logpath, sizeof(state->logpath));
		qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->promptdef);
		qsc_stringutils_copy_string(state->hostname, sizeof(state->hostname), state->srvname);

		/* default server ip address */
#if defined(AERN_NETWORK_PROTOCOL_IPV6)
		qsc_ipinfo_ipv6_address ipv6 = { 0 };

		ipv6 = qsc_netutils_get_ipv6_address();
		qsc_ipinfo_ipv6_address_to_string(state->localip, &ipv6);
#else
		qsc_ipinfo_ipv4_address ipv4 = { 0 };

		qsc_netutils_get_ipv4_address(&ipv4);
		qsc_ipinfo_ipv4_address_to_string(state->localip, &ipv4);
#endif

		qsc_netutils_get_domain_name(state->domain);
		state->srvtype = srvtype;
		state->timeout = AERN_DEFAULT_SESSION_TIMEOUT;
		state->retries = AERN_DEFAULT_AUTH_RETRIES;
		state->action = aern_command_action_none;
		state->mode = aern_console_mode_user;
		state->joined = false;
		state->loghost = true;
	}
}

bool aern_server_state_store(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
		uint8_t encs[AERN_SERVER_APPLICATION_STATE_SIZE + AERN_STORAGE_MAC_SIZE] = { 0U };
		uint8_t tmps[AERN_SERVER_APPLICATION_STATE_SIZE] = { 0U };

		server_config_path(state, fpath, sizeof(fpath));
		server_state_serialize(state, tmps);
		const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_STATE_INDEX * SERVER_KEYCHAIN_WIDTH);

		AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

		res = qsc_memutils_zeroed(pkey, SERVER_KEYCHAIN_WIDTH);

		if (res == false)
		{
			aern_crypto_encrypt_stream(encs, pkey, tmps, sizeof(tmps));
			res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)encs, sizeof(encs));
		}
	}

	return res;
}

void aern_server_state_unload(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		server_unload_signature_key(state);
		aern_topology_list_dispose(&state->tlist);
		aern_server_state_initialize(state, state->srvtype);
	}
}

bool aern_server_topology_adc_fetch(const aern_server_application_state* state, aern_child_certificate* dcert)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(dcert != NULL);

	bool res;

	res = false;

	if (state != NULL && dcert != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_ads(&state->tlist, &node) == true)
		{
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = aern_certificate_child_file_to_struct(fpath, dcert);
			}
		}
	}

	return res;
}

bool aern_server_topology_load(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_topology_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0U)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - AERN_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(fpath, (char*)penc, flen);

					if (mlen > 0U)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_TOPOLOGY_INDEX * SERVER_KEYCHAIN_WIDTH);

						AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = aern_crypto_decrypt_stream(pdec, pkey, penc, mlen - AERN_STORAGE_MAC_SIZE);

						if (res == true)
						{
							aern_topology_list_deserialize(&state->tlist, pdec, flen - AERN_STORAGE_MAC_SIZE);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

bool aern_server_topology_local_fetch(const aern_server_application_state* state, aern_child_certificate* ccert)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(ccert != NULL);

	bool res;

	res = false;

	if (state != NULL && ccert != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_issuer(&state->tlist, &node, state->issuer) == true)
		{
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = aern_certificate_child_file_to_struct(fpath, ccert);
			}
		}
	}

	return res;
}

void aern_server_topology_print_list(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	char* lstr;
	size_t rlen;
	size_t slen;

	if (state != NULL)
	{
		slen = (state->tlist.count * AERN_TOPOLOGY_NODE_ENCODED_SIZE);

		if (slen > 0U)
		{
			lstr = qsc_memutils_malloc(slen);

			if (lstr != NULL)
			{
				qsc_memutils_clear(lstr, slen);
				rlen = aern_topology_list_to_string(&state->tlist, lstr, slen);

				if (rlen != 0U)
				{
					qsc_consoleutils_print_safe(lstr);
				}

				qsc_memutils_alloc_free(lstr);
			}
		}
	}
}

void aern_server_topology_purge_externals(aern_server_application_state* state)
{
	aern_topology_list_state tcopy = { 0 };

	aern_topology_list_clone(&state->tlist, &tcopy);

	for (size_t i = 0U; i < tcopy.count; ++i)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_list_item(&tcopy, &node, i) == true)
		{
			if (qsc_memutils_are_equal((const uint8_t*)node.issuer, (const uint8_t*)state->issuer, AERN_CERTIFICATE_ISSUER_SIZE) == false)
			{
				if (node.designation != aern_network_designation_ars)
				{
					aern_topology_node_remove(&state->tlist, node.serial);
				}
			}
		}
	}

	aern_topology_list_dispose(&tcopy);
}

void aern_server_topology_remove_certificate(aern_server_application_state* state, const char* issuer)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(issuer != NULL);

	if (state != NULL && issuer != NULL)
	{
		aern_topology_node_state rnode = { 0 };

		if (aern_topology_node_find_issuer(&state->tlist, &rnode, issuer) == true)
		{
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_child_certificate_path_from_issuer(state, fpath, sizeof(fpath), rnode.issuer);

			/* delete the certificate */
			if (qsc_fileutils_exists(fpath) == true)
			{
				qsc_fileutils_delete(fpath);
			}
		}
	}
}

void aern_server_topology_remove_node(aern_server_application_state* state, const char* issuer)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(issuer != NULL);

	if (state != NULL && issuer != NULL)
	{
		aern_topology_node_state rnode = { 0 };

		if (aern_topology_node_find_issuer(&state->tlist, &rnode, issuer) == true)
		{
			/* delete the node from the database */
			aern_topology_node_remove(&state->tlist, rnode.serial);
		}
	}
}

void aern_server_topology_reset(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		aern_topology_list_dispose(&state->tlist);
		server_topology_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}
	}
}

bool aern_server_topology_root_exists(const aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		aern_topology_node_state node = { 0 };

		res = aern_topology_node_find_root(&state->tlist, &node);
	}

	return res;
}

bool aern_server_topology_root_fetch(const aern_server_application_state* state, aern_root_certificate* rcert)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(rcert != NULL);

	bool res;

	res = false;

	if (state != NULL && rcert != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_root(&state->tlist, &node) == true)
		{
			char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

			aern_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = aern_certificate_root_file_to_struct(fpath, rcert);
			}
		}
	}

	return res;
}

void aern_server_topology_to_file(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	size_t tlen;
	qsc_mutex mtx;

	if (state != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		tlen = aern_topology_list_size(&state->tlist);

		if (tlen > 0U)
		{
			uint8_t* ptxt;
			uint8_t* penc;

			ptxt = (uint8_t*)qsc_memutils_malloc(tlen);
			penc = (uint8_t*)qsc_memutils_malloc(tlen + AERN_STORAGE_MAC_SIZE);

			if (penc != NULL && ptxt != NULL)
			{
				char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
				const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_TOPOLOGY_INDEX * SERVER_KEYCHAIN_WIDTH);

				AERN_ASSERT(qsc_memutils_zeroed(pkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				server_topology_path(state, fpath, sizeof(fpath));

				if (qsc_fileutils_exists(fpath) == true)
				{
					qsc_fileutils_delete(fpath);
				}

				qsc_memutils_clear(ptxt, tlen);
				qsc_memutils_clear(penc, tlen + AERN_STORAGE_MAC_SIZE);
				aern_topology_list_serialize(ptxt, &state->tlist);
				aern_crypto_encrypt_stream(penc, pkey, ptxt, tlen);
				qsc_fileutils_copy_stream_to_file(fpath, (const char*)penc, tlen + AERN_STORAGE_MAC_SIZE);

				qsc_memutils_alloc_free(penc);
				qsc_memutils_alloc_free(ptxt);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool aern_server_user_login(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	size_t plen;
	size_t slen;
	bool res;

	res = false;

	if (state != NULL)
	{
		char cmsg[AERN_STORAGE_PASSWORD_MAX] = { 0 };
		char fpath[AERN_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);
		server_load_key_chain(state);

		/* first run */

		if (res == false)
		{
			/* print the intro message */
			aern_menu_print_predefined_message(aern_application_first_login, aern_console_mode_login_message, state->hostname);

			/* get the user name and store in state */

			while (true)
			{
				aern_menu_print_predefined_message(aern_application_choose_name, aern_console_mode_login_message, state->hostname);
				aern_menu_print_prompt(aern_console_mode_login_user, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

				if (slen >= AERN_STORAGE_USERNAME_MIN && slen <= AERN_STORAGE_USERNAME_MAX)
				{
					qsc_stringutils_copy_substring(state->username, AERN_STORAGE_USERNAME_MAX, cmsg, slen);
					break;
				}
			}

			/* get the password and generate the keychain */

			while (true)
			{
				aern_menu_print_predefined_message(aern_application_choose_password, aern_console_mode_login_message, state->hostname);
				aern_menu_print_prompt(aern_console_mode_login_password, state->hostname);
				qsc_stringutils_clear_string(cmsg);
				plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

				if (aern_crypto_password_minimum_check(cmsg, plen) == true)
				{
					break;
				}
			}

			server_initialize_key_chain(state, cmsg, plen, state->username, slen);
			aern_menu_print_predefined_message(aern_application_password_set, aern_console_mode_login_message, state->hostname);

			if (aern_logger_exists(state->logpath) == false)
			{
				aern_server_log_host(state);
			}

			/* get the device name and store in state */

			while (true)
			{
				aern_menu_print_predefined_message(aern_application_challenge_device_name, aern_console_mode_login_message, state->hostname);
				aern_menu_print_prompt(aern_console_mode_login_hostname, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

				if (slen >= AERN_STORAGE_DEVICENAME_MIN && slen <= AERN_STORAGE_DEVICENAME_MAX)
				{
					qsc_stringutils_clear_substring(state->hostname, AERN_STORAGE_USERNAME_MAX);
					qsc_stringutils_copy_substring(state->hostname, AERN_STORAGE_USERNAME_MAX, cmsg, slen);
					break;
				}
			}

#if defined(AERN_SERVER_IP_CHANGE_DIALOG)
			/* conditionally change the servers local ip address */

			aern_menu_print_predefined_text(aern_application_address_change_current, aern_console_mode_login_message, state->hostname);
			aern_menu_print_text_line(state->localip);
			res = aern_menu_print_predefined_message_confirm(aern_application_address_change_challenge, aern_console_mode_login_message, state->hostname);

			if (res == true)
			{
				while (true)
				{
					aern_menu_print_predefined_message(aern_application_address_change_message, aern_console_mode_login_message, state->hostname);
					aern_menu_print_prompt(aern_console_mode_login_address, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= AERN_STORAGE_ADDRESS_MIN && slen <= AERN_STORAGE_ADDRESS_MAX)
					{
						res = aern_server_set_ip_address(state, cmsg, slen);

						if (res == true)
						{
							aern_menu_print_predefined_message(aern_application_address_change_success, aern_console_mode_login_message, state->hostname);
							break;
						}
						else
						{
							aern_menu_print_predefined_message(aern_application_address_change_failure, aern_console_mode_login_message, state->hostname);
						}
					}
				}
			}
#endif

			/* conditionally change the servers domain name */

			aern_menu_print_predefined_text(aern_application_server_domain_change_current, aern_console_mode_login_message, state->hostname);
			aern_menu_print_text_line(state->domain);
			res = aern_menu_print_predefined_message_confirm(aern_application_server_domain_change_challenge, aern_console_mode_login_message, state->hostname);

			if (res == true)
			{
				while (true)
				{
					aern_menu_print_prompt(aern_console_mode_login_domain, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= AERN_STORAGE_DOMAINNAME_MIN && slen <= AERN_STORAGE_DOMAINNAME_MAX)
					{
						res = aern_server_set_domain_name(state, cmsg, slen);

						if (res == true)
						{
							aern_menu_print_predefined_message(aern_application_server_domain_change_success, aern_console_mode_login_message, state->hostname);
							break;
						}
						else
						{
							aern_menu_print_predefined_message(aern_application_server_domain_change_failure, aern_console_mode_login_message, state->hostname);
						}
					}
				}
			}
			else
			{
				/* set the default issuer */
				if (state->srvtype == aern_network_designation_ars)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}
			}

			if (state->srvtype != aern_network_designation_ars)
			{
				while (true)
				{
					aern_menu_print_predefined_message(aern_application_challenge_root_path, aern_console_mode_login_message, state->hostname);
					aern_menu_print_prompt(aern_console_mode_login_rootpath, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

					if (slen >= AERN_STORAGE_FILEPATH_MIN &&
						slen <= AERN_STORAGE_FILEPATH_MAX &&
						qsc_fileutils_exists(cmsg) == true &&
						qsc_stringutils_string_contains(cmsg, AERN_CERTIFICATE_ROOT_EXTENSION))
					{
						if (aern_certificate_root_file_to_struct(cmsg, &state->root) == true)
						{
							aern_server_root_certificate_store(state, &state->root);
							aern_menu_print_predefined_message(aern_application_challenge_root_path_success, aern_console_mode_login_message, state->hostname);

							break;
						}
						else
						{
							aern_menu_print_predefined_message(aern_application_challenge_root_path_failure, aern_console_mode_login_message, state->hostname);
						}
					}
					else
					{
						aern_menu_print_predefined_message(aern_application_challenge_root_path_failure, aern_console_mode_login_message, state->hostname);
					}
				}
			}

			/* store the state to file */
			res = aern_server_state_store(state);

			if (state->loghost == true)
			{
				slen = qsc_stringutils_string_size(state->username);
				aern_server_log_write_message(state, aern_application_log_user_added, state->username, slen);
			}
		}
		else
		{
			/* password was set */
			size_t rctr;

			res = false;
			slen = 0U;
			rctr = 0U;

			while (true)
			{
				if (rctr >= state->retries)
				{
					break;
				}

				++rctr;
				aern_menu_print_predefined_message(aern_application_challenge_user, aern_console_mode_login_message, state->hostname);
				aern_menu_print_prompt(aern_console_mode_login_user, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

				if (slen >= AERN_STORAGE_USERNAME_MIN && slen <= AERN_STORAGE_USERNAME_MAX)
				{
					qsc_memutils_copy(state->username, cmsg, slen);
					res = true;
					break;
				}
				else
				{
					qsc_memutils_clear(cmsg, sizeof(cmsg));
					aern_menu_print_predefined_message(aern_application_challenge_user_failure, aern_console_mode_login_user, state->hostname);
				}
			}

			if (res == true)
			{
				rctr = 0U;

				while (true)
				{
					qsc_stringutils_clear_string(cmsg);

					if (rctr >= state->retries)
					{
						res = false;
						break;
					}

					++rctr;
					aern_menu_print_predefined_message(aern_application_challenge_password, aern_console_mode_login_message, state->hostname);
					aern_menu_print_prompt(aern_console_mode_login_password, state->hostname);
					plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

					if (plen >= AERN_STORAGE_PASSWORD_MIN && plen <= AERN_STORAGE_PASSWORD_MAX)
					{
						/* load the key chain */
						server_initialize_key_chain(state, cmsg, plen, state->username, slen);
						/* decrypt the state file and load into memory */
						res = server_state_load(state);

						if (res == true)
						{
							if (state->loghost == true)
							{
								slen = qsc_stringutils_string_size(state->username);
								aern_server_log_write_message(state, aern_application_log_user_logged_in, state->username, slen);
							}

							break;
						}
						else
						{
							qsc_memutils_clear(state->kchain, SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
							aern_menu_print_predefined_message(aern_application_challenge_password_failure, aern_console_mode_login_message, state->hostname);
						}
					}
					else
					{
						aern_menu_print_predefined_message(aern_application_challenge_password_failure, aern_console_mode_login_message, state->hostname);
					}
				}
			}
		}
	}

	return res;
}

void aern_server_user_logout(aern_server_application_state* state)
{
	AERN_ASSERT(state != NULL);

	if (state != NULL)
	{
		server_unload_key_chain(state);
		qsc_memutils_clear(state->username, AERN_STORAGE_USERNAME_MAX);
		state->mode = aern_console_mode_user;
	}
}

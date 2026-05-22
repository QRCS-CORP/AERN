#include "client_test.h"
#include "aern.h"
#include "aern_utils.h"
#include "certificate.h"
#include "client.h"
#include "mek.h"
#include "memutils.h"
#include "stringutils.h"
#include "topology.h"

#define AERNTEST_CLIENT_APS_COUNT 3U

typedef struct aerntest_client_package
{
	aern_signature_keypair rootkp;
	aern_signature_keypair clientkp;
	aern_signature_keypair adckp;
	aern_signature_keypair apskp[AERNTEST_CLIENT_APS_COUNT];
	aern_root_certificate root;
	aern_child_certificate client;
	aern_child_certificate adc;
	aern_child_certificate aps[AERNTEST_CLIENT_APS_COUNT];
	aern_topology_list_state topology;
	aern_cipher_table ctable;
	uint8_t clientsig[AERN_ASYMMETRIC_SIGNING_KEY_SIZE];
} aerntest_client_package;

static void aerntest_client_serial_set(uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], uint8_t value)
{
	AERN_ASSERT(serial != NULL);

	if (serial != NULL)
	{
		qsc_memutils_clear(serial, AERN_CERTIFICATE_SERIAL_SIZE);
		serial[0U] = value;
	}
}

static void aerntest_client_address_set(char address[AERN_CERTIFICATE_ADDRESS_SIZE], uint8_t index)
{
	AERN_ASSERT(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address, AERN_CERTIFICATE_ADDRESS_SIZE);
		address[0U] = '1';
		address[1U] = '9';
		address[2U] = '2';
		address[3U] = '.';
		address[4U] = '1';
		address[5U] = '6';
		address[6U] = '8';
		address[7U] = '.';
		address[8U] = '2';
		address[9U] = '.';
		address[10U] = (char)('1' + index);
	}
}

static void aerntest_client_package_dispose(aerntest_client_package* pkg)
{
	AERN_ASSERT(pkg != NULL);

	if (pkg != NULL)
	{
		aern_cipher_table_dispose(&pkg->ctable);
		aern_topology_list_dispose(&pkg->topology);
		qsc_memutils_clear(pkg, sizeof(aerntest_client_package));
	}
}

static void aerntest_client_package_initialize(aerntest_client_package* pkg)
{
	AERN_ASSERT(pkg != NULL);

	aern_certificate_expiration exp = { 0 };
	char adcaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	char apsaddr[AERNTEST_CLIENT_APS_COUNT][AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	char rootaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	size_t pos;

	if (pkg != NULL)
	{
		qsc_memutils_clear(pkg, sizeof(aerntest_client_package));
		aern_topology_list_initialize(&pkg->topology);
		aern_cipher_table_initialize(&pkg->ctable);
		aern_certificate_expiration_set_days(&exp, 0U, 365U);

		aern_certificate_signature_generate_keypair(&pkg->rootkp);
		aern_certificate_root_create(&pkg->root, pkg->rootkp.pubkey, &exp, "XYZ_ARS1");
		aerntest_client_serial_set(pkg->root.serial, 1U);

		aern_certificate_signature_generate_keypair(&pkg->adckp);
		aern_certificate_child_create(&pkg->adc, pkg->adckp.pubkey, &exp, "XYZ_ADC1", aern_network_designation_adc);
		aerntest_client_serial_set(pkg->adc.serial, 2U);
		(void)aern_certificate_root_sign(&pkg->adc, &pkg->root, pkg->rootkp.prikey);

		aern_certificate_signature_generate_keypair(&pkg->clientkp);
		aern_certificate_child_create(&pkg->client, pkg->clientkp.pubkey, &exp, "XYZ_ACD1", aern_network_designation_client);
		aerntest_client_serial_set(pkg->client.serial, 3U);
		(void)aern_certificate_root_sign(&pkg->client, &pkg->root, pkg->rootkp.prikey);
		qsc_memutils_copy(pkg->clientsig, pkg->clientkp.prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);

		for (pos = 0U; pos < AERNTEST_CLIENT_APS_COUNT; ++pos)
		{
			char issuer[AERN_CERTIFICATE_ISSUER_SIZE] = { 0 };

			qsc_stringutils_copy_string(issuer, sizeof(issuer), "XYZ_APS");
			issuer[7U] = (char)('1' + pos);
			aern_certificate_signature_generate_keypair(&pkg->apskp[pos]);
			aern_certificate_child_create(&pkg->aps[pos], pkg->apskp[pos].pubkey, &exp, issuer, aern_network_designation_aps);
			aerntest_client_serial_set(pkg->aps[pos].serial, (uint8_t)(10U + pos));
			(void)aern_certificate_root_sign(&pkg->aps[pos], &pkg->root, pkg->rootkp.prikey);
			aerntest_client_address_set(apsaddr[pos], (uint8_t)pos);
		}

		qsc_stringutils_copy_string(rootaddr, sizeof(rootaddr), "192.168.2.1");
		qsc_stringutils_copy_string(adcaddr, sizeof(adcaddr), "192.168.2.2");

		aern_topology_root_register(&pkg->topology, &pkg->root, rootaddr);
		aern_topology_child_register(&pkg->topology, &pkg->adc, adcaddr);
		aern_topology_child_register(&pkg->topology, &pkg->aps[2U], apsaddr[2U]);
		aern_topology_child_register(&pkg->topology, &pkg->aps[0U], apsaddr[0U]);
		aern_topology_child_register(&pkg->topology, &pkg->aps[1U], apsaddr[1U]);
	}
}

static bool aerntest_client_add_entry_tunnel(aerntest_client_package* pkg, size_t index, aern_network_flags exflag, aern_mesh_peer_status status, bool rekeypending)
{
	AERN_ASSERT(pkg != NULL);

	aern_connection_state cns = { 0 };
	aern_topology_node_state node = { 0 };
	aern_protocol_errors merr;
	bool res;

	res = false;

	if (pkg != NULL && index < AERNTEST_CLIENT_APS_COUNT)
	{
		if (aern_topology_node_find(&pkg->topology, &node, pkg->aps[index].serial) == true)
		{
			qsc_memutils_clear(&cns, sizeof(cns));
			cns.exflag = exflag;
			cns.instance = (uint32_t)(index + 1U);
			merr = aern_cipher_table_add_peer(&pkg->ctable, node.address, node.serial, &cns, status);

			if (merr == aern_protocol_error_none)
			{
				pkg->ctable.slots[0U].rekeypending = rekeypending;
				res = true;
			}
		}
	}

	return res;
}

static bool aerntest_client_entry_context_valid_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_session_established, aern_mesh_peer_status_synchronized, false) == true)
	{
		res = aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &pkg.aps[0U], &pkg.ctable);
	}

	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_keypair_and_certificate_generation_test(void)
{
	aerntest_client_package pkg = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = (aern_certificate_child_is_valid(&pkg.client) == true);
	res = (res == true && pkg.client.designation == aern_network_designation_client);
	res = (res == true && aern_certificate_root_signature_verify(&pkg.client, &pkg.root) == true);
	res = (res == true && qsc_memutils_zeroed(pkg.clientsig, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);
	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_topology_hash_match_and_mismatch_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_list_state clone = { 0 };
	uint8_t hash1[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	uint8_t hash2[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	char apsaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	bool res;

	res = false;
	aerntest_client_package_initialize(&pkg);
	aern_topology_list_initialize(&clone);

	aern_topology_list_clone(&pkg.topology, &clone);

	if (clone.count == pkg.topology.count)
	{
		aern_topology_hash(&pkg.topology, hash1);
		aern_topology_hash(&clone, hash2);
		res = qsc_memutils_are_equal(hash1, hash2, AERN_CERTIFICATE_HASH_SIZE);

		if (res == true)
		{
			aern_topology_node_state node = { 0 };

			if (aern_topology_node_find(&clone, &node, pkg.aps[0U].serial) == true)
			{
				aerntest_client_address_set(apsaddr, 9U);
				qsc_stringutils_copy_string(node.address, AERN_CERTIFICATE_ADDRESS_SIZE, apsaddr);
				aern_topology_node_remove(&clone, node.serial);
				(void)aern_topology_child_add_item(&clone, &node);
				aern_topology_hash(&clone, hash2);
				res = (qsc_memutils_are_equal(hash1, hash2, AERN_CERTIFICATE_HASH_SIZE) == false);
			}
			else
			{
				res = false;
			}
		}
	}

	aern_topology_list_dispose(&clone);
	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_topology_flush_and_replacement_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_list_state repl = { 0 };
	aern_topology_node_state entry = { 0 };
	char apsaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	bool res;

	res = false;
	aerntest_client_package_initialize(&pkg);
	aern_topology_list_initialize(&repl);
	aerntest_client_address_set(apsaddr, 0U);

	aern_topology_child_register(&repl, &pkg.aps[0U], apsaddr);

	if (repl.count == 1U)
	{
		aern_topology_list_dispose(&pkg.topology);
		aern_topology_list_initialize(&pkg.topology);
		aern_topology_list_clone(&repl, &pkg.topology);
		res = (pkg.topology.count == 1U);
		res = (res == true && aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true);
		res = (res == true && aern_topology_node_find(&pkg.topology, &entry, pkg.aps[1U].serial) == false);
	}

	aern_topology_list_dispose(&repl);
	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_entry_context_missing_tunnel_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true)
	{
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &pkg.aps[0U], &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_entry_context_failed_tunnel_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_transfer_request, aern_mesh_peer_status_failed, false) == true)
	{
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &pkg.aps[0U], &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_entry_context_rekey_pending_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_session_established, aern_mesh_peer_status_synchronized, true) == true)
	{
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &pkg.aps[0U], &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_entry_context_stale_certificate_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	aern_child_certificate stale = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_session_established, aern_mesh_peer_status_synchronized, false) == true)
	{
		aern_certificate_child_copy(&stale, &pkg.aps[0U]);
		stale.serial[0U] ^= 0x55U;
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &stale, &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);
	qsc_memutils_clear(&stale, sizeof(stale));

	return res;
}


static bool aerntest_client_entry_context_revoked_topology_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_session_established, aern_mesh_peer_status_synchronized, false) == true)
	{
		aern_topology_node_remove(&pkg.topology, pkg.aps[0U].serial);
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &pkg.aps[0U], &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);

	return res;
}

static bool aerntest_client_entry_context_wrong_designation_reject_test(void)
{
	aerntest_client_package pkg = { 0 };
	aern_topology_node_state entry = { 0 };
	aern_child_certificate wrong = { 0 };
	bool res;

	aerntest_client_package_initialize(&pkg);
	res = false;

	if (aern_topology_node_find(&pkg.topology, &entry, pkg.aps[0U].serial) == true &&
		aerntest_client_add_entry_tunnel(&pkg, 0U, aern_network_flag_tunnel_session_established, aern_mesh_peer_status_synchronized, false) == true)
	{
		aern_certificate_child_copy(&wrong, &pkg.aps[0U]);
		wrong.designation = aern_network_designation_client;
		res = (aern_client_entry_context_is_valid(&pkg.root, &pkg.client, &pkg.topology, &entry, &wrong, &pkg.ctable) == false);
	}

	aerntest_client_package_dispose(&pkg);
	qsc_memutils_clear(&wrong, sizeof(wrong));

	return res;
}

bool aerntest_client_run(void)
{
	bool res;

	res = true;

	if (aerntest_client_keypair_and_certificate_generation_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client keypair and certificate generation.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client keypair and certificate generation.");
		res = false;
	}

	if (aerntest_client_topology_hash_match_and_mismatch_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client topology hash match and mismatch.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client topology hash match and mismatch.");
		res = false;
	}

	if (aerntest_client_topology_flush_and_replacement_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client topology flush and replacement.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client topology flush and replacement.");
		res = false;
	}

	if (aerntest_client_entry_context_valid_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client entry context valid.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client entry context valid.");
		res = false;
	}

	if (aerntest_client_entry_context_missing_tunnel_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client missing entry tunnel rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client missing entry tunnel rejection.");
		res = false;
	}

	if (aerntest_client_entry_context_failed_tunnel_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client failed entry tunnel rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client failed entry tunnel rejection.");
		res = false;
	}

	if (aerntest_client_entry_context_rekey_pending_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client pending rekey rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client pending rekey rejection.");
		res = false;
	}

	if (aerntest_client_entry_context_stale_certificate_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client stale entry certificate rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client stale entry certificate rejection.");
		res = false;
	}

	if (aerntest_client_entry_context_revoked_topology_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client revoked topology entry rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client revoked topology entry rejection.");
		res = false;
	}

	if (aerntest_client_entry_context_wrong_designation_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN Client wrong entry designation rejection.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN Client wrong entry designation rejection.");
		res = false;
	}

	return res;
}

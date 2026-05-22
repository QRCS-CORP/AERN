#include "aps_test.h"
#include "aern_utils.h"
#include "certificate.h"
#include "mek.h"
#include "memutils.h"
#include "stringutils.h"
#include "topology.h"

#include <stdint.h>

#define AERNTEST_APS_COUNT 4U
#define AERNTEST_NODE_COUNT (AERNTEST_APS_COUNT + 2U)

typedef struct aerntest_aps_package
{
	aern_signature_keypair rootkp;
	aern_signature_keypair adckp;
	aern_signature_keypair apskp[AERNTEST_APS_COUNT];
	aern_root_certificate root;
	aern_child_certificate adc;
	aern_child_certificate aps[AERNTEST_APS_COUNT];
	aern_topology_list_state topology;
	aern_cipher_table ctable;
	uint8_t adcsig[AERN_ASYMMETRIC_SIGNING_KEY_SIZE];
	uint8_t apssig[AERNTEST_APS_COUNT][AERN_ASYMMETRIC_SIGNING_KEY_SIZE];
} aerntest_aps_package;

static void aerntest_aps_serial_set(uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], uint8_t value)
{
	AERN_ASSERT(serial != NULL);

	if (serial != NULL)
	{
		qsc_memutils_clear(serial, AERN_CERTIFICATE_SERIAL_SIZE);
		serial[0U] = value;
	}
}

static void aerntest_aps_address_set(char address[AERN_CERTIFICATE_ADDRESS_SIZE], uint8_t index)
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
		address[8U] = '1';
		address[9U] = '.';
		address[10U] = (char)('1' + index);
	}
}

static bool aerntest_aps_node_certificate_match(const aern_topology_node_state* node, const aern_child_certificate* cert, const aern_root_certificate* root)
{
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(cert != NULL);
	AERN_ASSERT(root != NULL);

	uint8_t chash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (node != NULL && cert != NULL && root != NULL)
	{
		if (node->designation == aern_network_designation_aps &&
			cert->designation == aern_network_designation_aps &&
			aern_certificate_child_is_valid(cert) == true &&
			aern_certificate_root_signature_verify(cert, root) == true)
		{
			aern_certificate_child_hash(chash, cert);

			res = qsc_memutils_are_equal(node->chash, chash, AERN_CERTIFICATE_HASH_SIZE);
			res = (res == true && qsc_memutils_are_equal(node->serial, cert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true);
			res = (res == true && qsc_stringutils_strings_equal(node->issuer, cert->issuer) == true);
			res = (res == true && node->expiration.from == cert->expiration.from);
			res = (res == true && node->expiration.to == cert->expiration.to);
		}
	}

	return res;
}

static void aerntest_aps_package_dispose(aerntest_aps_package* pkg)
{
	AERN_ASSERT(pkg != NULL);

	if (pkg != NULL)
	{
		aern_cipher_table_dispose(&pkg->ctable);
		aern_topology_list_dispose(&pkg->topology);
		qsc_memutils_clear(pkg, sizeof(aerntest_aps_package));
	}
}

static void aerntest_aps_package_initialize(aerntest_aps_package* pkg)
{
	AERN_ASSERT(pkg != NULL);

	aern_certificate_expiration exp = { 0 };
	char adcaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	char apsaddr[AERNTEST_APS_COUNT][AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	char rootaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	size_t pos;

	if (pkg != NULL)
	{
		qsc_memutils_clear(pkg, sizeof(aerntest_aps_package));
		aern_topology_list_initialize(&pkg->topology);
		aern_cipher_table_initialize(&pkg->ctable);
		aern_certificate_expiration_set_days(&exp, 0U, 365U);

		aern_certificate_signature_generate_keypair(&pkg->rootkp);
		aern_certificate_root_create(&pkg->root, pkg->rootkp.pubkey, &exp, "XYZ_ARS1");
		aerntest_aps_serial_set(pkg->root.serial, 1U);

		aern_certificate_signature_generate_keypair(&pkg->adckp);
		aern_certificate_child_create(&pkg->adc, pkg->adckp.pubkey, &exp, "XYZ_ADC1", aern_network_designation_adc);
		aerntest_aps_serial_set(pkg->adc.serial, 2U);
		(void)aern_certificate_root_sign(&pkg->adc, &pkg->root, pkg->rootkp.prikey);
		qsc_memutils_copy(pkg->adcsig, pkg->adckp.prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);

		for (pos = 0U; pos < AERNTEST_APS_COUNT; ++pos)
		{
			char issuer[AERN_CERTIFICATE_ISSUER_SIZE] = { 0 };

			qsc_stringutils_copy_string(issuer, sizeof(issuer), "XYZ_APS");
			issuer[7U] = (char)('1' + pos);
			aern_certificate_signature_generate_keypair(&pkg->apskp[pos]);
			aern_certificate_child_create(&pkg->aps[pos], pkg->apskp[pos].pubkey, &exp, issuer, aern_network_designation_aps);
			aerntest_aps_serial_set(pkg->aps[pos].serial, (uint8_t)(10U + pos));
			(void)aern_certificate_root_sign(&pkg->aps[pos], &pkg->root, pkg->rootkp.prikey);
			qsc_memutils_copy(pkg->apssig[pos], pkg->apskp[pos].prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
			aerntest_aps_address_set(apsaddr[pos], (uint8_t)pos);
		}

		qsc_stringutils_copy_string(rootaddr, sizeof(rootaddr), "192.168.1.1");
		qsc_stringutils_copy_string(adcaddr, sizeof(adcaddr), "192.168.1.2");

		aern_topology_root_register(&pkg->topology, &pkg->root, rootaddr);
		aern_topology_child_register(&pkg->topology, &pkg->adc, adcaddr);
		aern_topology_child_register(&pkg->topology, &pkg->aps[2U], apsaddr[2U]);
		aern_topology_child_register(&pkg->topology, &pkg->aps[0U], apsaddr[0U]);
		aern_topology_child_register(&pkg->topology, &pkg->aps[3U], apsaddr[3U]);
		aern_topology_child_register(&pkg->topology, &pkg->aps[1U], apsaddr[1U]);
	}
}

static bool aerntest_aps_peer_cache_is_valid(const aerntest_aps_package* pkg, size_t local)
{
	AERN_ASSERT(pkg != NULL);

	aern_topology_node_state node = { 0 };
	size_t pos;
	bool res;

	res = false;

	if (pkg != NULL && local < AERNTEST_APS_COUNT)
	{
		res = true;

		for (pos = 0U; pos < AERNTEST_APS_COUNT; ++pos)
		{
			if (pos != local)
			{
				qsc_memutils_clear(&node, sizeof(node));

				if (aern_topology_node_find(&pkg->topology, &node, pkg->aps[pos].serial) == true)
				{
					res = aerntest_aps_node_certificate_match(&node, &pkg->aps[pos], &pkg->root);
				}
				else
				{
					res = false;
				}
			}

			if (res == false)
			{
				break;
			}
		}
	}

	return res;
}


static bool aerntest_aps_cipher_slot_synchronized(const aern_cipher_table* table, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE])
{
	AERN_ASSERT(table != NULL);
	AERN_ASSERT(serial != NULL);

	size_t pos;
	bool res;

	res = false;

	if (table != NULL && serial != NULL)
	{
		for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
		{
			if (table->slots[pos].used == true &&
				qsc_memutils_are_equal(table->slots[pos].serial, serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
			{
				res = (table->slots[pos].status == aern_mesh_peer_status_synchronized);
				break;
			}
		}
	}

	return res;
}

static bool aerntest_aps_mesh_is_synchronized(const aerntest_aps_package* pkg, size_t local)
{
	AERN_ASSERT(pkg != NULL);

	aern_connection_state* cns;
	aern_topology_node_state node = { 0 };
	size_t pos;
	bool res;

	res = false;

	if (pkg != NULL && local < AERNTEST_APS_COUNT)
	{
		res = (aern_certificate_root_is_valid(&pkg->root) == true);
		res = (res == true && aern_certificate_child_is_valid(&pkg->adc) == true);
		res = (res == true && aern_certificate_root_signature_verify(&pkg->adc, &pkg->root) == true);
		res = (res == true && aern_certificate_child_is_valid(&pkg->aps[local]) == true);
		res = (res == true && aern_certificate_root_signature_verify(&pkg->aps[local], &pkg->root) == true);
		res = (res == true && aern_topology_node_verify_issuer(&pkg->topology, &pkg->aps[local], pkg->aps[local].issuer) == true);
		res = (res == true && aern_topology_node_verify_adc(&pkg->topology, &pkg->adc) == true);
		res = (res == true && aerntest_aps_peer_cache_is_valid(pkg, local) == true);
		res = (res == true && pkg->ctable.count == (AERNTEST_APS_COUNT - 1U));

		for (pos = 0U; pos < AERNTEST_APS_COUNT && res == true; ++pos)
		{
			if (pos != local)
			{
				qsc_memutils_clear(&node, sizeof(node));

				if (aern_topology_node_find(&pkg->topology, &node, pkg->aps[pos].serial) == true)
				{
					cns = aern_cipher_table_get_by_serial((aern_cipher_table*)&pkg->ctable, node.serial);
					res = (cns != NULL);
					res = (res == true && cns->exflag == aern_network_flag_tunnel_session_established);
					res = (res == true && aerntest_aps_cipher_slot_synchronized(&pkg->ctable, node.serial) == true);
				}
				else
				{
					res = false;
				}
			}
		}
	}

	return res;
}

static void aerntest_aps_add_peer_tunnel(aerntest_aps_package* pkg, size_t peer, aern_mesh_peer_status status)
{
	AERN_ASSERT(pkg != NULL);

	aern_connection_state cns = { 0 };
	aern_topology_node_state node = { 0 };

	if (pkg != NULL && peer < AERNTEST_APS_COUNT)
	{
		if (aern_topology_node_find(&pkg->topology, &node, pkg->aps[peer].serial) == true)
		{
			cns.exflag = aern_network_flag_tunnel_session_established;
			cns.instance = (uint32_t)(peer + 1U);
			cns.rxseq = 0U;
			cns.txseq = 0U;
			(void)aern_cipher_table_add_peer(&pkg->ctable, node.address, node.serial, &cns, status);
		}
	}
}

static bool aerntest_aps_keypair_and_certificate_generation_test(void)
{
	aern_signature_keypair rkp = { 0 };
	aern_signature_keypair akp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate aps = { 0 };
	aern_certificate_expiration exp = { 0 };
	bool res;

	res = false;
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_signature_generate_keypair(&rkp);
	aern_certificate_root_create(&root, rkp.pubkey, &exp, "XYZ_ARS1");
	aern_certificate_signature_generate_keypair(&akp);
	aern_certificate_child_create(&aps, akp.pubkey, &exp, "XYZ_APS1", aern_network_designation_aps);

	if (aern_certificate_root_sign(&aps, &root, rkp.prikey) != 0U)
	{
		res = (aps.designation == aern_network_designation_aps);
		res = (res == true && qsc_memutils_zeroed(akp.prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);
		res = (res == true && aern_certificate_child_is_valid(&aps) == true);
		res = (res == true && aern_certificate_root_signature_verify(&aps, &root) == true);
		res = (res == true && qsc_memutils_are_equal(aps.rootser, root.serial, AERN_CERTIFICATE_SERIAL_SIZE) == true);
	}

	qsc_memutils_clear(&rkp, sizeof(rkp));
	qsc_memutils_clear(&akp, sizeof(akp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&aps, sizeof(aps));

	return res;
}

static bool aerntest_aps_topology_node_creation_test(void)
{
	aerntest_aps_package pkg = { 0 };
	aern_topology_node_state node = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	res = aern_topology_node_find(&pkg.topology, &node, pkg.aps[0U].serial);
	res = (res == true && node.designation == aern_network_designation_aps);
	res = (res == true && aerntest_aps_node_certificate_match(&node, &pkg.aps[0U], &pkg.root) == true);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_topology_sorted_insertion_test(void)
{
	aerntest_aps_package pkg = { 0 };
	aern_topology_list_state apslist = { 0 };
	aern_topology_node_state node = { 0 };
	char apsaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	size_t pos;
	bool res;

	aerntest_aps_package_initialize(&pkg);
	aern_topology_list_initialize(&apslist);
	aerntest_aps_address_set(apsaddr, 0U);
	aern_topology_child_register(&apslist, &pkg.aps[2U], apsaddr);
	aern_topology_child_register(&apslist, &pkg.aps[0U], apsaddr);
	aern_topology_child_register(&apslist, &pkg.aps[3U], apsaddr);
	aern_topology_child_register(&apslist, &pkg.aps[1U], apsaddr);

	res = (apslist.count == AERNTEST_APS_COUNT);

	for (pos = 0U; pos < AERNTEST_APS_COUNT && res == true; ++pos)
	{
		qsc_memutils_clear(&node, sizeof(node));
		res = aern_topology_list_item(&apslist, &node, pos);
		res = (res == true && node.serial[0U] == (uint8_t)(10U + pos));
	}

	aern_topology_list_dispose(&apslist);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_certificate_cache_coherence_test(void)
{
	aerntest_aps_package pkg = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	res = aerntest_aps_peer_cache_is_valid(&pkg, 0U);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_certificate_hash_mismatch_reject_test(void)
{
	aerntest_aps_package pkg = { 0 };
	aern_topology_node_state node = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	res = aern_topology_node_find(&pkg.topology, &node, pkg.aps[1U].serial);

	if (res == true)
	{
		node.chash[0U] ^= 0x5AU;
		res = (aerntest_aps_node_certificate_match(&node, &pkg.aps[1U], &pkg.root) == false);
	}

	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_full_mesh_synchronized_test(void)
{
	aerntest_aps_package pkg = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	aerntest_aps_add_peer_tunnel(&pkg, 1U, aern_mesh_peer_status_synchronized);
	aerntest_aps_add_peer_tunnel(&pkg, 2U, aern_mesh_peer_status_synchronized);
	aerntest_aps_add_peer_tunnel(&pkg, 3U, aern_mesh_peer_status_synchronized);
	res = aerntest_aps_mesh_is_synchronized(&pkg, 0U);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_missing_peer_tunnel_reject_test(void)
{
	aerntest_aps_package pkg = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	aerntest_aps_add_peer_tunnel(&pkg, 1U, aern_mesh_peer_status_synchronized);
	aerntest_aps_add_peer_tunnel(&pkg, 2U, aern_mesh_peer_status_synchronized);
	res = (aerntest_aps_mesh_is_synchronized(&pkg, 0U) == false);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

static bool aerntest_aps_failed_peer_tunnel_reject_test(void)
{
	aerntest_aps_package pkg = { 0 };
	bool res;

	aerntest_aps_package_initialize(&pkg);
	aerntest_aps_add_peer_tunnel(&pkg, 1U, aern_mesh_peer_status_synchronized);
	aerntest_aps_add_peer_tunnel(&pkg, 2U, aern_mesh_peer_status_failed);
	aerntest_aps_add_peer_tunnel(&pkg, 3U, aern_mesh_peer_status_synchronized);
	res = (pkg.ctable.count == (AERNTEST_APS_COUNT - 1U));
	res = (res == true && pkg.ctable.slots[1U].status == aern_mesh_peer_status_failed);
	res = (res == true && aerntest_aps_mesh_is_synchronized(&pkg, 0U) == false);
	aerntest_aps_package_dispose(&pkg);

	return res;
}

bool aerntest_aps_run(void)
{
	bool res;

	res = true;

	if (aerntest_aps_keypair_and_certificate_generation_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS keypair and certificate generation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS keypair and certificate generation test.");
		res = false;
	}

	if (aerntest_aps_topology_node_creation_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS topology-node creation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS topology-node creation test.");
		res = false;
	}

	if (aerntest_aps_topology_sorted_insertion_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS topology sorted insertion test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS topology sorted insertion test.");
		res = false;
	}

	if (aerntest_aps_certificate_cache_coherence_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS certificate-cache coherence test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS certificate-cache coherence test.");
		res = false;
	}

	if (aerntest_aps_certificate_hash_mismatch_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS certificate-hash mismatch reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS certificate-hash mismatch reject test.");
		res = false;
	}

	if (aerntest_aps_full_mesh_synchronized_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS full-mesh synchronized-state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS full-mesh synchronized-state test.");
		res = false;
	}

	if (aerntest_aps_missing_peer_tunnel_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS missing peer tunnel reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS missing peer tunnel reject test.");
		res = false;
	}

	if (aerntest_aps_failed_peer_tunnel_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN APS failed peer tunnel reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN APS failed peer tunnel reject test.");
		res = false;
	}

	return res;
}

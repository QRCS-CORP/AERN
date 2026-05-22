#include "topology_test.h"
#include "aern_utils.h"
#include "topology.h"
#include "certificate.h"
#include "acp.h"
#include "memutils.h"
#include "stringutils.h"
#include "intutils.h"

typedef struct aerntest_topology_device_package
{
	aern_signature_keypair akp;
	aern_signature_keypair ckp;
	aern_signature_keypair dkp;
	aern_signature_keypair mkp;
	aern_signature_keypair rkp;
	aern_child_certificate acrt;
	aern_child_certificate ccrt;
	aern_child_certificate dcrt;
	aern_child_certificate mcrt;
	aern_root_certificate root;
	aern_topology_node_state ande;
	aern_topology_node_state and2;
	aern_topology_node_state and3;
	aern_topology_node_state and4;
	aern_topology_node_state and5;
	aern_topology_node_state and6;
	aern_topology_node_state and7;
	aern_topology_node_state and8;
	aern_topology_node_state cnde;
	aern_topology_node_state dnde;
	aern_topology_node_state mnde;
	aern_topology_list_state list;
} aerntest_topology_device_package;

static void aerntest_topology_load_child_node(aern_topology_list_state* list, aern_topology_node_state* node, const aern_child_certificate* ccert)
{
	char ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { (char)192, (char)168, (char)1 };

	qsc_acp_generate((uint8_t*)ipa + 3U, 1U);
	aern_topology_child_register(list, ccert, ipa);
	aern_topology_node_find(list, node, (const uint8_t*)ccert->serial);
}

static void aerntest_topology_device_destroy(aerntest_topology_device_package* spkg)
{
	aern_topology_list_dispose(&spkg->list);
}

static void aerntest_topology_device_instantiate(aerntest_topology_device_package* spkg)
{
	aern_certificate_expiration exp = { 0 };

	aern_topology_list_initialize(&spkg->list);

	/* generate the root certificate */
	aern_certificate_signature_generate_keypair(&spkg->rkp);
	aern_certificate_expiration_set_days(&exp, 0U, 30U);
	aern_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ/ARS-1:rds1.xyz.com");
	
	/* create the aps responder */
	aern_certificate_signature_generate_keypair(&spkg->akp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-1:aps1.xyz.com", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);
	aerntest_topology_load_child_node(&spkg->list, &spkg->ande, &spkg->acrt);

	/* aps copies for list test */
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-2:aps2.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and2, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-3:aps3.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and3, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-4:aps4.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and4, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-5:aps5.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and5, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-6:aps6.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and6, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-7:aps7.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and7, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-8:aps8.xyz.com", aern_network_designation_aps);
	aerntest_topology_load_child_node(&spkg->list, &spkg->and8, &spkg->acrt);

	/* create a client */
	aern_certificate_signature_generate_keypair(&spkg->ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ/Client-1:client1.xyz.com", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	aerntest_topology_load_child_node(&spkg->list, &spkg->cnde, &spkg->ccrt);

	/* create the ads */
	aern_certificate_signature_generate_keypair(&spkg->dkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ/ADC-1:ads1.xyz.com", aern_network_designation_adc);
	aern_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	aerntest_topology_load_child_node(&spkg->list, &spkg->dnde, &spkg->dcrt);

	/* create the ars */
	aern_certificate_signature_generate_keypair(&spkg->mkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->mcrt, spkg->mkp.pubkey, &exp, "XYZ/ARS-1:mas1.xyz.com", aern_network_designation_ars);
	aern_certificate_root_sign(&spkg->mcrt, &spkg->root, spkg->rkp.prikey);
	aerntest_topology_load_child_node(&spkg->list, &spkg->mnde, &spkg->mcrt);
}

static bool aerntest_topology_find_test(aerntest_topology_device_package* spkg)
{
	aern_topology_node_state tand = { 0 };
	aern_topology_node_state tmnd = { 0 };
	bool res;

	res = false;

	if (spkg != NULL)
	{
		/* test find related functions */
		aern_topology_node_find(&spkg->list, &tand, spkg->ande.serial);

		if (aern_topology_nodes_are_equal(&tand, &spkg->ande) == true)
		{
			aern_topology_node_find_alias(&spkg->list, &tmnd, "mas1.xyz.com");

			if (aern_topology_nodes_are_equal(&tmnd, &spkg->mnde) == true)
			{
				aern_topology_node_find_issuer(&spkg->list, &tand, spkg->ande.issuer);

				if (aern_topology_nodes_are_equal(&tand, &spkg->ande) == true)
				{
					aern_topology_node_add_alias(&spkg->cnde, "client.xyz.com");

					if (qsc_stringutils_string_contains(spkg->cnde.issuer, "client.xyz.com") == true)
					{
						res = true;
					}
				}
			}
		}
	}

	return res;
}

static bool aerntest_topology_serialization_test(aerntest_topology_device_package* spkg)
{
	aern_topology_list_state lstc = { 0 };
	aern_topology_node_state itma = { 0 };
	aern_topology_node_state itmb = { 0 };
	size_t i;
	uint8_t* lbuf;
	size_t mlen;
	bool res;
	
	res = false;

	if (spkg != NULL)
	{
		mlen = sizeof(uint32_t) + (spkg->list.count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		lbuf = (uint8_t*)qsc_memutils_malloc(mlen);

		if (lbuf != NULL)
		{
			aern_topology_list_serialize(lbuf, &spkg->list);
			aern_topology_list_initialize(&lstc);
			aern_topology_list_deserialize(&lstc, lbuf, mlen);
			qsc_memutils_alloc_free(lbuf);
			res = true;

			for (i = 0U; i < lstc.count; ++i)
			{
				if (aern_topology_list_item(&lstc, &itma, i) == true)
				{
					if (aern_topology_list_item(&spkg->list, &itmb, i) == true)
					{
						if (aern_topology_nodes_are_equal(&itma, &itmb) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			if (res == true)
			{
				aern_topology_node_state ncpy = { 0 };
				uint8_t nser[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

				for (i = 0U; i < lstc.count; ++i)
				{
					if (aern_topology_list_item(&lstc, &itma, i) == true)
					{
						aern_topology_node_serialize(nser, &itma);
						aern_topology_node_deserialize(&ncpy, nser);

						if (aern_topology_nodes_are_equal(&itma, &ncpy) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			aern_topology_list_dispose(&lstc);
		}
	}

	return res;
}

static bool aerntest_topology_list_is_serial_sorted(const aern_topology_list_state* list)
{
	aern_topology_node_state itma = { 0 };
	aern_topology_node_state itmb = { 0 };
	size_t pos;
	bool res;

	pos = 0U;
	res = false;

	if (list != NULL)
	{
		res = true;

		for (pos = 0U; pos + 1U < list->count; ++pos)
		{
			if (aern_topology_list_item(list, &itma, pos) == false ||
				aern_topology_list_item(list, &itmb, pos + 1U) == false)
			{
				res = false;
				break;
			}

			if (qsc_memutils_greater_than_le128(itma.serial, itmb.serial) == true)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

static bool aerntest_topology_sorted_list_test(aerntest_topology_device_package* spkg)
{
	aern_topology_list_state olst = { 0 };
	aern_topology_node_state itma = { 0 };
	aern_topology_node_state itmb = { 0 };
	size_t acnt;
	size_t ncnt;
	size_t i;
	bool res;

	/* test the count */
	acnt = aern_topology_list_server_count(&spkg->list, aern_network_designation_aps);
	ncnt = aern_topology_ordered_server_list(&olst, &spkg->list, aern_network_designation_aps);

	res = (acnt == ncnt);

	if (res == true)
	{
		/* test the sort */
		for (i = 0U; i + 1U < olst.count; ++i)
		{
			if (aern_topology_list_item(&olst, &itma, i) == false ||
				aern_topology_list_item(&olst, &itmb, i + 1U) == false)
			{
				res = false;
				break;
			}

			if (qsc_memutils_greater_than_le128(itma.serial, itmb.serial) == true)
			{
				res = false;
				break;
			}
		}

		aern_topology_list_dispose(&olst);
	}

	return res;
}

static bool aerntest_topology_enforcement_test(aerntest_topology_device_package* spkg)
{
	aern_topology_node_state adcnode = { 0 };
	aern_topology_node_state apsnode = { 0 };
	aern_topology_list_state list = { 0 };
	aern_protocol_errors merr;
	uint64_t version;
	bool res;

	res = false;
	merr = aern_protocol_error_invalid_request;
	version = 0U;

	if (spkg != NULL)
	{
		if (aern_topology_node_find_adc(&spkg->list, &adcnode) == true && adcnode.designation == aern_network_designation_adc)
		{
			aern_topology_list_initialize(&list);
			version = list.version;
			merr = aern_topology_version_verify(&list, version);

			if (merr != aern_protocol_error_none)
			{
				merr = aern_topology_version_verify(&list, version + 1U);
			}

			if (merr == aern_protocol_error_none)
			{
				aern_topology_add(&list, &spkg->ande);
				aern_topology_remove(&list, spkg->ande.serial);
				res = (aern_topology_node_find(&list, &apsnode, spkg->ande.serial) == false);
			}

			aern_topology_list_dispose(&list);
		}
	}

	return res;
}

static bool aerntest_topology_negative_lookup_test(aerntest_topology_device_package* spkg)
{
	aern_topology_node_state node = { 0 };
	uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };
	bool res;

	res = false;

	if (spkg != NULL)
	{
		serial[0U] = 0xFFU;
		serial[1U] = 0xEEU;

		if (aern_topology_node_find(&spkg->list, &node, serial) == false &&
			aern_topology_node_find_alias(&spkg->list, &node, "missing.xyz.com") == false &&
			aern_topology_node_find_issuer(&spkg->list, &node, "missing.xyz.com") == false)
		{
			res = true;
		}
	}

	return res;
}

static bool aerntest_topology_add_item_sort_regression_test(void)
{
	aern_topology_list_state list = { 0 };
	aern_topology_node_state node = { 0 };
	bool res;

	res = false;
	aern_topology_list_initialize(&list);

	qsc_memutils_clear(&node, sizeof(node));
	qsc_stringutils_copy_string(node.issuer, sizeof(node.issuer), "XYZ/APS-30:aps30.xyz.com");
	node.serial[0U] = 30U;
	node.designation = aern_network_designation_aps;
	aern_topology_child_add_item(&list, &node);

	qsc_memutils_clear(&node, sizeof(node));
	qsc_stringutils_copy_string(node.issuer, sizeof(node.issuer), "XYZ/APS-10:aps10.xyz.com");
	node.serial[0U] = 10U;
	node.designation = aern_network_designation_aps;
	aern_topology_child_add_item(&list, &node);

	qsc_memutils_clear(&node, sizeof(node));
	qsc_stringutils_copy_string(node.issuer, sizeof(node.issuer), "XYZ/APS-20:aps20.xyz.com");
	node.serial[0U] = 20U;
	node.designation = aern_network_designation_aps;
	aern_topology_child_add_item(&list, &node);

	res = (list.count == 3U && aerntest_topology_list_is_serial_sorted(&list) == true);
	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_register_sort_regression_test(aerntest_topology_device_package* spkg)
{
	aern_child_certificate cert = { 0 };
	aern_topology_list_state list = { 0 };
	char ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { 127, 0, 0, 1 };
	bool res;

	res = false;
	aern_topology_list_initialize(&list);

	if (spkg != NULL)
	{
		qsc_memutils_copy(&cert, &spkg->acrt, sizeof(cert));
		qsc_memutils_clear(cert.issuer, sizeof(cert.issuer));
		qsc_stringutils_copy_string(cert.issuer, sizeof(cert.issuer), "XYZ/APS-33:aps33.xyz.com");
		qsc_memutils_clear(cert.serial, sizeof(cert.serial));
		cert.serial[0U] = 33U;
		aern_topology_child_register(&list, &cert, ipa);

		qsc_memutils_copy(&cert, &spkg->acrt, sizeof(cert));
		qsc_memutils_clear(cert.issuer, sizeof(cert.issuer));
		qsc_stringutils_copy_string(cert.issuer, sizeof(cert.issuer), "XYZ/APS-11:aps11.xyz.com");
		qsc_memutils_clear(cert.serial, sizeof(cert.serial));
		cert.serial[0U] = 11U;
		aern_topology_child_register(&list, &cert, ipa);

		qsc_memutils_copy(&cert, &spkg->acrt, sizeof(cert));
		qsc_memutils_clear(cert.issuer, sizeof(cert.issuer));
		qsc_stringutils_copy_string(cert.issuer, sizeof(cert.issuer), "XYZ/APS-22:aps22.xyz.com");
		qsc_memutils_clear(cert.serial, sizeof(cert.serial));
		cert.serial[0U] = 22U;
		aern_topology_child_register(&list, &cert, ipa);

		res = (list.count == 3U && aerntest_topology_list_is_serial_sorted(&list) == true);
	}

	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_clone_sort_regression_test(aerntest_topology_device_package* spkg)
{
	aern_topology_list_state copy = { 0 };
	bool res;

	res = false;
	aern_topology_list_initialize(&copy);

	if (spkg != NULL)
	{
		aern_topology_list_clone(&spkg->list, &copy);
		res = (copy.count == spkg->list.count && aerntest_topology_list_is_serial_sorted(&copy) == true);
	}

	aern_topology_list_dispose(&copy);

	return res;
}

static bool aerntest_topology_duplicate_register_test(aerntest_topology_device_package* spkg)
{
	aern_topology_node_state node = { 0 };
	char ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { 10, 20, 30, 40 };
	size_t count;
	bool res;

	count = 0U;
	res = false;

	if (spkg != NULL)
	{
		count = spkg->list.count;
		aern_topology_child_register(&spkg->list, &spkg->acrt, ipa);

		if (spkg->list.count == count &&
			aern_topology_node_find(&spkg->list, &node, spkg->acrt.serial) == true &&
			qsc_memutils_are_equal((const uint8_t*)node.address, (const uint8_t*)ipa, AERN_CERTIFICATE_ADDRESS_SIZE) == true)
		{
			res = true;
		}
	}

	return res;
}

static void aerntest_topology_make_node(aern_topology_node_state* node, uint8_t serial, const char* issuer, aern_network_designations designation)
{
	qsc_memutils_clear(node, sizeof(aern_topology_node_state));
	qsc_stringutils_copy_string(node->issuer, sizeof(node->issuer), issuer);
	node->serial[0U] = serial;
	node->address[0U] = (char)10;
	node->address[1U] = (char)0;
	node->address[2U] = (char)0;
	node->address[3U] = (char)serial;
	node->expiration.from = 1U;
	node->expiration.to = 2U;
	node->designation = designation;
}

static bool aerntest_topology_duplicate_serial_reject_test(void)
{
	aern_topology_list_state list = { 0 };
	aern_topology_node_state node = { 0 };
	aern_topology_node_state found = { 0 };
	bool res;

	res = false;
	aern_topology_list_initialize(&list);

	aerntest_topology_make_node(&node, 7U, "XYZ/APS-7:aps7.xyz.com", aern_network_designation_aps);
	aern_topology_child_add_item(&list, &node);
	aerntest_topology_make_node(&node, 7U, "XYZ/APS-8:aps8.xyz.com", aern_network_designation_aps);
	aern_topology_child_add_item(&list, &node);

	res = (list.count == 1U && aern_topology_node_find_issuer(&list, &found, "XYZ/APS-8:aps8.xyz.com") == false);
	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_remove_order_test(void)
{
	aern_topology_list_state list = { 0 };
	aern_topology_node_state node = { 0 };
	aern_topology_node_state item = { 0 };
	bool res;

	res = false;
	aern_topology_list_initialize(&list);

	aerntest_topology_make_node(&node, 10U, "XYZ/APS-10:aps10.xyz.com", aern_network_designation_aps);
	aern_topology_child_add_item(&list, &node);
	aerntest_topology_make_node(&node, 20U, "XYZ/APS-20:aps20.xyz.com", aern_network_designation_aps);
	aern_topology_child_add_item(&list, &node);
	aerntest_topology_make_node(&node, 30U, "XYZ/APS-30:aps30.xyz.com", aern_network_designation_aps);
	aern_topology_child_add_item(&list, &node);

	node.serial[0U] = 20U;
	aern_topology_node_remove(&list, node.serial);

	if (list.count == 2U && aerntest_topology_list_is_serial_sorted(&list) == true &&
		aern_topology_list_item(&list, &item, 0U) == true && item.serial[0U] == 10U &&
		aern_topology_list_item(&list, &item, 1U) == true && item.serial[0U] == 30U)
	{
		res = true;
	}

	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_address_full_compare_test(void)
{
	aern_topology_list_state list = { 0 };
	aern_topology_node_state node = { 0 };
	aern_topology_node_state found = { 0 };
	char addr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
	size_t i;
	bool res;

	res = false;
	aern_topology_list_initialize(&list);

	aerntest_topology_make_node(&node, 1U, "XYZ/APS-1:aps1.xyz.com", aern_network_designation_aps);
	for (i = 0U; i < AERN_CERTIFICATE_ADDRESS_SIZE; ++i)
	{
		node.address[i] = (char)i;
	}
	aern_topology_child_add_item(&list, &node);

	aerntest_topology_make_node(&node, 2U, "XYZ/APS-2:aps2.xyz.com", aern_network_designation_aps);
	for (i = 0U; i < AERN_CERTIFICATE_ADDRESS_SIZE; ++i)
	{
		node.address[i] = (char)i;
		addr[i] = (char)i;
	}
	node.address[AERN_CERTIFICATE_ADDRESS_SIZE - 1U] = (char)0x7EU;
	addr[AERN_CERTIFICATE_ADDRESS_SIZE - 1U] = (char)0x7EU;
	aern_topology_child_add_item(&list, &node);

	res = (aern_topology_node_find_address(&list, &found, addr) == true && found.serial[0U] == 2U);
	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_deserialize_bounds_test(void)
{
	aern_topology_list_state list = { 0 };
	aern_topology_node_state node = { 0 };
	uint8_t enc[sizeof(uint32_t) + AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	bool res;

	res = false;
	aern_topology_list_initialize(&list);
	aerntest_topology_make_node(&node, 1U, "XYZ/APS-1:aps1.xyz.com", aern_network_designation_aps);
	qsc_intutils_le32to8(enc, 1U);
	aern_topology_node_serialize(enc + sizeof(uint32_t), &node);
	aern_topology_list_deserialize(&list, enc, sizeof(enc) - 1U);
	res = (list.count == 0U);
	aern_topology_list_dispose(&list);

	return res;
}

static bool aerntest_topology_find_aps_test(aerntest_topology_device_package* spkg)
{
	aern_topology_node_state node = { 0 };
	bool res;

	res = false;

	if (spkg != NULL)
	{
		res = (aern_topology_node_find_aps(&spkg->list, &node) == true && node.designation == aern_network_designation_aps);
	}

	return res;
}

bool aerntest_topology_run(void)
{
	aerntest_topology_device_package spkg = { 0 };
	bool res;

	res = true;
	aerntest_topology_device_instantiate(&spkg);

	if (aerntest_topology_find_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology find test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology find test.");
		res = false;
	}

	if (aerntest_topology_serialization_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology serialization test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology serialization test.");
		res = false;
	}

	if (aerntest_topology_sorted_list_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology sorted list test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology sorted list test.");
		res = false;
	}

	if (aerntest_topology_enforcement_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology enforcement test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology enforcement test.");
		res = false;
	}

	if (aerntest_topology_negative_lookup_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology run checked.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology run checked.");
		res = false;
	}

	if (aerntest_topology_add_item_sort_regression_test() == true)
	{
		aerntest_print_line("[PASS] AERN topology add-item sort regression test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology add-item sort regression test.");
		res = false;
	}

	if (aerntest_topology_register_sort_regression_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology register sort regression test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology register sort regression test.");
		res = false;
	}

	if (aerntest_topology_clone_sort_regression_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology clone sort regression test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology clone sort regression test.");
		res = false;
	}

	if (aerntest_topology_duplicate_register_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology duplicate register test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology duplicate register test.");
		res = false;
	}

	if (aerntest_topology_duplicate_serial_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN topology duplicate serial rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology duplicate serial rejection test.");
		res = false;
	}

	if (aerntest_topology_remove_order_test() == true)
	{
		aerntest_print_line("[PASS] AERN topology removal ordering test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology removal ordering test.");
		res = false;
	}

	if (aerntest_topology_address_full_compare_test() == true)
	{
		aerntest_print_line("[PASS] AERN topology address comparison test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology address comparison test.");
		res = false;
	}

	if (aerntest_topology_deserialize_bounds_test() == true)
	{
		aerntest_print_line("[PASS] AERN topology deserialize bounds test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology deserialize bounds test.");
		res = false;
	}

	if (aerntest_topology_find_aps_test(&spkg) == true)
	{
		aerntest_print_line("[PASS] AERN topology APS lookup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN topology APS lookup test.");
		res = false;
	}

	aerntest_topology_device_destroy(&spkg);

	return res;
}

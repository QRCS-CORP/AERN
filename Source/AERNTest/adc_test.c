#include "adc_test.h"
#include "aern_utils.h"
#include "certificate.h"
#include "memutils.h"
#include "server.h"
#include "topology.h"

#include <stdint.h>

typedef struct aerntest_adc_device_package
{
	aern_signature_keypair rkp;
	aern_signature_keypair dkp;
	aern_root_certificate root;
	aern_child_certificate adc;
	aern_topology_list_state tlist;
	uint8_t sigkey[AERN_ASYMMETRIC_SIGNING_KEY_SIZE];
} aerntest_adc_device_package;

static void aerntest_adc_package_dispose(aerntest_adc_device_package* spkg)
{
	AERN_ASSERT(spkg != NULL);

	if (spkg != NULL)
	{
		aern_topology_list_dispose(&spkg->tlist);
		qsc_memutils_clear(spkg, sizeof(aerntest_adc_device_package));
	}
}

static void aerntest_adc_package_initialize(aerntest_adc_device_package* spkg)
{
	AERN_ASSERT(spkg != NULL);

	if (spkg != NULL)
	{
		aern_certificate_expiration exp = { 0 };
		char adcaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { (char)192, (char)168, (char)1, (char)2 };
		char rootaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { (char)192, (char)168, (char)1, (char)1 };

		qsc_memutils_clear(spkg, sizeof(aerntest_adc_device_package));
		aern_topology_list_initialize(&spkg->tlist);
		aern_certificate_expiration_set_days(&exp, 0U, 365U);

		aern_certificate_signature_generate_keypair(&spkg->rkp);
		aern_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ_ARS1");

		aern_certificate_signature_generate_keypair(&spkg->dkp);
		aern_certificate_child_create(&spkg->adc, spkg->dkp.pubkey, &exp, "XYZ_ADC1", aern_network_designation_adc);
		(void)aern_certificate_root_sign(&spkg->adc, &spkg->root, spkg->rkp.prikey);

		qsc_memutils_copy(spkg->sigkey, spkg->dkp.prikey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
		aern_topology_root_register(&spkg->tlist, &spkg->root, rootaddr);
		aern_topology_child_register(&spkg->tlist, &spkg->adc, adcaddr);
	}
}

static bool aerntest_adc_state_is_ready(const aern_root_certificate* root, const aern_child_certificate* adc, const aern_topology_list_state* tlist, const uint8_t* sigkey)
{
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(adc != NULL);
	AERN_ASSERT(tlist != NULL);
	AERN_ASSERT(sigkey != NULL);

	bool res;

	res = false;

	if (root != NULL && adc != NULL && tlist != NULL && sigkey != NULL)
	{
		if (qsc_memutils_zeroed(sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false &&
			aern_certificate_root_is_valid(root) == true &&
			aern_topology_node_verify_root(tlist, root) == true &&
			aern_certificate_child_is_valid(adc) == true &&
			adc->designation == aern_network_designation_adc &&
			aern_certificate_root_signature_verify(adc, root) == true &&
			aern_topology_node_verify_issuer(tlist, adc, adc->issuer) == true &&
			tlist->version != 0U)
		{
			res = true;
		}
	}

	return res;
}

static bool aerntest_adc_keypair_and_certificate_generation_test(void)
{
	aern_server_application_state state = { 0 };
	aern_child_certificate adc = { 0 };
	aern_root_certificate root = { 0 };
	aern_signature_keypair rkp = { 0 };
	aern_certificate_expiration exp = { 0 };
	uint8_t sigkey[AERN_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
	bool res;

	res = false;

	aern_server_state_initialize(&state, aern_network_designation_adc);
	state.sigkey = sigkey;

	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_signature_generate_keypair(&rkp);
	aern_certificate_root_create(&root, rkp.pubkey, &exp, "XYZ_ARS1");

	aern_server_child_certificate_generate(&state, &adc, AERN_CERTIFICATE_MINIMUM_PERIOD);

	if (adc.designation == aern_network_designation_adc && qsc_memutils_zeroed(sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false)
	{
		if (aern_certificate_root_sign(&adc, &root, rkp.prikey) != 0U)
		{
			if (aern_certificate_child_is_valid(&adc) == true && aern_certificate_root_signature_verify(&adc, &root) == true)
			{
				res = true;
			}
		}
	}

	aern_server_state_unload(&state);
	qsc_memutils_clear(&adc, sizeof(adc));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&rkp, sizeof(rkp));
	qsc_memutils_clear(sigkey, sizeof(sigkey));

	return res;
}

static bool aerntest_adc_certificate_validation_against_root_test(void)
{
	aerntest_adc_device_package spkg = { 0 };
	bool res;

	aerntest_adc_package_initialize(&spkg);
	res = aerntest_adc_state_is_ready(&spkg.root, &spkg.adc, &spkg.tlist, spkg.sigkey);
	aerntest_adc_package_dispose(&spkg);

	return res;
}

static bool aerntest_adc_invalid_root_signature_reject_test(void)
{
	aerntest_adc_device_package spkg = { 0 };
	aern_signature_keypair xkp = { 0 };
	aern_root_certificate xroot = { 0 };
	aern_certificate_expiration exp = { 0 };
	bool res;

	res = false;
	aerntest_adc_package_initialize(&spkg);
	aern_certificate_signature_generate_keypair(&xkp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&xroot, xkp.pubkey, &exp, "XYZ_ARS2");

	if (aern_certificate_root_signature_verify(&spkg.adc, &xroot) == false && 
		aerntest_adc_state_is_ready(&xroot, &spkg.adc, &spkg.tlist, spkg.sigkey) == false)
	{
		res = true;
	}

	qsc_memutils_clear(&xkp, sizeof(xkp));
	qsc_memutils_clear(&xroot, sizeof(xroot));
	aerntest_adc_package_dispose(&spkg);

	return res;
}

static bool aerntest_adc_startup_empty_aps_topology_test(void)
{
	aerntest_adc_device_package spkg = { 0 };
	bool res;

	aerntest_adc_package_initialize(&spkg);

	res = (aern_topology_list_server_count(&spkg.tlist, aern_network_designation_aps) == 0U);
	res = (res == true && aerntest_adc_state_is_ready(&spkg.root, &spkg.adc, &spkg.tlist, spkg.sigkey) == true);

	aerntest_adc_package_dispose(&spkg);

	return res;
}

static bool aerntest_adc_startup_empty_trust_topology_reject_test(void)
{
	aerntest_adc_device_package spkg = { 0 };
	aern_topology_list_state empty = { 0 };
	aern_topology_list_state rootonly = { 0 };
	char rootaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { (char)192, (char)168, (char)1, (char)1 };
	bool res;

	aerntest_adc_package_initialize(&spkg);
	aern_topology_list_initialize(&empty);
	aern_topology_list_initialize(&rootonly);
	aern_topology_root_register(&rootonly, &spkg.root, rootaddr);

	res = (aerntest_adc_state_is_ready(&spkg.root, &spkg.adc, &empty, spkg.sigkey) == false);
	res = (res == true && aerntest_adc_state_is_ready(&spkg.root, &spkg.adc, &rootonly, spkg.sigkey) == false);

	aern_topology_list_dispose(&empty);
	aern_topology_list_dispose(&rootonly);
	aerntest_adc_package_dispose(&spkg);

	return res;
}

static bool aerntest_adc_topology_version_initialization_test(void)
{
	aern_topology_list_state list = { 0 };
	bool res;

	aern_topology_list_initialize(&list);
	res = (list.version == 1U);
	aern_topology_list_dispose(&list);
	res = (res == true && list.version == 0U);

	return res;
}

static bool aerntest_adc_topology_version_reject_stale_test(void)
{
	aern_topology_list_state list = { 0 };
	uint64_t version;
	bool res;

	aern_topology_list_initialize(&list);
	version = list.version;
	res = (aern_topology_version_verify(&list, version) != aern_protocol_error_none);
	res = (res == true && aern_topology_version_verify(&list, version - 1U) != aern_protocol_error_none);
	res = (res == true && aern_topology_version_verify(&list, version + 1U) == aern_protocol_error_none);
	aern_topology_list_dispose(&list);

	return res;
}

bool aerntest_adc_run(void)
{
	bool res;

	res = true;

	if (aerntest_adc_keypair_and_certificate_generation_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC keypair and certificate generation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC keypair and certificate generation test.");
		res = false;
	}

	if (aerntest_adc_certificate_validation_against_root_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC certificate validation against root test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC certificate validation against root test.");
		res = false;
	}

	if (aerntest_adc_invalid_root_signature_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC invalid root signature reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC invalid root signature reject test.");
		res = false;
	}

	if (aerntest_adc_startup_empty_aps_topology_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC startup empty APS topology test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC startup empty APS topology test.");
		res = false;
	}

	if (aerntest_adc_startup_empty_trust_topology_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC startup empty trust topology reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC startup empty trust topology reject test.");
		res = false;
	}

	if (aerntest_adc_topology_version_initialization_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC topology version initialization test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC topology version initialization test.");
		res = false;
	}

	if (aerntest_adc_topology_version_reject_stale_test() == true)
	{
		aerntest_print_line("[PASS] AERN ADC topology stale version reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ADC topology stale version reject test.");
		res = false;
	}

	return res;
}

#include "ars_test.h"
#include "aern_utils.h"
#include "certificate.h"
#include "server.h"
#include "memutils.h"

#define AERNTEST_SERVER_KEYCHAIN_DEPTH 4U
#define AERNTEST_SERVER_KEYCHAIN_WIDTH 64U
#define AERNTEST_SERVER_KEYCHAIN_SIZE ((AERNTEST_SERVER_KEYCHAIN_DEPTH * AERNTEST_SERVER_KEYCHAIN_WIDTH) + AERN_ASYMMETRIC_SIGNING_KEY_SIZE)
#define AERNTEST_SERVER_SIGNING_KEY_OFFSET (AERNTEST_SERVER_KEYCHAIN_DEPTH * AERNTEST_SERVER_KEYCHAIN_WIDTH)

static bool ars_test_state_prepare(aern_server_application_state* state)
{
	bool res;

	res = false;

	if (state != NULL)
	{
		aern_server_state_initialize(state, aern_network_designation_ars);
		state->kchain = (uint8_t*)qsc_memutils_malloc(AERNTEST_SERVER_KEYCHAIN_SIZE);

		if (state->kchain != NULL)
		{
			qsc_memutils_clear(state->kchain, AERNTEST_SERVER_KEYCHAIN_SIZE);
			state->sigkey = state->kchain + AERNTEST_SERVER_SIGNING_KEY_OFFSET;
			res = true;
		}
	}

	return res;
}

static void ars_test_state_dispose(aern_server_application_state* state)
{
	if (state != NULL)
	{
		if (state->kchain != NULL)
		{
			qsc_memutils_clear(state->kchain, AERNTEST_SERVER_KEYCHAIN_SIZE);
			qsc_memutils_alloc_free(state->kchain);
			state->kchain = NULL;
			state->sigkey = NULL;
		}

		qsc_memutils_clear(state, sizeof(aern_server_application_state));
	}
}

static bool ars_test_sign_child_designation(const aern_server_application_state* state, const aern_root_certificate* root, aern_network_designations designation, const char* issuer)
{
	aern_signature_keypair ckp = { 0 };
	aern_child_certificate child = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;

	if (state != NULL && root != NULL && issuer != NULL)
	{
		aern_certificate_signature_generate_keypair(&ckp);
		exp.from = root->expiration.from;
		exp.to = root->expiration.to;
		aern_certificate_child_create(&child, ckp.pubkey, &exp, issuer, designation);
		siglen = aern_certificate_root_sign(&child, root, state->sigkey);

		res = (siglen != 0U);
		res = (res == true && aern_certificate_child_is_valid(&child) == true);
		res = (res == true && aern_certificate_root_signature_verify(&child, root) == true);
		res = (res == true && qsc_memutils_are_equal(child.rootser, root->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true);
	}

	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&exp, sizeof(exp));

	return res;
}

static bool aerntest_ars_root_generate_state_test(void)
{
	aern_server_application_state state = { 0 };
	bool res;

	res = false;

	if (ars_test_state_prepare(&state) == true)
	{
		aern_server_root_certificate_generate(&state, &state.root, AERN_CERTIFICATE_DEFAULT_PERIOD);

		res = aern_certificate_root_is_valid(&state.root);
		res = (res == true && state.srvtype == aern_network_designation_ars);
		res = (res == true && state.sigkey != NULL);
		res = (res == true && qsc_memutils_zeroed(state.sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);
	}

	ars_test_state_dispose(&state);

	return res;
}

static bool aerntest_ars_root_generate_invalid_parameter_test(void)
{
	aern_server_application_state state = { 0 };
	aern_server_application_state nstate = { 0 };
	aern_root_certificate root = { 0 };
	bool res;

	res = false;

	if (ars_test_state_prepare(&state) == true)
	{
		res = aern_server_root_certificate_generate(&state, &root, AERN_CERTIFICATE_MINIMUM_PERIOD - 1U);
		res = (res == true && aern_certificate_root_is_valid(&root) == true);
		res = (res == true && qsc_memutils_zeroed(state.sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);

		qsc_memutils_clear(&root, sizeof(root));
		res = (res == true && aern_server_root_certificate_generate(&state, &root, AERN_CERTIFICATE_MAXIMUM_PERIOD + 1U) == false);
		res = (res == true && aern_certificate_root_is_valid(&root) == false);
	}

	ars_test_state_dispose(&state);
	qsc_memutils_clear(&nstate, sizeof(nstate));
	qsc_memutils_clear(&root, sizeof(root));

	return res;
}

static bool aerntest_ars_root_signing_key_retention_test(void)
{
	aern_server_application_state state = { 0 };
	bool res;

	res = false;

	if (ars_test_state_prepare(&state) == true)
	{
		aern_server_root_certificate_generate(&state, &state.root, AERN_CERTIFICATE_DEFAULT_PERIOD);

		res = aern_certificate_root_is_valid(&state.root);
		res = (res == true && qsc_memutils_zeroed(state.sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);
		res = (res == true && ars_test_sign_child_designation(&state, &state.root, aern_network_designation_adc, "ADC-1") == true);
	}

	ars_test_state_dispose(&state);

	return res;
}

static bool aerntest_ars_root_child_signing_path_test(void)
{
	aern_server_application_state state = { 0 };
	bool res;

	res = false;

	if (ars_test_state_prepare(&state) == true)
	{
		aern_server_root_certificate_generate(&state, &state.root, AERN_CERTIFICATE_DEFAULT_PERIOD);

		res = aern_certificate_root_is_valid(&state.root);
		res = (res == true && ars_test_sign_child_designation(&state, &state.root, aern_network_designation_adc, "ADC-1") == true);
		res = (res == true && ars_test_sign_child_designation(&state, &state.root, aern_network_designation_aps, "APS-1") == true);
		res = (res == true && ars_test_sign_child_designation(&state, &state.root, aern_network_designation_client, "CLIENT-1") == true);
	}

	ars_test_state_dispose(&state);

	return res;
}

static bool aerntest_ars_root_signing_key_unload_idempotent_test(void)
{
	aern_server_application_state state = { 0 };
	bool res;

	res = false;

	if (ars_test_state_prepare(&state) == true)
	{
		res = aern_server_root_certificate_generate(&state, &state.root, AERN_CERTIFICATE_DEFAULT_PERIOD);
		res = (res == true && qsc_memutils_zeroed(state.sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE) == false);

		if (res == true)
		{
			aern_server_state_unload(&state);
			res = (state.kchain == NULL && state.sigkey == NULL);
			res = (res == true && state.srvtype == aern_network_designation_ars);
		}

		if (res == true)
		{
			aern_server_state_unload(&state);
			res = (state.kchain == NULL && state.sigkey == NULL);
			res = (res == true && state.srvtype == aern_network_designation_ars);
		}
	}

	if (state.kchain != NULL)
	{
		ars_test_state_dispose(&state);
	}

	return res;
}

bool aerntest_ars_run(void)
{
	bool res;

	res = true;

	if (aerntest_ars_root_generate_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN ARS root generate state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ARS root generate state test.");
		res = false;
	}

	if (aerntest_ars_root_generate_invalid_parameter_test() == true)
	{
		aerntest_print_line("[PASS] AERN ARS root generate invalid parameter test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ARS root generate invalid parameter test.");
		res = false;
	}

	if (aerntest_ars_root_signing_key_retention_test() == true)
	{
		aerntest_print_line("[PASS] AERN ARS root signing key retention test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ARS root signing key retention test.");
		res = false;
	}

	if (aerntest_ars_root_child_signing_path_test() == true)
	{
		aerntest_print_line("[PASS] AERN ARS root child signing path test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ARS root child signing path test.");
		res = false;
	}

	if (aerntest_ars_root_signing_key_unload_idempotent_test() == true)
	{
		aerntest_print_line("[PASS] AERN ARS root signing key unload idempotent test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ARS root signing key unload idempotent test.");
		res = false;
	}

	return res;
}

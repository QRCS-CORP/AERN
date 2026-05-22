#include "certificate_test.h"
#include "aern_utils.h"
#include "certificate.h"
#include "fileutils.h"
#include "memutils.h"
#include "timestamp.h"

static bool aerntest_certificate_size_test(void)
{
	size_t childlen;
	size_t rootlen;
	bool res;

	rootlen = AERN_CERTIFICATE_HASH_SIZE +
		AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE +
		AERN_CERTIFICATE_ISSUER_SIZE +
		AERN_CERTIFICATE_SERIAL_SIZE +
		AERN_CERTIFICATE_EXPIRATION_SIZE +
		AERN_CERTIFICATE_ALGORITHM_SIZE +
		AERN_CERTIFICATE_VERSION_SIZE;

	childlen = AERN_CERTIFICATE_SIGNED_HASH_SIZE +
		AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE +
		AERN_CERTIFICATE_ISSUER_SIZE +
		AERN_CERTIFICATE_SERIAL_SIZE +
		AERN_CERTIFICATE_SERIAL_SIZE +
		AERN_CERTIFICATE_EXPIRATION_SIZE +
		AERN_CERTIFICATE_DESIGNATION_SIZE +
		AERN_CERTIFICATE_ALGORITHM_SIZE +
		AERN_CERTIFICATE_VERSION_SIZE;

	res = true;

	res = (res == true && rootlen == AERN_CERTIFICATE_ROOT_SIZE);
	res = (res == true && childlen == AERN_CERTIFICATE_CHILD_SIZE);
	res = (res == true && AERN_CERTIFICATE_SIGNED_HASH_SIZE == (AERN_ASYMMETRIC_SIGNATURE_SIZE + AERN_CERTIFICATE_HASH_SIZE));
	res = (res == true && AERN_CERTIFICATE_EXPIRATION_SIZE == (2U * sizeof(uint64_t)));

	return res;
}

static bool aerntest_certificate_root_codec_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_root_certificate root = { 0 };
	aern_root_certificate rcpy = { 0 };
	aern_certificate_expiration exp = { 0 };
	uint8_t srt[AERN_CERTIFICATE_ROOT_SIZE] = { 0U };
	uint8_t srt2[AERN_CERTIFICATE_ROOT_SIZE] = { 0U };
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");

	if (aern_certificate_root_is_valid(&root) == true)
	{
		aern_certificate_root_serialize(srt, &root);
		aern_certificate_root_deserialize(&rcpy, srt);
		aern_certificate_root_serialize(srt2, &rcpy);

		if (rcpy.algorithm == root.algorithm && 
			rcpy.version == root.version && 
			rcpy.expiration.from == root.expiration.from && 
			rcpy.expiration.to == root.expiration.to &&
			qsc_memutils_are_equal((const uint8_t*)rcpy.issuer, (const uint8_t*)root.issuer, AERN_CERTIFICATE_ISSUER_SIZE) == true &&
			qsc_memutils_are_equal(rcpy.serial, root.serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
			qsc_memutils_are_equal(rcpy.verkey, root.verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE) == true &&
			qsc_memutils_are_equal(srt, srt2, AERN_CERTIFICATE_ROOT_SIZE) == true)
		{
			res = true;
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&rcpy, sizeof(rcpy));
	qsc_memutils_clear(srt, sizeof(srt));
	qsc_memutils_clear(srt2, sizeof(srt2));

	return res;
}

static bool aerntest_certificate_child_codec_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate ccpy = { 0 };
	aern_certificate_expiration exp = { 0 };
	uint8_t sct[AERN_CERTIFICATE_CHILD_SIZE] = { 0U };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_child_is_valid(&child) == true && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		aern_certificate_child_serialize(sct, &child);
		aern_certificate_child_deserialize(&ccpy, sct);

		if (aern_certificate_child_are_equal(&child, &ccpy) == true && aern_certificate_root_signature_verify(&ccpy, &root) == true)
		{
			res = true;
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&ccpy, sizeof(ccpy));
	qsc_memutils_clear(sct, sizeof(sct));

	return res;
}

static bool aerntest_certificate_negative_path_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_root_certificate xroot = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate bad = { 0 };
	aern_certificate_expiration exp = { 0 };
	uint64_t now;
	size_t siglen;
	bool res;

	res = false;
	now = qsc_timestamp_datetime_utc();
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.csig[0U] ^= 0x01U;

		if (aern_certificate_root_signature_verify(&bad, &root) == false)
		{
			qsc_memutils_copy(&bad, &child, sizeof(bad));
			bad.issuer[0U] ^= 0x01U;

			if (aern_certificate_root_signature_verify(&bad, &root) == false)
			{
				qsc_memutils_copy(&bad, &child, sizeof(bad));
				bad.designation = aern_network_designation_none;

				if (aern_certificate_child_is_valid(&bad) == false)
				{
					qsc_memutils_copy(&xroot, &root, sizeof(xroot));

					if (now > 2U)
					{
						xroot.expiration.from = now - 2U;
						xroot.expiration.to = now - 1U;
					}
					else
					{
						xroot.expiration.from = 1U;
						xroot.expiration.to = 1U;
					}

					res = (aern_certificate_root_is_valid(&xroot) == false);
				}
			}
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&xroot, sizeof(xroot));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&bad, sizeof(bad));

	return res;
}

static bool aerntest_certificate_child_rootser_binding_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate bad = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.rootser[0U] ^= 0x01U;
		res = (aern_certificate_root_signature_verify(&bad, &root) == false);
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&bad, sizeof(bad));

	return res;
}

static bool aerntest_certificate_child_wrong_root_reject_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair xkp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_root_certificate xroot = { 0 };
	aern_child_certificate child = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&xkp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_root_create(&xroot, xkp.pubkey, &exp, "ARS-2");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		res = (aern_certificate_root_signature_verify(&child, &xroot) == false);
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&xkp, sizeof(xkp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&xroot, sizeof(xroot));
	qsc_memutils_clear(&child, sizeof(child));

	return res;
}

static bool aerntest_certificate_root_algorithm_version_reject_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_root_certificate root = { 0 };
	aern_root_certificate bad = { 0 };
	aern_certificate_expiration exp = { 0 };
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");

	if (aern_certificate_root_is_valid(&root) == true)
	{
		qsc_memutils_copy(&bad, &root, sizeof(bad));
		bad.algorithm = aern_configuration_set_none;

		if (aern_certificate_root_is_valid(&bad) == false)
		{
			qsc_memutils_copy(&bad, &root, sizeof(bad));
			bad.version = aern_version_set_none;
			res = (aern_certificate_root_is_valid(&bad) == false);
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&bad, sizeof(bad));

	return res;
}

static bool aerntest_certificate_root_text_codec_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_root_certificate root = { 0 };
	aern_root_certificate rcpy = { 0 };
	aern_certificate_expiration exp = { 0 };
	char enc[AERN_ROOT_CERTIFICATE_STRING_SIZE + 8U] = { 0 };
	size_t enclen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	enclen = aern_certificate_root_encode(enc, &root);

	if (enclen != 0U && aern_certificate_root_decode(&rcpy, enc) == true)
	{
		res = (aern_certificate_root_compare(&root, &rcpy) == true);
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&rcpy, sizeof(rcpy));
	qsc_memutils_clear(enc, sizeof(enc));

	return res;
}

static bool aerntest_certificate_child_text_codec_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate ccpy = { 0 };
	aern_certificate_expiration exp = { 0 };
	char enc[AERN_CHILD_CERTIFICATE_STRING_SIZE + 8U] = { 0 };
	size_t enclen;
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		enclen = aern_certificate_child_encode(enc, &child);

		if (enclen != 0U)
		{
			if (aern_certificate_child_decode(&ccpy, enc) == true)
			{
				res = (aern_certificate_child_are_equal(&child, &ccpy) == true);
				res = (res == true && aern_certificate_root_signature_verify(&ccpy, &root) == true);
			}
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&ccpy, sizeof(ccpy));
	qsc_memutils_clear(enc, sizeof(enc));

	return res;
}

static bool aerntest_certificate_child_hash_generation_test(void)
{
	aern_signature_keypair ckp = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate ccpy = { 0 };
	aern_certificate_expiration exp = { 0 };
	uint8_t hash1[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	uint8_t hash2[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	uint8_t hash3[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	qsc_memutils_copy(&ccpy, &child, sizeof(ccpy));
	aern_certificate_child_hash(hash1, &child);
	aern_certificate_child_hash(hash2, &ccpy);
	ccpy.serial[0U] ^= 0x01U;
	aern_certificate_child_hash(hash3, &ccpy);

	res = (qsc_memutils_are_equal(hash1, hash2, AERN_CERTIFICATE_HASH_SIZE) == true);
	res = (res == true && qsc_memutils_are_equal(hash1, hash3, AERN_CERTIFICATE_HASH_SIZE) == false);

	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&ccpy, sizeof(ccpy));
	qsc_memutils_clear(hash1, sizeof(hash1));
	qsc_memutils_clear(hash2, sizeof(hash2));
	qsc_memutils_clear(hash3, sizeof(hash3));

	return res;
}

static bool aerntest_certificate_expiration_bounds_test(void)
{
	aern_certificate_expiration exp = { 0 };
	uint64_t now;
	bool res;

	now = qsc_timestamp_datetime_utc();
	res = false;

	if (now > 3U)
	{
		exp.from = now - 1U;
		exp.to = now + 1U;
		res = aern_certificate_expiration_time_verify(&exp);

		exp.from = now + 10U;
		exp.to = now + 20U;
		res = (res == true && aern_certificate_expiration_time_verify(&exp) == false);

		exp.from = now - 20U;
		exp.to = now - 10U;
		res = (res == true && aern_certificate_expiration_time_verify(&exp) == false);

		exp.from = now + 20U;
		exp.to = now + 10U;
		res = (res == true && aern_certificate_expiration_time_verify(&exp) == false);
	}

	qsc_memutils_clear(&exp, sizeof(exp));

	return res;
}

static bool aerntest_certificate_child_issuer_serial_binding_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate bad = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.serial[0U] ^= 0x01U;
		res = (aern_certificate_root_signature_verify(&bad, &root) == false);

		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.issuer[0U] ^= 0x01U;
		res = (res == true && aern_certificate_root_signature_verify(&bad, &root) == false);
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&bad, sizeof(bad));

	return res;
}

static bool aerntest_certificate_child_algorithm_version_reject_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate bad = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.algorithm = aern_configuration_set_none;
		res = (aern_certificate_child_is_valid(&bad) == false);
		res = (res == true && aern_certificate_root_signature_verify(&bad, &root) == false);

		qsc_memutils_copy(&bad, &child, sizeof(bad));
		bad.version = aern_version_set_none;
		res = (res == true && aern_certificate_child_is_valid(&bad) == false);
		res = (res == true && aern_certificate_root_signature_verify(&bad, &root) == false);
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&bad, sizeof(bad));

	return res;
}

static bool aerntest_certificate_child_invalid_designation_reject_test(void)
{
	aern_signature_keypair ckp = { 0 };
	aern_child_certificate child = { 0 };
	aern_certificate_expiration exp = { 0 };
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);

	child.designation = aern_network_designation_none;
	res = (aern_certificate_child_is_valid(&child) == false);

	child.designation = aern_network_designation_revoked;
	res = (res == true && aern_certificate_child_is_valid(&child) == false);

	child.designation = aern_network_designation_ars;
	res = (res == true && aern_certificate_child_is_valid(&child) == false);

	child.designation = aern_network_designation_all;
	res = (res == true && aern_certificate_child_is_valid(&child) == false);

	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&child, sizeof(child));

	return res;
}

static bool aerntest_certificate_child_expired_renewal_path_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate expired = { 0 };
	aern_child_certificate renewed = { 0 };
	aern_certificate_expiration rexp = { 0 };
	aern_certificate_expiration cexp = { 0 };
	uint64_t tnow;
	size_t siglen;
	bool res;

	res = false;
	tnow = qsc_timestamp_datetime_utc();

	if (tnow > 10U)
	{
		aern_certificate_signature_generate_keypair(&skp);
		aern_certificate_signature_generate_keypair(&ckp);
		rexp.from = tnow - 1U;
		rexp.to = tnow + AERN_CERTIFICATE_DEFAULT_PERIOD;
		aern_certificate_root_create(&root, skp.pubkey, &rexp, "ARS-1");

		cexp.from = tnow - 10U;
		cexp.to = tnow - 5U;
		aern_certificate_child_create(&expired, ckp.pubkey, &cexp, "APS-1", aern_network_designation_aps);
		siglen = aern_certificate_root_sign(&expired, &root, skp.prikey);

		if (siglen != 0U && aern_certificate_child_is_valid(&expired) == false)
		{
			cexp.from = tnow - 1U;
			cexp.to = tnow + AERN_CERTIFICATE_DEFAULT_PERIOD;
			aern_certificate_child_create(&renewed, ckp.pubkey, &cexp, "APS-1", aern_network_designation_aps);
			siglen = aern_certificate_root_sign(&renewed, &root, skp.prikey);

			if (siglen != 0U && aern_certificate_child_is_valid(&renewed) == true)
			{
				res = true;
			}
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&expired, sizeof(expired));
	qsc_memutils_clear(&renewed, sizeof(renewed));
	qsc_memutils_clear(&rexp, sizeof(rexp));
	qsc_memutils_clear(&cexp, sizeof(cexp));

	return res;
}

static bool aerntest_certificate_child_revoked_reject_test(void)
{
	aern_signature_keypair skp = { 0 };
	aern_signature_keypair ckp = { 0 };
	aern_root_certificate root = { 0 };
	aern_child_certificate child = { 0 };
	aern_child_certificate revoked = { 0 };
	aern_certificate_expiration exp = { 0 };
	size_t siglen;
	bool res;

	res = false;
	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 365U);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS-1", aern_network_designation_aps);
	siglen = aern_certificate_root_sign(&child, &root, skp.prikey);

	if (siglen != 0U && aern_certificate_root_signature_verify(&child, &root) == true)
	{
		qsc_memutils_copy(&revoked, &child, sizeof(revoked));

		/* revoke the child */
		aern_certificate_child_revoke(&revoked);

		if (aern_certificate_child_is_valid(&revoked) == false)
		{
			if (aern_certificate_root_signature_verify(&revoked, &root) == false)
			{
				res = true;
			}
		}
	}

	qsc_memutils_clear(&skp, sizeof(skp));
	qsc_memutils_clear(&ckp, sizeof(ckp));
	qsc_memutils_clear(&root, sizeof(root));
	qsc_memutils_clear(&child, sizeof(child));
	qsc_memutils_clear(&revoked, sizeof(revoked));

	return res;
}

bool aerntest_certificate_run(void)
{
	bool res;

	res = true;

	if (aerntest_certificate_size_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate size test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate size test.");
		res = false;
	}

	if (aerntest_certificate_root_codec_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate root codec test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate root codec test.");
		res = false;
	}

	if (aerntest_certificate_child_codec_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child codec test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child codec test.");
		res = false;
	}

	if (aerntest_certificate_negative_path_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate negative path test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate negative path test.");
		res = false;
	}

	if (aerntest_certificate_child_rootser_binding_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child root serial binding test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child root serial binding test.");
		res = false;
	}

	if (aerntest_certificate_child_wrong_root_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child wrong root reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child wrong root reject test.");
		res = false;
	}

	if (aerntest_certificate_root_algorithm_version_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate root algorithm and version reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate root algorithm and version reject test.");
		res = false;
	}

	if (aerntest_certificate_root_text_codec_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate root text codec test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate root text codec test.");
		res = false;
	}

	if (aerntest_certificate_child_text_codec_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child text codec test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child text codec test.");
		res = false;
	}

	if (aerntest_certificate_child_hash_generation_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child hash generation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child hash generation test.");
		res = false;
	}

	if (aerntest_certificate_expiration_bounds_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate expiration bounds test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate expiration bounds test.");
		res = false;
	}

	if (aerntest_certificate_child_issuer_serial_binding_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child issuer and serial binding test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child issuer and serial binding test.");
		res = false;
	}

	if (aerntest_certificate_child_algorithm_version_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child algorithm and version reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child algorithm and version reject test.");
		res = false;
	}

	if (aerntest_certificate_child_invalid_designation_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child invalid designation reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child invalid designation reject test.");
		res = false;
	}

	if (aerntest_certificate_child_expired_renewal_path_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child expired renewal path test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child expired renewal path test.");
		res = false;
	}

	if (aerntest_certificate_child_revoked_reject_test() == true)
	{
		aerntest_print_line("[PASS] AERN certificate child revoked reject test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN certificate child revoked reject test.");
		res = false;
	}

	return res;
}

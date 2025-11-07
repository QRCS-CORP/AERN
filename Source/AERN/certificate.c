#include "certificate.h"
#include "crypto.h"
#include "acp.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"
#if defined(AERN_DEBUG_TESTS_RUN)
#include "consoleutils.h"
#endif

aern_configuration_sets aern_certificate_algorithm_decode(const char* name)
{
	AERN_ASSERT(name != NULL);

	aern_configuration_sets cset;

	cset = aern_configuration_set_none;

	if (name != NULL)
	{
		if (qsc_stringutils_compare_strings("dilithium-s1_kyber-s1_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_dilithium1_kyber1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s3_kyber-s3_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_dilithium3_kyber3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s5_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_dilithium5_kyber5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s6_rcs-512_sha3-512", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_dilithium5_kyber6_rcs512_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1f_mceliece-s1_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1s_mceliece-s1_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3f_mceliece-s3_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3s_mceliece-s3_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s5_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s5_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s6_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s6_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s7_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s7_rcs-256_sha3-256", name, AERN_PROTOCOL_SET_SIZE))
		{
			cset = aern_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
		}
		else
		{
			cset = aern_configuration_set_none;
		}
	}

	return cset;
}

void aern_certificate_algorithm_encode(char* name, aern_configuration_sets conf)
{
	AERN_ASSERT(name != NULL);

	if (name != NULL)
	{
		if (conf == aern_configuration_set_dilithium1_kyber1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "dilithium-s1_kyber-s1_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_dilithium3_kyber3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "dilithium-s3_kyber-s3_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_dilithium5_kyber5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s5_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_dilithium5_kyber6_rcs512_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s6_rcs-512_sha3-512");
		}
		else if (conf == aern_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-1f_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-1s_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-3f_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-3s_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s7_rcs-256_sha3-256");
		}
		else if (conf == aern_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, AERN_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s7_rcs-256_sha3-256");
		}
	}
}

bool aern_certificate_algorithm_enabled(aern_configuration_sets conf)
{
	AERN_ASSERT(conf != 0);

	return (conf == AERN_CONFIGURATION_SET);
}

bool aern_certificate_child_are_equal(const aern_child_certificate* a, const aern_child_certificate* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version && a->designation == b->designation &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, AERN_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal(a->csig, b->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE) == true)
					{
						if (qsc_memutils_are_equal(a->rootser, b->rootser, AERN_CERTIFICATE_SERIAL_SIZE) == true)
						{
							res = qsc_memutils_are_equal(a->verkey, b->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
						}
					}
				}
			}
		}
	}

	return res;
}

void aern_certificate_child_copy(aern_child_certificate* output, const aern_child_certificate* input)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(input != NULL);

	if (output != NULL && input != NULL)
	{
		qsc_memutils_copy(output->csig, input->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE);
		qsc_memutils_copy(output->verkey, input->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_copy(output->issuer, input->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(output->serial, input->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(output->rootser, input->rootser, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(&output->expiration, &input->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(&output->designation, &input->designation, AERN_CERTIFICATE_DESIGNATION_SIZE);
		qsc_memutils_copy(&output->algorithm, &input->algorithm, AERN_CERTIFICATE_ALGORITHM_SIZE);
		qsc_memutils_copy(&output->version, &input->version, AERN_CERTIFICATE_VERSION_SIZE);
	}
}

void aern_certificate_child_create(aern_child_certificate* child, const uint8_t* pubkey, const aern_certificate_expiration* expiration, const char* issuer, aern_network_designations designation)
{
	AERN_ASSERT(child != NULL);
	AERN_ASSERT(pubkey != NULL);
	AERN_ASSERT(expiration != NULL);
	AERN_ASSERT(issuer != NULL);

	if (child != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		qsc_memutils_clear(child, AERN_CERTIFICATE_CHILD_SIZE);
		child->algorithm = (uint8_t)AERN_CONFIGURATION_SET;
		qsc_stringutils_copy_string(child->issuer, AERN_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&child->expiration, expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(child->verkey, pubkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(child->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		child->designation = (uint8_t)designation;
		child->version = (uint8_t)aern_version_set_one_zero;
	}
}

bool aern_certificate_child_decode(aern_child_certificate* child, const char enck[AERN_CHILD_CERTIFICATE_STRING_SIZE])
{
	AERN_ASSERT(child != NULL);
	AERN_ASSERT(enck != NULL);

	bool res;

	res = false;

	if (child != NULL && enck != NULL)
	{
		char tmpvk[AERN_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char tmpsg[AERN_SIGNATURE_ENCODING_SIZE + ((AERN_SIGNATURE_ENCODING_SIZE / 64U) + 1U)] = { 0 };
		const char* penc;
		size_t slen;

		penc = enck;
		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_HEADER) + qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_SERIAL_PREFIX) + 1U;
		qsc_intutils_hex_to_bin(penc, child->serial, AERN_CERTIFICATE_SERIAL_SIZE * 2U);
		penc += (AERN_CERTIFICATE_SERIAL_SIZE * 2U);

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ISSUER_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(child->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX) + 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->algorithm = aern_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_VERSION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, AERN_ACTIVE_VERSION_STRING, slen) == true)
		{
			child->version = aern_version_set_one_zero;
		}
		else
		{
			child->version = aern_version_set_none;
		}

		penc += slen;
		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->designation = aern_certificate_designation_decode(penc);
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		slen = qsc_stringutils_find_string(penc, "\n");
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX) + 1U;
		slen = sizeof(tmpsg);
		qsc_stringutils_remove_line_breaks(tmpsg, sizeof(tmpsg), penc, slen);
		res = qsc_encoding_base64_decode(child->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE, tmpsg, AERN_SIGNATURE_ENCODING_SIZE);
		penc += slen;

		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, AERN_CHILD_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(child->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, AERN_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void aern_certificate_child_deserialize(aern_child_certificate* child, const uint8_t* input)
{
	AERN_ASSERT(child != NULL);
	AERN_ASSERT(input != NULL);

	size_t pos;

	if (child != NULL && input != NULL)
	{
		qsc_memutils_copy(child->csig, input, AERN_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = AERN_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(child->verkey, input + pos, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(child->issuer, input + pos, AERN_CERTIFICATE_ISSUER_SIZE);
		pos += AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(child->serial, input + pos, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(child->rootser, input + pos, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&child->expiration, input + pos, AERN_CERTIFICATE_EXPIRATION_SIZE);
		pos += AERN_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&child->designation, input + pos, AERN_CERTIFICATE_DESIGNATION_SIZE);
		pos += AERN_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(&child->algorithm, input + pos, AERN_CERTIFICATE_ALGORITHM_SIZE);
		pos += AERN_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(&child->version, input + pos, AERN_CERTIFICATE_VERSION_SIZE);
	}
}

size_t aern_certificate_child_encode(char enck[AERN_CHILD_CERTIFICATE_STRING_SIZE], const aern_child_certificate* child)
{
	AERN_ASSERT(enck != NULL);
	AERN_ASSERT(child != NULL);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && child != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[AERN_CERTIFICATE_SERIAL_SIZE * 2U] = { 0 };
		char tmpvk[AERN_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char tmpsg[AERN_SIGNATURE_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, AERN_CHILD_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(child->issuer);
		qsc_memutils_copy((enck + spos), child->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->serial, hexid, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), AERN_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;

		if (child->version == aern_version_set_one_zero)
		{
			slen = qsc_stringutils_string_size(AERN_ACTIVE_VERSION_STRING);
			qsc_memutils_copy((enck + spos), AERN_ACTIVE_VERSION_STRING, slen);
		}
		else
		{
			const char defv[] = "0x00";
			slen = qsc_stringutils_string_size(defv);
			qsc_memutils_copy((enck + spos), defv, slen);
		}

		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += aern_certificate_designation_encode((enck + spos), child->designation);
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->rootser, hexid, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_ROOT_HASH_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		//size_t enclen = qsc_encoding_base64_encoded_size(sizeof(child->csig));
		slen = AERN_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_encoding_base64_encode(tmpsg, AERN_SIGNATURE_ENCODING_SIZE, child->csig, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), AERN_CHILD_CERTIFICATE_STRING_SIZE - spos, AERN_CERTIFICATE_LINE_LENGTH, tmpsg, sizeof(tmpsg));
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		//size_t enclen = qsc_encoding_base64_encoded_size(slen);
		qsc_encoding_base64_encode(tmpvk, AERN_VERIFICATION_KEY_ENCODING_SIZE, child->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), AERN_ROOT_CERTIFICATE_STRING_SIZE - spos, AERN_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), AERN_CHILD_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void aern_certificate_child_erase(aern_child_certificate* child)
{
	AERN_ASSERT(child != NULL);

	if (child != NULL)
	{
		qsc_memutils_clear(child->csig, AERN_ASYMMETRIC_SIGNATURE_SIZE);
		qsc_memutils_clear(child->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_clear(child->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(child->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(child->rootser, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(&child->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		child->designation = (uint8_t)aern_network_designation_none;
		child->algorithm = (uint8_t)aern_configuration_set_none;
		child->version = (uint8_t)aern_version_set_one_zero;
	}
}

bool aern_certificate_child_file_to_struct(const char* fpath, aern_child_certificate* child)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t schild[AERN_CERTIFICATE_CHILD_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)schild, AERN_CERTIFICATE_CHILD_SIZE) == AERN_CERTIFICATE_CHILD_SIZE)
			{
				aern_certificate_child_deserialize(child, schild);
				res = true;
			}
		}
	}

	return res;
}

void aern_certificate_child_hash(uint8_t* output, const aern_child_certificate* child)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(child != NULL);

	if (output != NULL && child != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0U };

		qsc_sha3_initialize(&hstate);
		nbuf[0U] = child->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = child->designation;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = child->version;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, child->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, child->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, (const uint8_t*)child->issuer, qsc_stringutils_string_size((const char*)child->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
	}
}

bool aern_certificate_child_is_valid(const aern_child_certificate* child)
{
	AERN_ASSERT(child != NULL);

	bool res;

	res = false;

	if (child != NULL)
	{
		if (child->algorithm == AERN_CONFIGURATION_SET &&
			child->designation != aern_network_designation_none &&
			child->version == AERN_ACTIVE_VERSION &&
			qsc_memutils_zeroed(child->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE) == false &&
			qsc_memutils_zeroed(child->rootser, AERN_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->serial, AERN_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
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

bool aern_certificate_child_message_verify(uint8_t* message, size_t* msglen, const uint8_t* signature, size_t siglen, const aern_child_certificate* child)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != NULL);
	AERN_ASSERT(signature != NULL);
	AERN_ASSERT(siglen != 0U);
	AERN_ASSERT(child != NULL);

	bool res;

	res = false;
	*msglen = 0U;

	if (message != NULL && msglen != NULL && signature != NULL && siglen != 0 && child != NULL)
	{
		res = aern_signature_verify(message, msglen, signature, siglen, child->verkey);
	}

	return res;
}

void aern_certificate_child_serialize(uint8_t* output, const aern_child_certificate* child)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(child != NULL);

	size_t pos;

	if (output != NULL && child != NULL)
	{
		qsc_memutils_copy(output, child->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = AERN_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, child->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, child->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		pos += AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, child->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, child->rootser, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &child->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		pos += AERN_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &child->designation, AERN_CERTIFICATE_DESIGNATION_SIZE);
		pos += AERN_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(output + pos, &child->algorithm, AERN_CERTIFICATE_ALGORITHM_SIZE);
		pos += AERN_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(output + pos, &child->version, AERN_CERTIFICATE_VERSION_SIZE);
	}
}

bool aern_certificate_signature_hash_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const aern_child_certificate* lcert)
{
	AERN_ASSERT(signature != NULL);
	AERN_ASSERT(siglen != 0U);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);
	AERN_ASSERT(lcert != NULL);

	size_t mlen;
	bool res;

	mlen = 0U;
	res = false;

	if (signature != NULL && siglen != 0 && message != NULL && msglen != 0 && lcert != NULL)
	{
		uint8_t rhash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

		res = aern_signature_verify(rhash, &mlen, signature, siglen, lcert->verkey);

		if (res == true && mlen == AERN_CERTIFICATE_HASH_SIZE)
		{
			uint8_t lhash[AERN_CERTIFICATE_HASH_SIZE] = { 0 };

			qsc_sha3_compute256(lhash, message, msglen);
			res = qsc_memutils_are_equal(rhash, lhash, AERN_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool aern_certificate_child_struct_to_file(const char* fpath, const aern_child_certificate* child)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		uint8_t schild[AERN_CERTIFICATE_CHILD_SIZE] = { 0U };

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		aern_certificate_child_serialize(schild, child);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)schild, sizeof(schild));
	}

	return res;
}

aern_network_designations aern_certificate_designation_decode(const char* sdsg)
{
	AERN_ASSERT(sdsg != NULL);

	aern_network_designations dsg;

	dsg = aern_network_designation_none;

	if (sdsg != NULL)
	{
		if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_APS) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_aps;
		}
		else if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_CLIENT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_client;
		}
		else if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_IDG) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_idg;
		}
		else if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_REMOTE) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_remote;
		}
		else if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_ROOT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_ars;
		}
		else if (qsc_stringutils_find_string(sdsg, AERN_NETWORK_DESIGNATION_ALL) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = aern_network_designation_all;
		}
		else
		{
			dsg = aern_network_designation_none;
		}
	}

	return dsg;
}

size_t aern_certificate_designation_encode(char* sdsg, aern_network_designations designation)
{
	AERN_ASSERT(sdsg != NULL);

	if (sdsg != NULL)
	{
		if (designation == aern_network_designation_aps)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_APS);
		}
		else if (designation == aern_network_designation_client)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_CLIENT);
		}
		else if (designation == aern_network_designation_ads)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_ADS);
		}
		else if (designation == aern_network_designation_idg)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_IDG);
		}
		else if (designation == aern_network_designation_remote)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_REMOTE);
		}
		else if (designation == aern_network_designation_ars)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_ROOT);
		}
		else if (designation == aern_network_designation_all)
		{
			qsc_stringutils_copy_string(sdsg, AERN_NETWORK_DESIGNATION_SIZE, AERN_NETWORK_DESIGNATION_ALL);
		}
	}

	return qsc_stringutils_string_size(sdsg);
}

void aern_certificate_expiration_set_days(aern_certificate_expiration* expiration, uint16_t start, uint16_t duration)
{
	AERN_ASSERT(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + (start * 24U * 60U * 60U);
		expiration->to = expiration->from + (duration * 24U * 60U * 60U);
	}
}

void aern_certificate_expiration_set_seconds(aern_certificate_expiration* expiration, uint64_t start, uint64_t period)
{
	AERN_ASSERT(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + start;
		expiration->to = expiration->from + period;
	}
}

bool aern_certificate_expiration_time_verify(const aern_certificate_expiration* expiration)
{
	AERN_ASSERT(expiration != NULL);

	uint64_t nsec;
	bool res;

	res = false;

	if (expiration != NULL)
	{
		nsec = qsc_timestamp_datetime_utc();

		if (nsec >= expiration->from && nsec <= expiration->to)
		{
			res = true;
		}
	}

	return res;
}

size_t aern_certificate_message_hash_sign(uint8_t* signature, const uint8_t* sigkey, const uint8_t* message, size_t msglen)
{
	AERN_ASSERT(signature != NULL);
	AERN_ASSERT(sigkey != NULL);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);

	size_t slen;

	slen = 0;

	if (signature != NULL && sigkey != NULL && message != NULL && msglen != 0U)
	{
		uint8_t hash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

		qsc_sha3_compute256(hash, message, msglen);
		aern_signature_sign(signature, &slen, hash, sizeof(hash), sigkey, qsc_acp_generate);
	}

	return slen;
}

bool aern_certificate_root_compare(const aern_root_certificate* a, const aern_root_certificate* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, AERN_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

void aern_certificate_root_create(aern_root_certificate* root, const uint8_t* pubkey, const aern_certificate_expiration* expiration, const char* issuer)
{
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(pubkey != NULL);
	AERN_ASSERT(expiration != NULL);
	AERN_ASSERT(issuer != NULL);

	if (root != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		root->algorithm = (uint8_t)AERN_CONFIGURATION_SET;
		root->version = AERN_ACTIVE_VERSION;
		qsc_stringutils_copy_string(root->issuer, AERN_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&root->expiration, expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(root->verkey, pubkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(root->serial, AERN_CERTIFICATE_SERIAL_SIZE);
	}
}

bool aern_certificate_root_decode(aern_root_certificate* root, const char* enck)
{
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(enck != NULL);

	const char* penc;
	size_t slen;
	bool res;

	res = false;

	if (root != NULL && enck != NULL)
	{
		char tmpvk[AERN_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		penc = enck;
		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_HEADER) + qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_SERIAL_PREFIX) + 1U;
		slen = AERN_CERTIFICATE_SERIAL_SIZE;

		qsc_intutils_hex_to_bin(penc, root->serial, AERN_CERTIFICATE_SERIAL_SIZE * 2U);
		penc += (AERN_CERTIFICATE_SERIAL_SIZE * 2U);

		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_ISSUER_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(root->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX) + 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		root->algorithm = aern_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_VERSION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, AERN_ACTIVE_VERSION_STRING, slen) == true)
		{
			root->version = aern_version_set_one_zero;
		}
		else
		{
			root->version = aern_version_set_none;
		}
		penc += slen;

		penc += qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) + 1U;
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, AERN_ROOT_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(root->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, AERN_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void aern_certificate_root_deserialize(aern_root_certificate* root, const uint8_t* input)
{
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(input != NULL);

	size_t pos;

	if (root != NULL && input != NULL)
	{
		qsc_memutils_copy(root->verkey, input, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(root->issuer, input + pos, AERN_CERTIFICATE_ISSUER_SIZE);
		pos += AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(root->serial, input + pos, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&root->expiration, input + pos, AERN_CERTIFICATE_EXPIRATION_SIZE);
		pos += AERN_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&root->algorithm, input + pos, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&root->version, input + pos, sizeof(uint8_t));
	}
}

size_t aern_certificate_root_encode(char* enck, const aern_root_certificate* root)
{
	AERN_ASSERT(enck != NULL);
	AERN_ASSERT(root != NULL);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && root != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[AERN_CERTIFICATE_SERIAL_SIZE * 2U] = { 0 };
		char tmpvk[AERN_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, AERN_ROOT_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(root->issuer);
		qsc_memutils_copy((enck + spos), root->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(root->serial, hexid, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), AERN_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_ACTIVE_VERSION_STRING);
		qsc_memutils_copy((enck + spos), AERN_ACTIVE_VERSION_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_PUBLICKEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
		slen = AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, AERN_VERIFICATION_KEY_ENCODING_SIZE, root->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), AERN_ROOT_CERTIFICATE_STRING_SIZE - spos, AERN_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), AERN_ROOT_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void aern_certificate_root_erase(aern_root_certificate* root)
{
	AERN_ASSERT(root != NULL);

	if (root != NULL)
	{
		root->algorithm = aern_configuration_set_none;
		root->version = aern_version_set_none;
		qsc_memutils_clear(&root->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_clear(root->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(root->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(root->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	}
}

bool aern_certificate_root_file_to_struct(const char* fpath, aern_root_certificate* root)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL && root != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t sroot[AERN_CERTIFICATE_ROOT_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)sroot, AERN_CERTIFICATE_ROOT_SIZE) == AERN_CERTIFICATE_ROOT_SIZE)
			{
				aern_certificate_root_deserialize(root, sroot);
				res = aern_certificate_root_is_valid(root);
			}
		}
	}

	return res;
}

void aern_certificate_root_hash(uint8_t* output, const aern_root_certificate* root)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(root != NULL);

	if (output != NULL && root != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0U };

		qsc_sha3_initialize(&hstate);
		nbuf[0U] = root->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = root->version;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, root->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, root->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, (const uint8_t*)root->issuer, qsc_stringutils_string_size((const char*)root->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
		qsc_keccak_dispose(&hstate);
	}
}

bool aern_certificate_root_is_valid(const aern_root_certificate* root)
{
	AERN_ASSERT(root != NULL);

	bool res;

	res = false;

	if (root != NULL)
	{
		if (root->algorithm == AERN_CONFIGURATION_SET &&
			root->version == AERN_ACTIVE_VERSION &&
			qsc_memutils_zeroed(root->issuer, AERN_CERTIFICATE_ISSUER_SIZE) == false &&
			qsc_memutils_zeroed(root->serial, AERN_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(root->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= root->expiration.from && nsec <= root->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

void aern_certificate_root_serialize(uint8_t* output, const aern_root_certificate* root)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(root != NULL);

	size_t pos;

	if (output != NULL && root != NULL)
	{
		qsc_memutils_copy(output, root->verkey, AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = AERN_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, root->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		pos += AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, root->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &root->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		pos += AERN_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &root->algorithm, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(output + pos, &root->version, sizeof(uint8_t));
	}
}

size_t aern_certificate_root_sign(aern_child_certificate* child, const aern_root_certificate* root, const uint8_t* rsigkey)
{
	AERN_ASSERT(child != NULL);
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(rsigkey != NULL);

	size_t slen;

	slen = 0U;

	if (child != NULL && root != NULL && rsigkey != NULL)
	{
		uint8_t hash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

		qsc_memutils_copy(child->rootser, root->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		aern_certificate_child_hash(hash, child);
		aern_signature_sign(child->csig, &slen, hash, sizeof(hash), rsigkey, qsc_acp_generate);
	}

	return slen;
}

bool aern_certificate_root_signature_verify(const aern_child_certificate* child, const aern_root_certificate* root)
{
	AERN_ASSERT(child != NULL);
	AERN_ASSERT(root != NULL);

	size_t mlen;
	bool res;

	res = false;
	mlen = 0U;

	if (child != NULL && root != NULL)
	{
		uint8_t msg[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

		res = aern_signature_verify(msg, &mlen, child->csig, AERN_CERTIFICATE_SIGNED_HASH_SIZE, root->verkey);

		if (res == true)
		{
			uint8_t hash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

			aern_certificate_child_hash(hash, child);

			res = qsc_memutils_are_equal(msg, hash, AERN_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool aern_certificate_root_struct_to_file(const char* fpath, const aern_root_certificate* root)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		uint8_t sroot[AERN_CERTIFICATE_ROOT_SIZE] = { 0U };

		aern_certificate_root_serialize(sroot, root);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)sroot, sizeof(sroot));
	}

	return res;
}

void aern_certificate_signature_generate_keypair(aern_signature_keypair* keypair)
{
	AERN_ASSERT(keypair != NULL);

	if (keypair != NULL)
	{
		aern_signature_generate_keypair(keypair->pubkey, keypair->prikey, qsc_acp_generate);
	}
}

size_t aern_certificate_signature_sign_message(uint8_t* signature, const uint8_t* message, size_t msglen, const uint8_t* prikey)
{
	AERN_ASSERT(signature != NULL);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);
	AERN_ASSERT(prikey != NULL);

	size_t slen;

	slen = 0U;

	if (signature != NULL && message != NULL && msglen != 0 && prikey != NULL)
	{
		slen = msglen + AERN_ASYMMETRIC_SIGNATURE_SIZE;
		aern_signature_sign(signature, &slen, message, msglen, prikey, qsc_acp_generate);
	}

	return slen;
}

bool aern_certificate_signature_verify_message(const uint8_t* message, size_t msglen, const uint8_t* signature, size_t siglen, const uint8_t* pubkey)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);
	AERN_ASSERT(signature != NULL);
	AERN_ASSERT(pubkey != NULL);

	size_t mlen;
	bool res;

	res = false;

	if (message != NULL && msglen != 0U && signature != NULL && pubkey != NULL)
	{
		uint8_t tmsg[AERN_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		mlen = AERN_CRYPTO_SYMMETRIC_HASH_SIZE;

		res = aern_signature_verify(tmsg, &mlen, signature, siglen, pubkey);

		if (res == true)
		{
			res = qsc_memutils_are_equal(message, tmsg, mlen);
		}
	}

	return res;
}

/** \cond */

#if defined(AERN_DEBUG_TESTS_RUN)
static void get_encoded_sizes()
{
	aern_signature_keypair ckp = { 0 };
	aern_child_certificate child = { 0 };
	aern_signature_keypair skp = { 0 };
	aern_root_certificate root = { 0 };
	aern_certificate_expiration exp = { 0 };
	char cenc[AERN_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };
	char renc[AERN_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };
	char rname[AERN_CERTIFICATE_ISSUER_SIZE] = "ARS-1";
	char name[AERN_PROTOCOL_SET_SIZE] = { 0 };
	size_t len;

	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0, 30);
	aern_certificate_root_create(&root, (const uint8_t*)skp.pubkey, &exp, rname);

	aern_certificate_signature_generate_keypair(&ckp);
	aern_certificate_expiration_set_days(&exp, 0, 100);
	aern_certificate_child_create(&child, (const uint8_t*)ckp.pubkey, &exp, "APS 1", aern_network_designation_aps);
	aern_certificate_root_sign(&child, &root, skp.prikey);

	qsc_consoleutils_print_safe("parameters: ");
	qsc_consoleutils_print_line(AERN_CONFIG_STRING);

	len = qsc_encoding_base64_encoded_size(sizeof(skp.pubkey));
	qsc_consoleutils_print_safe("pk: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = qsc_encoding_base64_encoded_size(sizeof(child.csig));
	qsc_consoleutils_print_safe("sig: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = aern_certificate_child_encode(cenc, &child);
	qsc_consoleutils_print_safe("child: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = aern_certificate_root_encode(renc, &root);
	qsc_consoleutils_print_safe("root: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");
}

static void certificate_child_print(const aern_child_certificate* child)
{
	AERN_ASSERT(child != NULL);

	char cenc[AERN_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };

	aern_certificate_child_encode(cenc, child);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

static void certificate_root_print(const aern_root_certificate* root)
{
	AERN_ASSERT(root != NULL);

	char cenc[AERN_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };

	aern_certificate_root_encode(cenc, root);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

bool aern_certificate_functions_test()
{
	aern_signature_keypair skp = { 0 };
	aern_root_certificate root = { 0 };
	aern_certificate_expiration exp = { 0 };
	bool res;

	qsc_consoleutils_print_line("Printing encoded sizes of certificate fields");
	get_encoded_sizes();

	aern_certificate_signature_generate_keypair(&skp);
	aern_certificate_expiration_set_days(&exp, 0, 30);
	aern_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	res = aern_certificate_root_is_valid(&root);

	certificate_root_print(&root);

	if (res == true)
	{
		aern_root_certificate rcpy = { 0 };
		uint8_t srt[AERN_CERTIFICATE_ROOT_SIZE] = { 0U };
		
		aern_certificate_root_serialize(srt, &root);
		aern_certificate_root_deserialize(&rcpy, srt);
		res = aern_certificate_root_compare(&root, &rcpy);

		if (res == true)
		{
			aern_signature_keypair ckp = { 0 };
			aern_child_certificate child = { 0 };
			aern_child_certificate ccpy = { 0 };

			aern_certificate_signature_generate_keypair(&ckp);
			aern_certificate_expiration_set_days(&exp, 0, 100U);
			aern_certificate_child_create(&child, ckp.pubkey, &exp, "APS 1", aern_network_designation_aps);
			aern_certificate_root_sign(&child, &root, skp.prikey);
			certificate_child_print(&child);
			res = aern_certificate_child_is_valid(&child);

			if (res == true)
			{
				res = aern_certificate_root_signature_verify(&child, &root);

				if (res == true)
				{
					uint8_t sct[AERN_CERTIFICATE_CHILD_SIZE] = { 0U };

					aern_certificate_child_serialize(sct, &child);
					aern_certificate_child_deserialize(&ccpy, sct);
					res = aern_certificate_child_are_equal(&child, &ccpy);
				}
			}
		}
	}

	return res;
}

#endif

/** \endcond */

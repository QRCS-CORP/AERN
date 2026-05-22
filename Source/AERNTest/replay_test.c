#include "replay_test.h"
#include "aern_utils.h"
#include "aern.h"
#include "memutils.h"
#include "timestamp.h"

bool aerntest_replay_policy_test(void)
{
	const uint8_t msg[48U] =
	{
		0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U,
		0xA8U, 0xA9U, 0xAAU, 0xABU, 0xACU, 0xADU, 0xAEU, 0xAFU,
		0xB0U, 0xB1U, 0xB2U, 0xB3U, 0xB4U, 0xB5U, 0xB6U, 0xB7U,
		0xB8U, 0xB9U, 0xBAU, 0xBBU, 0xBCU, 0xBDU, 0xBEU, 0xBFU,
		0xC0U, 0xC1U, 0xC2U, 0xC3U, 0xC4U, 0xC5U, 0xC6U, 0xC7U,
		0xC8U, 0xC9U, 0xCAU, 0xCBU, 0xCCU, 0xCDU, 0xCEU, 0xCFU
	};

	aern_connection_state rxcns = { 0 };
	aern_connection_state txcns = { 0 };
	aern_cipher_keyparams kp = { 0 };
	aern_network_packet badpkt = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	aern_network_packet pkt3 = { 0 };
	uint8_t bbad[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt1[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt2[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt3[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0U };
	uint8_t out[sizeof(msg)] = { 0U };
	size_t outlen;
	size_t pos;
	aern_protocol_errors err;
	bool res;

	badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
	pkt1.pmessage = bpkt1 + AERN_PACKET_HEADER_SIZE;
	pkt2.pmessage = bpkt2 + AERN_PACKET_HEADER_SIZE;
	pkt3.pmessage = bpkt3 + AERN_PACKET_HEADER_SIZE;
	outlen = 0U;
	res = true;

	for (pos = 0U; pos < sizeof(key); ++pos)
	{
		key[pos] = (uint8_t)(pos + 1U);
	}

	for (pos = 0U; pos < sizeof(nonce); ++pos)
	{
		nonce[pos] = (uint8_t)(0xD0U + pos);
	}

	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;

	txcns.exflag = aern_network_flag_tunnel_session_established;
	rxcns.exflag = aern_network_flag_tunnel_session_established;
	aern_cipher_initialize(&txcns.txcpr, &kp, true);
	aern_cipher_initialize(&rxcns.rxcpr, &kp, false);

	err = aern_encrypt_packet(&txcns, &pkt1, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt1.sequence == 1U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt1);
	res = (res == true && err == aern_protocol_error_none && outlen == sizeof(msg));
	res = (res == true && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	res = (res == true && rxcns.rxseq == 1U && rxcns.authfail == 0U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt1);
	res = (res == true && err == aern_protocol_error_packet_unsequenced);
	res = (res == true && rxcns.rxseq == 1U && rxcns.authfail == 0U && outlen == 0U);

	err = aern_encrypt_packet(&txcns, &pkt2, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt2.sequence == 2U);

	qsc_memutils_clear(out, sizeof(out));
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt2);
	res = (res == true && err == aern_protocol_error_none && outlen == sizeof(msg));
	res = (res == true && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	res = (res == true && rxcns.rxseq == 2U && rxcns.authfail == 0U);

	err = aern_encrypt_packet(&txcns, &pkt3, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt3.sequence == 3U);

	badpkt.flag = pkt3.flag;
	badpkt.msglen = pkt3.msglen;
	badpkt.sequence = pkt3.sequence;
	badpkt.utctime = pkt3.utctime;
	qsc_memutils_copy(badpkt.pmessage, pkt3.pmessage, pkt3.msglen);
	badpkt.pmessage[badpkt.msglen - 1U] ^= 0x01U;

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
	res = (res == true && err == aern_protocol_error_authentication_failure);
	res = (res == true && rxcns.rxseq == 2U && rxcns.authfail == 1U && outlen == 0U);

	/* an authenticated decrypt failure must restore the receive RCS MAC
	 * state. the valid packet at the same sequence is therefore still
	 * accepted after the tampered packet is rejected. */

	qsc_memutils_clear(out, sizeof(out));
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt3);
	res = (res == true && err == aern_protocol_error_none && outlen == sizeof(msg));
	res = (res == true && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	res = (res == true && rxcns.rxseq == 3U && rxcns.authfail == 0U);

	rxcns.exflag = aern_network_flag_none;
	pkt3.sequence = 4U;
	aern_packet_set_utc_time(&pkt3);
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt3);
	res = (res == true && err == aern_protocol_error_packet_header_invalid);
	res = (res == true && rxcns.rxseq == 3U && outlen == 0U);

	rxcns.rxseq = UINT64_MAX;
	pkt3.sequence = 0U;
	aern_packet_set_utc_time(&pkt3);
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt3);
	res = (res == true && err == aern_protocol_error_channel_down);

	aern_connection_state_dispose(&rxcns);
	aern_connection_state_dispose(&txcns);
	qsc_memutils_clear(bbad, sizeof(bbad));
	qsc_memutils_clear(bpkt1, sizeof(bpkt1));
	qsc_memutils_clear(bpkt2, sizeof(bpkt2));
	qsc_memutils_clear(bpkt3, sizeof(bpkt3));
	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear(out, sizeof(out));

	return res;
}

static bool aerntest_replay_sequence_window_test(void)
{
	const uint8_t msg[32U] =
	{
		0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U,
		0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U,
		0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U,
		0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU, 0x40U
	};

	aern_connection_state rxcns = { 0 };
	aern_connection_state txcns = { 0 };
	aern_cipher_keyparams kp = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	aern_network_packet pkt3 = { 0 };
	aern_network_packet badpkt = { 0 };
	uint8_t bbad[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt1[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt2[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt3[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0U };
	uint8_t out[sizeof(msg)] = { 0U };
	size_t outlen;
	size_t pos;
	aern_protocol_errors err;
	bool res;

	badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
	pkt1.pmessage = bpkt1 + AERN_PACKET_HEADER_SIZE;
	pkt2.pmessage = bpkt2 + AERN_PACKET_HEADER_SIZE;
	pkt3.pmessage = bpkt3 + AERN_PACKET_HEADER_SIZE;
	outlen = 0U;
	res = true;

	for (pos = 0U; pos < sizeof(key); ++pos)
	{
		key[pos] = (uint8_t)(0x41U + pos);
	}

	for (pos = 0U; pos < sizeof(nonce); ++pos)
	{
		nonce[pos] = (uint8_t)(0x91U + pos);
	}

	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;
	txcns.exflag = aern_network_flag_tunnel_session_established;
	rxcns.exflag = aern_network_flag_tunnel_session_established;
	aern_cipher_initialize(&txcns.txcpr, &kp, true);
	aern_cipher_initialize(&rxcns.rxcpr, &kp, false);

	err = aern_encrypt_packet(&txcns, &pkt1, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt1.sequence == 1U);
	err = aern_encrypt_packet(&txcns, &pkt2, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt2.sequence == 2U);
	err = aern_encrypt_packet(&txcns, &pkt3, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt3.sequence == 3U);

	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt1);
	res = (res == true && err == aern_protocol_error_none && rxcns.rxseq == 1U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt1);
	res = (res == true && err == aern_protocol_error_packet_unsequenced && rxcns.rxseq == 1U && outlen == 0U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt3);
	res = (res == true && err == aern_protocol_error_packet_unsequenced && rxcns.rxseq == 1U && outlen == 0U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt2);
	res = (res == true && err == aern_protocol_error_none && rxcns.rxseq == 2U && outlen == sizeof(msg));

	badpkt.flag = pkt2.flag;
	badpkt.msglen = pkt2.msglen;
	badpkt.sequence = 0U;
	badpkt.utctime = pkt2.utctime;
	qsc_memutils_copy(badpkt.pmessage, pkt2.pmessage, pkt2.msglen);
	aern_packet_set_utc_time(&badpkt);
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
	res = (res == true && err == aern_protocol_error_packet_unsequenced && rxcns.rxseq == 2U && outlen == 0U);

	badpkt.flag = pkt3.flag;
	badpkt.msglen = pkt3.msglen;
	badpkt.sequence = UINT64_MAX;
	badpkt.utctime = pkt3.utctime;
	qsc_memutils_copy(badpkt.pmessage, pkt3.pmessage, pkt3.msglen);
	aern_packet_set_utc_time(&badpkt);
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
	res = (res == true && err == aern_protocol_error_packet_unsequenced && rxcns.rxseq == 2U && outlen == 0U);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt3);
	res = (res == true && err == aern_protocol_error_none && rxcns.rxseq == 3U && outlen == sizeof(msg));

	rxcns.rxseq = UINT64_MAX;
	badpkt.flag = pkt3.flag;
	badpkt.msglen = pkt3.msglen;
	badpkt.sequence = 0U;
	badpkt.utctime = pkt3.utctime;
	qsc_memutils_copy(badpkt.pmessage, pkt3.pmessage, pkt3.msglen);
	aern_packet_set_utc_time(&badpkt);
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
	res = (res == true && err == aern_protocol_error_channel_down && outlen == 0U);

	aern_connection_state_dispose(&rxcns);
	aern_connection_state_dispose(&txcns);
	qsc_memutils_clear(bbad, sizeof(bbad));
	qsc_memutils_clear(bpkt1, sizeof(bpkt1));
	qsc_memutils_clear(bpkt2, sizeof(bpkt2));
	qsc_memutils_clear(bpkt3, sizeof(bpkt3));
	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear(out, sizeof(out));

	return res;
}

static bool aerntest_replay_authenticated_header_restore_test(void)
{
	const uint8_t msg[40U] =
	{
		0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U, 0x58U,
		0x59U, 0x5AU, 0x5BU, 0x5CU, 0x5DU, 0x5EU, 0x5FU, 0x60U,
		0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U,
		0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
		0x71U, 0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U
	};

	aern_connection_state rxcns = { 0 };
	aern_connection_state txcns = { 0 };
	aern_cipher_keyparams kp = { 0 };
	aern_network_packet badpkt = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t bbad[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0U };
	uint8_t out[sizeof(msg)] = { 0U };
	size_t outlen;
	size_t pos;
	aern_protocol_errors err;
	bool res;

	badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;
	outlen = 0U;
	res = true;

	for (pos = 0U; pos < sizeof(key); ++pos)
	{
		key[pos] = (uint8_t)(0x11U + pos);
	}

	for (pos = 0U; pos < sizeof(nonce); ++pos)
	{
		nonce[pos] = (uint8_t)(0x81U + pos);
	}

	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;
	txcns.exflag = aern_network_flag_tunnel_session_established;
	rxcns.exflag = aern_network_flag_tunnel_session_established;
	aern_cipher_initialize(&txcns.txcpr, &kp, true);
	aern_cipher_initialize(&rxcns.rxcpr, &kp, false);

	err = aern_encrypt_packet(&txcns, &pkt, msg, sizeof(msg));
	res = (res == true && err == aern_protocol_error_none && pkt.sequence == 1U);

	badpkt.flag = aern_network_flag_system_error_condition;
	badpkt.msglen = pkt.msglen;
	badpkt.sequence = pkt.sequence;
	badpkt.utctime = pkt.utctime;
	qsc_memutils_copy(badpkt.pmessage, pkt.pmessage, pkt.msglen);

	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
	res = (res == true && err == aern_protocol_error_authentication_failure);
	res = (res == true && rxcns.rxseq == 0U && rxcns.authfail == 1U && outlen == 0U);

	qsc_memutils_clear(out, sizeof(out));
	outlen = 0U;
	err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt);
	res = (res == true && err == aern_protocol_error_none && outlen == sizeof(msg));
	res = (res == true && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	res = (res == true && rxcns.rxseq == 1U && rxcns.authfail == 0U);

	aern_connection_state_dispose(&rxcns);
	aern_connection_state_dispose(&txcns);
	qsc_memutils_clear(bbad, sizeof(bbad));
	qsc_memutils_clear(bpkt, sizeof(bpkt));
	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear(out, sizeof(out));

	return res;
}

static bool aerntest_replay_encrypted_tunnel_load_recovery_test(void)
{
	aern_connection_state rxcns = { 0 };
	aern_connection_state txcns = { 0 };
	aern_cipher_keyparams kp = { 0 };
	aern_network_packet badpkt = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t bbad[AERN_PACKET_HEADER_SIZE + 96U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt[AERN_PACKET_HEADER_SIZE + 96U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t msg[96U] = { 0U };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0U };
	uint8_t out[96U] = { 0U };
	size_t outlen;
	size_t pos;
	uint32_t i;
	aern_protocol_errors err;
	bool res;

	badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;
	outlen = 0U;
	res = true;

	for (pos = 0U; pos < sizeof(key); ++pos)
	{
		key[pos] = (uint8_t)(0x31U + pos);
	}

	for (pos = 0U; pos < sizeof(nonce); ++pos)
	{
		nonce[pos] = (uint8_t)(0xB1U + pos);
	}

	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;
	txcns.exflag = aern_network_flag_tunnel_session_established;
	rxcns.exflag = aern_network_flag_tunnel_session_established;
	aern_cipher_initialize(&txcns.txcpr, &kp, true);
	aern_cipher_initialize(&rxcns.rxcpr, &kp, false);

	for (i = 0U; i < 64U && res == true; ++i)
	{
		for (pos = 0U; pos < sizeof(msg); ++pos)
		{
			msg[pos] = (uint8_t)(i + pos);
		}

		qsc_memutils_clear(bpkt, sizeof(bpkt));
		qsc_memutils_clear(bbad, sizeof(bbad));
		qsc_memutils_clear(out, sizeof(out));
		pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;
		badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;

		err = aern_encrypt_packet(&txcns, &pkt, msg, sizeof(msg));
		res = (err == aern_protocol_error_none && pkt.sequence == (uint64_t)(i + 1U));

		if (res == true && (i % 8U) == 3U)
		{
			badpkt.flag = pkt.flag;
			badpkt.msglen = pkt.msglen;
			badpkt.sequence = pkt.sequence;
			badpkt.utctime = pkt.utctime;
			qsc_memutils_copy(badpkt.pmessage, pkt.pmessage, pkt.msglen);
			badpkt.pmessage[0U] ^= 0x55U;

			outlen = 0U;
			err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);
			res = (err == aern_protocol_error_authentication_failure && rxcns.rxseq == i && rxcns.authfail == 1U && outlen == 0U);
			qsc_memutils_clear(out, sizeof(out));
		}

		if (res == true)
		{
			outlen = 0U;
			err = aern_decrypt_packet(&rxcns, out, &outlen, &pkt);
			res = (err == aern_protocol_error_none && outlen == sizeof(msg));
			res = (res == true && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
			res = (res == true && rxcns.rxseq == (uint64_t)(i + 1U) && rxcns.authfail == 0U);
		}
	}

	aern_connection_state_dispose(&rxcns);
	aern_connection_state_dispose(&txcns);
	qsc_memutils_clear(bbad, sizeof(bbad));
	qsc_memutils_clear(bpkt, sizeof(bpkt));
	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(msg, sizeof(msg));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear(out, sizeof(out));

	return res;
}

static bool aerntest_replay_auth_failure_limit_test(void)
{
	const uint8_t msg[48U] =
	{
		0x81U, 0x82U, 0x83U, 0x84U, 0x85U, 0x86U, 0x87U, 0x88U,
		0x89U, 0x8AU, 0x8BU, 0x8CU, 0x8DU, 0x8EU, 0x8FU, 0x90U,
		0x91U, 0x92U, 0x93U, 0x94U, 0x95U, 0x96U, 0x97U, 0x98U,
		0x99U, 0x9AU, 0x9BU, 0x9CU, 0x9DU, 0x9EU, 0x9FU, 0xA0U,
		0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U, 0xA8U,
		0xA9U, 0xAAU, 0xABU, 0xACU, 0xADU, 0xAEU, 0xAFU, 0xB0U
	};

	aern_connection_state rxcns = { 0 };
	aern_connection_state txcns = { 0 };
	aern_cipher_keyparams kp = { 0 };
	aern_network_packet badpkt = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t bbad[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t bpkt[AERN_PACKET_HEADER_SIZE + sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0U };
	uint8_t out[sizeof(msg)] = { 0U };
	size_t outlen;
	size_t pos;
	uint32_t i;
	aern_protocol_errors err;
	bool res;

	badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;
	outlen = 0U;
	res = true;

	for (pos = 0U; pos < sizeof(key); ++pos)
	{
		key[pos] = (uint8_t)(0x61U + pos);
	}

	for (pos = 0U; pos < sizeof(nonce); ++pos)
	{
		nonce[pos] = (uint8_t)(0xC1U + pos);
	}

	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;
	txcns.exflag = aern_network_flag_tunnel_session_established;
	rxcns.exflag = aern_network_flag_tunnel_session_established;
	aern_cipher_initialize(&txcns.txcpr, &kp, true);
	aern_cipher_initialize(&rxcns.rxcpr, &kp, false);

	err = aern_encrypt_packet(&txcns, &pkt, msg, sizeof(msg));
	res = (err == aern_protocol_error_none && pkt.sequence == 1U);

	for (i = 0U; i < AERN_RELAY_AUTH_FAILURE_LIMIT && res == true; ++i)
	{
		qsc_memutils_clear(bbad, sizeof(bbad));
		badpkt.pmessage = bbad + AERN_PACKET_HEADER_SIZE;
		badpkt.flag = pkt.flag;
		badpkt.msglen = pkt.msglen;
		badpkt.sequence = pkt.sequence;
		badpkt.utctime = pkt.utctime;
		qsc_memutils_copy(badpkt.pmessage, pkt.pmessage, pkt.msglen);
		badpkt.pmessage[badpkt.msglen - 1U] ^= (uint8_t)(i + 1U);

		qsc_memutils_clear(out, sizeof(out));
		outlen = 0U;
		err = aern_decrypt_packet(&rxcns, out, &outlen, &badpkt);

		if (i + 1U < AERN_RELAY_AUTH_FAILURE_LIMIT)
		{
			res = (err == aern_protocol_error_authentication_failure);
		}
		else
		{
			res = (err == aern_protocol_error_channel_down);
		}

		res = (res == true && rxcns.rxseq == 0U);
		res = (res == true && rxcns.authfail == (i + 1U));
		res = (res == true && outlen == 0U);
	}

	aern_connection_state_dispose(&rxcns);
	aern_connection_state_dispose(&txcns);
	qsc_memutils_clear(bbad, sizeof(bbad));
	qsc_memutils_clear(bpkt, sizeof(bpkt));
	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear(out, sizeof(out));

	return res;
}

static bool aerntest_packet_time_boundary_test(void)
{
	aern_network_packet pkt = { 0 };
	uint64_t tnow;
	bool res;

	qsc_memutils_clear(&pkt, sizeof(pkt));
	tnow = qsc_timestamp_datetime_utc();
	res = false;

	pkt.utctime = tnow;

	if (aern_packet_time_valid(&pkt) == true)
	{
		pkt.utctime = tnow + (AERN_PACKET_TIME_THRESHOLD - 1U);

		if (aern_packet_time_valid(&pkt) == true)
		{
			pkt.utctime = tnow + AERN_PACKET_TIME_THRESHOLD + 2U;

			if (aern_packet_time_valid(&pkt) == false)
			{
				if (tnow > (AERN_PACKET_TIME_THRESHOLD + 2U))
				{
					pkt.utctime = tnow - (AERN_PACKET_TIME_THRESHOLD - 1U);

					if (aern_packet_time_valid(&pkt) == true)
					{
						pkt.utctime = tnow - (AERN_PACKET_TIME_THRESHOLD + 2U);
						res = (aern_packet_time_valid(&pkt) == false);
					}
				}
			}
		}
	}

	qsc_memutils_clear(&pkt, sizeof(pkt));

	return res;
}

bool aerntest_replay_run(void)
{
	bool res;

	res = true;

	if (aerntest_replay_policy_test() == true)
	{
		aerntest_print_line("[PASS] AERN replay policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN replay policy test.");
		res = false;
	}

	if (aerntest_packet_time_boundary_test() == true)
	{
		aerntest_print_line("[PASS] AERN packet time boundary test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN packet time boundary test.");
		res = false;
	}

	if (aerntest_replay_sequence_window_test() == true)
	{
		aerntest_print_line("[PASS] AERN replay sequence window test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN replay sequence window test.");
		res = false;
	}

	if (aerntest_replay_authenticated_header_restore_test() == true)
	{
		aerntest_print_line("[PASS] AERN authenticated header restore test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN authenticated header restore test.");
		res = false;
	}

	if (aerntest_replay_encrypted_tunnel_load_recovery_test() == true)
	{
		aerntest_print_line("[PASS] AERN encrypted tunnel load recovery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN encrypted tunnel load recovery test.");
		res = false;
	}

	if (aerntest_replay_auth_failure_limit_test() == true)
	{
		aerntest_print_line("[PASS] AERN authentication failure limit test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN authentication failure limit test.");
		res = false;
	}

	return res;
}

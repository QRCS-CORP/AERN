#include "network.h"
#include "aern.h"
#include "certificate.h"
#include "topology.h"
#include "acp.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "netutils.h"
#include "socketclient.h"
#include "timestamp.h"

#define NETWORK_NODE_COMPRESSED_SIZE (AERN_CERTIFICATE_ISSUER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_HASH_SIZE)
#define NETWORK_CERTIFICATE_UPDATE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE)

#define NETWORK_ANNOUNCE_REQUEST_SEQUENCE 0xFFFFFF00UL
#define NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE)

#define NETWORK_CONVERGE_REQUEST_SEQUENCE 0xFFFFFF01UL
#define NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE)
#define NETWORK_CONVERGE_RESPONSE_SEQUENCE 0xFFFFFF02UL
#define NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE)
#define NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_UPDATE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE)

#define NETWORK_ERROR_MESSAGE_SIZE 1U
#define NETWORK_ERROR_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_ERROR_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE 0xFFFFFF03UL
#define NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE 0xFFFFFF04UL
#define NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE (AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_COLLECTION_REQUEST_SEQUENCE 0xFFFFFF05UL
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE (NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_SEQUENCE 0xFFFFFF06UL
#define NETWORK_FRAGMENT_QUERY_REQUEST_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_KEY_SIZE)
#define NETWORK_FRAGMENT_QUERY_RESPONSE_SEQUENCE 0xFFFFFF07UL
#define NETWORK_FRAGMENT_QUERY_RESPONSE_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_QUERY_RESPONSE_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_SEQUENCE 0xFFFFFF08UL
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_MESSAGE_SIZE (AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_COLLECTION_RESPONSE_MESSAGE_SIZE)

#define NETWORK_INCREMENTAL_UPDATE_REQUEST_SEQUENCE 0xFFFFFF09UL
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE (AERN_CERTIFICATE_SERIAL_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE 0xFFFFFF0AUL
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE)

#define NETWORK_JOIN_REQUEST_SEQUENCE 0xFFFFFF0BUL
#define NETWORK_JOIN_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_RESPONSE_SEQUENCE 0xFFFFFF0CUL
#define NETWORK_JOIN_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_RESPONSE_MESSAGE_SIZE)

#define NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE 0xFFFFFF0DUL
#define NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE 0xFFFFFF0EUL
#define NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE)

#define NETWORK_MFK_REQUEST_SEQUENCE 0xFFFFFF0FUL
#define NETWORK_MFK_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_REQUEST_MESSAGE_SIZE)
#define NETWORK_MFK_RESPONSE_SEQUENCE 0xFFFFFF10UL
#define NETWORK_MFK_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_ASYMMETRIC_PUBLIC_KEY_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_RESPONSE_MESSAGE_SIZE)
#define NETWORK_MFK_ESTABLISH_SEQUENCE 0xFFFFFF11UL
#define NETWORK_MFK_ESTABLISH_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_ASYMMETRIC_CIPHERTEXT_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_ESTABLISH_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_MFK_ESTABLISH_MESSAGE_SIZE)

#define NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE 0xFFFFFF12UL
#define NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE 0xFFFFFF13UL
#define NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE)

#define NETWORK_RESIGN_REQUEST_SEQUENCE 0xFFFFFF14UL
#define NETWORK_RESIGN_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_RESIGN_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_RESIGN_REQUEST_MESSAGE_SIZE)

#define NETWORK_REVOKE_REQUEST_SEQUENCE 0xFFFFFF15UL
#define NETWORK_REVOKE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REVOKE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_REVOKE_REQUEST_MESSAGE_SIZE)

#define NETWORK_TOPOLOGY_QUERY_SIZE (AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_ISSUER_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE 0xFFFFFF16UL
#define NETWORK_TOPOLOGY_QUERY_REQUEST_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + NETWORK_TOPOLOGY_QUERY_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE 0xFFFFFF17UL
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE)

#define NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE 0xFFFFFF18UL
#define NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE 0xFFFFFF19UL
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE)

#if defined(AERN_NETWORK_COMPRESS_NODE)
static size_t network_compress_node(uint8_t* snode, const aern_topology_node_state* lnode)
{
	AERN_ASSERT(snode != NULL);
	AERN_ASSERT(lnode != NULL);

	size_t pos;

	qsc_memutils_copy(snode, lnode->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
	pos = AERN_CERTIFICATE_ISSUER_SIZE;
	qsc_memutils_copy(snode + pos, lnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);
	pos += AERN_CERTIFICATE_SERIAL_SIZE;
	qsc_memutils_copy(snode + pos, lnode->chash, AERN_CERTIFICATE_HASH_SIZE);
	pos += AERN_CERTIFICATE_HASH_SIZE;

	return pos;
}
#endif

static void network_header_create(aern_network_packet* packetout, aern_network_flags flag, uint64_t sequence, uint32_t msglen)
{
	AERN_ASSERT(packetout != NULL);

	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	aern_packet_set_utc_time(packetout);
}

static aern_protocol_errors network_header_validate(const aern_network_packet* packetin, aern_network_flags flag, uint64_t sequence, uint32_t msglen)
{
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (packetin->flag == aern_network_flag_system_error_condition)
	{
		merr = (aern_protocol_errors)packetin->pmessage[0U];
	}
	else
	{
		if (aern_packet_time_valid(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == flag)
					{
						merr = aern_protocol_error_none;
					}
					else
					{
						merr = aern_protocol_error_invalid_request;
					}
				}
				else
				{
					merr = aern_protocol_error_packet_unsequenced;
				}
			}
			else
			{
				merr = aern_protocol_error_receive_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_message_time_invalid;
		}
	}

	return merr;
}

static void network_subheader_serialize(uint8_t* pstream, const aern_network_packet* packetin)
{
	AERN_ASSERT(pstream != NULL);
	AERN_ASSERT(packetin != NULL);

	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static aern_protocol_errors network_unpack_error(uint8_t* pmsg)
{
	AERN_ASSERT(pmsg != NULL);

	aern_protocol_errors merr;

	merr = aern_protocol_error_receive_failure;

	if (pmsg != NULL)
	{
		aern_network_packet resp = { 0 };

		/* get the server error message */
		aern_packet_header_deserialize(pmsg, &resp);
		resp.pmessage = pmsg + AERN_PACKET_HEADER_SIZE;

		if (resp.flag == aern_network_flag_system_error_condition && resp.pmessage != NULL)
		{
			merr = (aern_protocol_errors)resp.pmessage[0U];
		}
	}

	return merr;
}

static aern_protocol_errors network_certificate_hash_sign(const aern_network_packet* packetout, const uint8_t* sigkey, const aern_child_certificate* ccert)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(sigkey != NULL);
	AERN_ASSERT(ccert != NULL);

	size_t mlen;
	size_t mpos;
	aern_protocol_errors merr;

	/* serialize the packet time-stamp and sequence number and copy it to the message */
	network_subheader_serialize(packetout->pmessage, packetout);
	mpos = AERN_PACKET_SUBHEADER_SIZE;

	/* copy the certificate to the message */
	aern_certificate_child_serialize(packetout->pmessage + mpos, ccert);
	mpos += AERN_CERTIFICATE_CHILD_SIZE;

	/* sign the message */
	mlen = aern_certificate_message_hash_sign(packetout->pmessage + mpos, sigkey, packetout->pmessage, mpos);

	if (mlen == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		merr = aern_protocol_error_none;
	}
	else
	{
		merr = aern_protocol_error_signing_failure;
	}

	return merr;
}

static aern_protocol_errors network_certificate_signed_hash_verify(aern_child_certificate* ccert, const aern_network_packet* packetin, const aern_child_certificate* rcert, const aern_root_certificate* root)
{
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(rcert != NULL);
	AERN_ASSERT(root != NULL);

	aern_protocol_errors merr;

	/* verify the message signature */
	if (aern_certificate_signature_hash_verify(packetin->pmessage + NETWORK_CERTIFICATE_UPDATE_SIZE, AERN_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, NETWORK_CERTIFICATE_UPDATE_SIZE, rcert) == true)
	{
		uint8_t shdr[AERN_PACKET_SUBHEADER_SIZE] = { 0U };

		network_subheader_serialize(shdr, packetin);

		/* compare the sub-header time and sequence values with the signed values */
		if (qsc_memutils_are_equal(shdr, packetin->pmessage, AERN_PACKET_SUBHEADER_SIZE) == true)
		{
			aern_certificate_child_deserialize(ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

			/* validate the certificate format */
			merr = aern_network_certificate_verify(ccert, root);

			if (merr != aern_protocol_error_none)
			{
				qsc_memutils_clear(ccert, sizeof(aern_child_certificate));
			}
		}
		else
		{
			merr = aern_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = aern_protocol_error_authentication_failure;
	}

	return merr;
}

#if defined(AERN_NETWORK_MFK_HASH_CYCLED)
static void network_hash_cycle_mfk(const uint8_t* serial, qsc_collection_state* mfkcol)
{
	AERN_ASSERT(serial != NULL);
	AERN_ASSERT(mfkcol != NULL);

	uint8_t mfkey[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };

	if (qsc_collection_find(mfkcol, mfkey, serial) == true)
	{
		uint8_t ckey[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };

		qsc_shake256_compute(ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE, mfkey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_collection_remove(mfkcol, serial);
		qsc_collection_add(mfkcol, ckey, serial);
	}
}
#endif

static void network_derive_fkey(uint8_t* ckey, const uint8_t* mfk, const uint8_t* lhash, const uint8_t* rhash, const uint8_t* token)
{
	AERN_ASSERT(ckey != NULL);
	AERN_ASSERT(mfk != NULL);
	AERN_ASSERT(lhash != NULL);
	AERN_ASSERT(rhash != NULL);
	AERN_ASSERT(token != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the fragment encryption key */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, lhash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, rhash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, token, AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_512, ckey);
}

static AERN_FUTURE_RESERVED void network_derive_mkey(uint8_t* mkey, const uint8_t* mfk, const uint8_t* lhash, const uint8_t* rhash, const uint8_t* token)
{
	AERN_ASSERT(mkey != NULL);
	AERN_ASSERT(mfk != NULL);
	AERN_ASSERT(lhash != NULL);
	AERN_ASSERT(rhash != NULL);
	AERN_ASSERT(token != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the fragment encryption key */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, lhash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, rhash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, token, AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_256, mkey);
}

static void network_mac_message(uint8_t* mtag, const uint8_t* ckey, const uint8_t* ctxt, size_t ctxlen, const uint8_t* adata)
{
	AERN_ASSERT(mtag != NULL);
	AERN_ASSERT(ckey != NULL);
	AERN_ASSERT(ctxt != NULL);
	AERN_ASSERT(ctxlen != 0U);
	AERN_ASSERT(adata != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the mac tag */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, adata, AERN_PACKET_SUBHEADER_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, ctxt, ctxlen);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_256, mtag);
}

static aern_protocol_errors network_message_hash_sign(const aern_network_packet* packetout, const uint8_t* sigkey, const uint8_t* message, size_t msglen)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(sigkey != NULL);
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(msglen != 0U);

	size_t mlen;
	size_t mpos;
	aern_protocol_errors merr;

	/* serialize the packet time-stamp and sequence number and copy it to the packet */
	network_subheader_serialize(packetout->pmessage, packetout);
	mpos = AERN_PACKET_SUBHEADER_SIZE;

	/* copy the message to the packet */
	qsc_memutils_copy(packetout->pmessage + mpos, message, msglen);
	mpos += msglen;

	/* hash the message and time-stamp and sign the hash */
	mlen = aern_certificate_message_hash_sign(packetout->pmessage + mpos, sigkey, packetout->pmessage, mpos);

	if (mlen == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		merr = aern_protocol_error_none;
	}
	else
	{
		merr = aern_protocol_error_signing_failure;
	}

	return merr;
}

static aern_protocol_errors network_message_signed_hash_verify(uint8_t* message, const aern_network_packet* packetin, const aern_child_certificate* rcert)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(rcert != NULL);

	aern_protocol_errors merr;
	size_t mlen;

	merr = aern_protocol_error_none;
	mlen = packetin->msglen - AERN_CERTIFICATE_SIGNED_HASH_SIZE;

	/* verify the message signature */
	if (aern_certificate_signature_hash_verify(packetin->pmessage + mlen, AERN_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, mlen, rcert) == true)
	{
		uint8_t shdr[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
		
		network_subheader_serialize(shdr, packetin);

		/* compare the sub-header time and sequence values with the signed values */
		if (qsc_memutils_are_equal(shdr, packetin->pmessage, AERN_PACKET_SUBHEADER_SIZE) == true)
		{
			qsc_memutils_copy(message, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE, mlen - AERN_PACKET_SUBHEADER_SIZE);
		}
		else
		{
			merr = aern_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = aern_protocol_error_authentication_failure;
	}

	return merr;
}

/* ADC Announce Request: 
* The ADC broadcasts a hashed and signed certificate of a new APS or IDG to MAS servers and Clients.
* sig = Sign(H(ts | rcert)
* D(rcert | sig)->M
*/

static aern_protocol_errors network_announce_broadcast_packet(aern_network_packet* packetout, const aern_network_announce_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };
	aern_protocol_errors merr;

	/* serialize the node structure */
	aern_topology_node_serialize(snode, state->rnode);

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_network_announce_broadcast, NETWORK_ANNOUNCE_REQUEST_SEQUENCE, NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE);

	/* sign the serialized node and add it to the message */
	merr = network_message_hash_sign(packetout, state->sigkey, snode, AERN_NETWORK_TOPOLOGY_NODE_SIZE);

	return merr;
}

aern_protocol_errors aern_network_announce_broadcast(aern_network_announce_request_state* state)
{
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	if (state != NULL)
	{
		aern_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0U };

		/* create the packet */
		reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
		merr = network_announce_broadcast_packet(&reqt, state);

		/* serialize the header */
		aern_packet_header_serialize(&reqt, sbuf);

		if (merr == aern_protocol_error_none)
		{
			if (state->rnode->designation == aern_network_designation_aps)
			{
				/* broadcast a new aps to clients */
				aern_network_broadcast_message(state->list, sbuf, NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE, aern_network_designation_client);
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Device Announce Response: 
* Verifies the signature of the announce message.
* Performs a packet valid-time check, and compares that time with the signed hash
* of the serialized certificate, time-stamp, and sequence number.
* If the signature and time-stamp checks pass, the certificate is deserialized and passed back to the caller in the function state.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
*/

aern_protocol_errors aern_network_announce_response(aern_network_announce_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		merr = network_header_validate(packetin, aern_network_flag_network_announce_broadcast, NETWORK_ANNOUNCE_REQUEST_SEQUENCE, NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE);

		if (merr == aern_protocol_error_none)
		{
			uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

			/* verify the certificate update */
			merr = network_message_signed_hash_verify(snode, packetin, state->dcert);

			if (merr == aern_protocol_error_none)
			{
				/* serialize the node structure */
				aern_topology_node_deserialize(state->rnode, snode);
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* ADC Convergence Broadcast:
* Network convergence is an administrative event called from the ADC console.
* Each MAS server and APS on the network is sent a copy of their topological node database entry.
* The serialized node entry for the remote device is hashed, and the hash signed by the ADC, and sent to the device.
* The signature is verified by the device using the ADC's public certificate, the local node entry is serialized and hashed,
* and compared with the signed hash. If the hashes match, the entry in the ADC topological database is synchronized, 
* if the entries do not match, the device serializes the current database entry and the certificate, signs them with the current
* signature key, which is signed by the root (ARS), and sends it back to the ADC.
* The ADC verifies the new certificate using the Root public certificate.
* The old entry is purged, a new topological entry is added to the database, and the new certificate is stored.
* Note that the proper proceedure after a certificate update on a MAS or APS, is to resign from the network,
* and then rejoin with the new certificate.
* sig = Sign(H(ts | node)
* D(node | sig)->A,M,I
*/

static aern_protocol_errors network_converge_request_packet(aern_network_packet* packetout, const aern_network_converge_request_state* state, const uint8_t* snode)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(snode != NULL);

	aern_protocol_errors merr;

	if (packetout != NULL && state != NULL && snode != NULL)
	{
		/* create the packet header */
		network_header_create(packetout, aern_network_flag_network_converge_request, NETWORK_CONVERGE_REQUEST_SEQUENCE, NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE);

		/* hash the message and sign the hash */
		merr = network_message_hash_sign(packetout, state->sigkey, snode, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

static aern_protocol_errors network_converge_response_verify(const aern_network_converge_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* inspect the response packet parameters */
		merr = network_header_validate(packetin, aern_network_flag_network_converge_response, NETWORK_CONVERGE_RESPONSE_SEQUENCE, NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE);

		if (merr == aern_protocol_error_none)
		{
			uint8_t rnode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

			/* verify the hash and signature */
			merr = network_message_signed_hash_verify(rnode, packetin, state->rcert);

			/* check that the node descriptions are the same */
			if (merr == aern_protocol_error_none)
			{
				uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

				/* serialize the local node copy */
				aern_topology_node_serialize(snode, state->rnode);

				/* compare nodes for equality */
				if (qsc_memutils_are_equal(snode, rnode, AERN_NETWORK_TOPOLOGY_NODE_SIZE) == true)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_converge_request(const aern_network_converge_request_state* state)
{
	AERN_ASSERT(state != NULL);

	/* the ads loops through MAS and APS nodes in the topology, 
	sending them the signed topological node entry of that device for verification */

	aern_protocol_errors merr;

	merr = aern_protocol_error_memory_allocation;

	if (state != NULL)
	{
		aern_network_packet reqt = { 0 };

		uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

		/* add the serialized topological node to the message */
		if (aern_topology_node_serialize(snode, state->rnode) == AERN_NETWORK_TOPOLOGY_NODE_SIZE)
		{
			uint8_t sbuf[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0U };

			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			/* create a node-specific request packet */
			merr = network_converge_request_packet(&reqt, state, snode);

			if (merr == aern_protocol_error_none)
			{
				qsc_socket csock = { 0 };
				size_t slen;

				aern_packet_header_serialize(&reqt, sbuf);

				/* connect to the remote aps */
				if (aern_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
				{
					/* send the converge request */
					slen = qsc_socket_send(&csock, sbuf, NETWORK_CONVERGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
			
					if (slen == NETWORK_CONVERGE_REQUEST_PACKET_SIZE)
					{
						aern_network_packet resp = { 0 };
						uint8_t rbuf[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0U };
						size_t rlen;

						/* wait for the reply */
						rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

						if (rlen == NETWORK_CONVERGE_RESPONSE_PACKET_SIZE)
						{
							aern_packet_header_deserialize(rbuf, &resp);
							resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

							/* verify the response */
							merr = network_converge_response_verify(state, &resp);
						}
						else
						{
							merr = aern_protocol_error_receive_failure;
						}
					}
					else
					{
						merr = aern_protocol_error_transmit_failure;
					}

					/* shut down the socket */
					aern_network_socket_dispose(&csock);
				}
				else
				{
					merr = aern_protocol_error_connection_failure;
				}
			}
		}
		else
		{
			merr = aern_protocol_error_serialization_failure;
		}
	}

	return merr;
}

/* Convergence Response:
* If the node entry sent from the ADC matches the local node entry in the devices topology list,
* the device signs the serialized node and sends it back to the ADC.
* If the node entries do not match, the device serializes its certificate, hashes the time-stamp and certificate, 
* signs the hash and sends the updated certificate back to the ADC.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
* rnode = node ? M(node, Sign(H(ts | node))->D : M(cert, Sign(H(ts | cert))->D
*/

static aern_protocol_errors network_converge_response_packet(aern_network_packet* packetout, const aern_network_converge_response_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	if (packetout != NULL && state != NULL)
	{
		uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

		/* create the packet header */
		network_header_create(packetout, aern_network_flag_network_converge_response, NETWORK_CONVERGE_RESPONSE_SEQUENCE, NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE);

		/* serialize the node structure */
		aern_topology_node_serialize(snode, state->lnode);

		/* hash the message and sign the hash */
		merr = network_message_hash_sign(packetout, state->sigkey, snode, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}


/* Convergence Response Verify:
* When a node value is identical to the one on the ADC, the database entry is considered to be synchronized.
* The device will serialize its topological node entry, add the time-stamp and sequence number to the message, 
* hash the message, and sign the hash. The message is sent back to the ADC, which verifies the message.
* sig = Sign(H(ts | node)
* A,M,I(node | sig)->D
* rnode = (Vroot(rcert), Vrcert(H(ts | rnode)))
*/

static aern_protocol_errors network_converge_request_verify(const aern_network_converge_response_state* state, const aern_network_packet* packetin)
{
	uint8_t rnode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	aern_protocol_errors merr;

	/* inspect the request packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_network_converge_request, NETWORK_CONVERGE_REQUEST_SEQUENCE, NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		/* verify the ads certificates signature */
		merr = network_message_signed_hash_verify(rnode, packetin, state->rcert);

		if (merr == aern_protocol_error_none)
		{
			uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

			/* serialize the node structure */
			aern_topology_node_serialize(snode, state->lnode);

			/* compare nodes, if they match, send a confirmation */
			if (qsc_memutils_are_equal(snode, rnode, AERN_NETWORK_TOPOLOGY_NODE_SIZE) == true)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_none;
			}
		}
	}

	return merr;
}

aern_protocol_errors aern_network_converge_response(const aern_network_converge_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	/* the MAS, Client, or APS response to a converge request */

	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		merr = network_converge_request_verify(state, packetin);

		if (merr == aern_protocol_error_none)
		{
			aern_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0U };

			resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

			/* no update required, just verify */
			merr = network_converge_response_packet(&resp, state);

			if (merr == aern_protocol_error_none)
			{
				aern_packet_header_serialize(&resp, sbuf);

				/* send the request */
				slen = qsc_socket_send(state->csock, sbuf, NETWORK_CONVERGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_CONVERGE_RESPONSE_PACKET_SIZE)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Key Fragment Exchange Request: 
* Key fragments are exchanged between devices that share master fragment keys.
* The requestor sends the node serial number and a random token to the remote device.
* A(ser, tok)->B
* The responder generates an fkey, encrypts and Macs the fkey, and sends the ciphertext and Mac tag back to the requestor.
* The requestor hashes the shared mfk, the local and remote certificate hashes, and the token to create a key.
* The key is used to verify the Mac code and decrypt the ciphertext.
* k1,k2 = H(mfk | lhash | rhash | tok)
* fkey = Mk2(cpt), Dk1(cpt)
*/

static void network_fkey_request_packet(aern_network_packet* packetout, aern_network_fkey_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	/* the MAS/Client sends the local serial number and a random token */

	network_header_create(packetout, aern_network_flag_fragment_request, NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE);

	/* generate the token */
	qsc_acp_generate(state->token, AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE);

	/* add the local certificate serial number and token to the message */
	qsc_memutils_copy(packetout->pmessage, state->lnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(packetout->pmessage + AERN_CERTIFICATE_SERIAL_SIZE, state->token, AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE);
}

static aern_protocol_errors network_fkey_response_verify(aern_network_fkey_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	merr = network_header_validate(packetin, aern_network_flag_fragment_response, NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE, NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE);

	/* verify the packet parameters */
	if (merr == aern_protocol_error_none)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0U };
		uint8_t shdr[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
		uint8_t mtag[AERN_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		/* derive the session keys k = H(mfk | lhash | rhash | tok ) */
		network_derive_fkey(ckey, state->mfk, state->lnode->chash, state->rnode->chash, state->token);

		/* serialize the packet header */
		network_subheader_serialize(shdr, packetin);

		/* mac the ciphertext and check it against the packet tag */
		network_mac_message(mtag, ckey + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, packetin->msglen - AERN_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);

		if (qsc_memutils_are_equal(mtag, packetin->pmessage + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, AERN_CRYPTO_SYMMETRIC_HASH_SIZE) == true)
		{
			/* decrypt the cipher-text and copy to the fragment key */
			qsc_memutils_xor(ckey, packetin->pmessage, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_copy(state->frag, ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_clear(ckey, sizeof(ckey));
			merr = aern_protocol_error_none;
		}
		else
		{
			merr = aern_protocol_error_authentication_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_fkey_request(aern_network_fkey_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	qsc_socket csock = { 0 };
	aern_protocol_errors merr;

	if (state != NULL)
	{
		/* connect to the remote aps */
		if (aern_network_connect_to_device(&csock, state->rnode->address, aern_network_designation_aps) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE] = { 0U };
			size_t slen;

			/* create the request packet */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_fkey_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			/* send the request */
			slen = qsc_socket_send(&csock, sbuf, NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
			qsc_memutils_clear(sbuf, NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE);

			if (slen == NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE)
			{
				aern_network_packet resp = { 0 };
				uint8_t rbuf[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0U };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE)
				{
					aern_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

					/* verify the message and store the key */
					merr = network_fkey_response_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connect_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Key Fragment Exchange Response: 
* The device uses the node serial number to load the requestors certificate, hashes the master fragment key, the token, 
* local and remote certificates hashes, to produce a symmetric cipher key.
* The hash function derives a keystream, used to mac and xor encrypt a random fragment key.
* fkey = Gen()
* k1,k2 = H(mfk | rhash | lhash | tok)
* cpt = Mk2(Ek1(fkey))
* A(cpt | tag)->M
*/

static aern_protocol_errors network_fkey_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_fkey_response_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* The device hashes the token, local and remote certificate hashes, and the master fragment key.
	   The hash function derives a keystream, used to mac and xor encrypt a random fragmant key. */

	merr = network_header_validate(packetin, aern_network_flag_fragment_request, NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0U };
		uint8_t shdr[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
		uint8_t* ptok;

		ptok = packetin->pmessage + AERN_CERTIFICATE_SERIAL_SIZE;

		/* create the packet header */
		network_header_create(packetout, aern_network_flag_fragment_response, NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE, NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE);

		/* generate the random fragment */
		qsc_acp_generate(state->frag, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

		/* derive the session keys k = H(mfk | lhash | rhash | tok ) */
		network_derive_fkey(ckey, state->mfk, state->rnode->chash, state->lnode->chash, ptok);
			
		/* encrypt the fragment key and copy the cipher-text to the message */
		qsc_memutils_xor(ckey, state->frag, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_memutils_copy(packetout->pmessage, ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

		network_subheader_serialize(shdr, packetout);

		/* mac the ciphertext and check it against the packet tag */
		network_mac_message(packetout->pmessage + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, ckey + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, packetout->pmessage, packetout->msglen - AERN_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);

		merr = aern_protocol_error_none;
	}
	else
	{
		merr = aern_protocol_error_packet_header_invalid;
	}

	return merr;
}

aern_protocol_errors aern_network_fkey_response(aern_network_fkey_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		uint8_t sbuf[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0U };
		aern_network_packet resp = { 0 };

		/* create the response packet */
		resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
		merr = network_fkey_response_packet(&resp, packetin, state);
		aern_packet_header_serialize(&resp, sbuf);

		if (merr == aern_protocol_error_none)
		{
			size_t slen;

			/* send the response message */
			slen = qsc_socket_send(state->csock, sbuf, NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);
			qsc_memutils_clear(sbuf, NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE);

			if (slen == NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Incremental Update Request: 
* Request a public certificate from a device.
* The requestor sends the serial number of the devices certificate, 
* and the responder sends back the signed certificate.
* The requestor deserializes the certificate, checks the Root signature and verifies the certificate.
* The requestor uses the certificate to verify the message hash.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
* If the certificate is verified it is stored in the local cache.
*/

static void network_incremental_update_request_packet(aern_network_packet* packetout, const aern_network_incremental_update_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_incremental_update_request, NETWORK_INCREMENTAL_UPDATE_REQUEST_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE);

	qsc_memutils_copy(packetout->pmessage, state->rnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);
}

static aern_protocol_errors network_incremental_update_verify(const aern_network_incremental_update_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_incremental_update_response, NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);
	}

	return merr;
}

aern_protocol_errors aern_network_incremental_update_request(const aern_network_incremental_update_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };
		aern_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0 };

		if (aern_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			/* create the packet header */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_incremental_update_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };
				aern_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE)
				{
					aern_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

					/* verify the certificate update */
					merr = network_incremental_update_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Incremental Update Response: 
* The device has received a request for its public certificate. 
* The local certificate is serialized and added to the message,
* the message is hashed and signed and sent back to the requestor.
* sig = Sign(H(ts | lcert))
* B(lcert | sig)->A
*/

static aern_protocol_errors network_incremental_update_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, const aern_network_incremental_update_response_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	if (qsc_memutils_are_equal(packetin->pmessage, state->rcert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
	{
		/* create the packet header */
		network_header_create(packetout, aern_network_flag_incremental_update_response, NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE);

		/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
		merr = network_certificate_hash_sign(packetout, state->sigkey, state->rcert);
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_incremental_update_response(const aern_network_incremental_update_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		aern_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };

		resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

		/* create the update response packet */
		merr = network_incremental_update_response_packet(&resp, packetin, state);

		if (merr == aern_protocol_error_none)
		{
			size_t mlen;

			aern_packet_header_serialize(&resp, sbuf);

			/* send the response to the requestor */
			mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* MFK Exchange Request: 
* The MAS/Client sends the remote aps its root-signed certificate.
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the APS.
* M(lcert | Sign(H(ts | lcert)))->A
* The MAS/Client receive a signed asymmetric public cipher key and time-stamp. The message is verified,
* and the public cipher key is used to encapsulate a shared secret.
* Vrcert(H(ts | pk))
* cpt = Epk(mfk)
* M(cpt | Sign(H(cpt))->A
*/

static aern_protocol_errors network_mfk_request_packet(aern_network_packet* packetout, const aern_network_mfk_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* the server sends the remote apss certificate serial number and its serialized certificate */

	/* create the mfk request header */
	network_header_create(packetout, aern_network_flag_mfk_request, NETWORK_MFK_REQUEST_SEQUENCE, NETWORK_MFK_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);

	return merr;
}

static aern_protocol_errors network_mfk_establish_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_mfk_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* The server verifies the signature hash of the cipher public key, generates the cipher-text and stores the key.
	   The server signs the ciphertext hash and adds the signature and cipher-text to the message */

	/* check packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_mfk_response, NETWORK_MFK_RESPONSE_SEQUENCE, NETWORK_MFK_RESPONSE_MESSAGE_SIZE);
	
	if (merr == aern_protocol_error_none)
	{
		uint8_t pbk[AERN_ASYMMETRIC_PUBLIC_KEY_SIZE] = { 0U };

		merr = network_message_signed_hash_verify(pbk, packetin, state->rcert);

		if (merr == aern_protocol_error_none)
		{
			uint8_t cpt[AERN_ASYMMETRIC_CIPHERTEXT_SIZE] = { 0U };

			/* create the mfk establish packet */
			network_header_create(packetout, aern_network_flag_mfk_establish, NETWORK_MFK_ESTABLISH_SEQUENCE, NETWORK_MFK_ESTABLISH_MESSAGE_SIZE);

			/* create the shared secret and cipher-text */
			aern_cipher_encapsulate(state->mfk, cpt, pbk, qsc_acp_generate);

			/* hash the message and sign the hash */
			merr = network_message_hash_sign(packetout, state->sigkey, cpt, AERN_ASYMMETRIC_CIPHERTEXT_SIZE);
		}
		else
		{
			merr = aern_protocol_error_authentication_failure;
		}
	}

	return merr;
}

aern_protocol_errors aern_network_mfk_exchange_request(aern_network_mfk_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	qsc_socket csock = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t sbuf[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0 };
	size_t rlen;
	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL)
	{
		if (aern_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			/* create the mfk request packet */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_mfk_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			/* send the mfk request */
			slen = qsc_socket_send(&csock, sbuf, NETWORK_MFK_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_MFK_REQUEST_PACKET_SIZE)
			{
				/* allocate the receive buffer */
				uint8_t rbuf[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };

				/* receive the mfk response packet */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_MFK_RESPONSE_PACKET_SIZE)
				{
					aern_network_packet resp = { 0 };
					uint8_t ebuf[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };

					reqt.pmessage = ebuf + AERN_PACKET_HEADER_SIZE;

					aern_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

					/* create the mfk establish packet */
					merr = network_mfk_establish_packet(&reqt, &resp, state);

					if (merr == aern_protocol_error_none)
					{
						aern_packet_header_serialize(&reqt, ebuf);

						/* send the establish message */
						slen = qsc_socket_send(&csock, ebuf, NETWORK_MFK_ESTABLISH_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == NETWORK_MFK_ESTABLISH_PACKET_SIZE)
						{
							merr = aern_protocol_error_none;
						}
						else
						{
							merr = aern_protocol_error_transmit_failure;
						}
					}
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* MFK Exchange Response: 
* The APS validates the requestors certificate Root signature, and uses the certificate to verify the message signature and time-stamp.
* rcert = Vroot(rcert), Vrcert(ts | msg)
* The APS generates an asymmetric cipher key-pair, adds the public key to the message, hashes the key and timestamp,
* and signs the hash.
* pk,sk = G()
* A(ts | pk | Sign(H(ts | pk)))->M
* The APS receives the signed cipher-text, verifies the hash signature, and decrypts the shared secret.
* Vrcert(H(ts | cpt)),
* mfk = Dsk(cpt)
*/

static aern_protocol_errors network_mfk_response_packet(aern_network_packet* packetout, const aern_network_packet* packetin, aern_network_mfk_response_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_mfk_request, NETWORK_MFK_REQUEST_SEQUENCE, NETWORK_MFK_REQUEST_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

		/* the aps verifies the certificate */
		if (merr == aern_protocol_error_none)
		{
			/* The device generates a cipher key-pair, copies the public key to the packet,
				hashes the public key, signs the hash, and adds it to the message */

			/* create the packet header */
			network_header_create(packetout, aern_network_flag_mfk_response, NETWORK_MFK_RESPONSE_SEQUENCE, NETWORK_MFK_RESPONSE_MESSAGE_SIZE);

			/* initialize the asymmetric cipher keys */
			qsc_memutils_clear(state->ckp.pubkey, AERN_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_clear(state->ckp.prikey, AERN_ASYMMETRIC_PRIVATE_KEY_SIZE);

			/* generate the asymmetric keypair and copy the public encapsulation key to the message */
			aern_cipher_generate_keypair(state->ckp.pubkey, state->ckp.prikey, qsc_acp_generate);

			/* add the public key and timestamp to the message, then hash the message, sign the hash, and append the signature */
			merr = network_message_hash_sign(packetout, state->sigkey, state->ckp.pubkey, AERN_ASYMMETRIC_PUBLIC_KEY_SIZE);
		}
		else
		{
			merr = aern_protocol_error_authentication_failure;
		}
	}

	return merr;
}

static aern_protocol_errors network_mfk_verify_packet(const aern_network_packet* packetin, aern_network_mfk_response_state* state)
{
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* The aps verifies the cipher-text using the server's certificate, 
	 * and decapsulates the master fragment key */

	/* vaidate the packet header */
	merr = network_header_validate(packetin, aern_network_flag_mfk_establish, NETWORK_MFK_ESTABLISH_SEQUENCE, NETWORK_MFK_ESTABLISH_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		uint8_t cpt[AERN_ASYMMETRIC_CIPHERTEXT_SIZE] = { 0U };

		merr = network_message_signed_hash_verify(cpt, packetin, state->rcert);

		if (merr == aern_protocol_error_none)
		{
			if (aern_cipher_decapsulate(state->mfk, cpt, state->ckp.prikey) == true)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_decapsulation_failure;
			}
		}
	}

	return merr;
}

aern_protocol_errors aern_network_mfk_exchange_response(aern_network_mfk_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	size_t rlen;
	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		aern_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };

		resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

		/* create the mfk response packet */
		merr = network_mfk_response_packet(&resp, packetin, state);

		/* serialize the header */
		aern_packet_header_serialize(&resp, sbuf);

		/* send the establish message */
		slen = qsc_socket_send(state->csock, sbuf, NETWORK_MFK_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == NETWORK_MFK_RESPONSE_PACKET_SIZE)
		{
			/* allocate the receive buffer */
			uint8_t rbuf[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };

			/* receive the establish packet */
			rlen = qsc_socket_receive(state->csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

			if (rlen == NETWORK_MFK_ESTABLISH_PACKET_SIZE)
			{
				aern_network_packet rest = { 0 };

				aern_packet_header_deserialize(rbuf, &rest);
				rest.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

				/* verify the ciphertext and decapsulate the shared secret */
				merr = network_mfk_verify_packet(&rest, state);
			}
			else if (rlen == NETWORK_ERROR_PACKET_SIZE)
			{
				/* get the server error from the packet */
				merr = network_unpack_error(rbuf);
			}
			else
			{
				merr = aern_protocol_error_receive_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_transmit_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}
	return merr;
}

/* Network Join Request:
* When an APS joins the network, it sends a copy of its certificate, signed by the Root. 
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the ADC.
* sig = Sign(H(ts | lcert))
* A(lcert | sig)->D
* The APS receives the signed ADC certificate, verifies the certificates Root signature, and then uses the certificate 
* to verify the message and time-stamp.
* rcert = Vroot(rcert), Vrcert(ts | rcert)
*/

static aern_protocol_errors network_register_request_packet(aern_network_packet* packetout, const aern_network_register_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_register_request, NETWORK_JOIN_REQUEST_SEQUENCE, NETWORK_JOIN_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);
	
	return merr;
}

static aern_protocol_errors network_register_verify(aern_network_register_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	merr = network_header_validate(packetin, aern_network_flag_register_response, NETWORK_JOIN_RESPONSE_SEQUENCE, NETWORK_JOIN_RESPONSE_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);
	}

	return merr;
}

aern_protocol_errors aern_network_register_request(aern_network_register_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	/* Send an aps network join request to the ADC.
	   The message is the callers root-signed certificate. */

	qsc_socket csock = { 0 };
	aern_protocol_errors merr;

	if (state != NULL)
	{
		if (aern_network_connect_to_device(&csock, state->address, aern_network_designation_ads) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
			size_t mlen;

			/* create the join request packet */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_register_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			/* send the join request to the ads */
			mlen = qsc_socket_client_send(&csock, sbuf, NETWORK_JOIN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_JOIN_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };
				aern_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);
				resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

				if (rlen == NETWORK_JOIN_RESPONSE_PACKET_SIZE)
				{
					/* deseialize the response packet */
					aern_packet_header_deserialize(rbuf, &resp);

					/* verify the response packet */
					merr = network_register_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Network Join Response: 
* The ADC verifies the apss certificate, then sends a copy of its own root-signed certificate, and adds the device to the topology.
* rcert = Vroot(rcert), Vrcert(ts | rcert)
* D(lcert | Sign(H(ts | lcert)))->A
*/

static aern_protocol_errors network_register_response_packet(aern_network_packet* packetout, aern_network_register_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	/* validate the packet header */
	merr = network_header_validate(packetin, aern_network_flag_register_request, NETWORK_JOIN_REQUEST_SEQUENCE, NETWORK_JOIN_REQUEST_MESSAGE_SIZE);

	/* inspect the request packet parameters */
	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		/* verify the root certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

		if (merr == aern_protocol_error_none)
		{
			/* create the packet header */
			network_header_create(packetout, aern_network_flag_register_response, NETWORK_JOIN_RESPONSE_SEQUENCE, NETWORK_JOIN_RESPONSE_MESSAGE_SIZE);

			/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
			merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);
		}
	}

	return merr;
}

aern_protocol_errors aern_network_register_response(aern_network_register_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	/* The ADC network join response.
	   When the requests comes from an aps, the ADC verifies the root signature of the aps,
	   and sends its own certificate in the response. */

	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		aern_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };

		/* apss are sent only the root-signed ads certificate */
		resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
		merr = network_register_response_packet(&resp, state, packetin);

		if (merr == aern_protocol_error_none)
		{
			aern_packet_header_serialize(&resp, sbuf);

			slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_JOIN_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_JOIN_RESPONSE_PACKET_SIZE)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Network Join Update Request: 
* When an MAS or Client joins the network, it sends a copy of its certificate, signed by the Root.
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the ADC.
* A(lcert | Sign(H(ts | lcert)))->D
* The MAS/Client verifies the ADC certificate, stores the certificate and adds the ADC to the topology.
* It also receives an update, containing a list of serialized APS nodes, which it uses
* to contact each APS and request a certificate copy.
* The update message and a time-stamp are hashed, and the hash is signed.
* msg = Vroot(rcert), Vrcert(ts | msg)
* topology Add(msg)
*/

static aern_protocol_errors network_register_update_request_packet(aern_network_packet* packetout, const aern_network_register_update_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* create the update request header */
	network_header_create(packetout, aern_network_flag_register_update_request, NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE, NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);

	return merr;
}

static aern_protocol_errors network_register_update_verify(aern_network_register_update_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (packetin->flag == aern_network_flag_register_update_response &&
		packetin->sequence == NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE)
	{
		if (aern_packet_time_valid(packetin) == true)
		{
			aern_child_certificate ccert = { 0 };

			/* temp copy of inbound certificate */
			aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

			merr = aern_network_certificate_verify(&ccert, state->root);

			if (merr == aern_protocol_error_none)
			{
				uint8_t* pmsg;
				size_t mlen;

				mlen = packetin->msglen - (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE);
				pmsg = (uint8_t*)qsc_memutils_malloc(mlen);

				if (pmsg != NULL)
				{
					/* verify the ads certificate */
					merr = network_message_signed_hash_verify(pmsg, packetin, &ccert);

					if (merr == aern_protocol_error_none)
					{
						const uint8_t* pnds;

						/* copy the ads certificate */
						qsc_memutils_copy(state->rcert, &ccert, sizeof(aern_child_certificate));

						/* pointer to the topology update list */
						pnds = pmsg + AERN_CERTIFICATE_CHILD_SIZE;
						mlen = packetin->msglen - (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE);

						/* deserialize topological nodes and add to local database */
						aern_topology_list_update_unpack(state->list, pnds, mlen);
						merr = aern_protocol_error_none;
					}

					qsc_memutils_alloc_free(pmsg);
				}
				else
				{
					merr = aern_protocol_error_memory_allocation;
				}
			}
		}
		else
		{
			merr = aern_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_register_update_request(aern_network_register_update_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	/* Send a MAS or client network join request to the ADC.
	   The message is the callers root-signed certificate. */

	aern_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (aern_network_connect_to_device(&csock, state->address, aern_network_designation_ads) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
			size_t slen;

			/* create the join request packet  */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_register_update_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			/* send the join request to the ads */
			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_JOIN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_JOIN_REQUEST_PACKET_SIZE)
			{
				aern_network_packet resp = { 0 };
				uint8_t hdr[AERN_PACKET_HEADER_SIZE] = { 0U };
				uint8_t* rbuf;
				size_t mlen;
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_peek(&csock, hdr, AERN_PACKET_HEADER_SIZE);

				if (rlen >= AERN_PACKET_HEADER_SIZE)
				{
					aern_packet_header_deserialize(hdr, &resp);
					mlen = resp.msglen + AERN_PACKET_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_malloc(mlen);

					if (rbuf != NULL)
					{
						rlen = qsc_socket_receive(&csock, rbuf, mlen, qsc_socket_receive_flag_wait_all);

						if (rlen == mlen && resp.flag == aern_network_flag_register_update_response)
						{
							resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;
							merr = network_register_update_verify(state, &resp);
						}
						else if (rlen == NETWORK_ERROR_PACKET_SIZE)
						{
							/* get the server error from the packet */
							merr = network_unpack_error(rbuf);
						}
						else
						{
							merr = aern_protocol_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						merr = aern_protocol_error_memory_allocation;
					}
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Network Join Update Response: 
* The ADC verifies the MAS/Client certificate Root signature, uses the certificate to verify the message hash,
* adds the device to the topology, and caches the remote certificate.
* The ADC adds its serialized certificate, and a serialized list of APS nodes to the message.
* The ADC hashes the message along with the packet timestamp, and signs the hash.
* D(ts | lcert | update | Sign(H(ts | lcert | update))->M
*/

static aern_protocol_errors network_register_update_response_packet(aern_network_packet* packetout, aern_network_register_update_response_state* state, uint8_t* buffer, const aern_network_packet* packetin)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(buffer != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	merr = network_header_validate(packetin, aern_network_flag_register_update_request, NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE, NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		/* inspect the request packet parameters */
		if (state->rcert->designation == aern_network_designation_client)
		{
			aern_child_certificate ccert = { 0 };

			/* temp copy of inbound certificate */
			aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

			/* verify the certificate signature */
			merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

			/* assemble the updates */
			if (merr == aern_protocol_error_none)
			{
				size_t mlen;
				size_t mpos;
				size_t ncnt;

				/* get the number of apss in the topology */
				ncnt = aern_topology_list_server_count(state->list, aern_network_designation_aps);

				if (ncnt > 0U)
				{
					mlen = NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE;
					mlen += (ncnt * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

					/* resize the buffer to the full update size */
					buffer = (uint8_t*)qsc_memutils_realloc(buffer, mlen);

					if (buffer != NULL)
					{
						mlen -= AERN_PACKET_HEADER_SIZE;
						network_header_create(packetout, aern_network_flag_register_update_response, NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE, (uint32_t)mlen);
						packetout->pmessage = buffer + AERN_PACKET_HEADER_SIZE;

						/* serialize the packet time-stamp and sequence number and copy it to the packet */
						network_subheader_serialize(packetout->pmessage, packetout);
						mpos = AERN_PACKET_SUBHEADER_SIZE;

						/* serialize the ads certificate and add it to the message */
						aern_certificate_child_serialize(packetout->pmessage + mpos, state->lcert);
						mpos += AERN_CERTIFICATE_CHILD_SIZE;

						/* pack the list update */
						mlen = aern_topology_list_update_pack(packetout->pmessage + mpos, state->list, aern_network_designation_aps);
						mpos += mlen;

						/* hash the message and sign the hash */
						mlen = aern_certificate_message_hash_sign(packetout->pmessage + mpos, state->sigkey, packetout->pmessage, mpos);
						
						if (mlen != AERN_CERTIFICATE_SIGNED_HASH_SIZE)
						{
							merr = aern_protocol_error_signature_failure;
						}
					}
				}
				else
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
		}
		else
		{
			merr = aern_protocol_error_invalid_request;
		}
	}

	return merr;
}

aern_protocol_errors aern_network_register_update_response(aern_network_register_update_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	/* The ADC network join response.
	   When the requestor is a server, the ADC packages a list of aps node descriptions,
	   signs the list, and sends it along with the ADC certificate. 
	   The server then contacts unknown aps servers and exchanges master keys. */

	uint8_t* pbuf;
	size_t mlen;
	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		aern_network_packet resp = { 0 };
		pbuf = NULL;

		/* deserialize the remote certificate in the request */
		aern_certificate_child_deserialize(state->rcert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			/* create the update response packet */
			merr = network_register_update_response_packet(&resp, state, pbuf, packetin);

			if (merr == aern_protocol_error_none)
			{
				size_t slen;

				aern_packet_header_serialize(&resp, pbuf);
				mlen = resp.msglen + AERN_PACKET_HEADER_SIZE;

				slen = qsc_socket_client_send(state->csock, pbuf, mlen, qsc_socket_send_flag_none);

				if (slen == mlen)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}

				qsc_memutils_alloc_free(pbuf);
			}
		}
		else
		{
			merr = aern_protocol_error_memory_allocation;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Remote signature request 
* Sent by the ADC to the ARS server to remotely sign a certificate
* D(ts | cert, Sk(H(ts | cert)))->R
*/

static aern_protocol_errors network_remote_signing_request_packet(aern_network_remote_signing_request_state* state, aern_network_packet* packetout)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetout != NULL);

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_network_remote_signing_request, NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE, NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->rcert);
	
	return merr;
}

static aern_protocol_errors network_remote_signing_request_verify(const aern_network_remote_signing_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	merr = network_header_validate(packetin, aern_network_flag_network_remote_signing_response, NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE, NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(state->rcert, packetin->pmessage);

		/* verify the root certificate signature */
		merr = aern_network_certificate_verify(state->rcert, state->root);
	}

	return merr;
}

aern_protocol_errors aern_network_remote_signing_request(aern_network_remote_signing_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	aern_network_packet reqt = { 0 };
	uint8_t sbuf[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0U };
	size_t slen;
	aern_protocol_errors merr;

	if (state != NULL)
	{
		/* create the request packet */
		reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
		merr = network_remote_signing_request_packet(state, &reqt);

		if (merr == aern_protocol_error_none)
		{
			qsc_socket csock = { 0 };

			if (aern_network_connect_to_device(&csock, state->address, aern_network_designation_ars) == qsc_socket_exception_success)
			{
				aern_packet_header_serialize(&reqt, sbuf);

				slen = qsc_socket_client_send(&csock, sbuf, NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE)
				{
					uint8_t rbuf[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0U };
					size_t rlen;

					/* wait for the reply */
					rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

					if (rlen == NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE)
					{
						aern_network_packet resp = { 0 };

						aern_packet_header_deserialize(rbuf, &resp);
						resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

						/* verify the query response message */
						merr = network_remote_signing_request_verify(state, &resp);
					}
					else if (rlen == NETWORK_ERROR_PACKET_SIZE)
					{
						/* get the error from the packet */
						merr = network_unpack_error(rbuf);
					}
					else
					{
						merr = aern_protocol_error_receive_failure;
					}
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}

				aern_network_socket_dispose(&csock);
			}
			else
			{
				merr = aern_protocol_error_connection_failure;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Remote signature response
* Sent by the ARS to the ADC server as a certificate signing response
* R(ts | scert, Sk(H(ts | scert)))->D
*/

static aern_protocol_errors network_remote_signing_response_packet(aern_network_remote_signing_response_state* state, aern_network_packet* packetout)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetout != NULL);

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_network_remote_signing_response, NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE, NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	if (aern_certificate_root_sign(state->rcert, state->root, state->sigkey) == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		/* serialize the signed certificate to the message */
		aern_certificate_child_serialize(packetout->pmessage, state->rcert);
		merr = aern_protocol_error_none;
	}
	else
	{
		merr = aern_protocol_error_signature_failure;
	}

	return merr;
}

static aern_protocol_errors network_remote_signing_response_verify(const aern_network_remote_signing_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	/* validate the packet header */
	merr = network_header_validate(packetin, aern_network_flag_network_remote_signing_request, NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE, NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE);

	/* inspect the request packet parameters */
	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		aern_certificate_child_deserialize(&ccert, packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE);

		/* verify the message signature */
		if (aern_certificate_signature_hash_verify(packetin->pmessage + NETWORK_CERTIFICATE_UPDATE_SIZE, AERN_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, NETWORK_CERTIFICATE_UPDATE_SIZE, state->dcert) == true)
		{
			uint8_t shdr[AERN_PACKET_SUBHEADER_SIZE] = { 0U };

			network_subheader_serialize(shdr, packetin);

			/* compare the sub-header time and sequence values with the signed values */
			if (qsc_memutils_are_equal(shdr, packetin->pmessage, AERN_PACKET_SUBHEADER_SIZE) == false)
			{
				merr = aern_protocol_error_message_time_invalid;
			}
		}
		else
		{
			merr = aern_protocol_error_authentication_failure;
		}

		if (merr == aern_protocol_error_none)
		{
			aern_certificate_child_copy(state->rcert, &ccert);
		}
	}

	return merr;
}

aern_protocol_errors aern_network_remote_signing_response(aern_network_remote_signing_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	
	aern_protocol_errors merr;

	if (state != NULL)
	{
		merr = network_remote_signing_response_verify(state, packetin);

		if (merr == aern_protocol_error_none)
		{
			aern_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0U };
			size_t slen;

			/* create the request packet */
			resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			merr = network_remote_signing_response_packet(state, &resp);

			if (merr == aern_protocol_error_none)
			{
				aern_packet_header_serialize(&resp, sbuf);

				slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}
	
	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Device Resign Request: 
* Sent from an APS/MAS/IDG/Client to the ADC, resigning from the network.
* The ADC verifies the request and broadcasts a revocation message to the network.
* M(ts | ser | Sign(H(ts | ser)))->D
*/

static aern_protocol_errors network_resign_request_packet(aern_network_packet* packetout, const aern_network_resign_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_network_resign_request, NETWORK_RESIGN_REQUEST_SEQUENCE, NETWORK_RESIGN_REQUEST_MESSAGE_SIZE);

	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

aern_protocol_errors aern_network_resign_request(const aern_network_resign_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	aern_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (aern_network_connect_to_device(&csock, state->address, aern_network_designation_ads) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_RESIGN_REQUEST_PACKET_SIZE] = { 0U };
			size_t mlen;

			/* create the request packet */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			merr = network_resign_request_packet(&reqt, state);

			if (merr == aern_protocol_error_none)
			{
				aern_packet_header_serialize(&reqt, sbuf);

				mlen = qsc_socket_client_send(&csock, sbuf, NETWORK_RESIGN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (mlen == NETWORK_RESIGN_REQUEST_PACKET_SIZE)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Device Resign Response: 
* The ADC verifies the hash and signature, finds the node, then assembles a revocation broadcast message.
* The certificate is deleted on remote nodes, and the node is marked as revoked in the ADC topology, 
* and removed from the topology of other devices.
* Vrcert(ts | ser)
* revoke(ts | rcert | Sign(H(ts | rcert)))->...
*/

aern_protocol_errors aern_network_resign_response(aern_network_resign_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* verify the packet */
		merr = network_header_validate(packetin, aern_network_flag_network_resign_request, NETWORK_RESIGN_REQUEST_SEQUENCE, NETWORK_RESIGN_REQUEST_MESSAGE_SIZE);

		if (merr == aern_protocol_error_none)
		{
			uint8_t ser[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };

			merr = network_message_signed_hash_verify(ser, packetin, state->rcert);

			if (merr == aern_protocol_error_none)
			{
				const uint8_t* pser;

				/* find the node in the topological list */
				pser = packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE;

				if (aern_topology_node_find(state->list, state->rnode, pser) == true)
				{
					/* broadcast a certificate revocation message */
					aern_network_revoke_request_state rrs = {
						.designation = state->rnode->designation,
						.list = state->list,
						.rnode = state->rnode,
						.sigkey = state->sigkey
					};

					/* broadcast a certificate revocation to nodes on the network */
					merr = aern_network_revoke_broadcast(&rrs);
				}
				else
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Revocation Broadcast Call: 
* The broadcast revocation of a certificate by the ads.
* APS revocations are sent to servers and clients, and server or idg revocations are sent to the apss.
* D(ts | rcert | Sign(H(ts | rcert)))->...
*/

static aern_protocol_errors network_revoke_packet(aern_network_packet* packetout, const aern_network_revoke_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	/* The message is the certificate number and a time-stamp, both hashed and signed.
	* loop through topology and send to each aern network member.
	* aps revocation is sent to servers and clients, 
	* server and client revocation is sent to apss. */

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_network_revocation_broadcast, NETWORK_REVOKE_REQUEST_SEQUENCE, NETWORK_REVOKE_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate serial number to message, hash, sign the hash, and add the signature to the message */
	merr = network_message_hash_sign(packetout, state->sigkey, state->rnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

aern_protocol_errors aern_network_revoke_broadcast(aern_network_revoke_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	/* The message is the certificate serial number and a time-stamp, both signed.
	* loop through topology and send to each relative member.
	* aps revocation is sent to servers and clients, 
	* server and client revocation is sent to apss. */

	aern_protocol_errors merr;

	if (state != NULL)
	{
		aern_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_REVOKE_REQUEST_PACKET_SIZE] = { 0U };

		reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

		/* create the revocation packet */
		merr = network_revoke_packet(&reqt, state);

		/* send the packet to the type-associated target*/
		if (merr == aern_protocol_error_none)
		{
			aern_packet_header_serialize(&reqt, sbuf);

			if (state->designation == aern_network_designation_aps)
			{
				aern_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, aern_network_designation_client);
			}
			else if (state->designation == aern_network_designation_client)
			{
				aern_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, aern_network_designation_aps);
				aern_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, aern_network_designation_client);
			}
			else if (state->designation == aern_network_designation_all)
			{
				aern_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, aern_network_designation_aps);
				aern_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, aern_network_designation_client);
			}
			else
			{
				merr = aern_protocol_error_invalid_request;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Revocation Broadcast Response: 
* Processes the broadcast revocation of a certificate by the ads.
* APS revocations are sent to MAS and Clients, and MAS or IDG revocations are sent to the APSs.
* The responding device verifies the hash and signature, and removes the certificate and topological node from the database.
* Vrcert(ts | rcert)
* topology Remove(rcert)
*/

aern_protocol_errors aern_network_revoke_response(aern_network_revoke_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* verify the packet */
		merr = network_header_validate(packetin, aern_network_flag_network_revocation_broadcast, NETWORK_REVOKE_REQUEST_SEQUENCE, NETWORK_REVOKE_REQUEST_MESSAGE_SIZE);

		if (merr == aern_protocol_error_none)
		{
			uint8_t ser[AERN_CERTIFICATE_SERIAL_SIZE] = { 0 };

			merr = network_message_signed_hash_verify(ser, packetin, state->dcert);

			/* find the node in the topological list */
			if (aern_topology_node_find(state->list, state->rnode, ser) == true)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_node_not_found;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Query Request: 
* The client-requestor sends the hashed and signed issuer string of a remote node and the local certificate serial number to the ADC.
* C1(ts | serial | issuer | Sign(H(ts | serial | issuer )))->D
* The ADC uses the certificate serial number to load the requestors certificate, and verify the signature.
* The requesting client receives the remote clients node information, and uses it to synchronize certificates,
* and exchange master fragment keys.
*/

static aern_protocol_errors network_topological_query_request_packet(aern_network_packet* packetout, const aern_network_topological_query_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	uint8_t msg[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_topology_query_request, NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE);
	/* copy the requestors serial number and the issuer query string to the message */
	qsc_memutils_copy(msg, state->serial, AERN_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(msg + AERN_CERTIFICATE_SERIAL_SIZE, (uint8_t*)state->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, msg, NETWORK_TOPOLOGY_QUERY_SIZE);

	return merr;
}

static aern_protocol_errors network_topological_query_request_verify(const aern_network_topological_query_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(packetin != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_topology_query_response, NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

		/* verify the certificate signature */
		merr = network_message_signed_hash_verify(snode, packetin, state->dcert);

		if (merr == aern_protocol_error_none)
		{
			aern_topology_node_deserialize(state->rnode, snode);
		}
	}

	return merr;
}

aern_protocol_errors aern_network_topological_query_request(const aern_network_topological_query_request_state* state)
{
	AERN_ASSERT(state != NULL);
	
	aern_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (aern_network_connect_to_device(&csock, state->dnode->address, state->dnode->designation) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
			size_t slen;

			/* create the packet header */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_topological_query_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			/* send query to the ads */
			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE)
				{
					aern_network_packet qrsp = { 0 };

					aern_packet_header_deserialize(rbuf, &qrsp);
					qrsp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

					/* verify the query response message */
					merr = network_topological_query_request_verify(state, &qrsp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connect_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Query Response: 
* The ADC loads the requestors certificate and validates the query signature and hash.
* The ADC finds the remote node from the issuer string, signs the serialized node and sends it back to the requestor.
* D(ts | snode, Sign(H(ts | snode)))->C
*/

static aern_protocol_errors network_topological_query_response_packet(aern_network_packet* packetout, const aern_network_topological_query_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;
	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

	if (packetout != NULL && state != NULL && packetin != NULL)
	{
		/* add the serialized topological node to the message */
		if (aern_topology_node_serialize(snode, state->rnode) == AERN_NETWORK_TOPOLOGY_NODE_SIZE)
		{
			/* create the packet header */
			network_header_create(packetout, aern_network_flag_topology_query_response, NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE);

			/* hash the message and sign the hash */
			merr = network_message_hash_sign(packetout, state->sigkey, snode, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		}
		else
		{
			merr = aern_protocol_error_decoding_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

static aern_protocol_errors network_topological_query_response_verify(uint8_t* query, const aern_network_topological_query_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(query != NULL);
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_topology_query_request, NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE);

	if (merr == aern_protocol_error_none)
	{
		/* verify the certificate signature */
		merr = network_message_signed_hash_verify(query, packetin, state->ccert);
	}

	return merr;
}

aern_protocol_errors aern_network_topological_query_response(const aern_network_topological_query_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };

		merr = network_topological_query_response_verify(query, state, packetin);

		if (merr == aern_protocol_error_none)
		{
			aern_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
			size_t mlen;

			/* create the update response packet */
			resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			merr = network_topological_query_response_packet(&resp, state, packetin);

			if (merr == aern_protocol_error_none)
			{
				aern_packet_header_serialize(&resp, sbuf);

				/* send the response to the requestor */
				mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (mlen == NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE)
				{
					merr = aern_protocol_error_none;
				}
				else
				{
					merr = aern_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Topological Status Request: 
* The ADC sends a status request to the target client, verifying it is online and available.
* It sends a signed copy of its certificate serial number in the message.
* D(ts | lser | Sign(H(ts | lser)))->C
* The remote client receives the signed serial number for the remote node, verifies the hash, signature, and the serial number.
* rser = Verify(H(ts | lser)
* If the responder is available, it sends its signed serial number back to the requestor.
* C(ts | lser | Sign(H(ts | lser)))->D
* The ADC verifies the message, and the function signals if the node is available for connect.
* rser = Verify(H(ts | lser)
*/

static aern_protocol_errors network_topological_status_request_packet(aern_network_packet* packetout, const aern_network_topological_status_request_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	/* copy the remote node serial number and sign it with the local signing key */

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_topology_status_request, NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE);
	
	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

aern_protocol_errors aern_network_topological_status_request_verify(const aern_network_topological_status_request_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* check the packet parameters */
		merr = network_header_validate(packetin, aern_network_flag_topology_status_response, NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE);

		if (merr == aern_protocol_error_none)
		{
			uint8_t rser[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };

			/* verify the signature */
			merr = network_message_signed_hash_verify(rser, packetin, state->rcert);

			if (merr == aern_protocol_error_none)
			{
				if (qsc_memutils_are_equal(state->rcert->serial, rser, AERN_CERTIFICATE_SERIAL_SIZE) == false)
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_topological_status_request(const aern_network_topological_status_request_state* state)
{
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		/* connect to query target */
		if (aern_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			aern_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0U };
			size_t slen;

			/* create the packet header */
			reqt.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			network_topological_status_request_packet(&reqt, state);
			aern_packet_header_serialize(&reqt, sbuf);

			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0U };
				aern_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE)
				{
					aern_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

					/* verify the certificate update */
					merr = aern_network_topological_status_request_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = aern_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}

			aern_network_socket_dispose(&csock);
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Status Response: 
* The server sends a status response back to the requestor, using its signed certificate serial number.
* M(Sk(H(lser)))->C
* If the server is offline the receiver will time out, it can also signal that it is unavailable.
*/

static aern_protocol_errors network_topological_status_response_packet(aern_network_packet* packetout, const aern_network_topological_status_response_state* state)
{
	AERN_ASSERT(packetout != NULL);
	AERN_ASSERT(state != NULL);

	aern_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, aern_network_flag_topology_status_response, NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE);

	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, AERN_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

static aern_protocol_errors network_topological_status_response_verify(const aern_network_topological_status_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, aern_network_flag_topology_status_request, NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE);

	if (state != NULL && packetin != NULL)
	{
		if (merr == aern_protocol_error_none)
		{
			uint8_t rser[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };

			/* verify the certificate signature */
			merr = network_message_signed_hash_verify(rser, packetin, state->rcert);

			if (merr == aern_protocol_error_none)
			{
				/* compare the remote copy of the local certificate serial number with the local node copy */
				if (qsc_memutils_are_equal(state->rcert->serial, rser, AERN_CERTIFICATE_SERIAL_SIZE) == false)
				{
					merr = aern_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_protocol_errors aern_network_topological_status_response(const aern_network_topological_status_response_state* state, const aern_network_packet* packetin)
{
	AERN_ASSERT(state != NULL);
	AERN_ASSERT(packetin != NULL);

	aern_protocol_errors merr;

	if (state != NULL)
	{
		merr = network_topological_status_response_verify(state, packetin);

		if (merr == aern_protocol_error_none)
		{
			aern_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0U };
			size_t mlen;

			/* create the update response packet */
			resp.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;
			merr = network_topological_status_response_packet(&resp, state);
			aern_packet_header_serialize(&resp, sbuf);

			/* send the response to the requestor */
			mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}
	
	/* notify of failure with error message */
	if (merr != aern_protocol_error_none)
	{
		aern_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Helper Functions */

aern_protocol_errors aern_network_certificate_verify(const aern_child_certificate* ccert, const aern_root_certificate* root)
{
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(root != NULL);

	aern_protocol_errors merr;

	if (ccert != NULL && root != NULL)
	{
		/* validate the certificate format */
		if (aern_certificate_child_is_valid(ccert) == true)
		{
			/* authenticate the root signature */
			if (aern_certificate_root_signature_verify(ccert, root) == true)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_root_signature_invalid;
			}
		}
		else
		{
			merr = aern_protocol_error_verification_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_invalid_request;
	}

	return merr;
}

aern_network_designations aern_network_port_to_application(uint16_t port)
{
	aern_network_designations tnode;

	if (port == AERN_APPLICATION_APS_PORT)
	{
		tnode = aern_network_designation_aps;
	}
	else if (port == AERN_APPLICATION_CLIENT_PORT)
	{
		tnode = aern_network_designation_client;
	}
	else if (port == AERN_APPLICATION_ADC_PORT)
	{
		tnode = aern_network_designation_ads;
	}
	else if (port == AERN_APPLICATION_IDG_PORT)
	{
		tnode = aern_network_designation_idg;
	}
	else
	{
		tnode = aern_network_designation_ars;
	}

	return tnode;
}

uint16_t aern_network_application_to_port(aern_network_designations tnode)
{
	uint16_t port;

	if (tnode == aern_network_designation_aps)
	{
		port = AERN_APPLICATION_APS_PORT;
	}
	else if (tnode == aern_network_designation_client)
	{
		port = AERN_APPLICATION_CLIENT_PORT;
	}
	else if (tnode == aern_network_designation_ads)
	{
		port = AERN_APPLICATION_ADC_PORT;
	}
	else if (tnode == aern_network_designation_idg)
	{
		port = AERN_APPLICATION_IDG_PORT;
	}
	else if (tnode == aern_network_designation_ars)
	{
		port = AERN_APPLICATION_ARS_PORT;
	}
	else
	{
		port = 0U;
	}
		
	return port;
}

void aern_network_broadcast_message(const aern_topology_list_state* list, const uint8_t* message, size_t msglen, aern_network_designations tnode)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(message != NULL);

	size_t i;
	uint16_t port;

	if (list != NULL && message != NULL)
	{
		qsc_socket csock = { 0 };

		port = aern_network_application_to_port(tnode);

		for (i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state node = { 0 };

			if (aern_topology_list_item(list, &node, i) == true)
			{
				if (node.designation == tnode)
				{
					if (aern_network_connect_to_address(&csock, node.address, port) == qsc_socket_exception_success)
					{
						qsc_socket_client_send(&csock, message, msglen, qsc_socket_send_flag_none);
						aern_network_socket_dispose(&csock);
					}
				}
			}
		}
	}
}

qsc_socket_exceptions aern_network_connect_to_device(qsc_socket* csock, const char* address, aern_network_designations designation)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	qsc_ipinfo_address_types tadd;
	uint16_t port;

	serr = qsc_socket_exception_error;

	if (csock != NULL && address != NULL)
	{
		tadd = qsc_ipinfo_get_address_type(address);
		port = aern_network_application_to_port(designation);

		qsc_socket_client_initialize(csock);

		if (tadd == qsc_ipinfo_address_type_ipv4)
		{
			qsc_ipinfo_ipv4_address ipv4 = { 0 };

			ipv4 = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&ipv4) == true)
			{
				serr = qsc_socket_client_connect_ipv4(csock, &ipv4, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else if (tadd == qsc_ipinfo_address_type_ipv6)
		{
			qsc_ipinfo_ipv6_address ipv6 = { 0 };
			char tmpa[QSC_IPINFO_IPV6_STRNLEN] = { 0 };

			qsc_stringutils_copy_string(tmpa, sizeof(tmpa), address);
			ipv6 = qsc_ipinfo_ipv6_address_from_string(tmpa);


			if (qsc_ipinfo_ipv6_address_is_valid(&ipv6) == true)
			{
				serr = qsc_socket_client_connect_ipv6(csock, &ipv6, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else
		{
			serr = qsc_socket_exception_address_unsupported;
		}
	}

	return serr;
}

qsc_socket_exceptions aern_network_connect_to_address(qsc_socket* csock, const char* address, uint16_t port)
{
	AERN_ASSERT(csock != NULL);
	AERN_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	qsc_ipinfo_address_types tadd;

	serr = qsc_socket_exception_error;

	if (csock != NULL && address != NULL)
	{
		tadd = qsc_ipinfo_get_address_type(address);

		qsc_socket_client_initialize(csock);

		if (tadd == qsc_ipinfo_address_type_ipv4)
		{
			qsc_ipinfo_ipv4_address ipv4 = { 0 };

			ipv4 = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&ipv4) == true)
			{
				serr = qsc_socket_client_connect_ipv4(csock, &ipv4, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else if (tadd == qsc_ipinfo_address_type_ipv6)
		{
			qsc_ipinfo_ipv6_address ipv6 = { 0 };

			ipv6 = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&ipv6) == true)
			{
				serr = qsc_socket_client_connect_ipv6(csock, &ipv6, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else
		{
			serr = qsc_socket_exception_address_unsupported;
		}
	}

	return serr;
}

bool aern_network_get_local_address(char address[AERN_CERTIFICATE_ADDRESS_SIZE])
{
	bool res;

#if defined(AERN_NETWORK_PROTOCOL_IPV6)
	qsc_ipinfo_ipv6_address v6add = { 0 };

	res = qsc_netutils_get_ipv6_address(&v6add);

	if (res == true)
	{
		qsc_memutils_copy(address, v6add.ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}
#else
	qsc_ipinfo_ipv4_address v4add = { 0 };

	res = qsc_netutils_get_ipv4_address(&v4add);

	if (res == true)
	{
		qsc_ipinfo_ipv4_address_to_string(address, &v4add);
	}
#endif

	return res;
}

aern_protocol_errors aern_network_send_error(const qsc_socket* csock, aern_protocol_errors error)
{
	AERN_ASSERT(csock != NULL);
	
	aern_network_packet resp = { 0 };
	uint8_t ebuf[NETWORK_ERROR_PACKET_SIZE] = { 0U };
	size_t slen;
	aern_protocol_errors merr;

	merr = error;

	if (csock != NULL)
	{
		if (qsc_socket_is_connected(csock) == true)
		{
			resp.pmessage = ebuf + AERN_PACKET_HEADER_SIZE;
			aern_packet_error_message(&resp, error);
			aern_packet_header_serialize(&resp, ebuf);
			slen = qsc_socket_send(csock, ebuf, NETWORK_ERROR_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_ERROR_PACKET_SIZE)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_transmit_failure;
			}
		}
		else
		{
			merr = aern_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = aern_protocol_error_channel_down;
	}

	return merr;
}

void aern_network_socket_dispose(qsc_socket* csock)
{
	AERN_ASSERT(csock != NULL);

	if (csock != NULL)
	{
		qsc_socket_client_shut_down(csock);
	}
}

#if defined(AERN_DEBUG_MODE)
typedef struct network_test_device_package
{
	aern_signature_keypair akp;
	aern_signature_keypair akp2;
	aern_signature_keypair akp3;
	aern_signature_keypair akp4;
	aern_signature_keypair ckp;
	aern_signature_keypair ckp2;
	aern_signature_keypair dkp;
	aern_signature_keypair mkp;
	aern_signature_keypair rkp;
	aern_child_certificate acrt;
	aern_child_certificate acrt2;
	aern_child_certificate acrt3;
	aern_child_certificate acrt4;
	aern_child_certificate ccrt;
	aern_child_certificate ccrt2;
	aern_child_certificate dcrt;
	aern_child_certificate mcrt;
	aern_root_certificate root;
	aern_topology_node_state ande;
	aern_topology_node_state ande2;
	aern_topology_node_state ande3;
	aern_topology_node_state ande4;
	aern_topology_node_state cnde;
	aern_topology_node_state cnde2;
	aern_topology_node_state dnde;
	aern_topology_node_state mnde;
	aern_topology_list_state list;
	qsc_collection_state amfk;
	qsc_collection_state amfk2;
	qsc_collection_state amfk3;
	qsc_collection_state amfk4;
	qsc_collection_state cmfk;
	qsc_collection_state cmfk2;
	qsc_collection_state mmfk;

} network_test_device_package;

static void network_test_load_node(aern_topology_list_state* list, aern_topology_node_state* node, const aern_child_certificate* ccert)
{
	uint8_t ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { 192U, 168U, 1U };

	qsc_acp_generate(ipa + 3U, 1U);
	aern_topology_child_register(list, ccert, ipa);
	aern_topology_node_find(list, node, ccert->serial);
}

static void network_test_device_destroy(network_test_device_package* spkg)
{
	qsc_collection_dispose(&spkg->amfk);
	qsc_collection_dispose(&spkg->amfk2);
	qsc_collection_dispose(&spkg->amfk3);
	qsc_collection_dispose(&spkg->amfk4);
	qsc_collection_dispose(&spkg->cmfk);
	qsc_collection_dispose(&spkg->cmfk2);
	qsc_collection_dispose(&spkg->mmfk);
	aern_topology_list_dispose(&spkg->list);
}

static void network_test_device_instantiate(network_test_device_package* spkg)
{
	aern_certificate_expiration exp = { 0 };
	uint8_t mfk[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };

	qsc_collection_initialize(&spkg->amfk, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk2, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk3, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk4, sizeof(mfk));
	qsc_collection_initialize(&spkg->cmfk, sizeof(mfk));
	qsc_collection_initialize(&spkg->cmfk2, sizeof(mfk));
	qsc_collection_initialize(&spkg->mmfk, sizeof(mfk));

	aern_topology_list_initialize(&spkg->list);

	/* generate the root certificate */
	aern_certificate_signature_generate_keypair(&spkg->rkp);
	aern_certificate_expiration_set_days(&exp, 0U, 30U);
	aern_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ_ARS1");

	/* create the ads */
	aern_certificate_signature_generate_keypair(&spkg->dkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ_ADS1", aern_network_designation_ads);
	aern_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	network_test_load_node(&spkg->list, &spkg->dnde, &spkg->dcrt);
	
	/* create a client 1 */
	aern_certificate_signature_generate_keypair(&spkg->ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ_CLT1", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->mcrt.serial);
	network_test_load_node(&spkg->list, &spkg->cnde, &spkg->ccrt);
		
	/* create a client 2 */
	aern_certificate_signature_generate_keypair(&spkg->ckp2);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt2, spkg->ckp2.pubkey, &exp, "XYZ_CLT2", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt2, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt2.serial);
	qsc_collection_add(&spkg->cmfk2, mfk, spkg->mcrt.serial);
	network_test_load_node(&spkg->list, &spkg->cnde2, &spkg->ccrt2);

	/* create the apss */
	aern_certificate_signature_generate_keypair(&spkg->akp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ_AGT1", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);

	/* generate the shared mfk keys for a simulated topology */
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt.serial);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt.serial);
	network_test_load_node(&spkg->list, &spkg->ande, &spkg->acrt);

	aern_certificate_signature_generate_keypair(&spkg->akp2);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt2, spkg->akp2.pubkey, &exp, "XYZ_AGT2", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt2, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk2, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt2.serial);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk2, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt2.serial);
	network_test_load_node(&spkg->list, &spkg->ande2, &spkg->acrt2);

	aern_certificate_signature_generate_keypair(&spkg->akp3);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt3, spkg->akp3.pubkey, &exp, "XYZ_AGT3", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt3, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk3, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt3.serial);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk3, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt3.serial);
	network_test_load_node(&spkg->list, &spkg->ande3, &spkg->acrt3);
	
	aern_certificate_signature_generate_keypair(&spkg->akp4);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt4, spkg->akp4.pubkey, &exp, "XYZ_AGT4", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt4, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk4, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt4.serial);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk4, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt4.serial);
	network_test_load_node(&spkg->list, &spkg->ande4, &spkg->acrt4);
}

static bool network_test_announce_test(void)
{
	aern_topology_node_state rnode = { 0 };
	aern_child_certificate rcert = { 0 };
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	
	aern_network_announce_request_state aqs = { 
		.list = &spkg.list,		/* topology list */
		.rnode = &spkg.ande,	/* aps node */
		.sigkey = spkg.dkp.prikey };	/* ads signing key */

	/* the ads announces a new aps in a broadcast request */
	merr = network_announce_broadcast_packet(&reqt, &aqs);

	aern_network_announce_response_state ars = { 
		.dcert = &spkg.dcrt,	/* ads certificate*/
		.rnode = &rnode,		/* node copy */
		.root = &spkg.root };	/* root certificate */

	/* the mas/client process the request */
	merr = aern_network_announce_response(&ars, &reqt);

	/* compare received node with stored copy */
	if (aern_topology_nodes_are_equal(&spkg.ande, &rnode) != true)
	{
		merr = aern_protocol_error_exchange_failure;
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_converge(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_topology_node_serialize(snode, &spkg.mnde);

	aern_network_converge_request_state cqs = {
		.rcert = &spkg.mcrt,		/* mas cert */
		.rnode = &spkg.mnde,		/* mas node */
		.sigkey = spkg.dkp.prikey	/* ads signing key*/
	};

	/* the ads sends the converge request */
	merr = network_converge_request_packet(&reqt, &cqs, snode);

	if (merr == aern_protocol_error_none)
	{
		const aern_network_converge_response_state cus = {
			.csock = NULL,				/* the socket */
			.lcert = &spkg.mcrt,		/* mas certificate*/
			.lnode = &spkg.mnde,		/* mas topological node */
			.rcert = &spkg.dcrt,		/* ads certificate */
			.sigkey = spkg.mkp.prikey	/* the mas signing key */
		};

		merr = network_converge_request_verify(&cus, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the remote node sends the reply */
			merr = network_converge_response_packet(&resp, &cus);

			if (merr == aern_protocol_error_none)
			{
				/* verify the response */
				merr = network_converge_response_verify(&cqs, &resp);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_fkey_exchange(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t fra[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t frm[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t breqt[NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t mfa[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfm[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t atok[AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* generate the shared mfk */
	qsc_acp_generate(mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_memutils_copy(mfm, mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

	aern_network_fkey_request_state frs = {
		.frag = frm,		/* fragment storage */
		.lnode = &spkg.mnde,	/* local node */
		.mfk = mfm,		/* master fragment key */
		.rnode = &spkg.ande,	/* remote node */
		.token = atok		/* token storage */
	};

	/* the mas fkey request packet */
	network_fkey_request_packet(&reqt, &frs);

	aern_network_fkey_response_state frr = {
		.csock = NULL,		/* the socket */
		.frag = fra,		/* fragment storage */
		.lnode = &spkg.ande,	/* local node */
		.mfk = mfa,		/* master fragment key */
		.rnode = &spkg.mnde	/* remote node */
	};

	/* the aps fkey response packet */
	merr = network_fkey_response_packet(&resp, &reqt, &frr);

	if (merr == aern_protocol_error_none)
	{
		/* server verifies the fkey response packet */
		merr = network_fkey_response_verify(&frs, &resp);

		if (merr == aern_protocol_error_none)
		{
			/* test that both fragment keys are identical */
			res = qsc_memutils_are_equal(frs.frag, frr.frag, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_fkey_encryption(void)
{
	network_test_device_package spkg = { 0 };
	uint8_t data[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
	uint8_t frags[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t token[AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };
	uint8_t mfka[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	qsc_acp_generate(frags, sizeof(frags));
	qsc_acp_generate(token, sizeof(token));
	qsc_acp_generate(data, sizeof(data));

	/* aps uses mas shared key */
	if (qsc_collection_find(&spkg.amfk, mfka, spkg.mnde.serial) == true)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0U };
		uint8_t fragr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
		uint8_t mctxt[AERN_CRYPTO_SYMMETRIC_KEY_SIZE + AERN_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };
		uint8_t mfkm[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };

		/* generate the fragment encryption key */
		network_derive_fkey(ckey, mfka, spkg.cnde.chash, spkg.mnde.chash, token);

		/* encrypt fragment key and copy the cipher-text to the message */
		qsc_memutils_xor(ckey, frags, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_memutils_copy(mctxt, ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

		/* create the mac tag */
		network_mac_message(mctxt + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, ckey + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, mctxt, AERN_CRYPTO_SYMMETRIC_KEY_SIZE, data);

		/* mas uses apss shared key */
		if (qsc_collection_find(&spkg.mmfk, mfkm, spkg.ande.serial) == true)
		{
			uint8_t mtag[AERN_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

			/* generate the fragment encryption key */
			network_derive_fkey(ckey, mfkm, spkg.cnde.chash, spkg.mnde.chash, token);

			/* create the mac tag */
			network_mac_message(mtag, ckey + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, mctxt, AERN_CRYPTO_SYMMETRIC_KEY_SIZE, data);

			if (qsc_memutils_are_equal(mtag, mctxt + AERN_CRYPTO_SYMMETRIC_KEY_SIZE, AERN_CRYPTO_SYMMETRIC_HASH_SIZE) == true)
			{
				/* decrypt the fragment */
				qsc_memutils_xor(ckey, mctxt, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
				qsc_memutils_copy(fragr, ckey, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

				res = qsc_memutils_are_equal(frags, fragr, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_incremental_update(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_child_certificate ccert = { 0 };

	/* the server has received the aps topology node from the ads, 
	   and requests a certificate update from the aps */
	aern_network_incremental_update_request_state urs = {
		.rcert = &ccert,		/* certificate storage */
		.rnode = &spkg.mnde,	/* the remote node */
		.root = &spkg.root,		/* root certificate */
	};

	/* the server request packet */
	network_incremental_update_request_packet(&reqt, &urs);

	aern_network_incremental_update_response_state urr = {
		.csock = NULL,
		.rcert = &spkg.mcrt,
		.sigkey = spkg.mkp.prikey
	};

	/* the aps update response packet */
	merr = network_incremental_update_response_packet(&resp, &reqt, &urr);

	if (merr == aern_protocol_error_none)
	{
		/* server verifies the response */
		merr = network_incremental_update_verify(&urs, &resp);

		if (merr == aern_protocol_error_none)
		{
			/* received certificate and stored are identical */
			if (aern_certificate_child_are_equal(&ccert, &spkg.mcrt) == true)
			{
				merr = aern_protocol_error_none;
			}
			else
			{
				merr = aern_protocol_error_decoding_failure;
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_join(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate dccp = { 0 };
	uint8_t breqt[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* an aps joins the ads */
	aern_network_register_request_state jrs = {
		.lcert = &spkg.acrt,	/* aps certificate */
		.rcert = &spkg.dcrt,	/* ads certificate storage */
		.root = &spkg.root,		/* root certificate */
		.sigkey = spkg.akp.prikey	/* the apss signing key */
	};

	/* the aps join request packet */
	merr = network_register_request_packet(&reqt, &jrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_response_state jrr = {
			.csock = NULL,			/* the socket */
			.lcert = &spkg.dcrt,	/* ads certificate */
			.rcert = &spkg.acrt,	/* aps certificate storage */
			.root = &spkg.root,		/* root certificate */
			.sigkey = spkg.dkp.prikey	/* the ads signing key */
		};

		/* the ads join response packet */
		merr = network_register_response_packet(&resp, &jrr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the aps verifies the join response */
			merr = network_register_verify(&jrs, &resp);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_mfk_exchange(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet esta = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };
	uint8_t mfa[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfm[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	/* a server initiates an mfk exchange with an aps */
	aern_network_mfk_request_state sreqt = {
		.lcert = &spkg.mcrt,		/* mas certificate*/
		.rcert = &spkg.acrt,		/* aps certificate */
		.root = &spkg.root,			/* root certificate */
		.sigkey = spkg.mkp.prikey,	/* mas signing key */
		.mfk = mfm					/* mfk storage */
	};

	/* server starts the exchange with a request */
	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp = {
			.lcert = &spkg.acrt,		/* aps certificate */
			.rcert = &spkg.mcrt,		/* mas certificate*/
			.root = &spkg.root,			/* root certificate */
			.sigkey = spkg.akp.prikey,	/* aps signing key */
			.mfk = mfa					/* mfk storage */
		};

		/* the aps responds */
		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			/* the server creates the establish packet */
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);

			if (merr == aern_protocol_error_none)
			{
				/* the aps verifies the message */
				merr = network_mfk_verify_packet(&esta, &sresp);

				if (merr == aern_protocol_error_none)
				{
					/* both master keys are identical */
					res = qsc_memutils_are_equal(sreqt.mfk, sresp.mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
				}
			}
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_register_update(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate dccp = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (AERN_NETWORK_TOPOLOGY_NODE_SIZE * 2U) + sizeof(uint32_t)] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* a client joins the ads and receives a topological update */
	aern_network_register_update_request_state jus = {
		.lcert = &spkg.ccrt,	/* client certificate */
		.list = &spkg.list,		/* topology list */
		.rcert = &spkg.dcrt,	/* ads certificate storage */
		.root = &spkg.root,		/* root certificate */
		.sigkey = spkg.ckp.prikey	/* client signing key */
	};

	/* client join up date request */
	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == aern_protocol_error_none)
	{
		uint8_t* pbuf;

		aern_network_register_update_response_state jur = {
			.lcert = &spkg.dcrt,	/* ads certificate */
			.list = &spkg.list,		/* topology list */
			.rcert = &spkg.ccrt,	/* client certificate storage */
			.root = &spkg.root,		/* root certificate */
			.sigkey = spkg.dkp.prikey	/* ads signing key */
		};

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			/* ads join update resonse */
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);

			if (merr == aern_protocol_error_none)
			{
				/* client verifies the update, updates added to list */
				merr = network_register_update_verify(&jus, &resp);
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_remote_signing(void)
{
	network_test_device_package spkg = { 0 };
	aern_signature_keypair ckp3 = { 0 };
	aern_certificate_expiration exp = { 0 };
	aern_child_certificate rcert = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_certificate_signature_generate_keypair(&ckp3);
	aern_certificate_expiration_set_days(&exp, 0, 100);
	aern_certificate_child_create(&rcert, ckp3.pubkey, &exp, "XYZ_CLT3", aern_network_designation_client);

	aern_network_remote_signing_request_state rsr = {
		.address = NULL,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	merr = network_remote_signing_request_packet(&rsr, &reqt);

	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate scert = { 0 };

		aern_network_remote_signing_response_state rsq = {
			.csock = NULL,
			.dcert = &spkg.dcrt,
			.rcert = &scert,
			.root = &spkg.root,
			.sigkey = spkg.rkp.prikey
		};

		merr = network_remote_signing_response_verify(&rsq, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_remote_signing_response_packet(&rsq, &resp);

			if (merr == aern_protocol_error_none)
			{
				merr = network_remote_signing_request_verify(&rsr, &resp);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_topological_query(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	network_test_device_instantiate(&spkg);

	const aern_network_topological_query_request_state qrs = {
		.dcert = &spkg.dcrt,			/* the ads certificate */
		.dnode = &spkg.dnde,			/* the ads node */
		.issuer = spkg.ccrt2.issuer,	/* client target issuer string */
		.rnode = &rnode,				/* the remote node */
		.serial = spkg.ccrt.serial,		/* the local serial number */
		.sigkey = spkg.ckp.prikey		/* client signing key */
	};

	/* a client requests another clients node description from the ads */
	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_query_response_state tsr = {
			.csock = NULL,				/* the socket */
			.ccert = &spkg.ccrt,		/* the client certificate */
			.rnode = &spkg.cnde,		/* the remote client node */
			.sigkey = spkg.dkp.prikey,	/* the ads signing key */
		};

		/* the ADC verifies the request */
		merr = network_topological_query_response_verify(query, &tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the ADC creates the response packet */
			merr = network_topological_query_response_packet(&resp, &tsr, &reqt);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool network_test_topological_status(void)
{
	network_test_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_topological_status_request_state tsq = {
		.lnode = &spkg.cnde,		/* the client node */
		.rcert = &spkg.ccrt2,		/* the client certificate */
		.rnode = &spkg.cnde2,
		.sigkey = spkg.ckp.prikey	/* the ads signing key */
	};

	/* sent from the ADC to the client */
	merr = network_topological_status_request_packet(&reqt, &tsq);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_status_response_state tsr = {
			.csock = NULL,				/* the socket */
			.lnode = &spkg.cnde2,		/* the local client node */
			.rcert = &spkg.ccrt,		/* the ads certificate */
			.sigkey = spkg.ckp2.prikey	/* the client signing key */
		};

		/* the ADC creates the client response packet */
		merr = network_topological_status_response_verify(&tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the client verifies the request from the ADC */
			merr = network_topological_status_response_packet(&resp, &tsr);

			if (merr == aern_protocol_error_none)
			{
				/* the ADC checks the client response */
				merr = aern_network_topological_status_request_verify(&tsq, &resp);
			}
		}
	}
	
	network_test_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

bool aern_network_protocols_test(void)
{
	bool res;

	res = network_test_announce_test();

	if (res == true)
	{
		res = network_test_converge();

		if (res == true)
		{
			res = network_test_fkey_encryption();

			if (res == true)
			{
				res = network_test_fkey_exchange();

				if (res == true)
				{
					res = network_test_incremental_update();

					if (res == true)
					{
						res = network_test_join();

						if (res == true)
						{
							res = network_test_register_update();

							if (res == true)
							{
								res = network_test_mfk_exchange();

								if (res == true)
								{
									res = network_test_remote_signing();

									if (res == true)
									{
										res = network_test_topological_query();

										if (res == true)
										{
											res = network_test_topological_status();
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return res;
}
#endif

#include "network_test.h"
#include "aern_utils.h"
#include "network.h"
#include "mek.h"
#include "access_test.h"
#include "aern.h"
#include "certificate.h"
#include "topology.h"
#include "route.h"
#include "acp.h"
#include "collection.h"
#include "memutils.h"
#include "intutils.h"
#include "timestamp.h"

typedef struct aerntest_network_device_package
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

} aerntest_network_device_package;

#define AERNTEST_NETWORK_CONVERGE_UPDATE_SEQUENCE 0xFFFFFF1AUL
#define AERNTEST_NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define AERNTEST_NETWORK_CONVERGE_UPDATE_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + AERNTEST_NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE)
#define AERNTEST_NETWORK_RESIGN_REQUEST_SEQUENCE 0xFFFFFF14UL
#define AERNTEST_NETWORK_RESIGN_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define AERNTEST_NETWORK_RESIGN_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + AERNTEST_NETWORK_RESIGN_REQUEST_MESSAGE_SIZE)
#define AERNTEST_NETWORK_REVOKE_REQUEST_SEQUENCE 0xFFFFFF15UL
#define AERNTEST_NETWORK_REVOKE_REQUEST_MESSAGE_SIZE (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define AERNTEST_NETWORK_REVOKE_REQUEST_PACKET_SIZE (AERN_PACKET_HEADER_SIZE + AERNTEST_NETWORK_REVOKE_REQUEST_MESSAGE_SIZE)
#define AERNTEST_NETWORK_MFK_ESTABLISH_SEQUENCE 0xFFFFFF11UL

static bool aerntest_network_memory_is_zeroed(const uint8_t* data, size_t datalen)
{
	bool res;
	size_t i;

	res = true;

	for (i = 0U; i < datalen; ++i)
	{
		if (data[i] != 0U)
		{
			res = false;
			break;
		}
	}

	return res;
}

static void aerntest_network_subheader_serialize(uint8_t* pstream, const aern_network_packet* packetin)
{
	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static bool aerntest_network_signed_packet_create(aern_network_packet* packetout, aern_network_flags flag, uint64_t sequence,
	uint32_t msglen, const uint8_t* body, size_t bodylen, const uint8_t* sigkey)
{
	bool res;
	size_t siglen;

	res = false;

	if (packetout != NULL && packetout->pmessage != NULL && body != NULL && sigkey != NULL &&
		msglen == (AERN_PACKET_SUBHEADER_SIZE + bodylen + AERN_CERTIFICATE_SIGNED_HASH_SIZE))
	{
		packetout->flag = flag;
		packetout->msglen = msglen;
		packetout->sequence = sequence;
		aern_packet_set_utc_time(packetout);
		aerntest_network_subheader_serialize(packetout->pmessage, packetout);
		qsc_memutils_copy(packetout->pmessage + AERN_PACKET_SUBHEADER_SIZE, body, bodylen);
		siglen = aern_certificate_message_hash_sign(packetout->pmessage + AERN_PACKET_SUBHEADER_SIZE + bodylen, sigkey, packetout->pmessage, AERN_PACKET_SUBHEADER_SIZE + bodylen);
		res = (siglen == AERN_CERTIFICATE_SIGNED_HASH_SIZE);
	}

	return res;
}

static void aerntest_network_load_node(aern_topology_list_state* list, aern_topology_node_state* node, const aern_child_certificate* ccert)
{
	char ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { (char)192, (char)168, (char)1 };

	qsc_acp_generate((uint8_t*)ipa + 3U, 1U);
	aern_topology_child_register(list, ccert, ipa);
	aern_topology_node_find(list, node, ccert->serial);
}

static void aerntest_network_device_destroy(aerntest_network_device_package* spkg)
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

static void aerntest_network_device_instantiate(aerntest_network_device_package* spkg)
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

	/* create the ADC */
	aern_certificate_signature_generate_keypair(&spkg->dkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ_ADC1", aern_network_designation_adc);
	aern_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	aerntest_network_load_node(&spkg->list, &spkg->dnde, &spkg->dcrt);

	/* create the ARS */
	aern_certificate_signature_generate_keypair(&spkg->mkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->mcrt, spkg->mkp.pubkey, &exp, "XYZ_ARS1", aern_network_designation_ars);
	aern_certificate_root_sign(&spkg->mcrt, &spkg->root, spkg->rkp.prikey);
	aerntest_network_load_node(&spkg->list, &spkg->mnde, &spkg->mcrt);
	
	/* create a client 1 */
	aern_certificate_signature_generate_keypair(&spkg->ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ_CLT1", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->mcrt.serial);
	aerntest_network_load_node(&spkg->list, &spkg->cnde, &spkg->ccrt);
		
	/* create a client 2 */
	aern_certificate_signature_generate_keypair(&spkg->ckp2);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt2, spkg->ckp2.pubkey, &exp, "XYZ_CLT2", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt2, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt2.serial);
	qsc_collection_add(&spkg->cmfk2, mfk, spkg->mcrt.serial);
	aerntest_network_load_node(&spkg->list, &spkg->cnde2, &spkg->ccrt2);

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
	aerntest_network_load_node(&spkg->list, &spkg->ande, &spkg->acrt);

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
	aerntest_network_load_node(&spkg->list, &spkg->ande2, &spkg->acrt2);

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
	aerntest_network_load_node(&spkg->list, &spkg->ande3, &spkg->acrt3);
	
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
	aerntest_network_load_node(&spkg->list, &spkg->ande4, &spkg->acrt4);
}

static bool aerntest_network_announce_test(void)
{
	aern_topology_node_state rnode = { 0 };
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	
	aern_network_announce_request_state aqs = 
	{ 
		.list = &spkg.list,			/* topology list */
		.rnode = &spkg.ande,		/* aps node */
		.sigkey = spkg.dkp.prikey	/* ADC signing key */
	};

	/* the ADC announces a new aps in a broadcast request */
	merr = network_announce_broadcast_packet(&reqt, &aqs);

	aern_network_announce_response_state ars = 
	{ 
		.dcert = &spkg.dcrt,	/* ADC certificate*/
		.rnode = &rnode,		/* node copy */
		.root = &spkg.root		/* root certificate */
	};

	/* the mas/client process the request */
	merr = aern_network_announce_response(&ars, &reqt);

	/* compare received node with stored copy */
	if (aern_topology_nodes_are_equal(&spkg.ande, &rnode) != true)
	{
		merr = aern_protocol_error_exchange_failure;
	}

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_converge_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_topology_node_serialize(snode, &spkg.mnde);

	aern_network_converge_request_state cqs = 
	{
		.rcert = &spkg.mcrt,		/* mas cert */
		.rnode = &spkg.mnde,		/* mas node */
		.sigkey = spkg.dkp.prikey	/* ADC signing key*/
	};

	/* the ADC sends the converge request */
	merr = network_converge_request_packet(&reqt, &cqs, snode);

	if (merr == aern_protocol_error_none)
	{
		const aern_network_converge_response_state cus = 
		{
			.csock = NULL,				/* the socket */
			.lcert = &spkg.mcrt,		/* mas certificate*/
			.lnode = &spkg.mnde,		/* mas topological node */
			.rcert = &spkg.dcrt,		/* ADC certificate */
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

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_fkey_exchange_test(void)
{
	aerntest_network_device_package spkg = { 0 };
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
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* generate the shared mfk */
	qsc_acp_generate(mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_memutils_copy(mfm, mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

	aern_network_fkey_request_state frs = 
	{
		.frag = frm,			/* fragment storage */
		.lnode = &spkg.mnde,	/* local node */
		.mfk = mfm,				/* master fragment key */
		.rnode = &spkg.ande,	/* remote node */
		.token = atok			/* token storage */
	};

	/* the mas fkey request packet */
	network_fkey_request_packet(&reqt, &frs);

	aern_network_fkey_response_state frr = 
	{
		.csock = NULL,			/* the socket */
		.frag = fra,			/* fragment storage */
		.lnode = &spkg.ande,	/* local node */
		.mfk = mfa,				/* master fragment key */
		.rnode = &spkg.mnde		/* remote node */
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

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_fkey_encryption_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	uint8_t data[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
	uint8_t frags[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t token[AERN_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };
	uint8_t mfka[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);

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

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_incremental_update_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_child_certificate ccert = { 0 };

	/* the server has received the aps topology node from the ADC, 
	   and requests a certificate update from the aps */
	aern_network_incremental_update_request_state urs = 
	{
		.rcert = &ccert,		/* certificate storage */
		.rnode = &spkg.mnde,	/* the remote node */
		.root = &spkg.root,		/* root certificate */
	};

	/* the server request packet */
	network_incremental_update_request_packet(&reqt, &urs);

	aern_network_incremental_update_response_state urr = 
	{
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

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_join_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* an aps joins the ADC */
	aern_network_register_request_state jrs = 
	{
		.lcert = &spkg.acrt,		/* aps certificate */
		.rcert = &spkg.dcrt,		/* ADC certificate storage */
		.root = &spkg.root,			/* root certificate */
		.sigkey = spkg.akp.prikey	/* the apss signing key */
	};

	/* the aps join request packet */
	merr = network_register_request_packet(&reqt, &jrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_response_state jrr = 
		{
			.csock = NULL,				/* the socket */
			.lcert = &spkg.dcrt,		/* ADC certificate */
			.rcert = &spkg.acrt,		/* aps certificate storage */
			.root = &spkg.root,			/* root certificate */
			.sigkey = spkg.dkp.prikey	/* the ADC signing key */
		};

		/* the ADC join response packet */
		merr = network_register_response_packet(&resp, &jrr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the aps verifies the join response */
			merr = network_register_verify(&jrs, &resp);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_mfk_exchange_test(void)
{
	aerntest_network_device_package spkg = { 0 };
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
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	/* a server initiates an mfk exchange with an aps */
	aern_network_mfk_request_state sreqt = 
	{
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
		aern_network_mfk_response_state sresp = 
		{
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

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_register_update_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (AERN_NETWORK_TOPOLOGY_NODE_SIZE * 2U) + sizeof(uint32_t)] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	/* a client joins the ADC and receives a topological update */
	aern_network_register_update_request_state jus = 
	{
		.lcert = &spkg.ccrt,		/* client certificate */
		.list = &spkg.list,			/* topology list */
		.rcert = &spkg.dcrt,		/* ADC certificate storage */
		.root = &spkg.root,			/* root certificate */
		.sigkey = spkg.ckp.prikey	/* client signing key */
	};

	/* client join up date request */
	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == aern_protocol_error_none)
	{
		uint8_t* pbuf;

		aern_network_register_update_response_state jur = 
		{
			.lcert = &spkg.dcrt,		/* ADC certificate */
			.list = &spkg.list,			/* topology list */
			.rcert = &spkg.ccrt,		/* client certificate storage */
			.root = &spkg.root,			/* root certificate */
			.sigkey = spkg.dkp.prikey	/* ADC signing key */
		};

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			/* ADC join update resonse */
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);

			if (resp.pmessage != NULL)
			{
				pbuf = resp.pmessage - AERN_PACKET_HEADER_SIZE;
			}

			if (merr == aern_protocol_error_none)
			{
				/* client verifies the update, updates added to list */
				merr = network_register_update_verify(&jus, &resp);
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_remote_signing_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_signature_keypair ckp3 = { 0 };
	aern_certificate_expiration exp = { 0 };
	aern_child_certificate rcert = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_certificate_signature_generate_keypair(&ckp3);
	aern_certificate_expiration_set_days(&exp, 0, 100);
	aern_certificate_child_create(&rcert, ckp3.pubkey, &exp, "XYZ_CLT3", aern_network_designation_client);

	aern_network_remote_signing_request_state rsr =		
	{
		.address = NULL,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	merr = network_remote_signing_request_packet(&rsr, &reqt);

	if (merr == aern_protocol_error_none)
	{
		aern_child_certificate scert = { 0 };

		aern_network_remote_signing_response_state rsq =
		{
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

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_topological_query_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aerntest_network_device_instantiate(&spkg);

	const aern_network_topological_query_request_state qrs = 
	{
		.dcert = &spkg.dcrt,			/* the ADC certificate */
		.dnode = &spkg.dnde,			/* the ADC node */
		.issuer = spkg.ccrt2.issuer,	/* client target issuer string */
		.rnode = &rnode,				/* the remote node */
		.serial = spkg.ccrt.serial,		/* the local serial number */
		.sigkey = spkg.ckp.prikey		/* client signing key */
	};

	/* a client requests another clients node description from the ADC */
	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_query_response_state tsr = 
		{
			.csock = NULL,				/* the socket */
			.ccert = &spkg.ccrt,		/* the client certificate */
			.rnode = &spkg.cnde,		/* the remote client node */
			.sigkey = spkg.dkp.prikey,	/* the ADC signing key */
		};

		/* the ADC verifies the request */
		merr = network_topological_query_response_verify(query, &tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			/* the ADC creates the response packet */
			merr = network_topological_query_response_packet(&resp, &tsr, &reqt);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}

static bool aerntest_network_topological_status_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;

	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_topological_status_request_state tsq = 
	{
		.lnode = &spkg.cnde,		/* the client node */
		.rcert = &spkg.ccrt2,		/* the client certificate */
		.rnode = &spkg.cnde2,		/* the second client node */
		.sigkey = spkg.ckp.prikey	/* the ADC signing key */
	};

	/* sent from the ADC to the client */
	merr = network_topological_status_request_packet(&reqt, &tsq);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_status_response_state tsr = 
		{
			.csock = NULL,				/* the socket */
			.lnode = &spkg.cnde2,		/* the local client node */
			.rcert = &spkg.ccrt,		/* the ADC certificate */
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
	
	aerntest_network_device_destroy(&spkg);

	return (merr == aern_protocol_error_none);
}


static bool aerntest_network_converge_update_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet pkt = { 0 };
	aern_topology_list_state topo = { 0 };
	aern_topology_node_state node = { 0 };
	uint8_t bpkt[AERNTEST_NETWORK_CONVERGE_UPDATE_PACKET_SIZE] = { 0U };
	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	aern_topology_list_initialize(&topo);
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;
	aern_topology_node_serialize(snode, &spkg.ande);

	if (aerntest_network_signed_packet_create(&pkt, aern_network_flag_network_converge_update, AERNTEST_NETWORK_CONVERGE_UPDATE_SEQUENCE, 
		AERNTEST_NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE, snode, AERN_NETWORK_TOPOLOGY_NODE_SIZE, spkg.akp.prikey) == true)
	{
		aern_network_converge_update_state st =
		{
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.vtopo = &topo
		};

		merr = aern_network_converge_update(&st, &pkt);

		if (merr == aern_protocol_error_none && aern_topology_node_find(&topo, &node, spkg.ande.serial) == true &&
			aern_topology_nodes_are_equal(&node, &spkg.ande) == true)
		{
			uint32_t count;
			aern_network_packet badpkt;

			count = topo.count;
			badpkt = pkt;
			badpkt.pmessage[AERN_PACKET_SUBHEADER_SIZE + AERN_NETWORK_TOPOLOGY_NODE_SIZE] ^= 0x01U;
			merr = aern_network_converge_update(&st, &badpkt);
			res = (merr != aern_protocol_error_none && topo.count == count);
		}
	}

	aern_topology_list_dispose(&topo);
	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_resign_response_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet pkt = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t bpkt[AERNTEST_NETWORK_RESIGN_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;

	if (aerntest_network_signed_packet_create(&pkt, aern_network_flag_network_resign_request,
		AERNTEST_NETWORK_RESIGN_REQUEST_SEQUENCE, AERNTEST_NETWORK_RESIGN_REQUEST_MESSAGE_SIZE,
		spkg.ccrt.serial, AERN_CERTIFICATE_SERIAL_SIZE, spkg.ckp.prikey) == true)
	{
		aern_network_resign_response_state st =
		{
			.list = &spkg.list,
			.rcert = &spkg.ccrt,
			.rnode = &rnode,
			.sigkey = spkg.dkp.prikey
		};

		merr = aern_network_resign_response(&st, &pkt);
		res = (merr == aern_protocol_error_none && aern_topology_nodes_are_equal(&rnode, &spkg.cnde) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_resign_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet pkt = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t bpkt[AERNTEST_NETWORK_RESIGN_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;

	if (aerntest_network_signed_packet_create(&pkt, aern_network_flag_network_resign_request, AERNTEST_NETWORK_RESIGN_REQUEST_SEQUENCE, 
		AERNTEST_NETWORK_RESIGN_REQUEST_MESSAGE_SIZE, spkg.ccrt.serial, AERN_CERTIFICATE_SERIAL_SIZE, spkg.ckp.prikey) == true)
	{
		aern_network_resign_response_state st =
		{
			.list = &spkg.list,
			.rcert = &spkg.ccrt,
			.rnode = &rnode,
			.sigkey = spkg.dkp.prikey
		};

		pkt.pmessage[pkt.msglen - 1U] ^= 0x01U;
		merr = aern_network_resign_response(&st, &pkt);
		res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&rnode, sizeof(rnode)) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_revoke_response_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet pkt = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t bpkt[AERNTEST_NETWORK_REVOKE_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;

	if (aerntest_network_signed_packet_create(&pkt, aern_network_flag_network_revocation_broadcast, AERNTEST_NETWORK_REVOKE_REQUEST_SEQUENCE, 
		AERNTEST_NETWORK_REVOKE_REQUEST_MESSAGE_SIZE, spkg.acrt.serial, AERN_CERTIFICATE_SERIAL_SIZE, spkg.dkp.prikey) == true)
	{
		aern_network_revoke_response_state st =
		{
			.list = &spkg.list,
			.rnode = &rnode,
			.dcert = &spkg.dcrt
		};

		merr = aern_network_revoke_response(&st, &pkt);
		res = (merr == aern_protocol_error_none && aern_topology_nodes_are_equal(&rnode, &spkg.ande) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_revoke_response_failure_preserves_state_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet pkt = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t bpkt[AERNTEST_NETWORK_REVOKE_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	pkt.pmessage = bpkt + AERN_PACKET_HEADER_SIZE;

	if (aerntest_network_signed_packet_create(&pkt, aern_network_flag_network_revocation_broadcast, AERNTEST_NETWORK_REVOKE_REQUEST_SEQUENCE, 
		AERNTEST_NETWORK_REVOKE_REQUEST_MESSAGE_SIZE, spkg.acrt.serial, AERN_CERTIFICATE_SERIAL_SIZE, spkg.dkp.prikey) == true)
	{
		aern_network_revoke_response_state st =
		{
			.list = &spkg.list,
			.rnode = &rnode,
			.dcert = &spkg.dcrt
		};
		uint32_t count;

		count = spkg.list.count;
		pkt.sequence = AERNTEST_NETWORK_REVOKE_REQUEST_SEQUENCE + 1U;
		merr = aern_network_revoke_response(&st, &pkt);
		res = (merr != aern_protocol_error_none && spkg.list.count == count &&
			aerntest_network_memory_is_zeroed((const uint8_t*)&rnode, sizeof(rnode)) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_topological_query_response_verification_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aerntest_network_device_instantiate(&spkg);

	const aern_network_topological_query_request_state qrs =
	{
		.dcert = &spkg.dcrt,
		.dnode = &spkg.dnde,
		.issuer = spkg.ccrt2.issuer,
		.rnode = &rnode,
		.serial = spkg.ccrt.serial,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_query_response_state tsr =
		{
			.csock = NULL,
			.ccert = &spkg.ccrt,
			.rnode = &spkg.cnde2,
			.sigkey = spkg.dkp.prikey,
		};

		merr = network_topological_query_response_verify(query, &tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_topological_query_response_packet(&resp, &tsr, &reqt);

			if (merr == aern_protocol_error_none)
			{
				merr = network_topological_query_request_verify(&qrs, &resp);
				res = (merr == aern_protocol_error_none && aern_topology_nodes_are_equal(&rnode, &spkg.cnde2) == true);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}


static bool aerntest_network_register_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate dcert = { 0 };
	uint8_t breqt[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_register_request_state jrs =
	{
		.lcert = &spkg.acrt,
		.rcert = &dcert,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey
	};

	merr = network_register_request_packet(&reqt, &jrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_response_state jrr =
		{
			.csock = NULL,
			.lcert = &spkg.dcrt,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.dkp.prikey
		};

		merr = network_register_response_packet(&resp, &jrr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			resp.pmessage[resp.msglen - 1U] ^= 0x01U;
			merr = network_register_verify(&jrs, &resp);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&dcert, sizeof(dcert)) == true);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_incremental_update_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate ccert = { 0 };
	uint8_t breqt[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_incremental_update_request_state urs =
	{
		.rcert = &ccert,
		.rnode = &spkg.mnde,
		.root = &spkg.root
	};

	network_incremental_update_request_packet(&reqt, &urs);

	if (reqt.msglen == NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE)
	{
		aern_network_incremental_update_response_state urr =
		{
			.csock = NULL,
			.rcert = &spkg.mcrt,
			.sigkey = spkg.mkp.prikey
		};

		merr = network_incremental_update_response_packet(&resp, &reqt, &urr);

		if (merr == aern_protocol_error_none)
		{
			resp.pmessage[resp.msglen - 1U] ^= 0x01U;
			merr = network_incremental_update_verify(&urs, &resp);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&ccert, sizeof(ccert)) == true);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_register_update_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate dcert = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (AERN_NETWORK_TOPOLOGY_NODE_SIZE * 2U) + sizeof(uint32_t)] = { 0U };
	uint8_t* pbuf;
	aern_protocol_errors merr;
	bool res;

	pbuf = NULL;
	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_register_update_request_state jus =
	{
		.lcert = &spkg.ccrt,
		.list = &spkg.list,
		.rcert = &dcert,
		.root = &spkg.root,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_update_response_state jur =
		{
			.lcert = &spkg.dcrt,
			.list = &spkg.list,
			.rcert = &spkg.ccrt,
			.root = &spkg.root,
			.sigkey = spkg.dkp.prikey
		};

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);

			if (resp.pmessage != NULL && resp.pmessage != (bresp + AERN_PACKET_HEADER_SIZE))
			{
				pbuf = resp.pmessage - AERN_PACKET_HEADER_SIZE;
			}

			if (merr == aern_protocol_error_none)
			{
				resp.pmessage[resp.msglen - 1U] ^= 0x01U;
				merr = network_register_update_verify(&jus, &resp);
				res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&dcert, sizeof(dcert)) == true);
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_remote_signing_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_signature_keypair ckp3 = { 0 };
	aern_certificate_expiration exp = { 0 };
	aern_child_certificate rcert = { 0 };
	aern_child_certificate scert = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aern_certificate_signature_generate_keypair(&ckp3);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&rcert, ckp3.pubkey, &exp, "XYZ_CLT3", aern_network_designation_client);

	aern_network_remote_signing_request_state rsr =
	{
		.address = NULL,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	aern_network_remote_signing_response_state rsq =
	{
		.csock = NULL,
		.dcert = &spkg.dcrt,
		.rcert = &scert,
		.root = &spkg.root,
		.sigkey = spkg.rkp.prikey
	};

	merr = network_remote_signing_request_packet(&rsr, &reqt);

	if (merr == aern_protocol_error_none)
	{
		merr = network_remote_signing_response_verify(&rsq, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_remote_signing_response_packet(&rsq, &resp);

			if (merr == aern_protocol_error_none)
			{
				resp.pmessage[0U] ^= 0x01U;
				merr = network_remote_signing_request_verify(&rsr, &resp);
				res = (merr != aern_protocol_error_none);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_topological_status_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_topological_status_request_state tsq =
	{
		.lnode = &spkg.cnde,
		.rcert = &spkg.ccrt2,
		.rnode = &spkg.cnde2,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_topological_status_request_packet(&reqt, &tsq);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_status_response_state tsr =
		{
			.csock = NULL,
			.lnode = &spkg.cnde2,
			.rcert = &spkg.ccrt,
			.sigkey = spkg.ckp2.prikey
		};

		merr = network_topological_status_response_verify(&tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_topological_status_response_packet(&resp, &tsr);

			if (merr == aern_protocol_error_none)
			{
				resp.pmessage[resp.msglen - 1U] ^= 0x01U;
				merr = aern_network_topological_status_request_verify(&tsq, &resp);
				res = (merr != aern_protocol_error_none);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_register_request_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate rcert = { 0 };
	uint8_t breqt[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_register_request_state jrs =
	{
		.lcert = &spkg.acrt,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey
	};

	merr = network_register_request_packet(&reqt, &jrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_response_state jrr =
		{
			.csock = NULL,
			.lcert = &spkg.dcrt,
			.rcert = &rcert,
			.root = &spkg.root,
			.sigkey = spkg.dkp.prikey
		};

		reqt.pmessage[reqt.msglen - 1U] ^= 0x01U;
		merr = network_register_response_packet(&resp, &jrr, &reqt);
		res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&rcert, sizeof(rcert)) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_register_update_request_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate rcert = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (AERN_NETWORK_TOPOLOGY_NODE_SIZE * 2U) + sizeof(uint32_t)] = { 0U };
	uint8_t* pbuf;
	aern_protocol_errors merr;
	bool res;

	pbuf = NULL;
	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_register_update_request_state jus =
	{
		.lcert = &spkg.ccrt,
		.list = &spkg.list,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == aern_protocol_error_none)
	{
		aern_network_register_update_response_state jur =
		{
			.lcert = &spkg.dcrt,
			.list = &spkg.list,
			.rcert = &rcert,
			.root = &spkg.root,
			.sigkey = spkg.dkp.prikey
		};

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			reqt.pmessage[reqt.msglen - 1U] ^= 0x01U;
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&rcert, sizeof(rcert)) == true);

			if (resp.pmessage != NULL && resp.pmessage != (bresp + AERN_PACKET_HEADER_SIZE))
			{
				pbuf = resp.pmessage - AERN_PACKET_HEADER_SIZE;
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_incremental_update_truncated_response_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate ccert = { 0 };
	uint8_t breqt[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_incremental_update_request_state urs =
	{
		.rcert = &ccert,
		.rnode = &spkg.mnde,
		.root = &spkg.root
	};

	network_incremental_update_request_packet(&reqt, &urs);

	if (reqt.msglen == NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE)
	{
		aern_network_incremental_update_response_state urr =
		{
			.csock = NULL,
			.rcert = &spkg.mcrt,
			.sigkey = spkg.mkp.prikey
		};

		merr = network_incremental_update_response_packet(&resp, &reqt, &urr);

		if (merr == aern_protocol_error_none)
		{
			resp.msglen -= 1U;
			merr = network_incremental_update_verify(&urs, &resp);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&ccert, sizeof(ccert)) == true);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
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
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aern_network_packet esta = { 0 };
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.mcrt,
		.rcert = &spkg.acrt,
		.root = &spkg.root,
		.sigkey = spkg.mkp.prikey,
		.mfk = mfm
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt,
			.rcert = &spkg.mcrt,
			.root = &spkg.root,
			.sigkey = spkg.akp.prikey,
			.mfk = mfa
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			resp.pmessage[resp.msglen - 1U] ^= 0x01U;
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed(mfm, sizeof(mfm)) == true);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_establish_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
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
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.mcrt,
		.rcert = &spkg.acrt,
		.root = &spkg.root,
		.sigkey = spkg.mkp.prikey,
		.mfk = mfm
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt,
			.rcert = &spkg.mcrt,
			.root = &spkg.root,
			.sigkey = spkg.akp.prikey,
			.mfk = mfa
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);

			if (merr == aern_protocol_error_none)
			{
				esta.pmessage[esta.msglen - 1U] ^= 0x01U;
				merr = network_mfk_verify_packet(&esta, &sresp);
				res = (merr != aern_protocol_error_none);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_topological_query_response_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_topology_node_state rnode = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aerntest_network_device_instantiate(&spkg);

	const aern_network_topological_query_request_state qrs =
	{
		.dcert = &spkg.dcrt,
		.dnode = &spkg.dnde,
		.issuer = spkg.ccrt2.issuer,
		.rnode = &rnode,
		.serial = spkg.ccrt.serial,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_query_response_state tsr =
		{
			.csock = NULL,
			.ccert = &spkg.ccrt,
			.rnode = &spkg.cnde2,
			.sigkey = spkg.dkp.prikey,
		};

		merr = network_topological_query_response_verify(query, &tsr, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_topological_query_response_packet(&resp, &tsr, &reqt);

			if (merr == aern_protocol_error_none)
			{
				resp.pmessage[resp.msglen - 1U] ^= 0x01U;
				merr = network_topological_query_request_verify(&qrs, &resp);
				res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed((const uint8_t*)&rnode, sizeof(rnode)) == true);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_topological_query_request_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	aerntest_network_device_instantiate(&spkg);

	const aern_network_topological_query_request_state qrs =
	{
		.dcert = &spkg.dcrt,
		.dnode = &spkg.dnde,
		.issuer = spkg.ccrt2.issuer,
		.rnode = &spkg.cnde2,
		.serial = spkg.ccrt.serial,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_query_response_state tsr =
		{
			.csock = NULL,
			.ccert = &spkg.ccrt,
			.rnode = &spkg.cnde2,
			.sigkey = spkg.dkp.prikey,
		};

		reqt.pmessage[reqt.msglen - 1U] ^= 0x01U;
		merr = network_topological_query_response_verify(query, &tsr, &reqt);
		res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed(query, sizeof(query)) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_topological_status_request_bad_signature_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;

	aern_network_topological_status_request_state tsq =
	{
		.lnode = &spkg.cnde,
		.rcert = &spkg.ccrt2,
		.rnode = &spkg.cnde2,
		.sigkey = spkg.ckp.prikey
	};

	merr = network_topological_status_request_packet(&reqt, &tsq);

	if (merr == aern_protocol_error_none)
	{
		aern_network_topological_status_response_state tsr =
		{
			.csock = NULL,
			.lnode = &spkg.cnde2,
			.rcert = &spkg.ccrt,
			.sigkey = spkg.ckp2.prikey
		};

		reqt.pmessage[reqt.msglen - 1U] ^= 0x01U;
		merr = network_topological_status_response_verify(&tsr, &reqt);
		res = (merr != aern_protocol_error_none);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}


static bool aerntest_network_malformed_announce_test(void)
{
	aern_topology_node_state rnode = { 0 };
	aern_child_certificate rcert = { 0 };
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	merr = aern_protocol_error_invalid_request;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;

	aern_network_announce_request_state aqs = 
	{
		.list = &spkg.list,
		.rnode = &spkg.ande,
		.sigkey = spkg.dkp.prikey
	};

	aern_network_announce_response_state ars = 
	{
		.dcert = &spkg.dcrt,
		.rnode = &rnode,
		.root = &spkg.root
	};

	merr = network_announce_broadcast_packet(&reqt, &aqs);

	if (merr == aern_protocol_error_none)
	{
		aern_network_packet badpkt = { 0 };

		badpkt = reqt;
		badpkt.msglen -= 1U;
		merr = aern_network_announce_response(&ars, &badpkt);

		if (merr != aern_protocol_error_none)
		{
			badpkt = reqt;
			badpkt.flag = aern_network_flag_tunnel_session_established;
			merr = aern_network_announce_response(&ars, &badpkt);
			res = (merr != aern_protocol_error_none);
		}
	}

	aerntest_network_device_destroy(&spkg);
	qsc_memutils_clear(&rcert, sizeof(rcert));

	return res;
}

static bool aerntest_network_fkey_authentication_failure_test(void)
{
	aerntest_network_device_package spkg = { 0 };
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

	merr = aern_protocol_error_invalid_request;
	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	qsc_acp_generate(mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_memutils_copy(mfm, mfa, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);

	aern_network_fkey_request_state frs = 
	{
		.frag = frm,
		.lnode = &spkg.mnde,
		.mfk = mfm,
		.rnode = &spkg.ande,
		.token = atok
	};

	aern_network_fkey_response_state frr = 
	{
		.csock = NULL,
		.frag = fra,
		.lnode = &spkg.ande,
		.mfk = mfa,
		.rnode = &spkg.mnde
	};

	network_fkey_request_packet(&reqt, &frs);
	merr = network_fkey_response_packet(&resp, &reqt, &frr);

	if (merr == aern_protocol_error_none)
	{
		resp.pmessage[resp.msglen - 1U] ^= 0x01U;
		merr = network_fkey_response_verify(&frs, &resp);
		res = (merr != aern_protocol_error_none);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_register_update_malformed_request_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	aern_child_certificate dccp = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (AERN_NETWORK_TOPOLOGY_NODE_SIZE * 2U) + sizeof(uint32_t)] = { 0U };
	uint8_t* pbuf;
	aern_protocol_errors merr;
	bool res;

	pbuf = NULL;
	merr = aern_protocol_error_invalid_request;
	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_register_update_request_state jus = 
	{
		.lcert = &spkg.ccrt,
		.list = &spkg.list,
		.rcert = &dccp,
		.root = &spkg.root,
		.sigkey = spkg.ckp.prikey
	};

	aern_network_register_update_response_state jur = 
	{
		.lcert = &spkg.dcrt,
		.list = &spkg.list,
		.rcert = &spkg.ccrt,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == aern_protocol_error_none)
	{
		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			reqt.msglen -= 1U;
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);
			res = (merr != aern_protocol_error_none);

			if (resp.pmessage != NULL && resp.pmessage != (bresp + AERN_PACKET_HEADER_SIZE))
			{
				pbuf = resp.pmessage - AERN_PACKET_HEADER_SIZE;
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_remote_signing_malformed_request_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_signature_keypair ckp3 = { 0 };
	aern_certificate_expiration exp = { 0 };
	aern_child_certificate rcert = { 0 };
	aern_child_certificate scert = { 0 };
	aern_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	merr = aern_protocol_error_invalid_request;
	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	aern_certificate_signature_generate_keypair(&ckp3);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&rcert, ckp3.pubkey, &exp, "XYZ_CLT3", aern_network_designation_client);

	aern_network_remote_signing_request_state rsr = 
	{
		.address = NULL,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	aern_network_remote_signing_response_state rsq = 
	{
		.csock = NULL,
		.dcert = &spkg.dcrt,
		.rcert = &scert,
		.root = &spkg.root,
		.sigkey = spkg.rkp.prikey
	};

	merr = network_remote_signing_request_packet(&rsr, &reqt);

	if (merr == aern_protocol_error_none)
	{
		reqt.pmessage[reqt.msglen - 1U] ^= 0x01U;
		merr = network_remote_signing_response_verify(&rsq, &reqt);
		res = (merr != aern_protocol_error_none);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_malformed_converge_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t snode[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	merr = aern_protocol_error_invalid_request;
	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	aern_topology_node_serialize(snode, &spkg.mnde);

	aern_network_converge_request_state cqs = 
	{
		.rcert = &spkg.mcrt,
		.rnode = &spkg.mnde,
		.sigkey = spkg.dkp.prikey
	};

	merr = network_converge_request_packet(&reqt, &cqs, snode);

	if (merr == aern_protocol_error_none)
	{
		const aern_network_converge_response_state cus = 
		{
			.csock = NULL,
			.lcert = &spkg.mcrt,
			.lnode = &spkg.mnde,
			.rcert = &spkg.dcrt,
			.sigkey = spkg.mkp.prikey
		};

		merr = network_converge_request_verify(&cus, &reqt);

		if (merr == aern_protocol_error_none)
		{
			merr = network_converge_response_packet(&resp, &cus);

			if (merr == aern_protocol_error_none)
			{
				resp.pmessage[0U] ^= 0x01U;
				merr = network_converge_response_verify(&cqs, &resp);
				res = (merr != aern_protocol_error_none);
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}


static bool aerntest_network_mfk_aps_to_aps_exchange_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet esta = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };
	uint8_t mfki[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfkr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.acrt,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.mfk = mfki
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt2,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.akp2.prikey,
			.mfk = mfkr
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);

			if (merr == aern_protocol_error_none)
			{
				merr = network_mfk_verify_packet(&esta, &sresp);

				if (merr == aern_protocol_error_none)
				{
					res = qsc_memutils_are_equal(mfki, mfkr, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
				}
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_client_to_aps_exchange_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet esta = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };
	uint8_t mfkc[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfka[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.ccrt,
		.rcert = &spkg.acrt,
		.root = &spkg.root,
		.sigkey = spkg.ckp.prikey,
		.mfk = mfkc
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt,
			.rcert = &spkg.ccrt,
			.root = &spkg.root,
			.sigkey = spkg.akp.prikey,
			.mfk = mfka
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);

			if (merr == aern_protocol_error_none)
			{
				merr = network_mfk_verify_packet(&esta, &sresp);

				if (merr == aern_protocol_error_none)
				{
					res = qsc_memutils_are_equal(mfkc, mfka, AERN_CRYPTO_SYMMETRIC_KEY_SIZE);
				}
			}
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_request_corrupt_certificate_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t mfki[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfkr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.acrt,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.mfk = mfki
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		reqt.pmessage[AERN_PACKET_SUBHEADER_SIZE + 3U] ^= 0x01U;

		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt2,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.akp2.prikey,
			.mfk = mfkr
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);
		res = (merr != aern_protocol_error_none);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_decapsulation_failure_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet esta = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };
	uint8_t cpt[AERN_ASYMMETRIC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t mfki[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfkr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);

	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;
	qsc_memutils_set_value(cpt, sizeof(cpt), 0xA5U);

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.acrt,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.mfk = mfki
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt2,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.akp2.prikey,
			.mfk = mfkr
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none &&
			aerntest_network_signed_packet_create(&esta, aern_network_flag_mfk_establish, AERNTEST_NETWORK_MFK_ESTABLISH_SEQUENCE, NETWORK_MFK_ESTABLISH_MESSAGE_SIZE, cpt, sizeof(cpt), spkg.akp.prikey) == true)
		{
			merr = network_mfk_verify_packet(&esta, &sresp);
			res = (merr != aern_protocol_error_none);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}


static bool aerntest_network_mek_directional_state_roundtrip_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	uint8_t secret1[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t secret2[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	aerntest_network_device_instantiate(&spkg);
	qsc_acp_generate(secret1, sizeof(secret1));
	qsc_memutils_copy(secret2, secret1, sizeof(secret2));
	qsc_acp_generate(msg, sizeof(msg));
	pkt.pmessage = cpt;

	mek_derive_and_init_ciphers(&initiator, secret1, spkg.acrt.serial, spkg.acrt2.serial, true);
	mek_derive_and_init_ciphers(&responder, secret2, spkg.acrt.serial, spkg.acrt2.serial, false);

	if (initiator.exflag == aern_network_flag_tunnel_session_established &&
		responder.exflag == aern_network_flag_tunnel_session_established &&
		initiator.txseq == 0U && initiator.rxseq == 0U && responder.txseq == 0U && responder.rxseq == 0U &&
		initiator.authfail == 0U && responder.authfail == 0U)
	{
		merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

		if (merr == aern_protocol_error_none && initiator.txseq == 1U)
		{
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);

			if (merr == aern_protocol_error_none && responder.rxseq == 1U && mlen == sizeof(msg) && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true)
			{
				qsc_memutils_clear(cpt, sizeof(cpt));
				qsc_memutils_clear(out, sizeof(out));
				pkt.pmessage = cpt;
				merr = aern_encrypt_packet(&responder, &pkt, msg, sizeof(msg));

				if (merr == aern_protocol_error_none && responder.txseq == 1U)
				{
					merr = aern_decrypt_packet(&initiator, out, &mlen, &pkt);
					res = (merr == aern_protocol_error_none && initiator.rxseq == 1U && mlen == sizeof(msg) &&
						qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
				}
			}
		}
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);
	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mek_directional_material_separation_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	uint8_t secret1[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t secret2[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	qsc_acp_generate(secret1, sizeof(secret1));
	qsc_memutils_copy(secret2, secret1, sizeof(secret2));

	mek_derive_and_init_ciphers(&initiator, secret1, spkg.acrt.serial, spkg.acrt2.serial, true);
	mek_derive_and_init_ciphers(&responder, secret2, spkg.acrt.serial, spkg.acrt2.serial, false);

#if defined(AERN_USE_RCS_ENCRYPTION)
	res = (qsc_memutils_are_equal(initiator.txcpr.nonce, responder.rxcpr.nonce, AERN_CRYPTO_SYMMETRIC_NONCE_SIZE) == true &&
		qsc_memutils_are_equal(initiator.rxcpr.nonce, responder.txcpr.nonce, AERN_CRYPTO_SYMMETRIC_NONCE_SIZE) == true &&
		qsc_memutils_are_equal(initiator.txcpr.nonce, initiator.rxcpr.nonce, AERN_CRYPTO_SYMMETRIC_NONCE_SIZE) == false &&
		qsc_memutils_are_equal(responder.txcpr.nonce, responder.rxcpr.nonce, AERN_CRYPTO_SYMMETRIC_NONCE_SIZE) == false);
#else
	res = (qsc_memutils_are_equal(&initiator.txcpr, &responder.rxcpr, sizeof(aern_cipher_state)) == false &&
		qsc_memutils_are_equal(&initiator.rxcpr, &responder.txcpr, sizeof(aern_cipher_state)) == false);
#endif

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);
	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mek_request_invalid_certificate_no_state_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_child_certificate badcert = { 0 };
	aern_connection_state cns = { 0 };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	qsc_memutils_copy(&badcert, &spkg.acrt, sizeof(aern_child_certificate));
	badcert.csig[0U] ^= 0x01U;

	aern_mek_request_state st =
	{
		.remote_address = "192.168.1.2",
		.lcert = &badcert,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.cns_out = &cns
	};

	merr = aern_mek_exchange_request(&st);
	res = (merr == aern_protocol_error_authentication_failure && cns.exflag != aern_network_flag_tunnel_session_established &&
		aerntest_network_memory_is_zeroed((const uint8_t*)&cns, sizeof(cns)) == true);

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mek_response_invalid_certificate_no_state_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_child_certificate badcert = { 0 };
	aern_connection_state cns = { 0 };
	aern_network_packet pkt = { 0 };
	qsc_socket sock = { 0 };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	qsc_memutils_copy(&badcert, &spkg.acrt2, sizeof(aern_child_certificate));
	badcert.csig[0U] ^= 0x01U;

	aern_mek_response_state st =
	{
		.csock = &sock,
		.lcert = &badcert,
		.rcert = &spkg.acrt,
		.root = &spkg.root,
		.sigkey = spkg.akp2.prikey,
		.cns_out = &cns
	};

	merr = aern_mek_exchange_response(&st, &pkt);
	res = (merr == aern_protocol_error_authentication_failure && cns.exflag != aern_network_flag_tunnel_session_established &&
		aerntest_network_memory_is_zeroed((const uint8_t*)&cns, sizeof(cns)) == true);

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_request_corrupt_certificate_no_secret_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t mfki[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfkr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.acrt,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.mfk = mfki
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		reqt.pmessage[AERN_PACKET_SUBHEADER_SIZE] ^= 0x01U;

		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt2,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.akp2.prikey,
			.mfk = mfkr
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);
		res = (merr != aern_protocol_error_none &&
			aerntest_network_memory_is_zeroed(mfkr, sizeof(mfkr)) == true &&
			aerntest_network_memory_is_zeroed(sresp.ckp.pubkey, sizeof(sresp.ckp.pubkey)) == true &&
			aerntest_network_memory_is_zeroed(sresp.ckp.prikey, sizeof(sresp.ckp.prikey)) == true);
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}

static bool aerntest_network_mfk_bad_response_signature_no_secret_test(void)
{
	aerntest_network_device_package spkg = { 0 };
	aern_network_packet esta = { 0 };
	aern_network_packet reqt = { 0 };
	aern_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0U };
	uint8_t mfki[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t mfkr[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	aerntest_network_device_instantiate(&spkg);
	reqt.pmessage = breqt + AERN_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + AERN_PACKET_HEADER_SIZE;
	esta.pmessage = besta + AERN_PACKET_HEADER_SIZE;

	aern_network_mfk_request_state sreqt =
	{
		.lcert = &spkg.acrt,
		.rcert = &spkg.acrt2,
		.root = &spkg.root,
		.sigkey = spkg.akp.prikey,
		.mfk = mfki
	};

	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == aern_protocol_error_none)
	{
		aern_network_mfk_response_state sresp =
		{
			.lcert = &spkg.acrt2,
			.rcert = &spkg.acrt,
			.root = &spkg.root,
			.sigkey = spkg.akp2.prikey,
			.mfk = mfkr
		};

		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == aern_protocol_error_none)
		{
			resp.pmessage[AERN_PACKET_SUBHEADER_SIZE + AERN_ASYMMETRIC_PUBLIC_KEY_SIZE] ^= 0x01U;
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);
			res = (merr != aern_protocol_error_none && aerntest_network_memory_is_zeroed(mfki, sizeof(mfki)) == true);
		}
	}

	aerntest_network_device_destroy(&spkg);

	return res;
}


static void aerntest_network_mek_test_pair_initialize(aern_connection_state* initiator, aern_connection_state* responder)
{
	uint8_t secret1[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t secret2[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
	uint8_t serial1[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };
	uint8_t serial2[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };

	qsc_acp_generate(secret1, sizeof(secret1));
	qsc_memutils_copy(secret2, secret1, sizeof(secret2));
	qsc_acp_generate(serial1, sizeof(serial1));
	qsc_acp_generate(serial2, sizeof(serial2));
	mek_derive_and_init_ciphers(initiator, secret1, serial1, serial2, true);
	mek_derive_and_init_ciphers(responder, secret2, serial1, serial2, false);
}

static bool aerntest_network_connection_encrypt_sequence_policy_test(void)
{
	aern_connection_state cns = { 0 };
	aern_connection_state peer = { 0 };
	aern_connection_state inactive = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&cns, &peer);
	inactive.txseq = 7U;
	inactive.exflag = aern_network_flag_none;

	merr = aern_encrypt_packet(&cns, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none && cns.txseq == 1U && pkt.sequence == 1U &&
		pkt.flag == aern_network_flag_tunnel_encrypted_message &&
		pkt.msglen == (uint32_t)(sizeof(msg) + AERN_CRYPTO_SYMMETRIC_MAC_SIZE))
	{
		merr = aern_encrypt_packet(&inactive, &pkt, msg, sizeof(msg));
		res = (merr == aern_protocol_error_channel_down && inactive.txseq == 7U);
	}

	aern_connection_state_dispose(&cns);
	aern_connection_state_dispose(&peer);
	aern_connection_state_dispose(&inactive);

	return res;
}

static bool aerntest_network_connection_decrypt_success_sequence_policy_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none && initiator.txseq == 1U && responder.rxseq == 0U)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_none && responder.rxseq == 1U && responder.authfail == 0U &&
			mlen == sizeof(msg) && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_auth_failure_no_rx_advance_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		pkt.pmessage[0U] ^= 0x01U;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_authentication_failure && responder.rxseq == 0U &&
			responder.authfail == 1U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_auth_failure_preserves_rcs_state_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	aern_network_packet badpkt = { 0 };
	uint8_t cpt1[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t cpt2[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t badcpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg1[32U] = { 0U };
	uint8_t msg2[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt1.pmessage = cpt1;
	pkt2.pmessage = cpt2;
	qsc_acp_generate(msg1, sizeof(msg1));
	qsc_acp_generate(msg2, sizeof(msg2));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt1, msg1, sizeof(msg1));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt1);
	}

	if (merr == aern_protocol_error_none && responder.rxseq == 1U && initiator.txseq == 1U)
	{
		merr = aern_encrypt_packet(&initiator, &pkt2, msg2, sizeof(msg2));
	}

	if (merr == aern_protocol_error_none)
	{
		badpkt = pkt2;
		badpkt.pmessage = badcpt;
		qsc_memutils_copy(badcpt, cpt2, sizeof(badcpt));
		badpkt.pmessage[0U] ^= 0x01U;
		mlen = 0U;
		qsc_memutils_clear(out, sizeof(out));
		merr = aern_decrypt_packet(&responder, out, &mlen, &badpkt);
	}

	if (merr == aern_protocol_error_authentication_failure && responder.rxseq == 1U &&
		responder.authfail == 1U && mlen == 0U)
	{
		mlen = 0U;
		qsc_memutils_clear(out, sizeof(out));
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt2);
		res = (merr == aern_protocol_error_none && responder.rxseq == 2U && responder.authfail == 0U &&
			mlen == sizeof(msg2) && qsc_memutils_are_equal(out, msg2, sizeof(msg2)) == true);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_success_resets_authfail_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);
	responder.authfail = 2U;

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_none && responder.rxseq == 1U && responder.authfail == 0U &&
			mlen == sizeof(msg) && qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_time_failure_no_state_change_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		pkt.utctime -= (AERN_PACKET_TIME_THRESHOLD + 2ULL);
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_message_time_invalid && responder.rxseq == 0U &&
			responder.authfail == 0U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_tx_overflow_no_increment_test(void)
{
	aern_connection_state cns = { 0 };
	aern_connection_state peer = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&cns, &peer);
	cns.txseq = UINT64_MAX;

	merr = aern_encrypt_packet(&cns, &pkt, msg, sizeof(msg));
	res = (merr == aern_protocol_error_channel_down && cns.txseq == UINT64_MAX && pkt.msglen == 0U);

	aern_connection_state_dispose(&cns);
	aern_connection_state_dispose(&peer);

	return res;
}

static bool aerntest_network_connection_zero_length_send_no_increment_test(void)
{
	aern_connection_state cns = { 0 };
	aern_connection_state peer = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[1U] = { 0U };
	aern_protocol_errors merr;
	bool res;

	res = false;
	pkt.pmessage = cpt;
	aerntest_network_mek_test_pair_initialize(&cns, &peer);

	merr = aern_encrypt_packet(&cns, &pkt, msg, 0U);
	res = (merr == aern_protocol_error_channel_down && cns.txseq == 0U && pkt.msglen == 0U);

	aern_connection_state_dispose(&cns);
	aern_connection_state_dispose(&peer);

	return res;
}

static bool aerntest_network_connection_disposed_cannot_encrypt_or_decrypt_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		aern_connection_state_dispose(&initiator);
		aern_connection_state_dispose(&responder);
		merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

		if (merr == aern_protocol_error_channel_down && initiator.txseq == 0U)
		{
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
			res = (merr == aern_protocol_error_packet_header_invalid && responder.rxseq == 0U &&
				responder.authfail == 0U && mlen == 0U);
		}
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_malformed_packet_no_rx_advance_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.flag = aern_network_flag_tunnel_encrypted_message;
	pkt.sequence = 1U;
	pkt.msglen = AERN_CRYPTO_SYMMETRIC_MAC_SIZE;
	pkt.pmessage = cpt;
	aern_packet_set_utc_time(&pkt);
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
	res = (merr == aern_protocol_error_packet_header_invalid && responder.rxseq == 0U &&
		responder.authfail == 0U && mlen == 0U);

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_unsequenced_packet_no_rx_advance_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		responder.rxseq = 1U;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_packet_unsequenced && responder.rxseq == 1U &&
			responder.authfail == 0U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_auth_failure_threshold_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;
	uint32_t i;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		pkt.pmessage[0U] ^= 0x01U;

		for (i = 0U; i < AERN_RELAY_AUTH_FAILURE_LIMIT; ++i)
		{
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		}

		res = (merr == aern_protocol_error_channel_down && responder.rxseq == 0U &&
			responder.authfail == AERN_RELAY_AUTH_FAILURE_LIMIT);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_connection_dispose_resets_state_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	bool res;

	res = false;
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);
	initiator.instance = 42U;
	initiator.authfail = 3U;
	initiator.rxseq = 9U;
	initiator.txseq = 11U;
	aern_connection_state_dispose(&initiator);
	res = (initiator.rxseq == 0U && initiator.txseq == 0U && initiator.authfail == 0U &&
		initiator.instance == 0U && initiator.exflag == aern_network_flag_none);

	aern_connection_state_dispose(&responder);

	return res;
}


static bool aerntest_network_packet_header_roundtrip_test(void)
{
	aern_network_packet pkt = { 0 };
	aern_network_packet cmp = { 0 };
	uint8_t hdr[AERN_PACKET_HEADER_SIZE] = { 0U };
	bool res;

	pkt.flag = aern_network_flag_tunnel_encrypted_message;
	pkt.msglen = AERN_RELAY_CIPHERTEXT_SIZE;
	pkt.sequence = 0x0102030405060708ULL;
	pkt.utctime = 0x1112131415161718ULL;

	aern_packet_header_serialize(&pkt, hdr);
	aern_packet_header_deserialize(hdr, &cmp);

	res = (AERN_PACKET_HEADER_SIZE == 22U && hdr[21U] == 0U && cmp.flag == pkt.flag &&
		cmp.msglen == pkt.msglen && cmp.sequence == pkt.sequence && cmp.utctime == pkt.utctime);

	return res;
}

static bool aerntest_network_packet_stream_header_size_test(void)
{
	aern_network_packet pkt = { 0 };
	aern_network_packet cmp = { 0 };
	uint8_t msg[3U] = { 0xA1U, 0xB2U, 0xC3U };
	uint8_t out[3U] = { 0U };
	uint8_t stream[AERN_PACKET_HEADER_SIZE + sizeof(msg)] = { 0U };
	size_t slen;
	bool res;

	pkt.flag = aern_network_flag_tunnel_encrypted_message;
	pkt.msglen = (uint32_t)sizeof(msg);
	pkt.sequence = 7U;
	pkt.utctime = qsc_timestamp_datetime_utc();
	pkt.pmessage = msg;
	cmp.pmessage = out;

	slen = aern_packet_to_stream(&pkt, stream);
	aern_stream_to_packet(stream, &cmp);

	res = (slen == (AERN_PACKET_HEADER_SIZE + sizeof(msg)) && stream[21U] == 0U &&
		stream[AERN_PACKET_HEADER_SIZE] == msg[0U] && cmp.flag == pkt.flag && cmp.msglen == pkt.msglen &&
		cmp.sequence == pkt.sequence && cmp.utctime == pkt.utctime &&
		qsc_memutils_are_equal(out, msg, sizeof(msg)) == true);

	return res;
}

static bool aerntest_network_relay_packet_size_model_test(void)
{
	bool res;

	res = (AERN_NETWORK_CONNECTION_MTU == 1500U && AERN_RELAY_MTU == 1500U &&
		AERN_PACKET_HEADER_SIZE == 22U && AERN_RELAY_HEADER_SIZE == 22U &&
		AERN_PACKET_HEADER_SIZE != 54U && AERN_RELAY_CIPHERTEXT_SIZE == 1478U &&
		AERN_RELAY_MAC_SIZE == AERN_CRYPTO_SYMMETRIC_MAC_SIZE && AERN_RELAY_MAC_SIZE == 32U &&
		AERN_RELAY_PLAINTEXT_SIZE == 1446U && AERN_LEN_PREFIX_SIZE == 2U &&
		AERN_ROUTEMAP_SIZE == 16U && AERN_RELAY_PAYLOAD_HEADER_SIZE == 32U &&
		AERN_MAX_USER_PAYLOAD == 1428U && AERN_RELAY_DATA_PAYLOAD_SIZE == 1396U &&
		AERN_FRAG_CHUNK_SIZE == 1396U);

	return res;
}

static bool aerntest_network_fixed_relay_packet_serialization_size_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t msg[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t cpt[AERN_RELAY_CIPHERTEXT_SIZE] = { 0U };
	uint8_t stream[AERN_RELAY_MTU] = { 0U };
	size_t slen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		slen = aern_packet_to_stream(&pkt, stream);
		res = (pkt.msglen == AERN_RELAY_CIPHERTEXT_SIZE && slen == AERN_RELAY_MTU &&
			stream[0U] == (uint8_t)aern_network_flag_tunnel_encrypted_message && stream[21U] == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_outer_header_flag_aad_authentication_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		pkt.flag = aern_network_flag_tunnel_connection_terminate;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_authentication_failure && responder.rxseq == 0U &&
			responder.authfail == 1U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_outer_header_length_aad_authentication_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none && pkt.msglen > (AERN_CRYPTO_SYMMETRIC_MAC_SIZE + 1U))
	{
		--pkt.msglen;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_authentication_failure && responder.rxseq == 0U &&
			responder.authfail == 1U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_outer_header_timestamp_aad_authentication_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		++pkt.utctime;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_authentication_failure && responder.rxseq == 0U &&
			responder.authfail == 1U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_outer_header_future_timestamp_rejection_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		pkt.utctime += (AERN_PACKET_TIME_THRESHOLD + 2ULL);
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_message_time_invalid && responder.rxseq == 0U &&
			responder.authfail == 0U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}


static bool aerntest_network_replay_valid_ordered_sequence_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	uint8_t cpt1[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t cpt2[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg1[32U] = { 0U };
	uint8_t msg2[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt1.pmessage = cpt1;
	pkt2.pmessage = cpt2;
	qsc_acp_generate(msg1, sizeof(msg1));
	qsc_acp_generate(msg2, sizeof(msg2));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt1, msg1, sizeof(msg1));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_encrypt_packet(&initiator, &pkt2, msg2, sizeof(msg2));
	}

	if (merr == aern_protocol_error_none && pkt1.sequence == 1U && pkt2.sequence == 2U)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt1);

		if (merr == aern_protocol_error_none && responder.rxseq == 1U && mlen == sizeof(msg1) &&
			qsc_memutils_are_equal(out, msg1, sizeof(msg1)) == true)
		{
			qsc_memutils_clear(out, sizeof(out));
			mlen = 0U;
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt2);
			res = (merr == aern_protocol_error_none && responder.rxseq == 2U && responder.authfail == 0U &&
				mlen == sizeof(msg2) && qsc_memutils_are_equal(out, msg2, sizeof(msg2)) == true);
		}
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_replay_duplicate_packet_rejected_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);

		if (merr == aern_protocol_error_none && responder.rxseq == 1U)
		{
			mlen = 0U;
			qsc_memutils_clear(out, sizeof(out));
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
			res = (merr == aern_protocol_error_packet_unsequenced && responder.rxseq == 1U && responder.authfail == 0U && mlen == 0U);
		}
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_replay_future_sequence_rejected_without_state_change_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	uint8_t cpt1[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t cpt2[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg1[32U] = { 0U };
	uint8_t msg2[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt1.pmessage = cpt1;
	pkt2.pmessage = cpt2;
	qsc_acp_generate(msg1, sizeof(msg1));
	qsc_acp_generate(msg2, sizeof(msg2));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt1, msg1, sizeof(msg1));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_encrypt_packet(&initiator, &pkt2, msg2, sizeof(msg2));
	}

	if (merr == aern_protocol_error_none && pkt2.sequence == 2U)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt2);

		if (merr == aern_protocol_error_packet_unsequenced && responder.rxseq == 0U &&
			responder.authfail == 0U && mlen == 0U)
		{
			qsc_memutils_clear(out, sizeof(out));
			mlen = 0U;
			merr = aern_decrypt_packet(&responder, out, &mlen, &pkt1);
			res = (merr == aern_protocol_error_none && responder.rxseq == 1U && responder.authfail == 0U &&
				mlen == sizeof(msg1) && qsc_memutils_are_equal(out, msg1, sizeof(msg1)) == true);
		}
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_replay_old_sequence_rejected_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt1 = { 0 };
	aern_network_packet pkt2 = { 0 };
	uint8_t cpt1[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t cpt2[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg1[32U] = { 0U };
	uint8_t msg2[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt1.pmessage = cpt1;
	pkt2.pmessage = cpt2;
	qsc_acp_generate(msg1, sizeof(msg1));
	qsc_acp_generate(msg2, sizeof(msg2));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt1, msg1, sizeof(msg1));

	if (merr == aern_protocol_error_none)
	{
		merr = aern_encrypt_packet(&initiator, &pkt2, msg2, sizeof(msg2));
	}

	if (merr == aern_protocol_error_none)
	{
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt1);
	}

	if (merr == aern_protocol_error_none)
	{
		qsc_memutils_clear(out, sizeof(out));
		mlen = 0U;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt2);
	}

	if (merr == aern_protocol_error_none && responder.rxseq == 2U)
	{
		qsc_memutils_clear(out, sizeof(out));
		mlen = 0U;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt1);
		res = (merr == aern_protocol_error_packet_unsequenced && responder.rxseq == 2U && responder.authfail == 0U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_replay_modified_sequence_aad_failure_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	aern_network_packet pkt = { 0 };
	uint8_t cpt[32U + AERN_CRYPTO_SYMMETRIC_MAC_SIZE] = { 0U };
	uint8_t msg[32U] = { 0U };
	uint8_t out[32U] = { 0U };
	size_t mlen;
	aern_protocol_errors merr;
	bool res;

	res = false;
	mlen = 0U;
	pkt.pmessage = cpt;
	qsc_acp_generate(msg, sizeof(msg));
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	merr = aern_encrypt_packet(&initiator, &pkt, msg, sizeof(msg));

	if (merr == aern_protocol_error_none)
	{
		responder.rxseq = 1U;
		pkt.sequence = 2U;
		merr = aern_decrypt_packet(&responder, out, &mlen, &pkt);
		res = (merr == aern_protocol_error_authentication_failure && responder.rxseq == 1U && responder.authfail == 1U && mlen == 0U);
	}

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}

static bool aerntest_network_replay_window_zero_policy_test(void)
{
	bool res;

	res = (AERN_RELAY_REPLAY_WINDOW_SIZE == 0U);

	return res;
}

static bool aerntest_network_rekey_resets_sequence_state_test(void)
{
	aern_connection_state initiator = { 0 };
	aern_connection_state responder = { 0 };
	bool res;

	res = false;
	aerntest_network_mek_test_pair_initialize(&initiator, &responder);
	initiator.txseq = 99U;
	initiator.rxseq = 77U;
	initiator.authfail = 3U;
	responder.txseq = 55U;
	responder.rxseq = 44U;
	responder.authfail = 2U;

	aerntest_network_mek_test_pair_initialize(&initiator, &responder);

	res = (initiator.txseq == 0U && initiator.rxseq == 0U && initiator.authfail == 0U &&
		responder.txseq == 0U && responder.rxseq == 0U && responder.authfail == 0U &&
		initiator.exflag == aern_network_flag_tunnel_session_established &&
		responder.exflag == aern_network_flag_tunnel_session_established);

	aern_connection_state_dispose(&initiator);
	aern_connection_state_dispose(&responder);

	return res;
}


static bool aerntest_network_mek_rekey_threshold_test(void)
{
	aern_connection_state cns = { 0 };
	bool res;

	res = true;

	cns.txseq = AERN_MEK_REKEY_SOFT_THRESHOLD - 1ULL;
	cns.rxseq = 0U;

	if (aern_mek_rekey_required(&cns) == true)
	{
		res = false;
	}

	cns.txseq = AERN_MEK_REKEY_SOFT_THRESHOLD;

	if (aern_mek_rekey_required(&cns) == false)
	{
		res = false;
	}

	cns.txseq = 0U;
	cns.rxseq = AERN_MEK_REKEY_SOFT_THRESHOLD;

	if (aern_mek_rekey_required(&cns) == false)
	{
		res = false;
	}

	cns.rxseq = AERN_MEK_REKEY_PACKET_THRESHOLD - 1ULL;

	if (aern_mek_rekey_limit_exceeded(&cns) == true)
	{
		res = false;
	}

	cns.rxseq = AERN_MEK_REKEY_PACKET_THRESHOLD;

	if (aern_mek_rekey_limit_exceeded(&cns) == false)
	{
		res = false;
	}

	return res;
}

bool aerntest_network_run(void)
{
	bool res;

	res = true;

	if (aerntest_network_announce_test() == true)
	{
		aerntest_print_line("[PASS] AERN network announce test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network announce test.");
		res = false;
	}

	if (aerntest_network_converge_test() == true)
	{
		aerntest_print_line("[PASS] AERN network converge test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network converge test.");
		res = false;
	}

	if (aerntest_network_converge_update_test() == true)
	{
		aerntest_print_line("[PASS] AERN network converge update test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network converge update test.");
		res = false;
	}

	if (aerntest_network_malformed_announce_test() == true)
	{
		aerntest_print_line("[PASS] AERN network malformed announce test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network malformed announce test.");
		res = false;
	}

	if (aerntest_network_malformed_converge_test() == true)
	{
		aerntest_print_line("[PASS] AERN network malformed converge test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network malformed converge test.");
		res = false;
	}

	if (aerntest_network_fkey_encryption_test() == true)
	{
		aerntest_print_line("[PASS] AERN network fkey encryption test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network fkey encryption test.");
		res = false;
	}

	if (aerntest_network_fkey_exchange_test() == true)
	{
		aerntest_print_line("[PASS] AERN network fkey exchange test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network fkey exchange test.");
		res = false;
	}

	if (aerntest_network_fkey_authentication_failure_test() == true)
	{
		aerntest_print_line("[PASS] AERN network fkey authentication failure test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network fkey authentication failure test.");
		res = false;
	}

	if (aerntest_network_incremental_update_test() == true)
	{
		aerntest_print_line("[PASS] AERN network incremental update test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network incremental update test.");
		res = false;
	}

	if (aerntest_network_incremental_update_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network incremental update bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network incremental update bad signature test.");
		res = false;
	}

	if (aerntest_network_incremental_update_truncated_response_test() == true)
	{
		aerntest_print_line("[PASS] AERN network incremental update truncated response test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network incremental update truncated response test.");
		res = false;
	}

	if (aerntest_network_join_test() == true)
	{
		aerntest_print_line("[PASS] AERN network join test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network join test.");
		res = false;
	}

	if (aerntest_network_register_request_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register request bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register request bad signature test.");
		res = false;
	}

	if (aerntest_network_register_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register response bad signature test.");
		res = false;
	}

	if (aerntest_network_register_update_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register update test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register update test.");
		res = false;
	}

	if (aerntest_network_register_update_malformed_request_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register update malformed request test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register update malformed request test.");
		res = false;
	}

	if (aerntest_network_register_update_request_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register update request bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register update request bad signature test.");
		res = false;
	}

	if (aerntest_network_register_update_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network register update response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network register update response bad signature test.");
		res = false;
	}

	if (aerntest_network_mfk_exchange_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk exchange test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk exchange test.");
		res = false;
	}

	if (aerntest_network_mfk_aps_to_aps_exchange_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk APS-to-APS exchange test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk APS-to-APS exchange test.");
		res = false;
	}

	if (aerntest_network_mfk_client_to_aps_exchange_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk client-to-APS exchange test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk client-to-APS exchange test.");
		res = false;
	}

	if (aerntest_network_mfk_request_corrupt_certificate_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk request corrupt certificate test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk request corrupt certificate test.");
		res = false;
	}

	if (aerntest_network_mfk_decapsulation_failure_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk decapsulation failure test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk decapsulation failure test.");
		res = false;
	}

	if (aerntest_network_mfk_request_corrupt_certificate_no_secret_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk corrupt certificate no secret test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk corrupt certificate no secret test.");
		res = false;
	}

	if (aerntest_network_mfk_bad_response_signature_no_secret_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk bad response signature no secret test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk bad response signature no secret test.");
		res = false;
	}

	if (aerntest_network_mek_directional_state_roundtrip_test() == true)
	{
		aerntest_print_line("[PASS] AERN network MEK directional state roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network MEK directional state roundtrip test.");
		res = false;
	}

	if (aerntest_network_mek_directional_material_separation_test() == true)
	{
		aerntest_print_line("[PASS] AERN network MEK directional material separation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network MEK directional material separation test.");
		res = false;
	}

	if (aerntest_network_mek_request_invalid_certificate_no_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network MEK request invalid certificate no state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network MEK request invalid certificate no state test.");
		res = false;
	}

	if (aerntest_network_mek_response_invalid_certificate_no_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network MEK response invalid certificate no state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network MEK response invalid certificate no state test.");
		res = false;
	}

	if (aerntest_network_packet_header_roundtrip_test() == true)
	{
		aerntest_print_line("[PASS] AERN network packet header roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network packet header roundtrip test.");
		res = false;
	}

	if (aerntest_network_packet_stream_header_size_test() == true)
	{
		aerntest_print_line("[PASS] AERN network packet stream header size test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network packet stream header size test.");
		res = false;
	}

	if (aerntest_network_relay_packet_size_model_test() == true)
	{
		aerntest_print_line("[PASS] AERN network relay packet size model test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network relay packet size model test.");
		res = false;
	}

	if (aerntest_network_fixed_relay_packet_serialization_size_test() == true)
	{
		aerntest_print_line("[PASS] AERN network fixed relay packet serialization size test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network fixed relay packet serialization size test.");
		res = false;
	}

	if (aerntest_network_outer_header_flag_aad_authentication_test() == true)
	{
		aerntest_print_line("[PASS] AERN network outer header flag AAD authentication test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network outer header flag AAD authentication test.");
		res = false;
	}

	if (aerntest_network_outer_header_length_aad_authentication_test() == true)
	{
		aerntest_print_line("[PASS] AERN network outer header length AAD authentication test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network outer header length AAD authentication test.");
		res = false;
	}

	if (aerntest_network_outer_header_timestamp_aad_authentication_test() == true)
	{
		aerntest_print_line("[PASS] AERN network outer header timestamp AAD authentication test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network outer header timestamp AAD authentication test.");
		res = false;
	}

	if (aerntest_network_outer_header_future_timestamp_rejection_test() == true)
	{
		aerntest_print_line("[PASS] AERN network outer header future timestamp rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network outer header future timestamp rejection test.");
		res = false;
	}

	if (aerntest_network_connection_encrypt_sequence_policy_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection encrypt sequence policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection encrypt sequence policy test.");
		res = false;
	}

	if (aerntest_network_connection_decrypt_success_sequence_policy_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection decrypt success sequence policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection decrypt success sequence policy test.");
		res = false;
	}

	if (aerntest_network_connection_auth_failure_no_rx_advance_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection authentication failure no rx advance test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection authentication failure no rx advance test.");
		res = false;
	}

	if (aerntest_network_connection_auth_failure_preserves_rcs_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection authentication failure preserves RCS state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection authentication failure preserves RCS state test.");
		res = false;
	}

	if (aerntest_network_connection_success_resets_authfail_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection success resets authfail test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection success resets authfail test.");
		res = false;
	}

	if (aerntest_network_connection_time_failure_no_state_change_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection time failure no state change test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection time failure no state change test.");
		res = false;
	}

	if (aerntest_network_connection_tx_overflow_no_increment_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection tx overflow no increment test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection tx overflow no increment test.");
		res = false;
	}

	if (aerntest_network_connection_zero_length_send_no_increment_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection zero length send no increment test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection zero length send no increment test.");
		res = false;
	}

	if (aerntest_network_connection_disposed_cannot_encrypt_or_decrypt_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection disposed cannot encrypt or decrypt test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection disposed cannot encrypt or decrypt test.");
		res = false;
	}

	if (aerntest_network_connection_malformed_packet_no_rx_advance_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection malformed packet no rx advance test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection malformed packet no rx advance test.");
		res = false;
	}

	if (aerntest_network_connection_unsequenced_packet_no_rx_advance_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection unsequenced packet no rx advance test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection unsequenced packet no rx advance test.");
		res = false;
	}

	if (aerntest_network_connection_auth_failure_threshold_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection authentication failure threshold test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection authentication failure threshold test.");
		res = false;
	}

	if (aerntest_network_connection_dispose_resets_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network connection dispose resets state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network connection dispose resets state test.");
		res = false;
	}

	if (aerntest_network_replay_valid_ordered_sequence_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay valid ordered sequence test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay valid ordered sequence test.");
		res = false;
	}

	if (aerntest_network_replay_duplicate_packet_rejected_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay duplicate packet rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay duplicate packet rejection test.");
		res = false;
	}

	if (aerntest_network_replay_future_sequence_rejected_without_state_change_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay future sequence rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay future sequence rejection test.");
		res = false;
	}

	if (aerntest_network_replay_old_sequence_rejected_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay old sequence rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay old sequence rejection test.");
		res = false;
	}

	if (aerntest_network_replay_modified_sequence_aad_failure_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay modified sequence AAD failure test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay modified sequence AAD failure test.");
		res = false;
	}

	if (aerntest_network_replay_window_zero_policy_test() == true)
	{
		aerntest_print_line("[PASS] AERN network replay window zero policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network replay window zero policy test.");
		res = false;
	}

	if (aerntest_network_rekey_resets_sequence_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network rekey resets sequence state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network rekey resets sequence state test.");
		res = false;
	}

	if (aerntest_network_mek_rekey_threshold_test() == true)
	{
		aerntest_print_line("[PASS] AERN network MEK rekey threshold test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network MEK rekey threshold test.");
		res = false;
	}

	if (aerntest_network_mfk_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk response bad signature test.");
		res = false;
	}

	if (aerntest_network_mfk_establish_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network mfk establish bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network mfk establish bad signature test.");
		res = false;
	}

	if (aerntest_network_remote_signing_test() == true)
	{
		aerntest_print_line("[PASS] AERN network remote signing test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network remote signing test.");
		res = false;
	}

	if (aerntest_network_remote_signing_malformed_request_test() == true)
	{
		aerntest_print_line("[PASS] AERN network remote signing malformed request test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network remote signing malformed request test.");
		res = false;
	}

	if (aerntest_network_remote_signing_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network remote signing response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network remote signing response bad signature test.");
		res = false;
	}

	if (aerntest_network_resign_response_test() == true)
	{
		aerntest_print_line("[PASS] AERN network resign response test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network resign response test.");
		res = false;
	}

	if (aerntest_network_resign_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network resign response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network resign response bad signature test.");
		res = false;
	}

	if (aerntest_network_revoke_response_test() == true)
	{
		aerntest_print_line("[PASS] AERN network revoke response test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network revoke response test.");
		res = false;
	}

	if (aerntest_network_revoke_response_failure_preserves_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN network revoke response failure preserves state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network revoke response failure preserves state test.");
		res = false;
	}

	if (aerntest_network_topological_query_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological query test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological query test.");
		res = false;
	}


	if (aerntest_network_topological_query_response_verification_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological query response verification test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological query response verification test.");
		res = false;
	}

	if (aerntest_network_topological_query_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological query response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological query response bad signature test.");
		res = false;
	}

	if (aerntest_network_topological_query_request_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological query request bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological query request bad signature test.");
		res = false;
	}

	if (aerntest_network_topological_status_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological status test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological status test.");
		res = false;
	}

	if (aerntest_network_topological_status_request_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological status request bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological status request bad signature test.");
		res = false;
	}
	if (aerntest_network_topological_status_response_bad_signature_test() == true)
	{
		aerntest_print_line("[PASS] AERN network topological status response bad signature test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN network topological status response bad signature test.");
		res = false;
	}

	return res;
}

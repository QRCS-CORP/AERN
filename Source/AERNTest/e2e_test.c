#include "e2e_test.h"
#include "aern_utils.h"
#include "aern.h"
#include "mek.h"
#include "route.h"
#include "fragment.h"
#include "relayqueue.h"
#include "topology.h"
#include "memutils.h"

typedef struct aerntest_e2e_callback_state
{
	uint32_t exitcount;
	uint32_t ingresscount;
	uint64_t exitsessionid;
	uint64_t ingresssessionid;
	size_t exitlength;
	size_t ingresslength;
	uint16_t exitflags;
	uint16_t ingressflags;
	uint8_t exitpayloadtype;
	uint8_t ingresspayloadtype;
	uint8_t exitreserved;
	uint8_t ingressreserved;
	uint8_t exitpacket[32U];
	uint8_t ingresspacket[32U];
	aern_protocol_errors status;
} aerntest_e2e_callback_state;

static void aerntest_e2e_session_make(aern_relay_session_cache_entry* session, uint8_t context)
{
	if (session != NULL)
	{
		qsc_memutils_clear(session, sizeof(aern_relay_session_cache_entry));
		session->sessionid = 0x0102030405060708ULL;
		session->created = 1U;
		session->activity = 2U;
		session->expiry = 0xFFFFFFFFULL;
		session->ingresshint = 1U;
		session->egresshint = 2U;
		session->port = 443U;
		session->status = (uint8_t)aern_relay_session_status_active;
		session->context = context;
		session->transport = (uint8_t)aern_exit_transport_status_active;
	}
}

static void aerntest_e2e_header_make(aern_relay_payload_header* header, const aern_relay_session_cache_entry* session, uint16_t flags, size_t length)
{
	if (header != NULL && session != NULL)
	{
		qsc_memutils_clear(header, sizeof(aern_relay_payload_header));
		header->sessionid = session->sessionid;
		header->packetid = 0x1000ULL;
		header->fragseq = 0U;
		header->fragcount = 0U;
		header->msglen = (uint32_t)length;
		header->payloadtype = (uint8_t)aern_relay_payload_data;
		header->reserved = 0U;
		header->flags = flags;
	}
}

static aern_protocol_errors aerntest_e2e_exit_callback(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context)
{
	aerntest_e2e_callback_state* state;
	aern_protocol_errors res;

	state = (aerntest_e2e_callback_state*)context;
	res = aern_protocol_error_invalid_request;

	if (state != NULL && session != NULL && header != NULL && packet != NULL && pktlen == sizeof(state->exitpacket) &&
		header->payloadtype == (uint8_t)aern_relay_payload_data && header->reserved == 0U)
	{
		state->exitcount += 1U;
		state->exitsessionid = session->sessionid;
		state->exitlength = pktlen;
		state->exitflags = header->flags;
		state->exitpayloadtype = header->payloadtype;
		state->exitreserved = header->reserved;
		qsc_memutils_copy(state->exitpacket, packet, sizeof(state->exitpacket));
		res = state->status;
	}

	return res;
}

static aern_protocol_errors aerntest_e2e_ingress_callback(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context)
{
	aerntest_e2e_callback_state* state;
	aern_protocol_errors res;

	state = (aerntest_e2e_callback_state*)context;
	res = aern_protocol_error_invalid_request;

	if (state != NULL && session != NULL && header != NULL && packet != NULL && pktlen == sizeof(state->ingresspacket) &&
		header->payloadtype == (uint8_t)aern_relay_payload_data && header->reserved == 0U)
	{
		state->ingresscount += 1U;
		state->ingresssessionid = session->sessionid;
		state->ingresslength = pktlen;
		state->ingressflags = header->flags;
		state->ingresspayloadtype = header->payloadtype;
		state->ingressreserved = header->reserved;
		qsc_memutils_copy(state->ingresspacket, packet, sizeof(state->ingresspacket));
		res = state->status;
	}

	return res;
}

static bool aerntest_e2e_backend_callback_test(void)
{
	aerntest_e2e_callback_state state = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	uint8_t packet[32U] = { 0U };
	aern_protocol_errors eres;
	aern_protocol_errors ires;
	bool res;

	res = false;
	state.status = aern_protocol_error_none;

	for (size_t i = 0U; i < sizeof(packet); ++i)
	{
		packet[i] = (uint8_t)(0xA0U + i);
	}

	aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_EGRESS);
	aerntest_e2e_header_make(&header, &session, 0U, sizeof(packet));

	aern_exit_transport_set_callback(aerntest_e2e_exit_callback, &state);
	eres = aern_exit_transport_send_serialized_packet(&session, &header, packet, sizeof(packet));
	aern_exit_transport_set_callback(NULL, NULL);

	aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_INGRESS);
	aerntest_e2e_header_make(&header, &session, AERN_RELAY_PAYLOAD_FLAG_RETURN, sizeof(packet));

	aern_ingress_transport_set_callback(aerntest_e2e_ingress_callback, &state);
	ires = aern_ingress_transport_send_serialized_packet(&session, &header, packet, sizeof(packet));
	aern_ingress_transport_set_callback(NULL, NULL);

	if (eres == aern_protocol_error_none && ires == aern_protocol_error_none &&
		state.exitcount == 1U && state.ingresscount == 1U &&
		state.exitsessionid == 0x0102030405060708ULL && 
		state.ingresssessionid == 0x0102030405060708ULL &&
		state.exitlength == sizeof(packet) && 
		state.ingresslength == sizeof(packet) &&
		state.exitflags == 0U && 
		state.ingressflags == AERN_RELAY_PAYLOAD_FLAG_RETURN &&
		state.exitpayloadtype == (uint8_t)aern_relay_payload_data && 
		state.ingresspayloadtype == (uint8_t)aern_relay_payload_data &&
		state.exitreserved == 0U && 
		state.ingressreserved == 0U &&
		qsc_memutils_are_equal(state.exitpacket, packet, sizeof(packet)) == true &&
		qsc_memutils_are_equal(state.ingresspacket, packet, sizeof(packet)) == true)
	{
		res = true;
	}

	return res;
}

static bool aerntest_e2e_relay_cache_lifecycle_test(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	aern_ingress_pending_item pending = { 0 };
	uint8_t packet[AERN_PACKET_HEADER_SIZE + 32U] = { 0U };
	uint32_t removed;
	bool res;

	res = false;

	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true)
	{
		aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_INGRESS);

		if (aern_relay_session_add(&cache, &session) == true &&
			aern_relay_session_find(&cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
			found.sessionid == session.sessionid)
		{
			packet[0U] = 0xA5U;
			pending.packet = packet;
			pending.packetlen = sizeof(packet);
			pending.capacity = sizeof(packet);
			pending.sessionid = session.sessionid;
			pending.packetid = 2U;
			pending.expiry = 0xFFFFFFFFULL;
			pending.delayuntil = 0U;
			pending.active = true;

			if (aern_relay_pending_push(&cache, &pending) == true)
			{
				removed = aern_relay_pending_remove_session(&cache, session.sessionid);

				if (removed == 1U)
				{
					aern_relay_session_remove(&cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS);

					if (aern_relay_session_exists(&cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == false)
					{
						res = true;
					}
				}
			}
		}
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aerntest_e2e_fragment_reassembly_path_test(void)
{
	aern_fragment_cache cache = { 0 };
	aern_relay_payload_header hdra = { 0 };
	aern_relay_payload_header hdrb = { 0 };
	uint8_t partb[3U] = { 0x05U, 0x06U, 0x07U };
	uint8_t* out;
	uint8_t* parta;
	size_t outlen;
	bool accepted;
	bool complete;
	bool res;

	parta = NULL;
	out = NULL;
	outlen = 0U;
	accepted = false;
	complete = false;
	res = false;
	aern_fragment_cache_initialize(&cache);
	aern_fragment_cache_set_key(&cache, 7U, 9U, aern_relay_fragment_direction_inbound, 0xFFFFFFFFULL);

	parta = (uint8_t*)qsc_memutils_malloc(AERN_FRAG_CHUNK_SIZE);

	if (parta != NULL)
	{
		qsc_memutils_clear(parta, AERN_FRAG_CHUNK_SIZE);
		parta[0U] = 0x01U;
		parta[1U] = 0x02U;
		parta[2U] = 0x03U;
		parta[3U] = 0x04U;

		hdrb.sessionid = 7U;
		hdrb.packetid = 9U;
		hdrb.fragseq = 2U;
		hdrb.fragcount = 2U;
		hdrb.msglen = (uint32_t)sizeof(partb);
		hdrb.payloadtype = (uint8_t)aern_relay_payload_data;
		hdrb.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		hdrb.reserved = 0U;

		accepted = aern_fragment_cache_add_fragment(&cache, &hdrb, partb, sizeof(partb), (uint8_t)aern_relay_fragment_direction_inbound, &complete);

		if (accepted == true && complete == false)
		{
			hdra = hdrb;
			hdra.fragseq = 1U;
			hdra.msglen = (uint32_t)AERN_FRAG_CHUNK_SIZE;

			accepted = aern_fragment_cache_add_fragment(&cache, &hdra, parta, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_inbound, &complete);

			if (accepted == true && complete == true && 
				aern_fragment_cache_assemble_alloc(&cache, &out, &outlen) == true)
			{
				if (outlen == (AERN_FRAG_CHUNK_SIZE + sizeof(partb)) && 
					out[0U] == 0x01U &&
					out[3U] == 0x04U && 
					out[AERN_FRAG_CHUNK_SIZE] == 0x05U &&
					out[AERN_FRAG_CHUNK_SIZE + 2U] == 0x07U)
				{
					res = true;
				}
			}
		}
	}

	if (out != NULL)
	{
		qsc_memutils_secure_erase(out, outlen);
		qsc_memutils_alloc_free(out);
	}

	if (parta != NULL)
	{
		qsc_memutils_secure_erase(parta, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(parta);
	}

	aern_fragment_cache_dispose(&cache);

	return res;
}

static void aerntest_e2e_forward_state_make(aern_forward_state* fwd, aern_cipher_table* table, aern_relay_cache_state* cache, const aern_topology_list_state* topology, uint8_t apscount)
{
	if (fwd != NULL && table != NULL && cache != NULL && topology != NULL)
	{
		qsc_memutils_clear(fwd, sizeof(aern_forward_state));
		aern_cipher_table_initialize(table);
		aern_relay_cache_initialize(cache);
		fwd->conn_table = table;
		fwd->relay_cache = cache;
		fwd->topology = topology;
		fwd->apscount = apscount;
		fwd->ownhint = 1U;
		fwd->own_address = "127.0.0.1";
	}
}

static bool aerntest_e2e_ingress_delay_requeue_without_session_test(void)
{
	aern_forward_state fwd = { 0 };
	aern_relay_cache_state cache = { 0 };
	aern_ingress_pending_item item = { 0 };
	aern_ingress_pending_item out = { 0 };
	aern_protocol_errors status;
	bool pushed;
	bool popped;
	bool res;

	res = false;
	aern_relay_cache_initialize(&cache);

	item.packet = (uint8_t*)qsc_memutils_malloc(AERN_RELAY_MTU);

	if (item.packet != NULL)
	{
		item.sessionid = 0x3132333435363738ULL;
		item.packetid = 0x4142434445464748ULL;
		item.expiry = 0xFFFFFFFFFFFFFFFFULL;
		item.delayuntil = 0U;
		item.packetlen = AERN_RELAY_MTU;
		item.capacity = AERN_RELAY_MTU;
		item.active = true;
		qsc_memutils_clear(item.packet, item.capacity);
		item.packet[0U] = 0xA5U;
		fwd.relay_cache = &cache;

		pushed = aern_relay_delay_push(&cache, &item);
		status = aern_ingress_delay_flush(&fwd);
		popped = aern_relay_delay_pop(&cache, &out);

		if (pushed == true && 
			status == aern_protocol_error_none && 
			popped == true &&
			out.sessionid == item.sessionid && 
			out.packetid == item.packetid && 
			out.packet != NULL &&
			out.packet[0U] == item.packet[0U])
		{
			res = true;
		}
	}

	aern_relayqueue_item_dispose(&out);
	aern_relayqueue_item_dispose(&item);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aerntest_e2e_cache_cleanup_expired_state_test(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_fragment_cache fragment = { 0 };
	bool sessionadded;
	bool fragmentadded;
	bool res;

	res = false;
	aern_relay_cache_initialize(&cache);
	aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_INGRESS);
	aern_fragment_cache_initialize(&fragment);
	fragment.sessionid = session.sessionid;
	fragment.packetid = 0x5152535455565758ULL;
	fragment.direction = aern_relay_fragment_direction_inbound;
	fragment.expiry = 1U;
	fragment.total_frags = 1U;
	fragment.declared_length = 1U;
	session.expiry = 1U;
	session.activity = 1U;

	sessionadded = aern_relay_session_add(&cache, &session);
	fragmentadded = aern_relay_fragment_cache_add(&cache, &fragment);
	aern_relay_cache_cleanup(&cache);

	if (sessionadded == true && 
		fragmentadded == true &&
		aern_relay_session_exists(&cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == false &&
		aern_relay_fragment_cache_find(&cache, &fragment, session.sessionid, 0x5152535455565758ULL, aern_relay_fragment_direction_inbound) == false)
	{
		res = true;
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aerntest_e2e_return_packet_rejects_inactive_session_test(void)
{
	aern_forward_state fwd = { 0 };
	aern_cipher_table table = { 0 };
	aern_relay_cache_state cache = { 0 };
	aern_topology_list_state topology = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	uint8_t packet[32U] = { 0U };
	aern_protocol_errors status;
	bool res;

	res = false;
	qsc_memutils_clear(&topology, sizeof(topology));
	qsc_memutils_clear(packet, sizeof(packet));
	aerntest_e2e_forward_state_make(&fwd, &table, &cache, &topology, AERN_ROUTE_MINIMUM_HOPS);
	aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_EGRESS);
	session.status = (uint8_t)aern_relay_session_status_expired;
	packet[0U] = 0x01U;

	status = aern_return_packet_send(&fwd, &session, packet, sizeof(packet));

	if (status == aern_protocol_error_invalid_request && session.rxcount == 0U)
	{
		res = true;
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aerntest_e2e_dummy_traffic_suppression_test(void)
{
	aern_forward_state fwd = { 0 };
	aern_cipher_table table = { 0 };
	aern_relay_cache_state cache = { 0 };
	aern_topology_list_state topology = { 0 };
	aern_protocol_errors status;
	bool res;

	res = false;
	aerntest_e2e_forward_state_make(&fwd, &table, &cache, &topology, AERN_ROUTE_MINIMUM_HOPS);

	status = aern_dummy_traffic_generate(&fwd, AERN_DUMMY_TRAFFIC_BANDWIDTH_CEILING_PERCENT);

	if (status == aern_protocol_error_none && cache.dummysent == 0U && cache.dummysuppressed == true)
	{
		res = true;
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aerntest_e2e_forward_state_policy_test(void)
{
	aern_forward_state fwd = { 0 };
	aern_cipher_table table = { 0 };
	aern_relay_cache_state cache = { 0 };
	aern_topology_list_state topology = { 0 };
	bool valid;
	bool invalidtopology;
	bool invalidcache;

	aerntest_e2e_forward_state_make(&fwd, &table, &cache, &topology, AERN_ROUTE_MINIMUM_HOPS);
	valid = aern_relay_forward_state_is_valid(&fwd, true);
	fwd.apscount = AERN_ROUTE_MINIMUM_HOPS - 1U;
	invalidtopology = aern_relay_forward_state_is_valid(&fwd, true);
	fwd.apscount = AERN_ROUTE_MINIMUM_HOPS;
	cache.initialized = false;
	invalidcache = aern_relay_forward_state_is_valid(&fwd, true);
	cache.initialized = true;

	aern_relay_cache_dispose(&cache);

	return (valid == true && invalidtopology == false && invalidcache == false);
}

static bool aerntest_e2e_return_path_validation_test(void)
{
	aern_forward_state fwd = { 0 };
	aern_cipher_table table = { 0 };
	aern_relay_cache_state cache = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	uint8_t packet[32U] = { 0U };
	aern_protocol_errors rescode;
	bool res;

	res = false;
	aern_cipher_table_initialize(&table);
	aern_relay_cache_initialize(&cache);
	aerntest_e2e_session_make(&session, AERN_RELAY_SESSION_CONTEXT_EGRESS);

	fwd.conn_table = &table;
	fwd.relay_cache = &cache;
	fwd.apscount = 0U;
	fwd.ownhint = 0U;

	rescode = aern_exit_transport_return_serialized_packet(&fwd, &session, packet, sizeof(packet));

	if (rescode == aern_protocol_error_invalid_request)
	{
		res = true;
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

bool aerntest_e2e_run(void)
{
	bool res;

	res = true;

	if (aerntest_e2e_relay_cache_lifecycle_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end relay cache lifecycle test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end relay cache lifecycle test.");
		res = false;
	}

	if (aerntest_e2e_fragment_reassembly_path_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end fragment reassembly path test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end fragment reassembly path test.");
		res = false;
	}

	if (aerntest_e2e_backend_callback_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end backend callback test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end backend callback test.");
		res = false;
	}

	if (aerntest_e2e_ingress_delay_requeue_without_session_test() == true)
	{
		aerntest_print_line("[PASS] AERN ingress delay requeue without session test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ingress delay requeue without session test.");
		res = false;
	}

	if (aerntest_e2e_cache_cleanup_expired_state_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end cache cleanup expired state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end cache cleanup expired state test.");
		res = false;
	}

	if (aerntest_e2e_return_path_validation_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end return path validation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end return path validation test.");
		res = false;
	}

	if (aerntest_e2e_return_packet_rejects_inactive_session_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end return packet rejects inactive session test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end return packet rejects inactive session test.");
		res = false;
	}

	if (aerntest_e2e_dummy_traffic_suppression_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end dummy traffic suppression test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end dummy traffic suppression test.");
		res = false;
	}

	if (aerntest_e2e_forward_state_policy_test() == true)
	{
		aerntest_print_line("[PASS] AERN end-to-end forward state policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN end-to-end forward state policy test.");
		res = false;
	}

	return res;
}

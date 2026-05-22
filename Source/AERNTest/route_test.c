#include "route_test.h"
#include "aern_utils.h"
#include "access_test.h"
#include "route.h"
#include "fragment.h"
#include "relayqueue.h"
#include "relaysession.h"
#include "mek.h"
#include "topology.h"
#include "intutils.h"
#include "memutils.h"

typedef struct route_test_transport_context
{
	uint32_t calls;
	uint64_t sessionid;
	uint8_t payloadtype;
	uint16_t flags;
	size_t pktlen;
	uint8_t first;
	aern_protocol_errors result;
} route_test_transport_context;

typedef struct route_test_multihop_context
{
	aern_forward_state fwd[4U];
	aern_cipher_table ctable[4U];
	aern_relay_cache_state cache[4U];
	aern_topology_list_state topology;
	char address[4U][AERN_CERTIFICATE_ADDRESS_SIZE];
	uint32_t dispatches;
	uint32_t failures;
	uint32_t depth;
	uint32_t maxdepth;
} route_test_multihop_context;

static bool route_test_live_path_valid(const aern_route_map* rm, uint8_t apscount, uint8_t originhint, uint8_t targethint)
{
	uint8_t i;
	uint8_t lasthint;
	uint8_t livecount;
	bool res;

	i = 0U;
	lasthint = 0U;
	livecount = 0U;
	res = false;

	if (rm != NULL && rm->path[0U] == originhint && originhint != 0U && targethint != 0U && originhint <= apscount && targethint <= apscount)
	{
		lasthint = rm->path[0U];
		livecount = 1U;
		res = true;

		for (i = 1U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				if (rm->path[i] > apscount || rm->path[i] == lasthint)
				{
					res = false;
					break;
				}

				lasthint = rm->path[i];
				++livecount;
			}
		}

		if (res == true)
		{
			res = (lasthint == targethint && livecount >= AERN_ROUTE_MIN_HOPS && livecount <= AERN_ROUTE_MAX_HOPS);
		}
	}

	return res;
}

static uint8_t route_test_last_nonzero_hint(const aern_route_map* rm)
{
	uint8_t i;
	uint8_t last;

	i = 0U;
	last = 0U;

	if (rm != NULL)
	{
		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				last = rm->path[i];
			}
		}
	}

	return last;
}

static uint8_t route_test_active_hint_count(const aern_route_map* rm)
{
	uint8_t i;
	uint8_t count;

	i = 0U;
	count = 0U;

	if (rm != NULL)
	{
		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				++count;
			}
		}
	}

	return count;
}

static bool route_test_no_adjacent_self_hop(const aern_route_map* rm)
{
	uint8_t i;
	uint8_t last;
	bool res;

	i = 0U;
	last = 0U;
	res = false;

	if (rm != NULL)
	{
		res = true;

		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				if (rm->path[i] == last)
				{
					res = false;
					break;
				}

				last = rm->path[i];
			}
		}
	}

	return res;
}

static bool route_test_zero_termination_valid(const aern_route_map* rm)
{
	uint8_t i;
	bool foundzero;
	bool res;

	i = 0U;
	foundzero = false;
	res = false;

	if (rm != NULL)
	{
		res = true;

		for (i = 1U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] == 0U)
			{
				foundzero = true;
			}
			else if (foundzero == true)
			{
				res = false;
				break;
			}
			else
			{
				/* continue scanning active route entries. */
			}
		}
	}

	return res;
}

static bool route_test_interior_hints_valid(const aern_route_map* rm, uint8_t originhint, uint8_t targethint)
{
	uint8_t i;
	uint8_t lastpos;
	bool res;

	i = 0U;
	lastpos = 0U;
	res = false;

	if (rm != NULL)
	{
		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				lastpos = i;
			}
		}

		res = true;

		if (lastpos > 1U)
		{
			for (i = 1U; i < lastpos; ++i)
			{
				if (rm->path[i] == originhint || rm->path[i] == targethint)
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

static bool route_test_fill_allocated_packet(aern_ingress_pending_item* item, size_t len, uint64_t sessionid, uint64_t packetid, uint8_t seed)
{
	size_t i;
	bool res;

	res = false;

	if (item != NULL && len != 0U && len <= AERN_MAX_RELAY_PACKET_SIZE)
	{
		qsc_memutils_clear(item, sizeof(aern_ingress_pending_item));
		item->packet = (uint8_t*)qsc_memutils_malloc(len);

		if (item->packet != NULL)
		{
			for (i = 0U; i < len; ++i)
			{
				item->packet[i] = (uint8_t)(seed + (uint8_t)i);
			}

			item->packetlen = len;
			item->capacity = len;
			item->sessionid = sessionid;
			item->packetid = packetid;
			item->expiry = 1000U;
			item->delayuntil = 0U;
			item->active = true;
			res = true;
		}
	}

	return res;
}

static bool route_test_fill_fragment(uint8_t** data, size_t len, uint8_t seed)
{
	size_t i;
	bool res;

	res = false;

	if (data != NULL && len != 0U)
	{
		*data = (uint8_t*)qsc_memutils_malloc(len);

		if (*data != NULL)
		{
			for (i = 0U; i < len; ++i)
			{
				(*data)[i] = (uint8_t)(seed + (uint8_t)i);
			}

			res = true;
		}
	}

	return res;
}

static void route_test_fill_fragment_header(aern_relay_payload_header* hdr, uint64_t sessionid, uint64_t packetid, uint32_t fragseq, uint32_t fragcount, size_t fraglen, uint8_t flags)
{
	if (hdr != NULL)
	{
		qsc_memutils_clear(hdr, sizeof(aern_relay_payload_header));
		hdr->sessionid = sessionid;
		hdr->packetid = packetid;
		hdr->fragseq = fragseq;
		hdr->fragcount = fragcount;
		hdr->msglen = (uint32_t)fraglen;
		hdr->payloadtype = (uint8_t)aern_relay_payload_data;
		hdr->reserved = 0U;
		hdr->flags = flags;
	}
}

static uint8_t route_test_fragment_byte(uint32_t fragseq, size_t offset)
{
	return (uint8_t)((fragseq * 31U) + (uint32_t)(offset & 0xFFU));
}

static bool route_test_fill_numbered_fragment(uint8_t** data, size_t len, uint32_t fragseq)
{
	size_t i;
	bool res;

	res = false;

	if (data != NULL && len != 0U)
	{
		*data = (uint8_t*)qsc_memutils_malloc(len);

		if (*data != NULL)
		{
			for (i = 0U; i < len; ++i)
			{
				(*data)[i] = route_test_fragment_byte(fragseq, i);
			}

			res = true;
		}
	}

	return res;
}

static bool route_test_verify_numbered_assembly(const uint8_t* data, size_t datalen, uint32_t fragcount, size_t finallen)
{
	size_t off;
	size_t pos;
	size_t fraglen;
	uint32_t fragseq;
	bool res;

	off = 0U;
	res = false;

	if (data != NULL && datalen != 0U && fragcount != 0U && finallen != 0U)
	{
		res = true;

		for (fragseq = 1U; fragseq <= fragcount; ++fragseq)
		{
			fraglen = (fragseq == fragcount) ? finallen : (size_t)AERN_FRAG_CHUNK_SIZE;

			if (off > datalen || fraglen > (datalen - off))
			{
				res = false;
				break;
			}

			for (pos = 0U; pos < fraglen; ++pos)
			{
				if (data[off + pos] != route_test_fragment_byte(fragseq, pos))
				{
					res = false;
					break;
				}
			}

			if (res == false)
			{
				break;
			}

			off += fraglen;
		}

		res = (res == true && off == datalen);
	}

	return res;
}

static bool aern_route_test_relayqueue_ownership_cleanup(void)
{
	aern_relayqueue_state queue = { 0 };
	aern_ingress_pending_item item = { 0 };
	aern_ingress_pending_item out = { 0 };
	uint8_t dummy;
	bool res;

	dummy = 0U;
	res = false;

	aern_relayqueue_initialize(&queue, 3U);

	if (queue.initialized == true && route_test_fill_allocated_packet(&item, 32U, 1U, 2U, 0x10U) == true)
	{
		res = aern_relayqueue_push(&queue, &item);
		item.packet[0U] = 0xFFU;
		aern_relayqueue_item_dispose(&item);
	}

	if (res == true)
	{
		res = aern_relayqueue_pop(&queue, &out);
		res = (res == true && out.packet != NULL && out.packetlen == 32U && out.packet[0U] == 0x10U);
		aern_relayqueue_item_dispose(&out);
	}

	if (res == true)
	{
		qsc_memutils_clear(&item, sizeof(aern_ingress_pending_item));
		item.packet = &dummy;
		item.packetlen = (size_t)AERN_MAX_RELAY_PACKET_SIZE + 1U;
		item.capacity = item.packetlen;
		item.sessionid = 1U;
		item.packetid = 3U;
		item.active = true;
		res = (aern_relayqueue_push(&queue, &item) == false);
		qsc_memutils_clear(&item, sizeof(aern_ingress_pending_item));
	}

	if (res == true && route_test_fill_allocated_packet(&item, 16U, 9U, 1U, 0x20U) == true)
	{
		res = aern_relayqueue_push(&queue, &item);
		aern_relayqueue_item_dispose(&item);
	}

	if (res == true && route_test_fill_allocated_packet(&item, 16U, 10U, 2U, 0x30U) == true)
	{
		item.expiry = 1U;
		res = aern_relayqueue_push(&queue, &item);
		aern_relayqueue_item_dispose(&item);
	}

	if (res == true)
	{
		res = (aern_relayqueue_remove_session(&queue, 9U, 2U) == 1U);
		res = (res == true && aern_relayqueue_count(&queue) == 1U);
		res = (res == true && aern_relayqueue_cleanup_expired(&queue, 2U) == 1U);
		res = (res == true && aern_relayqueue_is_empty(&queue) == true);
	}

	aern_relayqueue_item_dispose(&item);
	aern_relayqueue_item_dispose(&out);
	aern_relayqueue_dispose(&queue);

	return res;
}

static bool aern_route_test_relayqueue_fifo_capacity_timeout(void)
{
	aern_relayqueue_state queue = { 0 };
	aern_ingress_pending_item first = { 0 };
	aern_ingress_pending_item second = { 0 };
	aern_ingress_pending_item third = { 0 };
	aern_ingress_pending_item out = { 0 };
	bool res;

	res = false;
	aern_relayqueue_initialize(&queue, 2U);

	if (queue.initialized == true &&
		route_test_fill_allocated_packet(&first, 24U, 1U, 1U, 0x11U) == true &&
		route_test_fill_allocated_packet(&second, 24U, 2U, 2U, 0x22U) == true &&
		route_test_fill_allocated_packet(&third, 24U, 3U, 3U, 0x33U) == true)
	{
		res = (aern_relayqueue_is_empty(&queue) == true);
		res = (res == true && aern_relayqueue_push(&queue, &first) == true);
		res = (res == true && aern_relayqueue_push(&queue, &second) == true);
		res = (res == true && aern_relayqueue_is_full(&queue) == true);
		res = (res == true && aern_relayqueue_push(&queue, &third) == false);
		res = (res == true && aern_relayqueue_count(&queue) == 2U);
	}

	if (res == true)
	{
		res = (aern_relayqueue_pop(&queue, &out) == true);
		res = (res == true && out.sessionid == 1U && out.packetid == 1U && out.packet != NULL && out.packet[0U] == 0x11U);
		aern_relayqueue_item_dispose(&out);
	}

	if (res == true)
	{
		res = (aern_relayqueue_pop(&queue, &out) == true);
		res = (res == true && out.sessionid == 2U && out.packetid == 2U && out.packet != NULL && out.packet[0U] == 0x22U);
		aern_relayqueue_item_dispose(&out);
		res = (res == true && aern_relayqueue_is_empty(&queue) == true);
	}

	if (res == true)
	{
		first.expiry = 10U;
		second.expiry = 20U;
		res = (aern_relayqueue_push(&queue, &first) == true);
		res = (res == true && aern_relayqueue_push(&queue, &second) == true);
		res = (res == true && aern_relayqueue_cleanup_expired(&queue, 15U) == 1U);
		res = (res == true && aern_relayqueue_count(&queue) == 1U);
	}

	if (res == true)
	{
		res = (aern_relayqueue_pop(&queue, &out) == true);
		res = (res == true && out.sessionid == 2U && out.packetid == 2U);
		aern_relayqueue_item_dispose(&out);
	}

	aern_relayqueue_item_dispose(&first);
	aern_relayqueue_item_dispose(&second);
	aern_relayqueue_item_dispose(&third);
	aern_relayqueue_item_dispose(&out);
	aern_relayqueue_dispose(&queue);

	return res;
}

static bool aern_route_test_relayqueue_session_purge_preserves_fifo(void)
{
	aern_relayqueue_state queue = { 0 };
	aern_ingress_pending_item item1 = { 0 };
	aern_ingress_pending_item item2 = { 0 };
	aern_ingress_pending_item item3 = { 0 };
	aern_ingress_pending_item item4 = { 0 };
	aern_ingress_pending_item out = { 0 };
	bool res;

	res = false;
	aern_relayqueue_initialize(&queue, 4U);

	if (queue.initialized == true &&
		route_test_fill_allocated_packet(&item1, 16U, 5U, 1U, 0x10U) == true &&
		route_test_fill_allocated_packet(&item2, 16U, 6U, 2U, 0x20U) == true &&
		route_test_fill_allocated_packet(&item3, 16U, 5U, 3U, 0x30U) == true &&
		route_test_fill_allocated_packet(&item4, 16U, 7U, 4U, 0x40U) == true)
	{
		res = (aern_relayqueue_push(&queue, &item1) == true);
		res = (res == true && aern_relayqueue_push(&queue, &item2) == true);
		res = (res == true && aern_relayqueue_push(&queue, &item3) == true);
		res = (res == true && aern_relayqueue_push(&queue, &item4) == true);
		res = (res == true && aern_relayqueue_remove_session(&queue, 5U, 100U) == 2U);
		res = (res == true && aern_relayqueue_count(&queue) == 2U);
	}

	if (res == true)
	{
		res = (aern_relayqueue_pop(&queue, &out) == true);
		res = (res == true && out.sessionid == 6U && out.packetid == 2U && out.packet != NULL && out.packet[0U] == 0x20U);
		aern_relayqueue_item_dispose(&out);
	}

	if (res == true)
	{
		res = (aern_relayqueue_pop(&queue, &out) == true);
		res = (res == true && out.sessionid == 7U && out.packetid == 4U && out.packet != NULL && out.packet[0U] == 0x40U);
		aern_relayqueue_item_dispose(&out);
		res = (res == true && aern_relayqueue_is_empty(&queue) == true);
	}

	aern_relayqueue_item_dispose(&item1);
	aern_relayqueue_item_dispose(&item2);
	aern_relayqueue_item_dispose(&item3);
	aern_relayqueue_item_dispose(&item4);
	aern_relayqueue_item_dispose(&out);
	aern_relayqueue_dispose(&queue);

	return res;
}

static bool aern_route_test_relay_cache_pending_delay_session_purge(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_ingress_pending_item pending1 = { 0 };
	aern_ingress_pending_item pending2 = { 0 };
	aern_ingress_pending_item delay1 = { 0 };
	aern_ingress_pending_item delay2 = { 0 };
	uint64_t tnow;
	uint64_t dropped;
	bool res;

	tnow = qsc_timestamp_datetime_utc();
	dropped = 0U;
	res = false;
	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true &&
		route_test_fill_allocated_packet(&pending1, 32U, 50U, 1U, 0x51U) == true &&
		route_test_fill_allocated_packet(&pending2, 32U, 60U, 2U, 0x61U) == true &&
		route_test_fill_allocated_packet(&delay1, 32U, 50U, 3U, 0x52U) == true &&
		route_test_fill_allocated_packet(&delay2, 32U, 60U, 4U, 0x62U) == true)
	{
		pending1.expiry = tnow + 60U;
		pending2.expiry = tnow + 60U;
		delay1.expiry = tnow + 60U;
		delay2.expiry = tnow + 60U;
		dropped = cache.pendingdropped;
		res = (aern_relay_pending_push(&cache, &pending1) == true);
		res = (res == true && aern_relay_pending_push(&cache, &pending2) == true);
		res = (res == true && aern_relay_delay_push(&cache, &delay1) == true);
		res = (res == true && aern_relay_delay_push(&cache, &delay2) == true);
		res = (res == true && aern_relay_pending_remove_session(&cache, 50U) == 2U);
		res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 1U);
		res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 1U);
		res = (res == true && cache.pendingdropped == (dropped + 2U));
	}

	aern_relayqueue_item_dispose(&pending1);
	aern_relayqueue_item_dispose(&pending2);
	aern_relayqueue_item_dispose(&delay1);
	aern_relayqueue_item_dispose(&delay2);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_ingress_delay_flush_queue_policy(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_forward_state fwd = { 0 };
	aern_ingress_pending_item item = { 0 };
	uint64_t nowsec;
	uint64_t nowms;
	bool res;

	nowsec = qsc_timestamp_datetime_utc();
	nowms = qsc_timestamp_epochtime_milliseconds();
	res = false;
	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true && route_test_fill_allocated_packet(&item, 24U, 70U, 1U, 0x70U) == true)
	{
		fwd.relay_cache = &cache;
		item.expiry = nowsec + 60U;
		item.delayuntil = nowms + 10000U;
		res = (aern_relay_delay_push(&cache, &item) == true);
		res = (res == true && aern_ingress_delay_flush(&fwd) == aern_protocol_error_none);
		res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 1U);
	}

	if (res == true)
	{
		aern_relayqueue_clear(&cache.delayqueue);
		aern_relayqueue_item_dispose(&item);
		res = route_test_fill_allocated_packet(&item, 24U, 71U, 2U, 0x71U);
	}

	if (res == true)
	{
		item.expiry = nowsec - 1U;
		item.delayuntil = 0U;
		res = (aern_relay_delay_push(&cache, &item) == true);
		res = (res == true && aern_ingress_delay_flush(&fwd) == aern_protocol_error_none);
		res = (res == true && aern_relayqueue_is_empty(&cache.delayqueue) == true);
	}

	aern_relayqueue_item_dispose(&item);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_relay_pending_capacity_overflow(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_ingress_pending_item item = { 0 };
	uint64_t overflow;
	uint64_t tnow;
	size_t i;
	bool res;

	overflow = 0U;
	tnow = qsc_timestamp_datetime_utc();
	i = 0U;
	res = false;
	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true)
	{
		overflow = cache.pendingoverflow;
		res = true;

		for (i = 0U; i < AERN_INGRESS_PENDING_QUEUE_DEPTH; ++i)
		{
			if (route_test_fill_allocated_packet(&item, 16U, 80U + (uint64_t)i, 1U + (uint64_t)i, (uint8_t)i) == false)
			{
				res = false;
				break;
			}

			item.expiry = tnow + 60U;

			if (aern_relay_pending_push(&cache, &item) == false)
			{
				res = false;
				aern_relayqueue_item_dispose(&item);
				break;
			}

			aern_relayqueue_item_dispose(&item);
		}
	}

	if (res == true && route_test_fill_allocated_packet(&item, 16U, 900U, 900U, 0x90U) == true)
	{
		item.expiry = tnow + 60U;
		res = (aern_relay_pending_push(&cache, &item) == false);
		res = (res == true && cache.pendingoverflow == (overflow + 1U));
	}

	aern_relayqueue_item_dispose(&item);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_fragment_ownership_cleanup(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag1;
	uint8_t* frag2;
	uint8_t* assembled;
	size_t len1;
	size_t len2;
	size_t outlen;
	bool res;

	frag1 = NULL;
	frag2 = NULL;
	assembled = NULL;
	len1 = AERN_FRAG_CHUNK_SIZE;
	len2 = 64U;
	outlen = 0U;
	res = false;

	if (aern_fragment_table_initialize(&table, 2U, (AERN_FRAG_CHUNK_SIZE * 4U)) == true &&
		route_test_fill_fragment(&frag1, len1, 0x40U) == true &&
		route_test_fill_fragment(&frag2, len2, 0x80U) == true)
	{
		set = aern_fragment_table_get_or_add(&table, 7U, 11U, (uint8_t)aern_relay_fragment_direction_outbound, 2U, 1000U, len1 + len2);

		if (set != NULL)
		{
			hdr.sessionid = 7U;
			hdr.packetid = 11U;
			hdr.fragseq = 1U;
			hdr.fragcount = 2U;
			hdr.msglen = (uint32_t)len1;
			hdr.payloadtype = (uint8_t)aern_relay_payload_data;
			hdr.reserved = 1U;
			hdr.flags = 0U;
			res = (aern_fragment_cache_add_relay_fragment(set, &hdr, frag1, len1, (uint8_t)aern_relay_fragment_direction_outbound) == false);

			hdr.reserved = 0U;
			res = (res == true && aern_fragment_cache_add_relay_fragment(set, &hdr, frag1, len1, (uint8_t)aern_relay_fragment_direction_outbound) == false);

			hdr.fragseq = 2U;
			hdr.msglen = (uint32_t)len2;
			res = (res == true && aern_fragment_cache_add_relay_fragment(set, &hdr, frag2, len2, (uint8_t)aern_relay_fragment_direction_outbound) == true);

			if (res == true)
			{
				res = aern_fragment_cache_assemble_alloc(set, &assembled, &outlen);
				res = (res == true && assembled != NULL && outlen == (len1 + len2));
				res = (res == true && qsc_memutils_are_equal(assembled, frag1, len1) == true);
				res = (res == true && qsc_memutils_are_equal(assembled + len1, frag2, len2) == true);
			}
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, outlen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, len1);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, len2);
		qsc_memutils_alloc_free(frag2);
	}

	if (res == true)
	{
		res = (aern_fragment_table_count(&table) == 1U);
		aern_fragment_table_remove(&table, 7U, 11U, (uint8_t)aern_relay_fragment_direction_outbound);
		res = (res == true && aern_fragment_table_count(&table) == 0U);
		res = (res == true && table.memoryused == 0U);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_fragment_large_out_of_order(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag;
	uint8_t* frag1;
	uint8_t* frag2;
	uint8_t* frag3;
	uint8_t* assembled;
	size_t finallen;
	size_t msglen;
	size_t reserve;
	size_t total;
	uint32_t fragcount;
	uint32_t fragseq;
	bool complete;
	bool res;

	set = NULL;
	frag = NULL;
	frag1 = NULL;
	frag2 = NULL;
	frag3 = NULL;
	assembled = NULL;
	finallen = 777U;
	msglen = 0U;
	fragcount = (uint32_t)(((size_t)1024U * (size_t)1024U) / (size_t)AERN_FRAG_CHUNK_SIZE) + 2U;
	total = (((size_t)fragcount - 1U) * (size_t)AERN_FRAG_CHUNK_SIZE) + finallen;
	reserve = (size_t)fragcount * (size_t)AERN_FRAG_CHUNK_SIZE;
	fragseq = 0U;
	complete = false;
	res = false;

	qsc_memutils_clear(&table, sizeof(aern_fragment_table));
	qsc_memutils_clear(&hdr, sizeof(aern_relay_payload_header));

	if (fragcount <= AERN_MAX_FRAGMENTS && 
		total > ((size_t)1024U * (size_t)1024U) &&
		aern_fragment_table_initialize(&table, 4U, reserve + (size_t)AERN_FRAG_CHUNK_SIZE) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, AERN_FRAG_CHUNK_SIZE, 2U) == true &&
		route_test_fill_numbered_fragment(&frag3, finallen, fragcount) == true)
	{
		route_test_fill_fragment_header(&hdr, 101U, 202U, 2U, fragcount, AERN_FRAG_CHUNK_SIZE, 0U);
		res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag2, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete);
		res = (res == true && complete == false && set != NULL);
		res = (res == true && set->declared_length == reserve);
		res = (res == true && table.memoryused == reserve);

		route_test_fill_fragment_header(&hdr, 101U, 202U, 1U, fragcount, AERN_FRAG_CHUNK_SIZE, 0U);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == true);
		res = (res == true && complete == false);

		for (fragseq = 3U; res == true && fragseq < fragcount; ++fragseq)
		{
			frag = NULL;

			if (route_test_fill_numbered_fragment(&frag, AERN_FRAG_CHUNK_SIZE, fragseq) == true)
			{
				route_test_fill_fragment_header(&hdr, 101U, 202U, fragseq, fragcount, AERN_FRAG_CHUNK_SIZE, 0U);
				res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete);
				res = (res == true && complete == false);
			}
			else
			{
				res = false;
			}

			if (frag != NULL)
			{
				qsc_memutils_secure_erase(frag, AERN_FRAG_CHUNK_SIZE);
				qsc_memutils_alloc_free(frag);
				frag = NULL;
			}
		}

		route_test_fill_fragment_header(&hdr, 101U, 202U, fragcount, fragcount, finallen, 0U);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag3, finallen, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == true);
		res = (res == true && complete == true && set != NULL);
		res = (res == true && set->declared_length == total);
		res = (res == true && table.memoryused == total);

		if (res == true)
		{
			res = aern_fragment_cache_assemble_alloc(set, &assembled, &msglen);
			res = (res == true && assembled != NULL && msglen == total);
			res = (res == true && route_test_verify_numbered_assembly(assembled, msglen, fragcount, finallen) == true);
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, msglen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag2);
	}

	if (frag3 != NULL)
	{
		qsc_memutils_secure_erase(frag3, finallen);
		qsc_memutils_alloc_free(frag3);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_fragment_final_first_shrink(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag1;
	uint8_t* frag2;
	uint8_t* frag3;
	uint8_t* assembled;
	size_t finallen;
	size_t msglen;
	size_t total;
	bool complete;
	bool res;

	set = NULL;
	frag1 = NULL;
	frag2 = NULL;
	frag3 = NULL;
	assembled = NULL;
	finallen = 31U;
	msglen = 0U;
	total = ((size_t)2U * (size_t)AERN_FRAG_CHUNK_SIZE) + finallen;
	complete = false;
	res = false;

	qsc_memutils_clear(&table, sizeof(aern_fragment_table));
	qsc_memutils_clear(&hdr, sizeof(aern_relay_payload_header));

	if (aern_fragment_table_initialize(&table, 2U, ((size_t)3U * (size_t)AERN_FRAG_CHUNK_SIZE)) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, AERN_FRAG_CHUNK_SIZE, 2U) == true &&
		route_test_fill_numbered_fragment(&frag3, finallen, 3U) == true)
	{
		route_test_fill_fragment_header(&hdr, 303U, 404U, 3U, 3U, finallen, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag3, finallen, (uint8_t)aern_relay_fragment_direction_inbound, 1000U, &set, &complete);
		res = (res == true && complete == false && set != NULL);
		res = (res == true && set->declared_length == total);
		res = (res == true && table.memoryused == total);

		route_test_fill_fragment_header(&hdr, 303U, 404U, 1U, 3U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_inbound, 1000U, &set, &complete) == true);
		res = (res == true && complete == false);

		route_test_fill_fragment_header(&hdr, 303U, 404U, 2U, 3U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag2, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_inbound, 1000U, &set, &complete) == true);
		res = (res == true && complete == true && set != NULL);

		if (res == true)
		{
			res = aern_fragment_cache_assemble_alloc(set, &assembled, &msglen);
			res = (res == true && assembled != NULL && msglen == total);
			res = (res == true && route_test_verify_numbered_assembly(assembled, msglen, 3U, finallen) == true);
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, msglen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag2);
	}

	if (frag3 != NULL)
	{
		qsc_memutils_secure_erase(frag3, finallen);
		qsc_memutils_alloc_free(frag3);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_map_roundtrip(void)
{
	aern_route_map rm = { 0 };
	aern_route_map cmp = { 0 };
	uint8_t enc[AERN_ROUTEMAP_SIZE] = { 0U };
	bool res;

	rm.path[0U] = 1U;
	rm.path[1U] = 4U;
	rm.path[2U] = 2U;
	rm.path[3U] = 7U;
	rm.path[4U] = 3U;
	rm.hopcount = 5U;

	aern_route_map_serialize(enc, &rm);
	aern_route_map_deserialize(&cmp, enc);

	res = (qsc_memutils_are_equal(rm.path, cmp.path, AERN_ROUTEMAP_SIZE) == true);
	res = (res == true && cmp.hopcount == 0U);

	return res;
}

static bool aern_route_test_generation(void)
{
	aern_route_map rm = { 0 };
	uint32_t i;
	bool res;

	i = 0U;
	res = true;

	for (i = 0U; i < 64U; ++i)
	{
		qsc_memutils_clear(&rm, sizeof(aern_route_map));

		if (aern_route_generate(&rm, 16U, 1U, 16U) != aern_protocol_error_none)
		{
			res = false;
			break;
		}

		if (route_test_live_path_valid(&rm, 16U, 1U, 16U) == false)
		{
			res = false;
			break;
		}
	}

	if (res == true)
	{
		res = (aern_route_generate(&rm, 2U, 1U, 2U) != aern_protocol_error_none);
	}

	if (res == true)
	{
		res = (aern_route_generate(&rm, 16U, 1U, 1U) != aern_protocol_error_none);
	}

	return res;
}


static bool aern_route_test_invalid_hint_rejection(void)
{
	aern_route_map rm = { 0 };
	bool res;

	qsc_memutils_clear(&rm, sizeof(aern_route_map));

	res = (aern_route_generate(&rm, 2U, 1U, 2U) != aern_protocol_error_none);
	res = (res == true && aern_route_generate(&rm, 16U, 0U, 2U) != aern_protocol_error_none);
	res = (res == true && aern_route_generate(&rm, 16U, 1U, 0U) != aern_protocol_error_none);
	res = (res == true && aern_route_generate(&rm, 16U, 17U, 2U) != aern_protocol_error_none);
	res = (res == true && aern_route_generate(&rm, 16U, 1U, 17U) != aern_protocol_error_none);
	res = (res == true && aern_route_generate(&rm, 16U, 4U, 4U) != aern_protocol_error_none);

	return res;
}

static bool aern_route_test_one_based_and_zero_terminator(void)
{
	aern_route_map rm = { 0 };
	uint8_t i;
	uint32_t pass;
	bool res;

	pass = 0U;
	res = true;

	for (pass = 0U; pass < 64U; ++pass)
	{
		qsc_memutils_clear(&rm, sizeof(aern_route_map));

		if (aern_route_generate(&rm, 8U, 1U, 8U) != aern_protocol_error_none)
		{
			res = false;
			break;
		}

		if (rm.path[0U] != 1U || route_test_last_nonzero_hint(&rm) != 8U || route_test_zero_termination_valid(&rm) == false)
		{
			res = false;
			break;
		}

		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm.path[i] > 8U)
			{
				res = false;
				break;
			}
		}

		if (res == false)
		{
			break;
		}
	}

	return res;
}

static bool aern_route_test_endpoint_stability_and_interior_policy(void)
{
	aern_route_map rm = { 0 };
	uint32_t pass;
	bool res;

	pass = 0U;
	res = true;

	for (pass = 0U; pass < 64U; ++pass)
	{
		qsc_memutils_clear(&rm, sizeof(aern_route_map));

		if (aern_route_generate(&rm, 12U, 2U, 11U) != aern_protocol_error_none)
		{
			res = false;
			break;
		}

		res = route_test_live_path_valid(&rm, 12U, 2U, 11U);
		res = (res == true && route_test_interior_hints_valid(&rm, 2U, 11U) == true);
		res = (res == true && rm.path[0U] == 2U);
		res = (res == true && route_test_last_nonzero_hint(&rm) == 11U);

		if (res == false)
		{
			break;
		}
	}

	return res;
}

static bool aern_route_test_per_packet_rerouting_variation(void)
{
	aern_route_map first = { 0 };
	aern_route_map next = { 0 };
	uint32_t pass;
	bool different;
	bool res;

	pass = 0U;
	different = false;
	res = false;

	if (aern_route_generate(&first, 16U, 1U, 16U) == aern_protocol_error_none)
	{
		res = true;

		for (pass = 0U; pass < 64U; ++pass)
		{
			qsc_memutils_clear(&next, sizeof(aern_route_map));

			if (aern_route_generate(&next, 16U, 1U, 16U) != aern_protocol_error_none)
			{
				res = false;
				break;
			}

			if (qsc_memutils_are_equal(first.path, next.path, AERN_ROUTE_PATH_SIZE) == false)
			{
				different = true;
			}
		}
	}

	res = (res == true && different == true);

	return res;
}

static bool aern_route_test_maximum_serialized_route_capacity(void)
{
	aern_route_map rm = { 0 };
	aern_route_map cmp = { 0 };
	uint8_t enc[AERN_ROUTEMAP_SIZE] = { 0U };
	uint8_t i;
	bool res;

	res = (AERN_ROUTEMAP_SIZE == 16U && AERN_ROUTE_PATH_SIZE == 16U && sizeof(enc) == 16U);

	if (res == true)
	{
		for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			rm.path[i] = (uint8_t)(i + 1U);
		}

		rm.hopcount = AERN_ROUTE_PATH_SIZE;
		aern_route_map_serialize(enc, &rm);
		aern_route_map_deserialize(&cmp, enc);

		res = (qsc_memutils_are_equal(rm.path, cmp.path, AERN_ROUTE_PATH_SIZE) == true);
		res = (res == true && cmp.hopcount == 0U);
	}

	return res;
}



static bool aern_route_test_local_state_not_serialized(void)
{
	aern_route_map rm = { 0 };
	aern_route_map cmp = { 0 };
	uint8_t enc[AERN_ROUTEMAP_SIZE] = { 0U };
	uint8_t i;
	bool res;

	for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
	{
		rm.path[i] = (uint8_t)(i + 1U);
	}

	rm.hopcount = 0xA5U;
	aern_route_map_serialize(enc, &rm);

	res = (qsc_memutils_are_equal(enc, rm.path, AERN_ROUTE_PATH_SIZE) == true);

	if (res == true)
	{
		aern_route_map_deserialize(&cmp, enc);
		res = (qsc_memutils_are_equal(cmp.path, rm.path, AERN_ROUTE_PATH_SIZE) == true);
		res = (res == true && cmp.hopcount == 0U);
	}

	if (res == true)
	{
		rm.hopcount = 0x5AU;
		aern_route_map_serialize(enc, &rm);
		res = (qsc_memutils_are_equal(enc, rm.path, AERN_ROUTE_PATH_SIZE) == true);
	}

	return res;
}

static bool aern_route_test_cursor_and_padding_not_serialized(void)
{
	aern_route_map rm = { 0 };
	aern_route_map cmp = { 0 };
	uint8_t enc[AERN_ROUTEMAP_SIZE] = { 0U };
	uint8_t path[AERN_ROUTE_PATH_SIZE] = { 0U };
	uint8_t i;
	bool res;

	path[0U] = 1U;
	path[1U] = 4U;
	path[2U] = 7U;
	path[3U] = 9U;
	path[4U] = 0U;

	for (i = 0U; i < AERN_ROUTE_PATH_SIZE; ++i)
	{
		rm.path[i] = path[i];
	}

	rm.hopcount = 4U;
	aern_route_map_serialize(enc, &rm);

	res = (sizeof(enc) == AERN_ROUTE_PATH_SIZE);
	res = (res == true && qsc_memutils_are_equal(enc, path, AERN_ROUTE_PATH_SIZE) == true);

	if (res == true)
	{
		aern_route_map_deserialize(&cmp, enc);
		res = (qsc_memutils_are_equal(cmp.path, path, AERN_ROUTE_PATH_SIZE) == true);
		res = (res == true && cmp.hopcount == 0U);
		res = (res == true && route_test_zero_termination_valid(&cmp) == true);
	}

	return res;
}

static bool aern_route_test_self_hop_rejection_policy(void)
{
	aern_route_map rm = { 0 };
	uint32_t pass;
	bool res;

	pass = 0U;
	res = true;

	for (pass = 0U; pass < 128U; ++pass)
	{
		qsc_memutils_clear(&rm, sizeof(aern_route_map));

		if (aern_route_generate(&rm, 16U, 1U, 16U) != aern_protocol_error_none)
		{
			res = false;
			break;
		}

		res = route_test_no_adjacent_self_hop(&rm);
		res = (res == true && route_test_interior_hints_valid(&rm, 1U, 16U) == true);
		res = (res == true && rm.path[0U] != rm.path[1U]);

		if (res == false)
		{
			break;
		}
	}

	return res;
}

static bool aern_route_test_randomness_distribution_sanity(void)
{
	aern_route_map first = { 0 };
	aern_route_map rm = { 0 };
	uint32_t pass;
	uint8_t count;
	uint8_t firstcount;
	uint8_t lastcount;
	bool differentpath;
	bool differentlength;
	bool res;

	pass = 0U;
	count = 0U;
	firstcount = 0U;
	lastcount = 0U;
	differentpath = false;
	differentlength = false;
	res = false;

	if (aern_route_generate(&first, 16U, 1U, 16U) == aern_protocol_error_none)
	{
		firstcount = route_test_active_hint_count(&first);
		res = (firstcount >= AERN_ROUTE_MIN_HOPS && firstcount <= AERN_ROUTE_MAX_HOPS);
	}

	for (pass = 0U; res == true && pass < 128U; ++pass)
	{
		qsc_memutils_clear(&rm, sizeof(aern_route_map));

		if (aern_route_generate(&rm, 16U, 1U, 16U) != aern_protocol_error_none)
		{
			res = false;
			break;
		}

		count = route_test_active_hint_count(&rm);
		res = (count >= AERN_ROUTE_MIN_HOPS && count <= AERN_ROUTE_MAX_HOPS);
		res = (res == true && route_test_live_path_valid(&rm, 16U, 1U, 16U) == true);

		if (res == false)
		{
			break;
		}

		if (qsc_memutils_are_equal(first.path, rm.path, AERN_ROUTE_PATH_SIZE) == false)
		{
			differentpath = true;
		}

		if (count != firstcount)
		{
			differentlength = true;
		}

		lastcount = count;
	}

	if (res == true)
	{
		res = (differentpath == true && lastcount >= AERN_ROUTE_MIN_HOPS);
		(void)differentlength;
	}

	return res;
}

static bool aern_route_test_payload_header_roundtrip(void)
{
	aern_relay_payload_header hdr = { 0 };
	aern_relay_payload_header cmp = { 0 };
	uint8_t enc[AERN_RELAY_PAYLOAD_HEADER_SIZE] = { 0U };
	bool res;


	hdr.sessionid = 0x0102030405060708ULL;
	hdr.packetid = 0x1112131415161718ULL;
	hdr.fragseq = 2U;
	hdr.fragcount = 4U;
	hdr.msglen = 512U;
	hdr.payloadtype = (uint8_t)aern_relay_payload_data;
	hdr.reserved = 0U;
	hdr.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;

	aern_relay_payload_header_serialize(enc, &hdr);
	aern_relay_payload_header_deserialize(&cmp, enc);

	res = cmp.sessionid == hdr.sessionid;
	res = (res == true && cmp.packetid == hdr.packetid);
	res = (res == true && cmp.fragseq == hdr.fragseq);
	res = (res == true && cmp.fragcount == hdr.fragcount);
	res = (res == true && cmp.msglen == hdr.msglen);
	res = (res == true && cmp.payloadtype == hdr.payloadtype);
	res = (res == true && cmp.reserved == 0U);
	res = (res == true && cmp.flags == hdr.flags);

	return res;
}


static bool aern_route_test_payload_header_fixed_layout(void)
{
	aern_relay_payload_header hdr = { 0 };
	aern_relay_payload_header cmp = { 0 };
	uint8_t enc[AERN_RELAY_PAYLOAD_HEADER_SIZE];
	bool res;

	qsc_memutils_clear(enc, sizeof(enc));
	hdr.sessionid = 0x0102030405060708ULL;
	hdr.packetid = 0x1112131415161718ULL;
	hdr.fragseq = 0x21222324UL;
	hdr.fragcount = 0x31323334UL;
	hdr.msglen = 0x41424344UL;
	hdr.payloadtype = (uint8_t)aern_relay_payload_data;
	hdr.reserved = 0x00U;
	hdr.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;

	aern_relay_payload_header_serialize(enc, &hdr);
	aern_relay_payload_header_deserialize(&cmp, enc);

	res = (AERN_RELAY_PAYLOAD_HEADER_SIZE == 32U);
	res = (res == true && enc[0U] == 0x08U && enc[1U] == 0x07U && enc[2U] == 0x06U && enc[3U] == 0x05U);
	res = (res == true && enc[4U] == 0x04U && enc[5U] == 0x03U && enc[6U] == 0x02U && enc[7U] == 0x01U);
	res = (res == true && enc[8U] == 0x18U && enc[9U] == 0x17U && enc[10U] == 0x16U && enc[11U] == 0x15U);
	res = (res == true && enc[12U] == 0x14U && enc[13U] == 0x13U && enc[14U] == 0x12U && enc[15U] == 0x11U);
	res = (res == true && enc[16U] == 0x24U && enc[17U] == 0x23U && enc[18U] == 0x22U && enc[19U] == 0x21U);
	res = (res == true && enc[20U] == 0x34U && enc[21U] == 0x33U && enc[22U] == 0x32U && enc[23U] == 0x31U);
	res = (res == true && enc[24U] == 0x44U && enc[25U] == 0x43U && enc[26U] == 0x42U && enc[27U] == 0x41U);
	res = (res == true && enc[28U] == (uint8_t)aern_relay_payload_data);
	res = (res == true && enc[29U] == 0U);
	res = (res == true && enc[30U] == 0x01U && enc[31U] == 0x00U);
	res = (res == true && cmp.sessionid == hdr.sessionid && cmp.packetid == hdr.packetid);
	res = (res == true && cmp.fragseq == hdr.fragseq && cmp.fragcount == hdr.fragcount && cmp.msglen == hdr.msglen);
	res = (res == true && cmp.payloadtype == hdr.payloadtype && cmp.reserved == hdr.reserved && cmp.flags == hdr.flags);

	return res;
}

static bool aern_route_test_payload_header_type_and_flag_roundtrip(void)
{
	aern_relay_payload_header hdr = { 0 };
	aern_relay_payload_header cmp = { 0 };
	uint8_t enc[AERN_RELAY_PAYLOAD_HEADER_SIZE] = { 0U };
	uint8_t types[6U] = { 0U };
	uint16_t flags[2U] = { 0U };
	size_t i;
	size_t j;
	bool res;

	types[0U] = (uint8_t)aern_relay_payload_session_open;
	types[1U] = (uint8_t)aern_relay_payload_session_open_ack;
	types[2U] = (uint8_t)aern_relay_payload_session_close;
	types[3U] = (uint8_t)aern_relay_payload_data;
	types[4U] = (uint8_t)aern_relay_payload_dummy;
	types[5U] = (uint8_t)aern_relay_payload_error;
	flags[0U] = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
	flags[1U] = AERN_RELAY_PAYLOAD_FLAG_RETURN;
	res = (AERN_RELAY_PAYLOAD_FLAG_OUTBOUND == 0U && AERN_RELAY_PAYLOAD_FLAG_RETURN == 1U);

	for (i = 0U; res == true && i < sizeof(types); ++i)
	{
		for (j = 0U; res == true && j < (sizeof(flags) / sizeof(flags[0U])); ++j)
		{
			qsc_memutils_clear(&hdr, sizeof(hdr));
			qsc_memutils_clear(&cmp, sizeof(cmp));
			qsc_memutils_clear(enc, sizeof(enc));
			hdr.sessionid = 0xABCDEF0102030405ULL + (uint64_t)i;
			hdr.packetid = 0x1111111111111111ULL + (uint64_t)j;
			hdr.fragseq = (uint32_t)i;
			hdr.fragcount = (uint32_t)(i + j);
			hdr.msglen = 16U + (uint32_t)i;
			hdr.payloadtype = types[i];
			hdr.reserved = 0U;
			hdr.flags = flags[j];

			aern_relay_payload_header_serialize(enc, &hdr);
			aern_relay_payload_header_deserialize(&cmp, enc);
			res = (cmp.sessionid == hdr.sessionid && cmp.packetid == hdr.packetid);
			res = (res == true && cmp.fragseq == hdr.fragseq && cmp.fragcount == hdr.fragcount && cmp.msglen == hdr.msglen);
			res = (res == true && cmp.payloadtype == hdr.payloadtype && cmp.reserved == 0U && cmp.flags == hdr.flags);
		}
	}

	return res;
}

static bool aern_route_test_session_control_roundtrip(void)
{
	aern_relay_session_open opn = { 0 };
	aern_relay_session_open ocp = { 0 };
	aern_relay_session_open_ack ack = { 0 };
	aern_relay_session_open_ack acp = { 0 };
	uint8_t openbuf[AERN_RELAY_SESSION_OPEN_SIZE] = { 0U };
	uint8_t ackbuf[AERN_RELAY_SESSION_OPEN_ACK_SIZE] = { 0U };
	bool res;

	opn.sessionid = 0x1112131415161718ULL;
	opn.destination[0U] = 192U;
	opn.destination[1U] = 168U;
	opn.destination[2U] = 1U;
	opn.destination[3U] = 7U;
	opn.ingresshint = 1U;
	opn.egresshint = 3U;
	opn.port = 443U;
	opn.reserved = 0U;
	opn.flags = 0x5AU;

	aern_relay_session_open_serialize(openbuf, &opn);
	aern_relay_session_open_deserialize(&ocp, openbuf);

	res = ocp.sessionid == opn.sessionid;
	res = (res == true && ocp.ingresshint == opn.ingresshint);
	res = (res == true && ocp.egresshint == opn.egresshint);
	res = (res == true && ocp.port == opn.port);
	res = (res == true && ocp.reserved == 0U);
	res = (res == true && ocp.flags == opn.flags);
	res = (res == true && qsc_memutils_are_equal(ocp.destination, opn.destination, sizeof(opn.destination)) == true);

	ack.sessionid = 0x2122232425262728ULL;
	ack.status = 1U;
	ack.flags = 0xA5U;
	ack.reserved = 0x3456U;

	if (res == true)
	{
		aern_relay_session_open_ack_serialize(ackbuf, &ack);
		aern_relay_session_open_ack_deserialize(&acp, ackbuf);
	}

	res = (res == true && acp.sessionid == ack.sessionid);
	res = (res == true && acp.status == ack.status);
	res = (res == true && acp.flags == ack.flags);
	res = (res == true && acp.reserved == ack.reserved);

	return res;
}

static aern_protocol_errors route_test_exit_callback(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context)
{
	route_test_transport_context* ctx;
	aern_protocol_errors res;

	ctx = (route_test_transport_context*)context;
	res = aern_protocol_error_invalid_request;

	if (ctx != NULL && session != NULL && header != NULL && packet != NULL && pktlen != 0U)
	{
		ctx->calls += 1U;
		ctx->sessionid = session->sessionid;
		ctx->payloadtype = header->payloadtype;
		ctx->flags = header->flags;
		ctx->pktlen = pktlen;
		ctx->first = packet[0U];

		if (ctx->result != aern_protocol_error_none)
		{
			res = ctx->result;
		}
		else
		{
			res = aern_protocol_error_none;
		}
	}

	return res;
}

static aern_protocol_errors route_test_ingress_callback(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen, void* context)
{
	route_test_transport_context* ctx;
	aern_protocol_errors res;

	ctx = (route_test_transport_context*)context;
	res = aern_protocol_error_invalid_request;

	if (ctx != NULL && session != NULL && header != NULL && packet != NULL && pktlen != 0U)
	{
		ctx->calls += 1U;
		ctx->sessionid = session->sessionid;
		ctx->payloadtype = header->payloadtype;
		ctx->flags = header->flags;
		ctx->pktlen = pktlen;
		ctx->first = packet[0U];

		if (ctx->result != aern_protocol_error_none)
		{
			res = ctx->result;
		}
		else
		{
			res = aern_protocol_error_none;
		}
	}

	return res;
}

static void route_test_set_string(char* dst, size_t dstlen, const char* src)
{
	size_t i;

	i = 0U;

	if (dst != NULL && dstlen != 0U && src != NULL)
	{
		while (i + 1U < dstlen && src[i] != '\0')
		{
			dst[i] = src[i];
			++i;
		}

		dst[i] = '\0';
	}
}

static bool route_test_topology_build(aern_topology_list_state* list)
{
	aern_topology_node_state node = { 0 };
	uint8_t i;
	bool res;

	res = false;

	if (list != NULL)
	{
		aern_topology_list_initialize(list);

		for (i = 1U; i <= 3U; ++i)
		{
			qsc_memutils_clear(&node, sizeof(node));
			node.serial[AERN_CERTIFICATE_SERIAL_SIZE - 1U] = i;
			node.designation = aern_network_designation_aps;

			if (i == 1U)
			{
				route_test_set_string(node.address, sizeof(node.address), "10.0.0.1");
				route_test_set_string(node.issuer, sizeof(node.issuer), "aps-1");
			}
			else if (i == 2U)
			{
				route_test_set_string(node.address, sizeof(node.address), "10.0.0.2");
				route_test_set_string(node.issuer, sizeof(node.issuer), "aps-2");
			}
			else
			{
				route_test_set_string(node.address, sizeof(node.address), "10.0.0.3");
				route_test_set_string(node.issuer, sizeof(node.issuer), "aps-3");
			}

			aern_topology_add(list, &node);
		}

		res = (list->count == 3U);
	}

	return res;
}

static void route_test_connection_pair_initialize(aern_connection_state* sender, aern_connection_state* receiver, uint8_t seed)
{
	aern_cipher_keyparams kp = { 0 };
	uint8_t key[AERN_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t nonce[AERN_CRYPTO_SYMMETRIC_NONCE_SIZE] = { 0 };
	size_t i;

	if (sender != NULL && receiver != NULL)
	{
		qsc_memutils_clear(sender, sizeof(aern_connection_state));
		qsc_memutils_clear(receiver, sizeof(aern_connection_state));

		for (i = 0U; i < sizeof(key); ++i)
		{
			key[i] = (uint8_t)(seed + (uint8_t)i);
		}

		for (i = 0U; i < sizeof(nonce); ++i)
		{
			nonce[i] = (uint8_t)(0xA0U + seed + (uint8_t)i);
		}

		kp.key = key;
		kp.keylen = AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
		kp.nonce = nonce;
		kp.info = NULL;
		kp.infolen = 0U;
		aern_cipher_initialize(&sender->txcpr, &kp, true);
		aern_cipher_initialize(&receiver->rxcpr, &kp, false);

		for (i = 0U; i < sizeof(key); ++i)
		{
			key[i] = (uint8_t)(seed + 0x40U + (uint8_t)i);
		}

		for (i = 0U; i < sizeof(nonce); ++i)
		{
			nonce[i] = (uint8_t)(0xE0U + seed + (uint8_t)i);
		}

		aern_cipher_initialize(&receiver->txcpr, &kp, true);
		aern_cipher_initialize(&sender->rxcpr, &kp, false);
		sender->exflag = aern_network_flag_tunnel_session_established;
		receiver->exflag = aern_network_flag_tunnel_session_established;
	}
}

static void route_test_plaintext_make(uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], const aern_route_map* rm, const aern_relay_payload_header* header, const uint8_t* body)
{
	uint16_t actual;

	actual = 0U;

	if (plaintext != NULL && rm != NULL && header != NULL && body != NULL)
	{
		qsc_memutils_clear(plaintext, AERN_RELAY_PLAINTEXT_SIZE);
		actual = (uint16_t)(AERN_RELAY_PAYLOAD_HEADER_SIZE + header->msglen);
		qsc_intutils_le16to8(plaintext, actual);
		aern_route_map_serialize(plaintext + AERN_LEN_PREFIX_SIZE, rm);
		aern_relay_payload_header_serialize(plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE, header);

		if (header->msglen != 0U)
		{
			const size_t bodymax = AERN_RELAY_PLAINTEXT_SIZE - AERN_LEN_PREFIX_SIZE - AERN_ROUTEMAP_SIZE - AERN_RELAY_PAYLOAD_HEADER_SIZE;
			const size_t copylen = (header->msglen <= bodymax) ? (size_t)header->msglen : bodymax;

			qsc_memutils_copy(plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE + AERN_RELAY_PAYLOAD_HEADER_SIZE, body, copylen);
		}
	}
}

static bool route_test_wire_make(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender, const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE])
{
	aern_network_packet pkt = { 0 };
	bool res;

	res = false;

	if (wire != NULL && sender != NULL && plaintext != NULL)
	{
		qsc_memutils_clear(wire, AERN_RELAY_MTU);
		pkt.pmessage = wire + AERN_RELAY_HEADER_SIZE;

		if (aern_encrypt_packet(sender, &pkt, plaintext, AERN_RELAY_PLAINTEXT_SIZE) == aern_protocol_error_none)
		{
			aern_packet_header_serialize(&pkt, wire);
			res = true;
		}
	}

	return res;
}

static void route_test_session_set(aern_relay_session_cache_entry* session, uint64_t sessionid, uint8_t context, uint8_t flags)
{
	uint64_t tnow;

	tnow = qsc_timestamp_datetime_utc();

	if (session != NULL)
	{
		qsc_memutils_clear(session, sizeof(aern_relay_session_cache_entry));
		session->sessionid = sessionid;
		session->created = tnow;
		session->activity = tnow;
		session->expiry = tnow + 3600U;
		session->ingresshint = 1U;
		session->egresshint = 3U;
		session->status = (uint8_t)aern_relay_session_status_active;
		session->context = context;
		session->flags = flags;
		session->transport = (uint8_t)aern_exit_transport_status_active;
	}
}

static bool route_test_context_initialize(aern_cipher_table** ctable, aern_relay_cache_state** cache, aern_topology_list_state** topology, aern_forward_state* fwd)
{
	bool res;

	res = false;

	if (ctable != NULL && cache != NULL && topology != NULL && fwd != NULL)
	{
		*ctable = (aern_cipher_table*)qsc_memutils_malloc(sizeof(aern_cipher_table));
		*cache = (aern_relay_cache_state*)qsc_memutils_malloc(sizeof(aern_relay_cache_state));
		*topology = (aern_topology_list_state*)qsc_memutils_malloc(sizeof(aern_topology_list_state));

		if (*ctable != NULL && *cache != NULL && *topology != NULL)
		{
			aern_cipher_table_initialize(*ctable);
			aern_relay_cache_initialize(*cache);
			res = route_test_topology_build(*topology);

			if (res == true)
			{
				qsc_memutils_clear(fwd, sizeof(aern_forward_state));
				fwd->conn_table = *ctable;
				fwd->relay_cache = *cache;
				fwd->topology = *topology;
				fwd->apscount = 3U;
				fwd->ownhint = 1U;
				fwd->own_address = "10.0.0.1";
			}
		}
	}

	return res;
}

static void route_test_context_dispose(aern_cipher_table* ctable, aern_relay_cache_state* cache, aern_topology_list_state* topology)
{
	if (ctable != NULL)
	{
		aern_cipher_table_dispose(ctable);
		qsc_memutils_alloc_free(ctable);
	}

	if (cache != NULL)
	{
		aern_relay_cache_dispose(cache);
		qsc_memutils_alloc_free(cache);
	}

	if (topology != NULL)
	{
		aern_topology_list_dispose(topology);
		qsc_memutils_alloc_free(topology);
	}
}

static bool route_test_topology_build_four(aern_topology_list_state* list)
{
	aern_topology_node_state node = { 0 };
	uint8_t i;
	bool res;

	res = false;

	if (list != NULL)
	{
		aern_topology_list_initialize(list);

		for (i = 0U; i < 4U; ++i)
		{
			qsc_memutils_clear(&node, sizeof(node));
			node.serial[AERN_CERTIFICATE_SERIAL_SIZE - 1U] = (uint8_t)(i + 1U);
			node.designation = aern_network_designation_aps;
			(void)snprintf((char*)node.address, sizeof(node.address), "10.0.0.%u", (uint32_t)(i + 1U));
			(void)snprintf((char*)node.issuer, sizeof(node.issuer), "aps-%u", (uint32_t)(i + 1U));
			aern_topology_add(list, &node);
		}

		res = (list->count == 4U);
	}

	return res;
}

static void route_test_multihop_dispose(route_test_multihop_context* ctx)
{
	uint8_t i;

	if (ctx != NULL)
	{
		for (i = 0U; i < 4U; ++i)
		{
			aern_relay_cache_dispose(&ctx->cache[i]);
			aern_cipher_table_dispose(&ctx->ctable[i]);
		}

		aern_topology_list_dispose(&ctx->topology);
		qsc_memutils_clear(ctx, sizeof(route_test_multihop_context));
	}
}

static bool route_test_multihop_add_pair(route_test_multihop_context* ctx, uint8_t left, uint8_t right, uint8_t seed)
{
	aern_connection_state lstate = { 0 };
	aern_connection_state rstate = { 0 };
	bool res;

	res = false;

	if (ctx != NULL && left < 4U && right < 4U && left != right)
	{
		route_test_connection_pair_initialize(&lstate, &rstate, seed);
		res = (aern_cipher_table_add(&ctx->ctable[left], ctx->address[right], &lstate) == aern_protocol_error_none);
		res = (res == true && aern_cipher_table_add(&ctx->ctable[right], ctx->address[left], &rstate) == aern_protocol_error_none);
	}

	return res;
}

static bool route_test_multihop_initialize(route_test_multihop_context* ctx)
{
	uint8_t i;
	uint8_t j;
	uint8_t seed;
	bool res;

	res = false;
	seed = 0x60U;

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx, sizeof(route_test_multihop_context));
		res = route_test_topology_build_four(&ctx->topology);

		for (i = 0U; i < 4U && res == true; ++i)
		{
			(void)snprintf(ctx->address[i], sizeof(ctx->address[i]), "10.0.0.%u", (uint32_t)(i + 1U));
			aern_cipher_table_initialize(&ctx->ctable[i]);
			aern_relay_cache_initialize(&ctx->cache[i]);
			ctx->fwd[i].conn_table = &ctx->ctable[i];
			ctx->fwd[i].relay_cache = &ctx->cache[i];
			ctx->fwd[i].topology = &ctx->topology;
			ctx->fwd[i].apscount = 4U;
			ctx->fwd[i].ownhint = (uint8_t)(i + 1U);
			ctx->fwd[i].own_address = ctx->address[i];
			res = (ctx->cache[i].initialized == true);
		}

		for (i = 0U; i < 4U && res == true; ++i)
		{
			for (j = (uint8_t)(i + 1U); j < 4U && res == true; ++j)
			{
				res = route_test_multihop_add_pair(ctx, i, j, seed);
				++seed;
			}
		}
	}

	return res;
}

static uint8_t route_test_multihop_address_index(route_test_multihop_context* ctx, const char* address)
{
	uint8_t i;
	uint8_t res;

	res = UINT8_MAX;

	if (ctx != NULL && address != NULL)
	{
		for (i = 0U; i < 4U; ++i)
		{
			if (qsc_stringutils_compare_strings(ctx->address[i], address, sizeof(ctx->address[i])) == true)
			{
				res = i;
				break;
			}
		}
	}

	return res;
}

static bool route_test_multihop_has_future(const aern_route_map* rm)
{
	uint8_t i;
	bool res;

	res = false;

	if (rm != NULL)
	{
		for (i = 1U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				res = true;
				break;
			}
		}
	}

	return res;
}

static bool route_test_multihop_consume_next(aern_route_map* rm, uint8_t apscount, uint8_t* nexthint)
{
	uint8_t i;
	bool res;

	res = false;

	if (rm != NULL && nexthint != NULL)
	{
		*nexthint = 0U;

		for (i = 1U; i < AERN_ROUTE_PATH_SIZE; ++i)
		{
			if (rm->path[i] != 0U)
			{
				if (rm->path[i] <= apscount)
				{
					*nexthint = rm->path[i];
					rm->path[i] = 0U;
					res = true;
				}

				break;
			}
		}
	}

	return res;
}

static bool route_test_multihop_reencrypt(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* txcns, const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE])
{
	aern_network_packet pktout = { 0 };
	bool res;

	res = false;

	if (wire != NULL && txcns != NULL && plaintext != NULL)
	{
		qsc_memutils_clear(wire, AERN_RELAY_MTU);
		pktout.pmessage = wire + AERN_RELAY_HEADER_SIZE;

		if (aern_encrypt_packet(txcns, &pktout, plaintext, AERN_RELAY_PLAINTEXT_SIZE) == aern_protocol_error_none)
		{
			pktout.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
			aern_packet_header_serialize(&pktout, wire);
			res = true;
		}
	}

	return res;
}

static aern_protocol_errors route_test_multihop_drive(route_test_multihop_context* ctx, uint8_t start, uint8_t src, uint8_t wire[AERN_RELAY_MTU])
{
	aern_network_packet pktin = { 0 };
	aern_route_map rm = { 0 };
	aern_connection_state* rxcns;
	aern_connection_state* txcns;
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0 };
	uint8_t nexthint;
	uint8_t current;
	uint8_t previous;
	size_t ptlen;
	aern_protocol_errors res;
	bool terminalnext;

	rxcns = NULL;
	txcns = NULL;
	nexthint = 0U;
	current = start;
	previous = src;
	ptlen = 0U;
	res = aern_protocol_error_invalid_request;
	terminalnext = false;

	if (ctx != NULL && wire != NULL && start < 4U && src < 4U)
	{
		res = aern_protocol_error_none;

		while (res == aern_protocol_error_none)
		{
			if (ctx->depth >= 8U)
			{
				++ctx->failures;
				res = aern_protocol_error_node_not_found;
				break;
			}

			++ctx->depth;

			if (ctx->depth > ctx->maxdepth)
			{
				ctx->maxdepth = ctx->depth;
			}

			aern_packet_header_deserialize(wire, &pktin);
			pktin.pmessage = wire + AERN_RELAY_HEADER_SIZE;
			rxcns = aern_cipher_table_get_by_ip(&ctx->ctable[current], ctx->address[previous]);

			if (rxcns == NULL)
			{
				++ctx->failures;
				res = aern_protocol_error_channel_down;
			}
			else
			{
				res = aern_decrypt_packet(rxcns, plaintext, &ptlen, &pktin);
			}

			if (res == aern_protocol_error_none)
			{
				if (ptlen != AERN_RELAY_PLAINTEXT_SIZE)
				{
					++ctx->failures;
					res = aern_protocol_error_packet_header_invalid;
				}
				else
				{
					aern_route_map_deserialize(&rm, plaintext + AERN_LEN_PREFIX_SIZE);

					if (route_test_multihop_consume_next(&rm, 4U, &nexthint) == false)
					{
						++ctx->failures;
						res = aern_protocol_error_node_not_found;
					}
				}
			}

			if (res == aern_protocol_error_none)
			{
				if (nexthint == 0U || nexthint > 4U)
				{
					++ctx->failures;
					res = aern_protocol_error_node_not_found;
				}
				else
				{
					terminalnext = (route_test_multihop_has_future(&rm) == false);
					txcns = aern_cipher_table_get_by_ip(&ctx->ctable[current], ctx->address[nexthint - 1U]);

					if (txcns == NULL)
					{
						++ctx->failures;
						res = aern_protocol_error_channel_down;
					}
					else
					{
						aern_route_map_serialize(plaintext + AERN_LEN_PREFIX_SIZE, &rm);

						if (route_test_multihop_reencrypt(wire, txcns, plaintext) == true)
						{
							++ctx->dispatches;
						}
						else
						{
							++ctx->failures;
							res = aern_protocol_error_transmit_failure;
						}
					}
				}
			}

			--ctx->depth;

			if (res == aern_protocol_error_none)
			{
				previous = current;
				current = (uint8_t)(nexthint - 1U);

				if (terminalnext == true)
				{
					res = aern_packet_forward(&ctx->fwd[current], wire, ctx->address[previous]);
					break;
				}
			}
		}
	}

	return res;
}

static bool aern_route_test_multihop_virtual_dispatch_load_profile(void)
{
	route_test_transport_context exitctx = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	uint8_t body[AERN_RELAY_DATA_PAYLOAD_SIZE] = { 0U };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	route_test_multihop_context* ctx;
	aern_connection_state* sender;
	uint32_t i;
	bool res;

	ctx = (route_test_multihop_context*)qsc_memutils_malloc(sizeof(route_test_multihop_context));
	res = (ctx != NULL);

	if (res == true)
	{
		res = route_test_multihop_initialize(ctx);
	}

	if (res == true)
	{
		route_test_session_set(&session, 0x0102030405060708ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[3U], &session);
	}

	if (res == true)
	{
		header.sessionid = session.sessionid;
		header.packetid = 0x1112131415161718ULL;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = 96U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);

		for (i = 0U; i < 16U && res == true; ++i)
		{
			body[0U] = (uint8_t)(0x80U + i);
			body[1U] = (uint8_t)(i ^ 0xA5U);
			header.packetid = 0x1112131415161718ULL + i;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
			res = (sender != NULL);

			if (res == true)
			{
				res = route_test_wire_make(wire, sender, plaintext);
			}

			if (res == true)
			{
				res = (route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);
			}
		}

		res = (res == true && exitctx.calls == 16U);
		res = (res == true && exitctx.sessionid == session.sessionid);
		res = (res == true && exitctx.payloadtype == (uint8_t)aern_relay_payload_data);
		res = (res == true && exitctx.flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && ctx->dispatches == 32U && ctx->failures == 0U && ctx->maxdepth == 1U);
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	if (ctx != NULL)
	{
		route_test_multihop_dispose(ctx);
		qsc_memutils_alloc_free(ctx);
	}

	return res;
}

static bool route_test_terminal_header_process(const aern_relay_payload_header* header, const uint8_t* body, bool addsession, aern_protocol_errors expected, uint32_t* exitcalls, uint32_t* ingresscalls)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 11U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		if (addsession == true && header != NULL)
		{
			route_test_session_set(&session, header->sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
			(void)aern_relay_session_add(cache, &session);
		}

		rm.path[0U] = 1U;
		rm.hopcount = 1U;
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (header != NULL && body != NULL)
		{
			route_test_plaintext_make(plaintext, &rm, header, body);

			if (route_test_wire_make(wire, &sender, plaintext) == true)
			{
				err = aern_packet_forward(&fwd, wire, "10.0.0.2");
				res = (err == expected);
			}
		}
	}

	if (exitcalls != NULL)
	{
		*exitcalls = exitctx.calls;
	}

	if (ingresscalls != NULL)
	{
		*ingresscalls = ingressctx.calls;
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_payload_header_invalid_semantics(void)
{
	aern_relay_payload_header header = { 0 };
	uint8_t body[AERN_RELAY_DATA_PAYLOAD_SIZE + 1U] = { 0U };
	uint32_t exitcalls;
	uint32_t ingresscalls;
	bool res;

	qsc_memutils_clear(&header, sizeof(header));
	qsc_memutils_clear(body, sizeof(body));
	body[0U] = 0x33U;
	header.sessionid = 0x3132333435363738ULL;
	header.packetid = 0x4142434445464748ULL;
	header.msglen = 8U;
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
	res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_none, &exitcalls, &ingresscalls);
	res = (res == true && exitcalls == 1U && ingresscalls == 0U);

	if (res == true)
	{
		header.reserved = 1U;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.reserved = 0U;
	}

	if (res == true)
	{
		header.payloadtype = (uint8_t)aern_relay_payload_none;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
	}

	if (res == true)
	{
		header.payloadtype = 0x7EU;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
	}

	if (res == true)
	{
		header.msglen = AERN_RELAY_DATA_PAYLOAD_SIZE + 1U;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.msglen = 8U;
	}

	if (res == true)
	{
		header.flags = 0x8000U;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
	}

	if (res == true)
	{
		header.fragseq = 5U;
		header.fragcount = 3U;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.fragseq = 0U;
		header.fragcount = 0U;
	}

	if (res == true)
	{
		header.fragseq = 1U;
		header.fragcount = AERN_MAX_FRAGMENTS + 1U;
		res = route_test_terminal_header_process(&header, body, true, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
	}

	return res;
}

static bool aern_route_test_payload_header_control_semantics(void)
{
	aern_relay_payload_header header = { 0 };
	uint8_t body[AERN_RELAY_SESSION_OPEN_SIZE] = { 0 };
	uint32_t exitcalls;
	uint32_t ingresscalls;
	bool res;

	header.sessionid = 0x8182838485868788ULL;
	header.packetid = 0U;
	header.fragseq = 0U;
	header.fragcount = 0U;
	header.msglen = AERN_RELAY_SESSION_OPEN_SIZE;
	header.payloadtype = (uint8_t)aern_relay_payload_session_open;
	header.reserved = 0U;
	header.flags = 0U;
	res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_invalid_request, &exitcalls, &ingresscalls);
	res = (res == true && exitcalls == 0U && ingresscalls == 0U);

	if (res == true)
	{
		header.packetid = 1U;
		res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.packetid = 0U;
	}

	if (res == true)
	{
		header.msglen = AERN_RELAY_SESSION_OPEN_SIZE - 1U;
		res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_packet_header_invalid, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
		header.msglen = AERN_RELAY_SESSION_OPEN_SIZE;
	}

	if (res == true)
	{
		header.payloadtype = (uint8_t)aern_relay_payload_session_open_ack;
		header.msglen = AERN_RELAY_SESSION_OPEN_ACK_SIZE;
		res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_invalid_request, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
	}

	if (res == true)
	{
		header.payloadtype = (uint8_t)aern_relay_payload_error;
		header.msglen = 0U;
		res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_invalid_request, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
	}

	return res;
}

static bool aern_route_test_terminal_egress_backend_delivery(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	body[0U] = 0x42U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 1U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x11223344U, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		rm.path[0U] = 1U;
		header.sessionid = session.sessionid;
		header.packetid = 2U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true &&
			aern_packet_forward(&fwd, wire, "10.0.0.2") == aern_protocol_error_none)
		{
			res = (exitctx.calls == 1U && ingressctx.calls == 0U && exitctx.sessionid == session.sessionid &&
				exitctx.payloadtype == (uint8_t)aern_relay_payload_data && exitctx.flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND &&
				exitctx.pktlen == sizeof(body) && exitctx.first == 0x42U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_terminal_backend_failure_forwarding(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0xC3U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 43U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xC3C3C3C3C3C3C3C3ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		rm.path[0U] = 1U;
		header.sessionid = session.sessionid;
		header.packetid = 0xC3C3U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		exitctx.result = aern_protocol_error_transmit_failure;
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_transmit_failure && exitctx.calls == 1U && ingressctx.calls == 0U &&
				exitctx.sessionid == session.sessionid && exitctx.payloadtype == (uint8_t)aern_relay_payload_data &&
				exitctx.pktlen == sizeof(body) && exitctx.first == 0xC3U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_terminal_ingress_return_delivery(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	body[0U] = 0x55U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 2U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x55667788U, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		(void)aern_relay_session_add(cache, &session);

		rm.path[0U] = 3U;
		header.sessionid = session.sessionid;
		header.packetid = 3U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true &&
			aern_packet_forward(&fwd, wire, "10.0.0.2") == aern_protocol_error_none)
		{
			res = (exitctx.calls == 0U && ingressctx.calls == 1U && ingressctx.sessionid == session.sessionid &&
				ingressctx.payloadtype == (uint8_t)aern_relay_payload_data && ingressctx.flags == AERN_RELAY_PAYLOAD_FLAG_RETURN &&
				ingressctx.pktlen == sizeof(body) && ingressctx.first == 0x55U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_forwarding_node_no_backend_delivery(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0x66U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 3U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);

		rm.path[0U] = 1U;
		rm.path[1U] = 2U;
		header.sessionid = 0x1010U;
		header.packetid = 4U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_channel_down && exitctx.calls == 0U && ingressctx.calls == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_terminal_dummy_discard(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	body[0U] = 0x77U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 4U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		rm.path[0U] = 1U;
		header.sessionid = 0U;
		header.packetid = 0U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_dummy;
		header.flags = 0U;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true &&
			aern_packet_forward(&fwd, wire, "10.0.0.2") == aern_protocol_error_none)
		{
			res = (exitctx.calls == 0U && ingressctx.calls == 0U && cache->dummydropped == 1U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_dummy_mutation_recovery_forwarding(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t corrupt[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0x79U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 44U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		rm.path[0U] = 1U;
		header.sessionid = 0U;
		header.packetid = 0U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_dummy;
		header.flags = 0U;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			qsc_memutils_copy(corrupt, wire, sizeof(corrupt));
			corrupt[AERN_RELAY_HEADER_SIZE + 19U] ^= 0x80U;

			err = aern_packet_forward(&fwd, corrupt, "10.0.0.2");
			res = (err == aern_protocol_error_authentication_failure && exitctx.calls == 0U &&
				ingressctx.calls == 0U && cache->dummydropped == 0U);

			if (res == true)
			{
				err = aern_packet_forward(&fwd, wire, "10.0.0.2");
				res = (err == aern_protocol_error_none && exitctx.calls == 0U &&
					ingressctx.calls == 0U && cache->dummydropped == 1U);
			}
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_terminal_unknown_session_drop(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	body[0U] = 0x88U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 5U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		rm.path[0U] = 1U;
		header.sessionid = 0x9999U;
		header.packetid = 5U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true &&
			aern_packet_forward(&fwd, wire, "10.0.0.2") == aern_protocol_error_none)
		{
			res = (exitctx.calls == 0U && ingressctx.calls == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool route_test_session_open_wire_make_ex(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender,
	uint64_t sessionid, uint8_t routeorigin, uint8_t ingresshint, uint8_t egresshint, uint16_t port, uint8_t reserved, uint8_t flags)
{
	aern_relay_payload_header header = { 0 };
	aern_relay_session_open open = { 0 };
	aern_route_map rm = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t body[AERN_RELAY_SESSION_OPEN_SIZE] = { 0U };
	bool res;

	res = false;

	if (wire != NULL && sender != NULL)
	{
		header.sessionid = sessionid;
		header.packetid = 0U;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = AERN_RELAY_SESSION_OPEN_SIZE;
		header.payloadtype = (uint8_t)aern_relay_payload_session_open;
		header.reserved = 0U;
		header.flags = 0U;

		open.sessionid = sessionid;
		open.destination[0U] = 192U;
		open.destination[1U] = 168U;
		open.destination[2U] = 10U;
		open.destination[3U] = 20U;
		open.ingresshint = ingresshint;
		open.egresshint = egresshint;
		open.port = port;
		open.reserved = reserved;
		open.flags = flags;

		aern_relay_session_open_serialize(body, &open);
		rm.path[0U] = routeorigin;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		res = route_test_wire_make(wire, sender, plaintext);
	}

	qsc_memutils_clear(plaintext, sizeof(plaintext));
	qsc_memutils_clear(body, sizeof(body));

	return res;
}

static bool route_test_session_open_wire_make(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender,
	uint64_t sessionid, uint8_t ingresshint, uint8_t egresshint, uint16_t port, uint8_t reserved, uint8_t flags)
{
	return route_test_session_open_wire_make_ex(wire, sender, sessionid, ingresshint, ingresshint, egresshint, port, reserved, flags);
}

static bool route_test_session_ack_wire_make(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender,
	uint64_t sessionid, uint8_t status, uint8_t flags, uint16_t reserved)
{
	aern_relay_payload_header header = { 0 };
	aern_relay_session_open_ack ack = { 0 };
	aern_route_map rm = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t body[AERN_RELAY_SESSION_OPEN_ACK_SIZE] = { 0U };
	bool res;

	res = false;

	if (wire != NULL && sender != NULL)
	{
		header.sessionid = sessionid;
		header.packetid = 0U;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = AERN_RELAY_SESSION_OPEN_ACK_SIZE;
		header.payloadtype = (uint8_t)aern_relay_payload_session_open_ack;
		header.reserved = 0U;
		header.flags = 0U;

		ack.sessionid = sessionid;
		ack.status = status;
		ack.flags = flags;
		ack.reserved = reserved;

		aern_relay_session_open_ack_serialize(body, &ack);
		rm.path[0U] = 3U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		res = route_test_wire_make(wire, sender, plaintext);
	}

	qsc_memutils_clear(plaintext, sizeof(plaintext));
	qsc_memutils_clear(body, sizeof(body));

	return res;
}


static bool route_test_entry_data_wire_make(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender, uint64_t sessionid, uint64_t packetid, uint8_t reserved, uint16_t flags)
{
	aern_relay_payload_header header = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t data[8U] = { 0U };
	uint8_t* body;
	uint16_t actual;
	bool res;

	res = false;
	actual = (uint16_t)(AERN_RELAY_PAYLOAD_HEADER_SIZE + sizeof(data));
	data[0U] = 0xA5U;
	body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;

	if (wire != NULL && sender != NULL)
	{
		header.sessionid = sessionid;
		header.packetid = packetid;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = (uint32_t)sizeof(data);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = reserved;
		header.flags = flags;

		aern_packet_pad(plaintext, actual);
		aern_relay_payload_header_serialize(body, &header);
		qsc_memutils_copy(body + AERN_RELAY_PAYLOAD_HEADER_SIZE, data, sizeof(data));
		res = route_test_wire_make(wire, sender, plaintext);
	}

	qsc_memutils_clear(plaintext, sizeof(plaintext));

	return res;
}

static void route_test_pending_session_set(aern_relay_session_cache_entry* session, uint64_t sessionid)
{
	uint64_t tnow;

	tnow = qsc_timestamp_datetime_utc();

	if (session != NULL)
	{
		qsc_memutils_clear(session, sizeof(aern_relay_session_cache_entry));
		session->sessionid = sessionid;
		session->created = tnow;
		session->activity = tnow;
		session->expiry = tnow + 3600U;
		session->ingresshint = 1U;
		session->egresshint = 3U;
		session->port = 443U;
		session->status = (uint8_t)aern_relay_session_status_pending;
		session->context = AERN_RELAY_SESSION_CONTEXT_INGRESS;
		session->flags = 0U;
		session->transport = (uint8_t)aern_exit_transport_status_none;
	}
}

static bool aern_route_test_session_open_creates_egress_session(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_connection_pair_initialize(&sender, &receiver, 7U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_session_open_wire_make(wire, &sender, 0xABCDEF01ULL, 1U, 3U, 443U, 0U, 0x5AU) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = ((err == aern_protocol_error_channel_down || err == aern_protocol_error_connection_failure || err == aern_protocol_error_none) &&
				aern_relay_session_find(cache, &found, 0xABCDEF01ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_active && found.ingresshint == 1U && found.egresshint == 3U &&
				found.port == 443U && found.transport == (uint8_t)aern_exit_transport_status_pending &&
				exitctx.calls == 0U && ingressctx.calls == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_session_open_bad_reserved_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_connection_pair_initialize(&sender, &receiver, 8U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		if (route_test_session_open_wire_make(wire, &sender, 0xABCDEF02ULL, 1U, 3U, 443U, 1U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, 0xABCDEF02ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false);
		}
	}

	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_session_ack_activates_pending_session(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 9U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);
		route_test_pending_session_set(&session, 0xABCDEF03ULL);
		(void)aern_relay_session_add(cache, &session);

		if (route_test_session_ack_wire_make(wire, &sender, session.sessionid, 0U, 0U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_none &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_active && cache->pendingreleased == 0U &&
				aern_relayqueue_count(&cache->pendingqueue) == 0U);
		}
	}

	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_session_ack_wrong_session_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 10U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);
		route_test_pending_session_set(&session, 0xABCDEF04ULL);
		(void)aern_relay_session_add(cache, &session);

		if (route_test_session_ack_wire_make(wire, &sender, 0xABCDEF05ULL, 0U, 0U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_pending);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_session_ack_flags_reserved_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	uint32_t scount;
	uint32_t pcount;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	scount = 0U;
	pcount = 0U;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 23U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);
		route_test_pending_session_set(&session, 0xABCDEF09ULL);
		(void)aern_relay_session_add(cache, &session);
		scount = aern_relaysession_count(&cache->sessions);
		pcount = aern_relayqueue_count(&cache->pendingqueue);

		if (route_test_session_ack_wire_make(wire, &sender, session.sessionid, 0U, 1U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_pending &&
				aern_relaysession_count(&cache->sessions) == scount &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount);
		}

		if (res == true)
		{
			qsc_memutils_clear(wire, sizeof(wire));
			qsc_memutils_clear(&found, sizeof(found));
			res = route_test_session_ack_wire_make(wire, &sender, session.sessionid, 0U, 0U, 1U);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_pending &&
				aern_relaysession_count(&cache->sessions) == scount &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_session_ack_failure_closes_session_and_drops_pending(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	aern_ingress_pending_item item = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 11U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);
		route_test_pending_session_set(&session, 0xABCDEF06ULL);
		(void)aern_relay_session_add(cache, &session);

		if (route_test_fill_allocated_packet(&item, 64U, session.sessionid, 2U, 0x33U) == true)
		{
			item.expiry = qsc_timestamp_datetime_utc() + 3600U;
			(void)aern_relay_pending_push(cache, &item);
			aern_relayqueue_item_dispose(&item);
		}

		if (route_test_session_ack_wire_make(wire, &sender, session.sessionid, 1U, 0U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_connection_failure &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_closing &&
				aern_relayqueue_count(&cache->pendingqueue) == 0U);
		}
	}

	aern_relayqueue_item_dispose(&item);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_session_ack_bad_flags_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 12U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);
		route_test_pending_session_set(&session, 0xABCDEF07ULL);
		(void)aern_relay_session_add(cache, &session);

		if (route_test_session_ack_wire_make(wire, &sender, session.sessionid, 0U, 1U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_pending);
		}
	}

	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_pending_session_timeout_cleanup(void)
{
	aern_forward_state fwd = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_ingress_pending_item item = { 0 };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint64_t tnow;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	tnow = qsc_timestamp_datetime_utc();

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_pending_session_set(&session, 0xABCDEF08ULL);
		session.expiry = tnow - 1U;
		(void)aern_relay_session_add(cache, &session);

		if (route_test_fill_allocated_packet(&item, 64U, session.sessionid, 3U, 0x44U) == true)
		{
			item.expiry = tnow - 1U;
			(void)aern_relay_pending_push(cache, &item);
			aern_relayqueue_item_dispose(&item);
		}

		aern_relay_cache_cleanup(cache);
		res = (aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == false &&
			aern_relayqueue_count(&cache->pendingqueue) == 0U);
	}

	aern_relayqueue_item_dispose(&item);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_first_outbound_packet_creates_pending_session(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state client_sender = { 0 };
	aern_connection_state client_receiver = { 0 };
	aern_connection_state peer2_sender = { 0 };
	aern_connection_state peer2_receiver = { 0 };
	aern_connection_state peer3_sender = { 0 };
	aern_connection_state peer3_receiver = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&client_sender, &client_receiver, 30U);
		route_test_connection_pair_initialize(&peer2_sender, &peer2_receiver, 31U);
		route_test_connection_pair_initialize(&peer3_sender, &peer3_receiver, 32U);
		(void)aern_cipher_table_add(ctable, "client", &client_receiver);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &peer2_sender);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &peer3_sender);

		if (route_test_entry_data_wire_make(wire, &client_sender, 0xABCDEF09ULL, 1U, 0U, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND) == true)
		{
			err = aern_entry_packet_forward(&fwd, wire, "client");
			res = ((err == aern_protocol_error_connection_failure || err == aern_protocol_error_channel_down || err == aern_protocol_error_none) &&
				aern_relay_session_find(cache, &found, 0xABCDEF09ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_pending &&
				aern_relayqueue_count(&cache->pendingqueue) == 1U);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_session_open_bad_ingress_hint_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_connection_pair_initialize(&sender, &receiver, 33U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		if (route_test_session_open_wire_make_ex(wire, &sender, 0xABCDEF0AULL, 1U, 0U, 3U, 443U, 0U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, 0xABCDEF0AULL, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false);
		}
	}

	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_session_open_bad_egress_hint_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_connection_pair_initialize(&sender, &receiver, 34U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		if (route_test_session_open_wire_make(wire, &sender, 0xABCDEF0BULL, 1U, 4U, 443U, 0U, 0U) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_find(cache, &found, 0xABCDEF0BULL, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_duplicate_session_open_preserves_existing_session(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_connection_pair_initialize(&sender, &receiver, 35U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xABCDEF0CULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0x5AU);
		session.ingresshint = 1U;
		session.egresshint = 3U;
		session.port = 443U;
		session.destination[0U] = 192U;
		session.destination[1U] = 168U;
		session.destination[2U] = 10U;
		session.destination[3U] = 20U;
		(void)aern_relay_session_add(cache, &session);

		if (route_test_session_open_wire_make(wire, &sender, session.sessionid, 1U, 3U, 443U, 0U, 0x5AU) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = ((err == aern_protocol_error_channel_down || err == aern_protocol_error_connection_failure || err == aern_protocol_error_none) &&
				aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true &&
				found.status == (uint8_t)aern_relay_session_status_active && found.port == 443U && found.flags == 0x5AU &&
				aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == false);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_active_session_idle_cleanup(void)
{
	aern_forward_state fwd = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint64_t tnow;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	tnow = qsc_timestamp_datetime_utc();

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_session_set(&session, 0xABCDEF0DULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.activity = tnow;
		session.expiry = tnow - 1U;
		(void)aern_relay_session_add(cache, &session);
		aern_relay_cache_cleanup(cache);
		res = (aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false);
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_session_close_payload_currently_rejected(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_route_map rm = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 36U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xABCDEF0EULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);
		rm.path[0U] = 1U;
		header.sessionid = session.sessionid;
		header.packetid = 0U;
		header.msglen = 0U;
		header.payloadtype = (uint8_t)aern_relay_payload_session_close;
		header.reserved = 0U;
		header.flags = 0U;
		route_test_plaintext_make(plaintext, &rm, &header, (const uint8_t*)"x");

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_invalid_request &&
				aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true);
		}
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_invalid_next_hint_rejected_before_backend(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0x99U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 6U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		rm.path[0U] = 1U;
		rm.path[1U] = 4U;
		header.sessionid = 0x7777U;
		header.packetid = 6U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_packet_header_invalid && exitctx.calls == 0U && ingressctx.calls == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_fragment_single_boundary_payload(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag;
	uint8_t* assembled;
	size_t msglen;
	bool complete;
	bool res;

	set = NULL;
	frag = NULL;
	assembled = NULL;
	msglen = 0U;
	complete = false;
	res = false;

	if (aern_fragment_table_initialize(&table, 1U, AERN_FRAG_CHUNK_SIZE) == true &&
		route_test_fill_numbered_fragment(&frag, AERN_FRAG_CHUNK_SIZE, 1U) == true)
	{
		route_test_fill_fragment_header(&hdr, 0x1111111111111111ULL, 0x2222222222222222ULL,
			1U, 1U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag, AERN_FRAG_CHUNK_SIZE,
			(uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete);
		res = (res == true && complete == true && set != NULL && set->complete == true);
		res = (res == true && set->total_bytes == AERN_FRAG_CHUNK_SIZE && set->declared_length == AERN_FRAG_CHUNK_SIZE);

		if (res == true)
		{
			res = aern_fragment_cache_assemble_alloc(set, &assembled, &msglen);
			res = (res == true && assembled != NULL && msglen == AERN_FRAG_CHUNK_SIZE);
			res = (res == true && route_test_verify_numbered_assembly(assembled, msglen, 1U, AERN_FRAG_CHUNK_SIZE) == true);
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, msglen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag != NULL)
	{
		qsc_memutils_secure_erase(frag, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_fragment_two_fragment_payload(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag1;
	uint8_t* frag2;
	uint8_t* assembled;
	size_t finallen;
	size_t msglen;
	bool complete;
	bool res;

	set = NULL;
	frag1 = NULL;
	frag2 = NULL;
	assembled = NULL;
	finallen = 17U;
	msglen = 0U;
	complete = false;
	res = false;

	if (aern_fragment_table_initialize(&table, 1U, ((size_t)2U * (size_t)AERN_FRAG_CHUNK_SIZE)) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, finallen, 2U) == true)
	{
		route_test_fill_fragment_header(&hdr, 0x1212121212121212ULL, 0x3434343434343434ULL, 1U, 2U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete);
		res = (res == true && complete == false && set != NULL && set->received_count == 1U);

		route_test_fill_fragment_header(&hdr, 0x1212121212121212ULL, 0x3434343434343434ULL, 2U, 2U, finallen, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag2, finallen, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == true);
		res = (res == true && complete == true && set != NULL && set->complete == true);

		if (res == true)
		{
			res = aern_fragment_cache_assemble_alloc(set, &assembled, &msglen);
			res = (res == true && assembled != NULL && msglen == (AERN_FRAG_CHUNK_SIZE + finallen));
			res = (res == true && route_test_verify_numbered_assembly(assembled, msglen, 2U, finallen) == true);
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, msglen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, finallen);
		qsc_memutils_alloc_free(frag2);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_fragment_duplicate_policy(void)
{
	aern_fragment_cache cache = { 0 };
	aern_relay_payload_header hdr = { 0 };
	uint8_t* frag1;
	uint8_t* frag2;
	uint8_t* assembled;
	size_t msglen;
	bool complete;
	bool res;

	frag1 = NULL;
	frag2 = NULL;
	assembled = NULL;
	msglen = 0U;
	complete = false;
	res = false;
	aern_fragment_cache_initialize(&cache);
	aern_fragment_cache_set_key(&cache, 0x5151515151515151ULL, 0x6161616161616161ULL, (uint8_t)aern_relay_fragment_direction_outbound, 1000U);

	if (route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, 9U, 2U) == true)
	{
		route_test_fill_fragment_header(&hdr, cache.sessionid, cache.packetid, 1U, 2U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = aern_fragment_cache_add_fragment(&cache, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, &complete);
		res = (res == true && complete == false && cache.received_count == 1U && cache.total_bytes == AERN_FRAG_CHUNK_SIZE);

		if (res == true)
		{
			frag1[0U] ^= 0x01U;
			res = (aern_fragment_cache_add_fragment(&cache, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == false);
			frag1[0U] ^= 0x01U;
		}

		res = (res == true && cache.received_count == 1U && cache.total_bytes == AERN_FRAG_CHUNK_SIZE);
		res = (res == true && aern_fragment_cache_add_fragment(&cache, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == true);
		res = (res == true && complete == false && cache.received_count == 1U && cache.total_bytes == AERN_FRAG_CHUNK_SIZE);

		route_test_fill_fragment_header(&hdr, cache.sessionid, cache.packetid, 2U, 2U, 9U, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && aern_fragment_cache_add_fragment(&cache, &hdr, frag2, 9U, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == true);
		res = (res == true && complete == true && cache.complete == true && cache.received_count == 2U);

		if (res == true)
		{
			res = aern_fragment_cache_assemble_alloc(&cache, &assembled, &msglen);
			res = (res == true && assembled != NULL && msglen == (AERN_FRAG_CHUNK_SIZE + 9U));
		}
	}

	if (assembled != NULL)
	{
		qsc_memutils_secure_erase(assembled, msglen);
		qsc_memutils_alloc_free(assembled);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, 9U);
		qsc_memutils_alloc_free(frag2);
	}

	aern_fragment_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_fragment_invalid_metadata_rejection(void)
{
	aern_fragment_table table = { 0 };
	aern_relay_payload_header hdr = { 0 };
	aern_fragment_cache* set;
	uint8_t* frag1;
	uint8_t* fragshort;
	uint8_t* large;
	bool complete;
	bool res;

	set = NULL;
	frag1 = NULL;
	fragshort = NULL;
	large = NULL;
	complete = false;
	res = false;

	if (aern_fragment_table_initialize(&table, 2U, ((size_t)4U * (size_t)AERN_FRAG_CHUNK_SIZE)) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&fragshort, 8U, 2U) == true &&
		route_test_fill_numbered_fragment(&large, AERN_FRAG_CHUNK_SIZE + 1U, 1U) == true)
	{
		route_test_fill_fragment_header(&hdr, 0x7171717171717171ULL, 0x8181818181818181ULL, 1U, 2U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = aern_fragment_table_add_relay_fragment(&table, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete);
		res = (res == true && complete == false && set != NULL);

		hdr.sessionid ^= 1U;
		res = (res == true && aern_fragment_cache_add_fragment(set, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == false);
		hdr.sessionid ^= 1U;

		hdr.packetid ^= 1U;
		res = (res == true && aern_fragment_cache_add_fragment(set, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == false);
		hdr.packetid ^= 1U;

		hdr.payloadtype = (uint8_t)aern_relay_payload_dummy;
		res = (res == true && aern_fragment_cache_add_fragment(set, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == false);
		hdr.payloadtype = (uint8_t)aern_relay_payload_data;

		hdr.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		res = (res == true && aern_fragment_cache_add_fragment(set, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_outbound, &complete) == false);
		hdr.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

		res = (res == true && aern_fragment_cache_add_fragment(set, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_inbound, &complete) == false);
		res = (res == true && set->received_count == 1U && set->total_bytes == AERN_FRAG_CHUNK_SIZE);

		route_test_fill_fragment_header(&hdr, 0x9191919191919191ULL, 0xA1A1A1A1A1A1A1A1ULL, 1U, 2U, 8U, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, fragshort, 8U, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == false);

		route_test_fill_fragment_header(&hdr, 0x9292929292929292ULL, 0xA2A2A2A2A2A2A2A2ULL, 1U, 1U, AERN_FRAG_CHUNK_SIZE + 1U, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, large, AERN_FRAG_CHUNK_SIZE + 1U, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == false);

		route_test_fill_fragment_header(&hdr, 0x9393939393939393ULL, 0xA3A3A3A3A3A3A3A3ULL, 1U, AERN_MAX_FRAGMENTS + 1U, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && aern_fragment_table_add_relay_fragment(&table, &hdr, frag1, AERN_FRAG_CHUNK_SIZE, (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &set, &complete) == false);
	}

	if (large != NULL)
	{
		qsc_memutils_secure_erase(large, AERN_FRAG_CHUNK_SIZE + 1U);
		qsc_memutils_alloc_free(large);
	}

	if (fragshort != NULL)
	{
		qsc_memutils_secure_erase(fragshort, 8U);
		qsc_memutils_alloc_free(fragshort);
	}

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	aern_fragment_table_dispose(&table);

	return res;
}

static bool aern_route_test_fragment_timeout_and_session_cleanup(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_relay_fragment_set_entry entry = { 0 };
	aern_fragment_cache found = { 0 };
	uint32_t removed;
	bool res;

	removed = 0U;
	res = false;
	aern_relay_cache_initialize(&cache);
	aern_fragment_cache_initialize(&found);

	if (cache.initialized == true)
	{
		entry.sessionid = 0x0101010101010101ULL;
		entry.packetid = 0x0202020202020202ULL;
		entry.created = 1U;
		entry.expiry = 1U;
		entry.fragcount = 2U;
		entry.totalsize = (uint32_t)(2U * AERN_FRAG_CHUNK_SIZE);
		entry.direction = (uint8_t)aern_relay_fragment_direction_outbound;
		res = aern_relay_fragment_set_add(&cache, &entry);
		res = (res == true && aern_fragment_table_count(&cache.fragments) == 1U);
		removed = aern_fragment_table_cleanup_expired(&cache.fragments, 2U);
		res = (res == true && removed == 1U && aern_fragment_table_count(&cache.fragments) == 0U && cache.fragments.memoryused == 0U);

		entry.sessionid = 0x0303030303030303ULL;
		entry.packetid = 0x0404040404040404ULL;
		entry.expiry = 1000U;
		res = (res == true && aern_relay_fragment_set_add(&cache, &entry) == true);
		entry.packetid = 0x0505050505050505ULL;
		res = (res == true && aern_relay_fragment_set_add(&cache, &entry) == true);
		res = (res == true && aern_fragment_table_count(&cache.fragments) == 2U);
		removed = aern_fragment_table_remove_session(&cache.fragments, 0x0303030303030303ULL);
		res = (res == true && removed == 2U && aern_fragment_table_count(&cache.fragments) == 0U && cache.fragments.memoryused == 0U);
		res = (res == true && aern_relay_fragment_cache_find(&cache, &found, 0x0303030303030303ULL, 0x0404040404040404ULL, (uint8_t)aern_relay_fragment_direction_outbound) == false);
	}

	aern_fragment_cache_dispose(&found);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool route_test_fragment_wire_make(uint8_t wire[AERN_RELAY_MTU], aern_connection_state* sender, uint64_t sessionid, uint64_t packetid, 
	uint32_t fragseq, uint32_t fragcount, const uint8_t* body, size_t bodylen, uint16_t flags)
{
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	bool res;

	res = false;

	if (wire != NULL && sender != NULL && body != NULL && bodylen != 0U && bodylen <= AERN_RELAY_DATA_PAYLOAD_SIZE)
	{
		header.sessionid = sessionid;
		header.packetid = packetid;
		header.fragseq = fragseq;
		header.fragcount = fragcount;
		header.msglen = (uint32_t)bodylen;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = flags;
		rm.path[0U] = 1U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		res = route_test_wire_make(wire, sender, plaintext);
	}

	qsc_memutils_clear(plaintext, sizeof(plaintext));

	return res;
}


static bool aern_route_test_backend_direct_egress_boundary(void)
{
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	route_test_transport_context exitctx = { 0 };
	uint8_t body[12U] = { 0U };
	aern_protocol_errors err;
	bool res;

	res = false;
	body[0U] = 0xA1U;

	route_test_session_set(&session, 0x1818181818181818ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
	header.sessionid = session.sessionid;
	header.packetid = 0x1818U;
	header.msglen = (uint32_t)sizeof(body);
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

	aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
	err = aern_exit_transport_send_serialized_packet(&session, &header, body, sizeof(body));
	res = (err == aern_protocol_error_none && exitctx.calls == 1U && exitctx.sessionid == session.sessionid &&
		exitctx.payloadtype == (uint8_t)aern_relay_payload_data && exitctx.flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND &&
		exitctx.pktlen == sizeof(body) && exitctx.first == body[0U]);

	if (res == true)
	{
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		err = aern_exit_transport_send_serialized_packet(&session, &header, body, sizeof(body));
		res = (err == aern_protocol_error_invalid_request && exitctx.calls == 1U);
	}

	aern_exit_transport_set_callback(NULL, NULL);

	return res;
}

static bool aern_route_test_backend_direct_ingress_boundary(void)
{
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t body[12U] = { 0U };
	aern_protocol_errors err;
	bool res;

	res = false;
	body[0U] = 0xB1U;

	route_test_session_set(&session, 0x2828282828282828ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
	header.sessionid = session.sessionid;
	header.packetid = 0x2828U;
	header.msglen = (uint32_t)sizeof(body);
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;

	aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);
	err = aern_ingress_transport_send_serialized_packet(&session, &header, body, sizeof(body));
	res = (err == aern_protocol_error_none && ingressctx.calls == 1U && ingressctx.sessionid == session.sessionid &&
		ingressctx.payloadtype == (uint8_t)aern_relay_payload_data && ingressctx.flags == AERN_RELAY_PAYLOAD_FLAG_RETURN &&
		ingressctx.pktlen == sizeof(body) && ingressctx.first == body[0U]);

	if (res == true)
	{
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		err = aern_ingress_transport_send_serialized_packet(&session, &header, body, sizeof(body));
		res = (err == aern_protocol_error_invalid_request && ingressctx.calls == 1U);
	}

	aern_ingress_transport_set_callback(NULL, NULL);

	return res;
}

static bool aern_route_test_backend_missing_callback_policy(void)
{
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	uint8_t body[8U] = { 0U };
	aern_protocol_errors err;
	bool res;

	res = false;
	body[0U] = 0xC1U;

	route_test_session_set(&session, 0x3838383838383838ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
	header.sessionid = session.sessionid;
	header.packetid = 0x3838U;
	header.msglen = (uint32_t)sizeof(body);
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

	aern_exit_transport_set_callback(NULL, NULL);
	err = aern_exit_transport_send_serialized_packet(&session, &header, body, sizeof(body));
	res = (err == aern_protocol_error_operation_cancelled);

	if (res == true)
	{
		route_test_session_set(&session, 0x4848484848484848ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		header.sessionid = session.sessionid;
		header.packetid = 0x4848U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		aern_ingress_transport_set_callback(NULL, NULL);
		err = aern_ingress_transport_send_serialized_packet(&session, &header, body, sizeof(body));
		res = (err == aern_protocol_error_operation_cancelled);
	}

	return res;
}

static bool aern_route_test_backend_failure_status_propagation(void)
{
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t body[8U] = { 0U };
	aern_protocol_errors err;
	bool res;

	res = false;
	body[0U] = 0xD1U;

	route_test_session_set(&session, 0x5858585858585858ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
	header.sessionid = session.sessionid;
	header.packetid = 0x5858U;
	header.msglen = (uint32_t)sizeof(body);
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
	exitctx.result = aern_protocol_error_transmit_failure;
	aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
	err = aern_exit_transport_send_serialized_packet(&session, &header, body, sizeof(body));
	res = (err == aern_protocol_error_transmit_failure && exitctx.calls == 1U);

	if (res == true)
	{
		route_test_session_set(&session, 0x6868686868686868ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		header.sessionid = session.sessionid;
		header.packetid = 0x6868U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		ingressctx.result = aern_protocol_error_transmit_failure;
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);
		err = aern_ingress_transport_send_serialized_packet(&session, &header, body, sizeof(body));
		res = (err == aern_protocol_error_transmit_failure && ingressctx.calls == 1U);
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	return res;
}

static bool aern_route_test_backend_error_and_dummy_no_delivery(void)
{
	aern_relay_payload_header header = { 0 };
	uint8_t body[8U] = { 0 };
	uint32_t exitcalls;
	uint32_t ingresscalls;
	bool res;

	res = false;
	body[0U] = 0xE1U;

	header.sessionid = 0x7878787878787878ULL;
	header.packetid = 0U;
	header.msglen = 0U;
	header.payloadtype = (uint8_t)aern_relay_payload_error;
	header.flags = 0U;
	res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_invalid_request, &exitcalls, &ingresscalls);
	res = (res == true && exitcalls == 0U && ingresscalls == 0U);

	if (res == true)
	{
		header.sessionid = 0U;
		header.packetid = 0U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_dummy;
		header.flags = 0U;
		res = route_test_terminal_header_process(&header, body, false, aern_protocol_error_none, &exitcalls, &ingresscalls);
		res = (res == true && exitcalls == 0U && ingresscalls == 0U);
	}

	return res;
}

static bool aern_route_test_backend_return_injection_no_tunnel_failure(void)
{
	aern_forward_state fwd = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	uint8_t body[16U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;
	body[0U] = 0xF1U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		fwd.ownhint = 3U;
		fwd.own_address = "10.0.0.3";
		route_test_session_set(&session, 0x8888888888888888ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.ingresshint = 1U;
		session.egresshint = 3U;
		(void)aern_relay_session_add(cache, &session);

		err = aern_exit_transport_return_serialized_packet(&fwd, &session, body, sizeof(body));
		res = (err == aern_protocol_error_channel_down || err == aern_protocol_error_node_not_found || err == aern_protocol_error_connection_failure);
		res = (res == true && aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true);
		res = (res == true && found.rxcount == 0U && found.rxfail == 1U);
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_fragment_terminal_backend_once(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_cache_entry found = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t wire1[AERN_RELAY_MTU] = { 0U };
	uint8_t wire2[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint8_t* frag1;
	uint8_t* frag2;
	size_t finallen;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	frag1 = NULL;
	frag2 = NULL;
	finallen = 23U;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, finallen, 2U) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 31U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xD1D2D3D4D5D6D7D8ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		(void)aern_relay_session_add(cache, &session);
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		res = route_test_fragment_wire_make(wire1, &sender, session.sessionid, 0x0102030405060708ULL, 1U, 2U, frag1, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && route_test_fragment_wire_make(wire2, &sender, session.sessionid, 0x0102030405060708ULL, 2U, 2U, frag2, finallen, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND) == true);

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire1, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 0U && ingressctx.calls == 0U);
			res = (res == true && aern_fragment_table_count(&cache->fragments) == 1U);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire2, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 1U && ingressctx.calls == 0U);
			res = (res == true && exitctx.sessionid == session.sessionid && exitctx.payloadtype == (uint8_t)aern_relay_payload_data);
			res = (res == true && exitctx.flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND && exitctx.pktlen == (AERN_FRAG_CHUNK_SIZE + finallen));
			res = (res == true && exitctx.first == route_test_fragment_byte(1U, 0U));
			res = (res == true && aern_fragment_table_count(&cache->fragments) == 0U && cache->fragments.memoryused == 0U);
			res = (res == true && aern_relay_session_find(cache, &found, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true && found.txcount == 1U && found.txfail == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, finallen);
		qsc_memutils_alloc_free(frag2);
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_dummy_traffic_policy_bounds(void)
{
	aern_relay_cache_state cache;
	uint64_t nowms;
	bool res;

	qsc_memutils_clear(&cache, sizeof(cache));
	res = false;
	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true)
	{
		nowms = qsc_timestamp_epochtime_milliseconds();
		cache.nextdummyms = nowms;
		cache.dummywindowms = nowms;
		cache.dummywindowcount = 0U;
		cache.dummysuppressed = false;

		res = (route_dummy_traffic_allowed(&cache, 0U, nowms) == true);

		cache.dummywindowcount = AERN_DUMMY_TRAFFIC_MAXIMUM_PER_WINDOW;
		res = (res == true && route_dummy_traffic_allowed(&cache, 0U, nowms) == false);

		cache.dummywindowcount = 0U;
		cache.nextdummyms = nowms + 1000U;
		res = (res == true && route_dummy_traffic_allowed(&cache, 0U, nowms) == false);

		cache.nextdummyms = nowms;
		res = (res == true && route_dummy_traffic_allowed(&cache, AERN_DUMMY_TRAFFIC_BANDWIDTH_CEILING_PERCENT, nowms) == false);
		res = (res == true && cache.dummysuppressed == true);

		res = (res == true && route_dummy_traffic_allowed(&cache, AERN_DUMMY_TRAFFIC_BANDWIDTH_FLOOR_PERCENT, nowms) == true);
		res = (res == true && cache.dummysuppressed == false);

		cache.dummywindowms = nowms - ((uint64_t)AERN_RELAY_TRAFFIC_WINDOW_MILLISECONDS + 1U);
		cache.dummywindowcount = AERN_DUMMY_TRAFFIC_MAXIMUM_PER_WINDOW;
		res = (res == true && route_dummy_traffic_allowed(&cache, 0U, nowms) == true);
		res = (res == true && cache.dummywindowcount == 0U);
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_relay_traffic_utilization_counters(void)
{
	aern_relay_cache_state cache = { 0 };
	uint32_t util;
	bool res;

	res = false;
	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true)
	{
		res = (aern_relay_traffic_utilization(&cache) == 0U);
		aern_relay_traffic_observe(&cache, AERN_RELAY_MTU, false);
		aern_relay_traffic_observe(&cache, AERN_RELAY_MTU, true);
		util = aern_relay_traffic_utilization(&cache);
		res = (res == true && cache.relaytxbytes == AERN_RELAY_MTU);
		res = (res == true && cache.relayrxbytes == AERN_RELAY_MTU);
		res = (res == true && util != 0U && util < 100U);

		cache.relaytxbytes = AERN_DUMMY_TRAFFIC_WINDOW_TARGET_BYTES * 2U;
		cache.relayrxbytes = AERN_DUMMY_TRAFFIC_WINDOW_TARGET_BYTES;
		res = (res == true && aern_relay_traffic_utilization(&cache) == 100U);
	}

	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_dummy_generation_suppressed_policy(void)
{
	aern_forward_state fwd = { 0 };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint64_t nowms;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		nowms = qsc_timestamp_epochtime_milliseconds();
		cache->nextdummyms = nowms;
		cache->dummywindowms = nowms;
		cache->dummywindowcount = 0U;
		cache->dummysuppressed = false;

		res = (aern_dummy_traffic_generate(&fwd, AERN_DUMMY_TRAFFIC_BANDWIDTH_CEILING_PERCENT) == aern_protocol_error_none);
		res = (res == true && cache->dummysuppressed == true);
		res = (res == true && cache->dummysent == 0U);
		res = (res == true && cache->dummywindowcount == 0U);

		cache->dummysuppressed = false;
		cache->dummywindowcount = AERN_DUMMY_TRAFFIC_MAXIMUM_PER_WINDOW;
		res = (res == true && aern_dummy_traffic_generate(&fwd, 0U) == aern_protocol_error_none);
		res = (res == true && cache->dummysent == 0U);
		res = (res == true && cache->dummywindowcount == AERN_DUMMY_TRAFFIC_MAXIMUM_PER_WINDOW);
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_ingress_delay_expired_item_cleanup(void)
{
	aern_forward_state fwd = { 0 };
	aern_ingress_pending_item item = { 0 };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint64_t nowsec;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true &&
		route_test_fill_allocated_packet(&item, 32U, 0x19191919ULL, 1U, 0x19U) == true)
	{
		nowsec = qsc_timestamp_datetime_utc();
		item.expiry = nowsec - 1U;
		item.delayuntil = 0U;
		res = (aern_relay_delay_push(cache, &item) == true);
		res = (res == true && aern_ingress_delay_flush(&fwd) == aern_protocol_error_none);
		res = (res == true && aern_relayqueue_is_empty(&cache->delayqueue) == true);
	}

	aern_relayqueue_item_dispose(&item);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_dummy_terminal_no_session_state(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[AERN_RELAY_DATA_PAYLOAD_SIZE] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 0x19U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);

		rm.path[0U] = 1U;
		header.sessionid = 0x1919191919191919ULL;
		header.packetid = 0x2929292929292929ULL;
		header.msglen = AERN_RELAY_DATA_PAYLOAD_SIZE;
		header.payloadtype = (uint8_t)aern_relay_payload_dummy;
		header.reserved = 0U;
		header.flags = 0U;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true &&
			aern_packet_forward(&fwd, wire, "10.0.0.2") == aern_protocol_error_none)
		{
			res = (exitctx.calls == 0U && ingressctx.calls == 0U);
			res = (res == true && cache->dummydropped == 1U);
			res = (res == true && aern_relay_session_exists(cache, header.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false &&
				aern_relay_session_exists(cache, header.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == false);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);
	return res;
}

static bool aern_route_test_failure_route_parse_no_backend_mutation(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	uint32_t scount;
	uint32_t pcount;
	uint32_t dcount;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	scount = 0U;
	pcount = 0U;
	dcount = 0U;
	res = false;
	body[0U] = 0xA1U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 41U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x21210001ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		header.sessionid = session.sessionid;
		header.packetid = 1U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

		rm.path[0U] = 0U;
		scount = aern_relaysession_count(&cache->sessions);
		pcount = aern_relayqueue_count(&cache->pendingqueue);
		dcount = aern_relayqueue_count(&cache->delayqueue);
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_packet_header_invalid &&
				exitctx.calls == 0U && ingressctx.calls == 0U &&
				aern_relaysession_count(&cache->sessions) == scount &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount &&
				aern_relayqueue_count(&cache->delayqueue) == dcount);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_failure_invalid_future_hint_no_backend_mutation(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	uint32_t scount;
	uint32_t pcount;
	uint32_t dcount;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	scount = 0U;
	pcount = 0U;
	dcount = 0U;
	res = false;
	body[0U] = 0xA4U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 45U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x21210005ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		header.sessionid = session.sessionid;
		header.packetid = 5U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

		rm.path[0U] = 1U;
		rm.path[1U] = (uint8_t)(fwd.apscount + 1U);
		scount = aern_relaysession_count(&cache->sessions);
		pcount = aern_relayqueue_count(&cache->pendingqueue);
		dcount = aern_relayqueue_count(&cache->delayqueue);
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_packet_header_invalid &&
				exitctx.calls == 0U && ingressctx.calls == 0U &&
				aern_relaysession_count(&cache->sessions) == scount &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount &&
				aern_relayqueue_count(&cache->delayqueue) == dcount);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_failure_payload_header_no_backend_mutation(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	uint32_t scount;
	uint32_t pcount;
	uint32_t dcount;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	scount = 0U;
	pcount = 0U;
	dcount = 0U;
	res = false;
	body[0U] = 0xA2U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 44U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x21210004ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		header.sessionid = session.sessionid;
		header.packetid = 4U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 1U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;

		scount = aern_relaysession_count(&cache->sessions);
		pcount = aern_relayqueue_count(&cache->pendingqueue);
		dcount = aern_relayqueue_count(&cache->delayqueue);
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_packet_header_invalid &&
				exitctx.calls == 0U && ingressctx.calls == 0U &&
				aern_relaysession_count(&cache->sessions) == scount &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount &&
				aern_relayqueue_count(&cache->delayqueue) == dcount);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_failure_missing_peer_no_backend_or_queue_mutation(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	uint32_t pcount;
	uint32_t dcount;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	pcount = 0U;
	dcount = 0U;
	res = false;
	body[0U] = 0xB1U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 42U);
		(void)aern_cipher_table_add(ctable, "10.0.0.3", &receiver);

		rm.path[0U] = 1U;
		rm.path[1U] = 2U;
		header.sessionid = 0x21210002ULL;
		header.packetid = 2U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		pcount = aern_relayqueue_count(&cache->pendingqueue);
		dcount = aern_relayqueue_count(&cache->delayqueue);
		route_test_plaintext_make(plaintext, &rm, &header, body);

		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.3");
			res = (err == aern_protocol_error_channel_down &&
				exitctx.calls == 0U && ingressctx.calls == 0U &&
				aern_relayqueue_count(&cache->pendingqueue) == pcount &&
				aern_relayqueue_count(&cache->delayqueue) == dcount);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_failure_backend_error_preserves_session_state(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0xC1U;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 43U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0x21210003ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		(void)aern_relay_session_add(cache, &session);

		rm.path[0U] = 1U;
		header.sessionid = session.sessionid;
		header.packetid = 3U;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		exitctx.result = aern_protocol_error_transmit_failure;
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_transmit_failure && exitctx.calls == 1U &&
				aern_relaysession_count(&cache->sessions) == 1U &&
				aern_relayqueue_count(&cache->pendingqueue) == 0U &&
				aern_fragment_table_count(&cache->fragments) == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_failure_cache_cleanup_removes_expired_runtime_state(void)
{
	aern_relay_cache_state cache = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_ingress_pending_item pending = { 0 };
	aern_ingress_pending_item delayed = { 0 };
	aern_fragment_cache* frag;
	uint64_t tnow;
	bool res;

	frag = NULL;
	tnow = qsc_timestamp_datetime_utc();
	res = false;

	aern_relay_cache_initialize(&cache);

	if (cache.initialized == true)
	{
		route_test_session_set(&session, 0x21210004ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.expiry = tnow - 1U;
		res = aern_relay_session_add(&cache, &session);

		if (res == true)
		{
			frag = aern_fragment_table_get_or_add(&cache.fragments, 0x21210004ULL, 1U, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND, 2U, tnow - 1U, 64U);
			res = (frag != NULL);
		}

		if (res == true)
		{
			res = route_test_fill_allocated_packet(&pending, 16U, 0x21210004ULL, 2U, 0xD1U);
		}

		if (res == true)
		{
			pending.expiry = tnow - 1U;
			res = aern_relay_pending_push(&cache, &pending);
		}

		if (res == true)
		{
			res = route_test_fill_allocated_packet(&delayed, 16U, 0x21210005ULL, 3U, 0xD2U);
		}

		if (res == true)
		{
			delayed.expiry = tnow - 1U;
			delayed.delayuntil = 0U;
			res = aern_relay_delay_push(&cache, &delayed);
		}

		if (res == true)
		{
			res = (aern_relaysession_count(&cache.sessions) == 1U &&
				aern_fragment_table_count(&cache.fragments) == 1U &&
				aern_relayqueue_count(&cache.pendingqueue) == 1U &&
				aern_relayqueue_count(&cache.delayqueue) == 1U);
		}

		if (res == true)
		{
			aern_relay_cache_cleanup(&cache);
			res = (aern_relaysession_count(&cache.sessions) == 0U &&
				aern_fragment_table_count(&cache.fragments) == 0U &&
				aern_relayqueue_count(&cache.pendingqueue) == 0U &&
				aern_relayqueue_count(&cache.delayqueue) == 0U);
		}
	}

	aern_relayqueue_item_dispose(&pending);
	aern_relayqueue_item_dispose(&delayed);
	aern_relay_cache_dispose(&cache);

	return res;
}

static bool aern_route_test_fragment_forwarding_out_of_order_delivery(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t wire1[AERN_RELAY_MTU] = { 0U };
	uint8_t wire2[AERN_RELAY_MTU] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint8_t* frag1;
	uint8_t* frag2;
	size_t finallen;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	frag1 = NULL;
	frag2 = NULL;
	finallen = 37U;
	err = aern_protocol_error_none;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true &&
		route_test_fill_numbered_fragment(&frag1, AERN_FRAG_CHUNK_SIZE, 1U) == true &&
		route_test_fill_numbered_fragment(&frag2, finallen, 2U) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 51U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xF1F2F3F4F5F6F7F8ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		(void)aern_relay_session_add(cache, &session);
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		res = route_test_fragment_wire_make(wire1, &sender, session.sessionid, 0x1112131415161718ULL, 2U, 2U, frag2, finallen, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		res = (res == true && route_test_fragment_wire_make(wire2, &sender, session.sessionid, 0x1112131415161718ULL, 1U, 2U, frag1, AERN_FRAG_CHUNK_SIZE, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND) == true);

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire1, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 0U && ingressctx.calls == 0U);
			res = (res == true && aern_fragment_table_count(&cache->fragments) == 1U);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire2, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 1U && ingressctx.calls == 0U);
			res = (res == true && exitctx.sessionid == session.sessionid && exitctx.pktlen == (AERN_FRAG_CHUNK_SIZE + finallen));
			res = (res == true && exitctx.first == route_test_fragment_byte(1U, 0U));
			res = (res == true && aern_fragment_table_count(&cache->fragments) == 0U && cache->fragments.memoryused == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	if (frag1 != NULL)
	{
		qsc_memutils_secure_erase(frag1, AERN_FRAG_CHUNK_SIZE);
		qsc_memutils_alloc_free(frag1);
	}

	if (frag2 != NULL)
	{
		qsc_memutils_secure_erase(frag2, finallen);
		qsc_memutils_alloc_free(frag2);
	}

	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_fragment_forwarding_invalid_short_nonfinal_no_delivery(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[8U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0x5AU;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 52U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xE1E2E3E4E5E6E7E8ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		(void)aern_relay_session_add(cache, &session);
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (route_test_fragment_wire_make(wire, &sender, session.sessionid, 0x2122232425262728ULL, 1U, 2U, body, sizeof(body), AERN_RELAY_PAYLOAD_FLAG_OUTBOUND) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 0U && ingressctx.calls == 0U);
			res = (res == true && aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_active_session_revocation_forwarding_drop(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[16U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	err = aern_protocol_error_none;
	res = false;
	body[0U] = 0x6AU;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 53U);
		(void)aern_cipher_table_add(ctable, "10.0.0.2", &receiver);
		route_test_session_set(&session, 0xD1D2D3D4D5D6D7D8ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
		(void)aern_relay_session_add(cache, &session);
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		rm.path[0U] = 1U;
		header.sessionid = session.sessionid;
		header.packetid = 0x3132333435363738ULL;
		header.msglen = (uint32_t)sizeof(body);
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		route_test_plaintext_make(plaintext, &rm, &header, body);

		if (route_test_wire_make(wire, &sender, plaintext) == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 1U && ingressctx.calls == 0U);
		}

		if (res == true)
		{
			aern_relay_session_remove(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS);
			header.packetid = 0x4142434445464748ULL;
			body[0U] = 0x6BU;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			res = route_test_wire_make(wire, &sender, plaintext);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err == aern_protocol_error_none && exitctx.calls == 1U && ingressctx.calls == 0U);
			res = (res == true && aern_relay_session_exists(cache, session.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == false);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

static bool aern_route_test_route_domain_boundary_counts(void)
{
	aern_route_map rm = { 0 };
	uint8_t counts[2U] = { 0U };
	uint8_t ci;
	uint8_t i;
	uint8_t last;
	uint8_t active;
	aern_protocol_errors err;
	bool res;

	counts[0U] = 254U;
	counts[1U] = 255U;
	res = true;

	for (ci = 0U; ci < 2U && res == true; ++ci)
	{
		qsc_memutils_clear(&rm, sizeof(rm));
		err = aern_route_generate(&rm, counts[ci], 1U, counts[ci]);
		res = (err == aern_protocol_error_none);
		res = (res == true && rm.path[0U] == 1U);
		res = (res == true && rm.hopcount >= AERN_ROUTE_MIN_HOPS && rm.hopcount <= AERN_ROUTE_PATH_SIZE);

		last = 0U;
		active = 0U;

		for (i = 0U; i < AERN_ROUTE_PATH_SIZE && res == true; ++i)
		{
			if (rm.path[i] != 0U)
			{
				res = (rm.path[i] <= counts[ci]);
				res = (res == true && (last == 0U || last != rm.path[i]));
				last = rm.path[i];
				++active;

				if (i != 0U && i != (uint8_t)(rm.hopcount - 1U))
				{
					res = (res == true && rm.path[i] != 1U && rm.path[i] != counts[ci]);
				}
			}
		}

		res = (res == true && active == rm.hopcount);
		res = (res == true && rm.path[rm.hopcount - 1U] == counts[ci]);
	}

	if (res == true)
	{
		qsc_memutils_clear(&rm, sizeof(rm));
		err = aern_route_generate(&rm, 2U, 1U, 2U);
		res = (err != aern_protocol_error_none);
	}

	if (res == true)
	{
		qsc_memutils_clear(&rm, sizeof(rm));
		err = aern_route_generate(&rm, 255U, 0U, 255U);
		res = (err != aern_protocol_error_none);
	}

	if (res == true)
	{
		qsc_memutils_clear(&rm, sizeof(rm));
		err = aern_route_generate(&rm, 255U, 1U, 0U);
		res = (err != aern_protocol_error_none);
	}

	if (res == true)
	{
		qsc_memutils_clear(&rm, sizeof(rm));
		err = aern_route_generate(&rm, 255U, 1U, 1U);
		res = (err != aern_protocol_error_none);
	}

	return res;
}

static bool aern_route_test_backend_bounded_load_profile(void)
{
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t body[32U] = { 0U };
	uint32_t i;
	aern_protocol_errors err;
	bool res;

	res = true;

	aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
	aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

	route_test_session_set(&session, 0x5151515151515151ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
	header.sessionid = session.sessionid;
	header.payloadtype = (uint8_t)aern_relay_payload_data;
	header.reserved = 0U;
	header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
	header.msglen = (uint32_t)sizeof(body);

	for (i = 0U; i < 64U && res == true; ++i)
	{
		body[0U] = (uint8_t)i;
		header.packetid = (uint64_t)(0x61000000UL + i);
		err = aern_exit_transport_send_serialized_packet(&session, &header, body, sizeof(body));
		res = (err == aern_protocol_error_none);
	}

	res = (res == true && exitctx.calls == 64U && exitctx.sessionid == session.sessionid && exitctx.pktlen == sizeof(body));

	if (res == true)
	{
		route_test_session_set(&session, 0x5252525252525252ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		header.sessionid = session.sessionid;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;

		for (i = 0U; i < 64U && res == true; ++i)
		{
			body[0U] = (uint8_t)(0x80U + i);
			header.packetid = (uint64_t)(0x62000000UL + i);
			err = aern_ingress_transport_send_serialized_packet(&session, &header, body, sizeof(body));
			res = (err == aern_protocol_error_none);
		}
	}

	res = (res == true && ingressctx.calls == 64U && ingressctx.sessionid == session.sessionid && ingressctx.pktlen == sizeof(body));

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	return res;
}

static bool aern_route_test_encrypted_terminal_load_profile(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[48U] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	uint32_t i;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 21U);
		res = (aern_cipher_table_add(ctable, "10.0.0.2", &receiver) == aern_protocol_error_none);
		rm.path[0U] = 1U;
		rm.hopcount = 1U;
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		if (res == true)
		{
			route_test_session_set(&session, 0x6363636363636363ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, AERN_RELAY_PAYLOAD_FLAG_OUTBOUND);
			res = aern_relay_session_add(cache, &session);
		}

		if (res == true)
		{
			header.sessionid = session.sessionid;
			header.payloadtype = (uint8_t)aern_relay_payload_data;
			header.reserved = 0U;
			header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
			header.msglen = (uint32_t)sizeof(body);

			for (i = 0U; i < 32U && res == true; ++i)
			{
				body[0U] = (uint8_t)i;
				header.packetid = (uint64_t)(0x71000000UL + i);
				route_test_plaintext_make(plaintext, &rm, &header, body);
				res = route_test_wire_make(wire, &sender, plaintext);

				if (res == true)
				{
					err = aern_packet_forward(&fwd, wire, "10.0.0.2");
					res = (err == aern_protocol_error_none);
				}
			}
		}

		res = (res == true && exitctx.calls == 32U && exitctx.sessionid == session.sessionid && exitctx.pktlen == sizeof(body) && exitctx.first == 31U);

		if (res == true)
		{
			aern_relay_cache_dispose(cache);
			aern_relay_cache_initialize(cache);
			qsc_memutils_clear(&session, sizeof(session));
			route_test_session_set(&session, 0x6464646464646464ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
			res = aern_relay_session_add(cache, &session);
		}

		if (res == true)
		{
			header.sessionid = session.sessionid;
			header.payloadtype = (uint8_t)aern_relay_payload_data;
			header.reserved = 0U;
			header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
			header.msglen = (uint32_t)sizeof(body);

			for (i = 0U; i < 32U && res == true; ++i)
			{
				body[0U] = (uint8_t)(0x80U + i);
				header.packetid = (uint64_t)(0x72000000UL + i);
				route_test_plaintext_make(plaintext, &rm, &header, body);
				res = route_test_wire_make(wire, &sender, plaintext);

				if (res == true)
				{
					err = aern_packet_forward(&fwd, wire, "10.0.0.2");
					res = (err == aern_protocol_error_none);
				}
			}
		}

		res = (res == true && ingressctx.calls == 32U && ingressctx.sessionid == session.sessionid && ingressctx.pktlen == sizeof(body) && ingressctx.first == (uint8_t)(0x80U + 31U));
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}


static bool aern_route_test_multihop_full_4aps_profiles(void)
{
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	aern_connection_state* sender = { 0 };
	uint8_t body[AERN_RELAY_DATA_PAYLOAD_SIZE] = { 0U };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	route_test_multihop_context* ctx;
	uint32_t i;
	uint32_t expectedexit;
	uint32_t expectedingress;
	bool res;

	ctx = (route_test_multihop_context*)qsc_memutils_malloc(sizeof(route_test_multihop_context));
	res = (ctx != NULL);
	expectedexit = 0U;
	expectedingress = 0U;

	if (res == true)
	{
		res = route_test_multihop_initialize(ctx);
	}

	if (res == true)
	{
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		route_test_session_set(&session, 0x0A0B0C0D0E0F0001ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[3U], &session);
	}

	if (res == true)
	{
		route_test_session_set(&session, 0x0A0B0C0D0E0F0002ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[0U], &session);
	}

	if (res == true)
	{
		/* Outbound profile: APS-1 -> APS-2 -> APS-3 -> APS-4 terminal egress. */
		header.sessionid = 0x0A0B0C0D0E0F0001ULL;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = 80U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;

		for (i = 0U; i < 24U && res == true; ++i)
		{
			body[0U] = (uint8_t)(0x20U + i);
			body[1U] = (uint8_t)(i ^ 0x5AU);
			header.packetid = 0x1010000000000000ULL + i;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
			res = (sender != NULL);

			if (res == true)
			{
				res = route_test_wire_make(wire, sender, plaintext);
			}

			if (res == true)
			{
				res = (route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);
			}
		}

		expectedexit += 24U;
		res = (res == true && exitctx.calls == expectedexit && exitctx.first == (uint8_t)(0x20U + 23U));
	}

	if (res == true)
	{
		/* return profile: APS-4 -> APS-3 -> APS-2 -> APS-1 terminal ingress. */
		header.sessionid = 0x0A0B0C0D0E0F0002ULL;
		header.fragseq = 0U;
		header.fragcount = 0U;
		header.msglen = 72U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
		qsc_memutils_clear(&rm, sizeof(rm));
		rm.path[0U] = 4U;
		rm.path[1U] = 2U;
		rm.path[2U] = 1U;
		rm.hopcount = 3U;

		for (i = 0U; i < 24U && res == true; ++i)
		{
			body[0U] = (uint8_t)(0x60U + i);
			body[1U] = (uint8_t)(i ^ 0xA5U);
			header.packetid = 0x2020000000000000ULL + i;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[3U], ctx->address[2U]);
			res = (sender != NULL);

			if (res == true)
			{
				res = route_test_wire_make(wire, sender, plaintext);
			}

			if (res == true)
			{
				res = (route_test_multihop_drive(ctx, 2U, 3U, wire) == aern_protocol_error_none);
			}
		}

		expectedingress += 24U;
		res = (res == true && ingressctx.calls == expectedingress && ingressctx.first == (uint8_t)(0x60U + 23U));
	}

	if (res == true)
	{
		/* mixed bidirectional profile across the same four APS fabric. */
		for (i = 0U; i < 16U && res == true; ++i)
		{
			header.sessionid = 0x0A0B0C0D0E0F0001ULL;
			header.packetid = 0x3030000000000000ULL + i;
			header.fragseq = 0U;
			header.fragcount = 0U;
			header.msglen = 64U;
			header.payloadtype = (uint8_t)aern_relay_payload_data;
			header.reserved = 0U;
			header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
			qsc_memutils_clear(&rm, sizeof(rm));
			rm.path[0U] = 1U;
			rm.path[1U] = 3U;
			rm.path[2U] = 4U;
			rm.hopcount = 3U;
			body[0U] = (uint8_t)(0x90U + i);
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
			res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
				route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);

			if (res == true)
			{
				header.sessionid = 0x0A0B0C0D0E0F0002ULL;
				header.packetid = 0x4040000000000000ULL + i;
				header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
				qsc_memutils_clear(&rm, sizeof(rm));
				rm.path[0U] = 4U;
				rm.path[1U] = 2U;
				rm.path[2U] = 1U;
				rm.hopcount = 3U;
				body[0U] = (uint8_t)(0xB0U + i);
				route_test_plaintext_make(plaintext, &rm, &header, body);
				sender = aern_cipher_table_get_by_ip(&ctx->ctable[3U], ctx->address[2U]);
				res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
					route_test_multihop_drive(ctx, 2U, 3U, wire) == aern_protocol_error_none);
			}
		}

		expectedexit += 16U;
		expectedingress += 16U;
		res = (res == true && exitctx.calls == expectedexit && ingressctx.calls == expectedingress);
		res = (res == true && exitctx.first == (uint8_t)(0x90U + 15U) && ingressctx.first == (uint8_t)(0xB0U + 15U));
	}

	if (res == true)
	{
		/* Large fragmented outbound payload across the complete multi-hop path. */
		header.sessionid = 0x0A0B0C0D0E0F0001ULL;
		header.packetid = 0x5050000000000000ULL;
		header.fragcount = 2U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.reserved = 0U;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		qsc_memutils_clear(&rm, sizeof(rm));
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;

		for (i = 0U; i < AERN_RELAY_DATA_PAYLOAD_SIZE; ++i)
		{
			body[i] = route_test_fragment_byte(1U, i);
		}

		header.fragseq = 1U;
		header.msglen = AERN_RELAY_DATA_PAYLOAD_SIZE;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
			route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);
		res = (res == true && exitctx.calls == expectedexit);

		if (res == true)
		{
			for (i = 0U; i < 96U; ++i)
			{
				body[i] = route_test_fragment_byte(2U, i);
			}

			header.fragseq = 2U;
			header.msglen = 96U;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
			res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
				route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);
		}

		expectedexit += 1U;
		res = (res == true && exitctx.calls == expectedexit && exitctx.sessionid == header.sessionid &&
			exitctx.pktlen == (AERN_RELAY_DATA_PAYLOAD_SIZE + 96U) && exitctx.first == route_test_fragment_byte(1U, 0U));
		res = (res == true && aern_fragment_table_count(&ctx->cache[3U].fragments) == 0U);
	}

	res = (res == true && ctx->failures == 0U && ctx->dispatches >= 162U);

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	if (ctx != NULL)
	{
		route_test_multihop_dispose(ctx);
		qsc_memutils_alloc_free(ctx);
	}

	return res;
}

static bool aern_route_test_extended_multihop_stress_attack_campaign(void)
{
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_route_map rm = { 0 };
	uint8_t body[AERN_RELAY_DATA_PAYLOAD_SIZE] = { 0U };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t good[AERN_RELAY_MTU] = { 0U };
	route_test_multihop_context* ctx;
	aern_connection_state* sender;
	uint32_t i;
	uint32_t expectedexit;
	uint32_t expectedingress;
	uint32_t failures;
	bool res;

	ctx = (route_test_multihop_context*)qsc_memutils_malloc(sizeof(route_test_multihop_context));
	res = (ctx != NULL);
	expectedexit = 0U;
	expectedingress = 0U;
	failures = 0U;

	if (res == true)
	{
		res = route_test_multihop_initialize(ctx);
	}

	if (res == true)
	{
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);

		route_test_session_set(&session, 0x1111222233334444ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[3U], &session);
	}

	if (res == true)
	{
		route_test_session_set(&session, 0x5555666677778888ULL, AERN_RELAY_SESSION_CONTEXT_INGRESS, AERN_RELAY_PAYLOAD_FLAG_RETURN);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[0U], &session);
	}

	if (res == true)
	{
		/* bounded outbound and return stress profile through the four-APS encrypted path. */
		for (i = 0U; i < 64U && res == true; ++i)
		{
			qsc_memutils_clear(&header, sizeof(header));
			qsc_memutils_clear(&rm, sizeof(rm));
			body[0U] = (uint8_t)(i + 1U);
			body[1U] = (uint8_t)(i ^ 0xC3U);
			header.sessionid = 0x1111222233334444ULL;
			header.packetid = 0x6100000000000000ULL + i;
			header.msglen = 96U;
			header.payloadtype = (uint8_t)aern_relay_payload_data;
			header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
			rm.path[0U] = 1U;
			rm.path[1U] = 3U;
			rm.path[2U] = 4U;
			rm.hopcount = 3U;
			route_test_plaintext_make(plaintext, &rm, &header, body);
			sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
			res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
				route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);

			if (res == true)
			{
				qsc_memutils_clear(&header, sizeof(header));
				qsc_memutils_clear(&rm, sizeof(rm));
				body[0U] = (uint8_t)(0x80U + i);
				body[1U] = (uint8_t)(i ^ 0x3CU);
				header.sessionid = 0x5555666677778888ULL;
				header.packetid = 0x6200000000000000ULL + i;
				header.msglen = 88U;
				header.payloadtype = (uint8_t)aern_relay_payload_data;
				header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;
				rm.path[0U] = 4U;
				rm.path[1U] = 2U;
				rm.path[2U] = 1U;
				rm.hopcount = 3U;
				route_test_plaintext_make(plaintext, &rm, &header, body);
				sender = aern_cipher_table_get_by_ip(&ctx->ctable[3U], ctx->address[2U]);
				res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
					route_test_multihop_drive(ctx, 2U, 3U, wire) == aern_protocol_error_none);
			}
		}

		expectedexit += 64U;
		expectedingress += 64U;
		res = (res == true && exitctx.calls == expectedexit && ingressctx.calls == expectedingress);
	}

	if (res == true)
	{
		/* corrupted ciphertext must fail authentication without poisoning the first-hop tunnel state. */
		qsc_memutils_clear(&header, sizeof(header));
		qsc_memutils_clear(&rm, sizeof(rm));
		body[0U] = 0xA1U;
		header.sessionid = 0x1111222233334444ULL;
		header.packetid = 0x6300000000000000ULL;
		header.msglen = 32U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		res = (sender != NULL && route_test_wire_make(good, sender, plaintext) == true);
		qsc_memutils_copy(wire, good, sizeof(wire));
		wire[AERN_RELAY_HEADER_SIZE + 17U] ^= 0x5AU;

		if (res == true)
		{
			res = (route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_authentication_failure);
			res = (res == true && exitctx.calls == expectedexit && ingressctx.calls == expectedingress);
		}

		if (res == true)
		{
			res = (route_test_multihop_drive(ctx, 1U, 0U, good) == aern_protocol_error_none);
			expectedexit += 1U;
			res = (res == true && exitctx.calls == expectedexit);
		}
	}

	if (res == true)
	{
		/* invalid future-hop hint is rejected before backend delivery. */
		qsc_memutils_clear(&header, sizeof(header));
		qsc_memutils_clear(&rm, sizeof(rm));
		body[0U] = 0xB2U;
		header.sessionid = 0x1111222233334444ULL;
		header.packetid = 0x6400000000000000ULL;
		header.msglen = 32U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 5U;
		rm.hopcount = 2U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		failures = ctx->failures;
		res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
			route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_node_not_found);
		res = (res == true && ctx->failures == failures + 1U && exitctx.calls == expectedexit && ingressctx.calls == expectedingress);
	}

	if (res == true)
	{
		/* missing peer tunnel is reported as channel down without terminal delivery. */
		(void)aern_cipher_table_remove(&ctx->ctable[1U], ctx->address[2U]);
		qsc_memutils_clear(&header, sizeof(header));
		qsc_memutils_clear(&rm, sizeof(rm));
		body[0U] = 0xC4U;
		header.sessionid = 0x1111222233334444ULL;
		header.packetid = 0x6500000000000000ULL;
		header.msglen = 32U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		failures = ctx->failures;
		res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
			route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_channel_down);
		res = (res == true && ctx->failures == failures + 1U && exitctx.calls == expectedexit && ingressctx.calls == expectedingress);
	}

	if (res == true)
	{
		/* reinitialize after missing-peer attack and verify active-session revocation during forwarding. */
		route_test_multihop_dispose(ctx);
		res = route_test_multihop_initialize(ctx);
	}

	if (res == true)
	{
		aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
		aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);
		route_test_session_set(&session, 0x1111222233334444ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS, 0U);
		session.ingresshint = 1U;
		session.egresshint = 4U;
		res = aern_relay_session_add(&ctx->cache[3U], &session);
	}

	if (res == true)
	{
		qsc_memutils_clear(&header, sizeof(header));
		qsc_memutils_clear(&rm, sizeof(rm));
		body[0U] = 0xD5U;
		header.sessionid = 0x1111222233334444ULL;
		header.packetid = 0x6600000000000000ULL;
		header.msglen = 40U;
		header.payloadtype = (uint8_t)aern_relay_payload_data;
		header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;
		rm.path[0U] = 1U;
		rm.path[1U] = 3U;
		rm.path[2U] = 4U;
		rm.hopcount = 3U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true &&
			route_test_multihop_drive(ctx, 1U, 0U, wire) == aern_protocol_error_none);
		expectedexit += 1U;
		res = (res == true && exitctx.calls == expectedexit);
	}

	if (res == true)
	{
		aern_relaysession_remove(&ctx->cache[3U].sessions, 0x1111222233334444ULL, AERN_RELAY_SESSION_CONTEXT_EGRESS);
		header.packetid = 0x6600000000000001ULL;
		body[0U] = 0xD6U;
		route_test_plaintext_make(plaintext, &rm, &header, body);
		sender = aern_cipher_table_get_by_ip(&ctx->ctable[0U], ctx->address[1U]);
		res = (sender != NULL && route_test_wire_make(wire, sender, plaintext) == true);

		if (res == true)
		{
			(void)route_test_multihop_drive(ctx, 1U, 0U, wire);
			res = (exitctx.calls == expectedexit && aern_relaysession_count(&ctx->cache[3U].sessions) == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);

	if (ctx != NULL)
	{
		route_test_multihop_dispose(ctx);
		qsc_memutils_alloc_free(ctx);
	}

	return res;
}

static bool aern_route_test_session_open_duplicate_forwarding_state(void)
{
	aern_forward_state fwd = { 0 };
	aern_connection_state sender = { 0 };
	aern_connection_state receiver = { 0 };
	aern_relay_payload_header header = { 0 };
	aern_relay_session_cache_entry session = { 0 };
	aern_relay_session_open open = { 0 };
	aern_route_map rm = { 0 };
	route_test_transport_context exitctx = { 0 };
	route_test_transport_context ingressctx = { 0 };
	uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
	uint8_t wire[AERN_RELAY_MTU] = { 0U };
	uint8_t body[AERN_RELAY_SESSION_OPEN_SIZE] = { 0U };
	aern_cipher_table* ctable;
	aern_relay_cache_state* cache;
	aern_topology_list_state* topology;
	aern_protocol_errors err;
	bool res;

	ctable = NULL;
	cache = NULL;
	topology = NULL;
	res = false;

	if (route_test_context_initialize(&ctable, &cache, &topology, &fwd) == true)
	{
		route_test_connection_pair_initialize(&sender, &receiver, 22U);
		res = (aern_cipher_table_add(ctable, "10.0.0.2", &receiver) == aern_protocol_error_none);

		if (res == true)
		{
			rm.path[0U] = 1U;
			rm.hopcount = 1U;
			header.sessionid = 0x7777777777777777ULL;
			header.packetid = 0U;
			header.fragseq = 0U;
			header.fragcount = 0U;
			header.msglen = AERN_RELAY_SESSION_OPEN_SIZE;
			header.payloadtype = (uint8_t)aern_relay_payload_session_open;
			header.reserved = 0U;
			header.flags = 0U;

			open.sessionid = header.sessionid;
			route_test_set_string((char*)open.destination, sizeof(open.destination), "203.0.113.10");
			open.ingresshint = 1U;
			open.egresshint = 2U;
			open.port = 443U;
			open.reserved = 0U;
			open.flags = 0U;
			aern_relay_session_open_serialize(body, &open);

			aern_exit_transport_set_callback(route_test_exit_callback, &exitctx);
			aern_ingress_transport_set_callback(route_test_ingress_callback, &ingressctx);
			route_test_plaintext_make(plaintext, &rm, &header, body);
			res = route_test_wire_make(wire, &sender, plaintext);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err != aern_protocol_error_authentication_failure && err != aern_protocol_error_packet_header_invalid);
			res = (res == true && aern_relaysession_count(&cache->sessions) == 1U);
			res = (res == true && aern_relay_session_find(cache, &session, header.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true);
			res = (res == true && session.status == (uint8_t)aern_relay_session_status_active);
		}

		if (res == true)
		{
			qsc_memutils_clear(wire, sizeof(wire));
			res = route_test_wire_make(wire, &sender, plaintext);
		}

		if (res == true)
		{
			err = aern_packet_forward(&fwd, wire, "10.0.0.2");
			res = (err != aern_protocol_error_authentication_failure && err != aern_protocol_error_packet_header_invalid);
			res = (res == true && aern_relaysession_count(&cache->sessions) == 1U);
			res = (res == true && aern_relay_session_find(cache, &session, header.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS) == true);
			res = (res == true && session.status == (uint8_t)aern_relay_session_status_active);
			res = (res == true && exitctx.calls == 0U && ingressctx.calls == 0U);
		}
	}

	aern_exit_transport_set_callback(NULL, NULL);
	aern_ingress_transport_set_callback(NULL, NULL);
	route_test_context_dispose(ctable, cache, topology);

	return res;
}

bool aerntest_route_run(void)
{
	bool res;

	res = true;

	if (aern_route_test_map_roundtrip() == true)
	{
		aerntest_print_line("[PASS] AERN route map roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route map roundtrip test.");
		res = false;
	}

	if (aern_route_test_generation() == true)
	{
		aerntest_print_line("[PASS] AERN route map generation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route map generation test.");
		res = false;
	}

	if (aern_route_test_invalid_hint_rejection() == true)
	{
		aerntest_print_line("[PASS] AERN route invalid hint rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route invalid hint rejection test.");
		res = false;
	}

	if (aern_route_test_one_based_and_zero_terminator() == true)
	{
		aerntest_print_line("[PASS] AERN route one-based hint and zero terminator test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route one-based hint and zero terminator test.");
		res = false;
	}

	if (aern_route_test_endpoint_stability_and_interior_policy() == true)
	{
		aerntest_print_line("[PASS] AERN route endpoint stability and interior policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route endpoint stability and interior policy test.");
		res = false;
	}

	if (aern_route_test_per_packet_rerouting_variation() == true)
	{
		aerntest_print_line("[PASS] AERN route per-packet rerouting variation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route per-packet rerouting variation test.");
		res = false;
	}

	if (aern_route_test_maximum_serialized_route_capacity() == true)
	{
		aerntest_print_line("[PASS] AERN route maximum serialized capacity test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route maximum serialized capacity test.");
		res = false;
	}

	if (aern_route_test_local_state_not_serialized() == true)
	{
		aerntest_print_line("[PASS] AERN route local state not serialized test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route local state not serialized test.");
		res = false;
	}

	if (aern_route_test_cursor_and_padding_not_serialized() == true)
	{
		aerntest_print_line("[PASS] AERN route cursor and padding not serialized test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route cursor and padding not serialized test.");
		res = false;
	}

	if (aern_route_test_self_hop_rejection_policy() == true)
	{
		aerntest_print_line("[PASS] AERN route self-hop rejection policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route self-hop rejection policy test.");
		res = false;
	}

	if (aern_route_test_randomness_distribution_sanity() == true)
	{
		aerntest_print_line("[PASS] AERN route randomness sanity test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route randomness sanity test.");
		res = false;
	}

	if (aern_route_test_session_open_creates_egress_session() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open egress activation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open egress activation test.");
		res = false;
	}

	if (aern_route_test_session_open_bad_reserved_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open bad reserved rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open bad reserved rejection test.");
		res = false;
	}

	if (aern_route_test_session_ack_activates_pending_session() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open ack activation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open ack activation test.");
		res = false;
	}

	if (aern_route_test_session_ack_wrong_session_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open ack wrong session rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open ack wrong session rejection test.");
		res = false;
	}

	if (aern_route_test_session_ack_flags_reserved_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open ack flags/reserved rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open ack flags/reserved rejection test.");
		res = false;
	}

	if (aern_route_test_session_ack_failure_closes_session_and_drops_pending() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open ack failure cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open ack failure cleanup test.");
		res = false;
	}

	if (aern_route_test_session_ack_bad_flags_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session-open ack bad flags rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session-open ack bad flags rejection test.");
		res = false;
	}

	if (aern_route_test_pending_session_timeout_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN relay pending session timeout cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay pending session timeout cleanup test.");
		res = false;
	}

	if (aern_route_test_first_outbound_packet_creates_pending_session() == true)
	{
		aerntest_print_line("[PASS] AERN relay first outbound packet pending session test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay first outbound packet pending session test.");
		res = false;
	}

	if (aern_route_test_session_open_bad_ingress_hint_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session open bad ingress hint rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session open bad ingress hint rejection test.");
		res = false;
	}

	if (aern_route_test_session_open_bad_egress_hint_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session open bad egress hint rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session open bad egress hint rejection test.");
		res = false;
	}

	if (aern_route_test_duplicate_session_open_preserves_existing_session() == true)
	{
		aerntest_print_line("[PASS] AERN relay duplicate session open preservation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay duplicate session open preservation test.");
		res = false;
	}

	if (aern_route_test_active_session_idle_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN relay active session idle cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay active session idle cleanup test.");
		res = false;
	}

	if (aern_route_test_session_close_payload_currently_rejected() == true)
	{
		aerntest_print_line("[PASS] AERN relay session close current behavior test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay session close current behavior test.");
		res = false;
	}

	if (aern_route_test_terminal_egress_backend_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN relay terminal egress backend delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay terminal egress backend delivery test.");
		res = false;
	}

	if (aern_route_test_terminal_backend_failure_forwarding() == true)
	{
		aerntest_print_line("[PASS] AERN relay terminal backend failure forwarding test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay terminal backend failure forwarding test.");
		res = false;
	}

	if (aern_route_test_terminal_ingress_return_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN relay terminal ingress return delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay terminal ingress return delivery test.");
		res = false;
	}

	if (aern_route_test_forwarding_node_no_backend_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN relay forwarding node no backend delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay forwarding node no backend delivery test.");
		res = false;
	}

	if (aern_route_test_terminal_dummy_discard() == true)
	{
		aerntest_print_line("[PASS] AERN relay terminal dummy discard test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay terminal dummy discard test.");
		res = false;
	}

	if (aern_route_test_dummy_mutation_recovery_forwarding() == true)
	{
		aerntest_print_line("[PASS] AERN encrypted dummy mutation recovery forwarding test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN encrypted dummy mutation recovery forwarding test.");
		res = false;
	}

	if (aern_route_test_terminal_unknown_session_drop() == true)
	{
		aerntest_print_line("[PASS] AERN relay terminal unknown session drop test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay terminal unknown session drop test.");
		res = false;
	}

	if (aern_route_test_invalid_next_hint_rejected_before_backend() == true)
	{
		aerntest_print_line("[PASS] AERN relay invalid next hint rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay invalid next hint rejection test.");
		res = false;
	}

	if (aern_route_test_payload_header_roundtrip() == true)
	{
		aerntest_print_line("[PASS] AERN payload header roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN payload header roundtrip test.");
		res = false;
	}

	if (aern_route_test_payload_header_fixed_layout() == true)
	{
		aerntest_print_line("[PASS] AERN payload header fixed layout test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN payload header fixed layout test.");
		res = false;
	}

	if (aern_route_test_payload_header_type_and_flag_roundtrip() == true)
	{
		aerntest_print_line("[PASS] AERN payload header type and flag roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN payload header type and flag roundtrip test.");
		res = false;
	}

	if (aern_route_test_payload_header_invalid_semantics() == true)
	{
		aerntest_print_line("[PASS] AERN payload header invalid semantics test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN payload header invalid semantics test.");
		res = false;
	}

	if (aern_route_test_payload_header_control_semantics() == true)
	{
		aerntest_print_line("[PASS] AERN payload header control semantics test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN payload header control semantics test.");
		res = false;
	}

	if (aern_route_test_session_control_roundtrip() == true)
	{
		aerntest_print_line("[PASS] AERN session control roundtrip test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN session control roundtrip test.");
		res = false;
	}

	if (aern_route_test_relayqueue_ownership_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN relayqueue ownership cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relayqueue ownership cleanup test.");
		res = false;
	}

	if (aern_route_test_relayqueue_fifo_capacity_timeout() == true)
	{
		aerntest_print_line("[PASS] AERN relayqueue FIFO capacity timeout test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relayqueue FIFO capacity timeout test.");
		res = false;
	}

	if (aern_route_test_relayqueue_session_purge_preserves_fifo() == true)
	{
		aerntest_print_line("[PASS] AERN relayqueue session purge FIFO preservation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relayqueue session purge FIFO preservation test.");
		res = false;
	}

	if (aern_route_test_relay_cache_pending_delay_session_purge() == true)
	{
		aerntest_print_line("[PASS] AERN relay cache pending delay session purge test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay cache pending delay session purge test.");
		res = false;
	}

	if (aern_route_test_ingress_delay_flush_queue_policy() == true)
	{
		aerntest_print_line("[PASS] AERN ingress delay queue flush policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ingress delay queue flush policy test.");
		res = false;
	}

	if (aern_route_test_relay_pending_capacity_overflow() == true)
	{
		aerntest_print_line("[PASS] AERN relay pending capacity overflow test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay pending capacity overflow test.");
		res = false;
	}

	if (aern_route_test_backend_direct_egress_boundary() == true)
	{
		aerntest_print_line("[PASS] AERN backend egress boundary validation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend egress boundary validation test.");
		res = false;
	}

	if (aern_route_test_backend_direct_ingress_boundary() == true)
	{
		aerntest_print_line("[PASS] AERN backend ingress boundary validation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend ingress boundary validation test.");
		res = false;
	}

	if (aern_route_test_backend_missing_callback_policy() == true)
	{
		aerntest_print_line("[PASS] AERN backend missing callback policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend missing callback policy test.");
		res = false;
	}

	if (aern_route_test_backend_failure_status_propagation() == true)
	{
		aerntest_print_line("[PASS] AERN backend failure status propagation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend failure status propagation test.");
		res = false;
	}

	if (aern_route_test_backend_error_and_dummy_no_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN backend error and dummy no delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend error and dummy no delivery test.");
		res = false;
	}

	if (aern_route_test_backend_return_injection_no_tunnel_failure() == true)
	{
		aerntest_print_line("[PASS] AERN backend return injection no tunnel failure test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend return injection no tunnel failure test.");
		res = false;
	}

	if (aern_route_test_dummy_traffic_policy_bounds() == true)
	{
		aerntest_print_line("[PASS] AERN dummy traffic policy bounds test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN dummy traffic policy bounds test.");
		res = false;
	}

	if (aern_route_test_relay_traffic_utilization_counters() == true)
	{
		aerntest_print_line("[PASS] AERN relay traffic utilization counters test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN relay traffic utilization counters test.");
		res = false;
	}

	if (aern_route_test_dummy_generation_suppressed_policy() == true)
	{
		aerntest_print_line("[PASS] AERN dummy generation suppressed policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN dummy generation suppressed policy test.");
		res = false;
	}

	if (aern_route_test_ingress_delay_expired_item_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN ingress delay expired item cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN ingress delay expired item cleanup test.");
		res = false;
	}

	if (aern_route_test_dummy_terminal_no_session_state() == true)
	{
		aerntest_print_line("[PASS] AERN dummy terminal no session state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN dummy terminal no session state test.");
		res = false;
	}

	if (aern_route_test_failure_route_parse_no_backend_mutation() == true)
	{
		aerntest_print_line("[PASS] AERN failure route-parse no backend mutation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure route-parse no backend mutation test.");
		res = false;
	}

	if (aern_route_test_failure_invalid_future_hint_no_backend_mutation() == true)
	{
		aerntest_print_line("[PASS] AERN failure invalid future hint no backend mutation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure invalid future hint no backend mutation test.");
		res = false;
	}

	if (aern_route_test_failure_payload_header_no_backend_mutation() == true)
	{
		aerntest_print_line("[PASS] AERN failure relay-header no backend mutation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure relay-header no backend mutation test.");
		res = false;
	}

	if (aern_route_test_failure_missing_peer_no_backend_or_queue_mutation() == true)
	{
		aerntest_print_line("[PASS] AERN failure missing peer no backend or queue mutation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure missing peer no backend or queue mutation test.");
		res = false;
	}

	if (aern_route_test_failure_backend_error_preserves_session_state() == true)
	{
		aerntest_print_line("[PASS] AERN failure backend error session preservation test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure backend error session preservation test.");
		res = false;
	}

	if (aern_route_test_failure_cache_cleanup_removes_expired_runtime_state() == true)
	{
		aerntest_print_line("[PASS] AERN failure expired runtime state cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN failure expired runtime state cleanup test.");
		res = false;
	}

	if (aern_route_test_fragment_single_boundary_payload() == true)
	{
		aerntest_print_line("[PASS] AERN fragment single boundary payload test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment single boundary payload test.");
		res = false;
	}

	if (aern_route_test_fragment_two_fragment_payload() == true)
	{
		aerntest_print_line("[PASS] AERN fragment two-fragment payload test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment two-fragment payload test.");
		res = false;
	}

	if (aern_route_test_fragment_duplicate_policy() == true)
	{
		aerntest_print_line("[PASS] AERN fragment duplicate policy test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment duplicate policy test.");
		res = false;
	}

	if (aern_route_test_fragment_invalid_metadata_rejection() == true)
	{
		aerntest_print_line("[PASS] AERN fragment invalid metadata rejection test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment invalid metadata rejection test.");
		res = false;
	}

	if (aern_route_test_fragment_timeout_and_session_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN fragment timeout and session cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment timeout and session cleanup test.");
		res = false;
	}

	if (aern_route_test_fragment_terminal_backend_once() == true)
	{
		aerntest_print_line("[PASS] AERN fragment terminal backend exactly once test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment terminal backend exactly once test.");
		res = false;
	}

	if (aern_route_test_fragment_ownership_cleanup() == true)
	{
		aerntest_print_line("[PASS] AERN fragment ownership cleanup test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment ownership cleanup test.");
		res = false;
	}

	if (aern_route_test_fragment_large_out_of_order() == true)
	{
		aerntest_print_line("[PASS] AERN fragment large out of order test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment large out of order test.");
		res = false;
	}
	
	if (aern_route_test_fragment_final_first_shrink() == true)
	{
		aerntest_print_line("[PASS] AERN fragment final first shrink test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment final first shrink test.");
		res = false;
	}


	if (aern_route_test_fragment_forwarding_out_of_order_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN fragment forwarding out-of-order delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment forwarding out-of-order delivery test.");
		res = false;
	}

	if (aern_route_test_fragment_forwarding_invalid_short_nonfinal_no_delivery() == true)
	{
		aerntest_print_line("[PASS] AERN fragment forwarding invalid non-final no-delivery test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN fragment forwarding invalid non-final no-delivery test.");
		res = false;
	}

	if (aern_route_test_active_session_revocation_forwarding_drop() == true)
	{
		aerntest_print_line("[PASS] AERN active-session revocation forwarding drop test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN active-session revocation forwarding drop test.");
		res = false;
	}

	if (aern_route_test_route_domain_boundary_counts() == true)
	{
		aerntest_print_line("[PASS] AERN route domain boundary count test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN route domain boundary count test.");
		res = false;
	}

	if (aern_route_test_backend_bounded_load_profile() == true)
	{
		aerntest_print_line("[PASS] AERN backend bounded load profile test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN backend bounded load profile test.");
		res = false;
	}

	if (aern_route_test_encrypted_terminal_load_profile() == true)
	{
		aerntest_print_line("[PASS] AERN encrypted terminal load profile test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN encrypted terminal load profile test.");
		res = false;
	}

	if (aern_route_test_multihop_virtual_dispatch_load_profile() == true)
	{
		aerntest_print_line("[PASS] AERN multi-hop virtual dispatch load profile test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN multi-hop virtual dispatch load profile test.");
		res = false;
	}

	if (aern_route_test_multihop_full_4aps_profiles() == true)
	{
		aerntest_print_line("[PASS] AERN full 4-APS encrypted multi-hop profile test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN full 4-APS encrypted multi-hop profile test.");
		res = false;
	}

	if (aern_route_test_extended_multihop_stress_attack_campaign() == true)
	{
		aerntest_print_line("[PASS] AERN extended multi-hop stress and attack campaign test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN extended multi-hop stress and attack campaign test.");
		res = false;
	}

	if (aern_route_test_session_open_duplicate_forwarding_state() == true)
	{
		aerntest_print_line("[PASS] AERN encrypted session-open duplicate state test.");
	}
	else
	{
		aerntest_print_line("[FAIL] AERN encrypted session-open duplicate state test.");
		res = false;
	}

	return res;
}

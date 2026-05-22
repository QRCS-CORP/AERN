#include "route.h"
#include "aern.h"
#include "network.h"
#include "fragment.h"
#include "relayqueue.h"
#include "relaysession.h"
#include "csp.h"
#include "async.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "netutils.h"
#include "sha3.h"
#include "socketclient.h"
#include "stringutils.h"
#include "timestamp.h"

static aern_exit_transport_send_callback m_exit_transport_callback = NULL;
static void* m_exit_transport_context = NULL;
static aern_ingress_transport_send_callback m_ingress_transport_callback = NULL;
static void* m_ingress_transport_context = NULL;
static qsc_mutex m_transportcallbackmtx = NULL;
static volatile int32_t m_transportcallbackmtxstate = 0;
static void route_dummy_window_update(aern_relay_cache_state* cache, uint64_t nowms);

static qsc_mutex route_transport_callback_mutex(void)
{
    qsc_mutex mtx;
    int32_t state;
    bool init;

    mtx = NULL;
    state = qsc_async_atomic_int32_load(&m_transportcallbackmtxstate);

    if (state != 2)
    {
        init = qsc_async_atomic_int32_compare_exchange(&m_transportcallbackmtxstate, 0, 1);

        if (init == true)
        {
            mtx = qsc_async_mutex_create();
            m_transportcallbackmtx = mtx;
            qsc_async_atomic_int32_store(&m_transportcallbackmtxstate, (mtx != NULL) ? 2 : -1);
        }
        else
        {
            do
            {
                qsc_async_thread_sleep(1U);
                state = qsc_async_atomic_int32_load(&m_transportcallbackmtxstate);
            }
            while (state == 1);
        }
    }

    if (qsc_async_atomic_int32_load(&m_transportcallbackmtxstate) == 2)
    {
        mtx = m_transportcallbackmtx;
    }

    return mtx;
}

static uint8_t rng_uint8_range(uint8_t range)
{
    uint16_t lim;
    uint8_t val;
    uint8_t res;

    lim = 0U;
    val = 0U;
    res = 0U;

    if (range > 1U)
    {
        lim = (uint16_t)(256U - (256U % (uint16_t)range));

        do
        {
            if (qsc_csp_generate(&val, sizeof(val)) == false)
            {
                val = 0U;
                break;
            }
        }
        while ((uint16_t)val >= lim);

        res = (uint8_t)(val % range);
    }

    return res;
}

static uint8_t route_hint_from_index(uint8_t index)
{
    uint8_t res;

    res = 0U;

    if (index < UINT8_MAX)
    {
        res = (uint8_t)(index + 1U);
    }

    return res;
}

static bool route_aps_ordinal_from_hint(uint8_t hint, uint8_t* index)
{
    bool res;

    res = false;

    if (index != NULL && hint != 0U)
    {
        *index = (uint8_t)(hint - 1U);
        res = true;
    }

    return res;
}

static bool route_hint_in_range(uint8_t hint, uint8_t count)
{
    bool res;

    res = false;

    if (hint != 0U && hint <= count)
    {
        res = true;
    }

    return res;
}

static bool route_relay_header_valid(const aern_network_packet* packet)
{
    /* validate the clear AERN relay header before authenticated decryption. */
    bool res;

    res = false;

    if (packet != NULL)
    {
        if (packet->flag == aern_network_flag_tunnel_encrypted_message && packet->msglen == AERN_RELAY_CIPHERTEXT_SIZE)
        {
            res = true;
        }
    }

    return res;
}

static bool route_map_audit_valid(const aern_route_map* rm, uint8_t count)
{
    uint8_t pos;
    uint8_t lasthint;
    bool res;

    pos = 0U;
    lasthint = 0U;
    res = false;

    if (rm != NULL && count >= AERN_ROUTE_MIN_HOPS && rm->path[0U] != 0U &&
        route_hint_in_range(rm->path[0U], count) == true)
    {
        res = true;
        lasthint = rm->path[0U];

        for (pos = 1U; pos < AERN_ROUTE_PATH_SIZE; ++pos)
        {
            if (rm->path[pos] != 0U)
            {
                if (route_hint_in_range(rm->path[pos], count) == false || rm->path[pos] == lasthint)
                {
                    res = false;
                    break;
                }

                lasthint = rm->path[pos];
            }
        }
    }

    return res;
}

static bool route_map_has_future(const aern_route_map* rm)
{
    uint8_t pos;
    bool res;

    pos = 0U;
    res = false;

    if (rm != NULL)
    {
        for (pos = 1U; pos < AERN_ROUTE_PATH_SIZE; ++pos)
        {
            if (rm->path[pos] != 0U)
            {
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool route_relay_plaintext_valid(const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint8_t count, aern_route_map* rm, uint16_t* actual)
{
    uint16_t plen;
    bool res;

    plen = 0U;
    res = false;

    if (plaintext != NULL && rm != NULL && actual != NULL)
    {
        plen = qsc_intutils_le8to16(plaintext);

        if (plen >= AERN_RELAY_PAYLOAD_HEADER_SIZE && plen <= AERN_MAX_USER_PAYLOAD)
        {
            aern_route_map_deserialize(rm, plaintext + AERN_LEN_PREFIX_SIZE);

            if (route_map_audit_valid(rm, count) == true)
            {
                *actual = plen;
                res = true;
            }
        }
    }

    return res;
}

static bool route_entry_plaintext_valid(const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint16_t* actual)
{
    /* validate an entry-APS plaintext packet received from a client tunnel. */
    uint16_t plen;
    bool res;

    plen = 0U;
    res = false;

    if (plaintext != NULL && actual != NULL)
    {
        *actual = 0U;
        plen = aern_packet_unpad(plaintext);

        if (plen >= AERN_RELAY_PAYLOAD_HEADER_SIZE && plen <= AERN_MAX_USER_PAYLOAD)
        {
            *actual = plen;
            res = true;
        }
    }

    return res;
}

static bool route_pending_item_valid(const aern_ingress_pending_item* item, uint64_t now)
{
    bool res;

    res = false;

    if (item != NULL)
    {
        if (item->sessionid != 0U && item->packetid != 0U && item->expiry != 0U && item->expiry > now &&
            item->packet != NULL && item->packetlen == AERN_RELAY_PLAINTEXT_SIZE)
        {
            res = true;
        }
    }

    return res;
}

static bool route_pending_item_set_packet(aern_ingress_pending_item* item, const uint8_t* packet, size_t packetlen,
    uint64_t sessionid, uint64_t packetid, uint64_t expiry, uint64_t delayuntil)
{
    bool res;

    res = false;

    if (item != NULL && packet != NULL && packetlen != 0U)
    {
        aern_relayqueue_item_dispose(item);
        item->packet = (uint8_t*)qsc_memutils_malloc(packetlen);

        if (item->packet != NULL)
        {
            qsc_memutils_copy(item->packet, packet, packetlen);
            item->packetlen = packetlen;
            item->capacity = packetlen;
            item->sessionid = sessionid;
            item->packetid = packetid;
            item->expiry = expiry;
            item->delayuntil = delayuntil;
            item->active = true;
            res = true;
        }
    }

    return res;
}

static aern_protocol_errors route_consume_next(aern_route_map* rm, uint8_t count, uint8_t* next)
{
    uint8_t pos;
    aern_protocol_errors res;

    pos = 0U;
    res = aern_protocol_error_invalid_request;

    if (rm != NULL && next != NULL && route_map_audit_valid(rm, count) == true)
    {
        *next = 0U;

        for (pos = 1U; pos < AERN_ROUTE_PATH_SIZE; ++pos)
        {
            if (rm->path[pos] != 0U)
            {
                *next = rm->path[pos];
                rm->path[pos] = 0U;
                res = aern_protocol_error_none;
                break;
            }
        }

        if (*next == 0U)
        {
            res = aern_protocol_error_node_not_found;
        }
    }

    return res;
}

static bool route_node_from_hint(const aern_topology_list_state* topology, uint8_t hint, aern_topology_node_state* node)
{
    /* find an APS topology node by one-based route hint. */
    aern_topology_node_state item;
    uint8_t index;
    uint8_t apsctr;
    bool res;

    apsctr = 0U;
    index = 0U;
    res = false;

    if (topology != NULL && node != NULL && route_aps_ordinal_from_hint(hint, &index) == true)
    {
        qsc_memutils_clear(node, sizeof(aern_topology_node_state));

        for (size_t i = 0U; i < topology->count; ++i)
        {
            qsc_memutils_clear(&item, sizeof(item));

            if (aern_topology_list_item(topology, &item, i) == true && item.designation == aern_network_designation_aps)
            {
                if (apsctr == index)
                {
                    *node = item;
                    res = true;
                    break;
                }

                ++apsctr;
            }
        }
    }

    return res;
}

static uint64_t route_random64_raw(void)
{
    uint8_t buf[sizeof(uint64_t)];
    uint64_t res;

    res = 0U;
    qsc_memutils_clear(buf, sizeof(buf));

    if (qsc_csp_generate(buf, sizeof(buf)) == true)
    {
        res = qsc_intutils_le8to64(buf);
    }

    return res;
}

static uint64_t route_random64(void)
{
    uint64_t res;

    res = route_random64_raw();

    if (res == 0U)
    {
        res = 1U;
    }

    return res;
}

static uint64_t rng_uint64_range(uint64_t range)
{
    uint64_t res;
    uint64_t thrsh;
    uint64_t val;

    thrsh = 0U;
    val = 0U;
    res = 0U;

    if (range > 1U)
    {
        thrsh = (uint64_t)(0U - range) % range;

        do
        {
            val = route_random64_raw();
        }
        while (val < thrsh);

        res = val % range;
    }

    return res;
}

static uint64_t route_random_delay_milliseconds(void)
{
    uint64_t delta;
    uint64_t range;
    uint64_t res;

    delta = 0U;
    range = 0U;
    res = 0U;

    if (AERN_INGRESS_DELAY_ENABLED != 0U)
    {
        if (AERN_INGRESS_DELAY_MAXIMUM_MILLISECONDS > AERN_INGRESS_DELAY_MINIMUM_MILLISECONDS)
        {
            range = ((uint64_t)AERN_INGRESS_DELAY_MAXIMUM_MILLISECONDS - (uint64_t)AERN_INGRESS_DELAY_MINIMUM_MILLISECONDS) + 1U;
            delta = rng_uint64_range(range);
            res = (uint64_t)AERN_INGRESS_DELAY_MINIMUM_MILLISECONDS + delta;
        }
        else
        {
            res = (uint64_t)AERN_INGRESS_DELAY_MINIMUM_MILLISECONDS;
        }
    }

    return res;
}

static bool route_ingress_delay_enabled(void)
{
    bool res;

    res = false;

    if (AERN_INGRESS_DELAY_ENABLED != 0U && AERN_INGRESS_DELAY_MAXIMUM_MILLISECONDS != 0U)
    {
        res = true;
    }

    return res;
}

static uint64_t route_random_dummy_interval_milliseconds(void)
{
    uint64_t delta;
    uint64_t range;
    uint64_t res;

    delta = 0U;
    range = 0U;
    res = 0U;

    if (AERN_DUMMY_TRAFFIC_ENABLED != 0U)
    {
        if (AERN_DUMMY_TRAFFIC_INTERVAL_MAXIMUM_MILLISECONDS > AERN_DUMMY_TRAFFIC_INTERVAL_MINIMUM_MILLISECONDS)
        {
            range = ((uint64_t)AERN_DUMMY_TRAFFIC_INTERVAL_MAXIMUM_MILLISECONDS - (uint64_t)AERN_DUMMY_TRAFFIC_INTERVAL_MINIMUM_MILLISECONDS) + 1U;
            delta = rng_uint64_range(range);
            res = (uint64_t)AERN_DUMMY_TRAFFIC_INTERVAL_MINIMUM_MILLISECONDS + delta;
        }
        else
        {
            res = (uint64_t)AERN_DUMMY_TRAFFIC_INTERVAL_MINIMUM_MILLISECONDS;
        }
    }

    return res;
}

static void route_dummy_window_update(aern_relay_cache_state* cache, uint64_t nowms)
{
    if (cache != NULL && cache->initialized == true)
    {
        if (cache->dummywindowms == 0U || (nowms - cache->dummywindowms) >= AERN_RELAY_TRAFFIC_WINDOW_MILLISECONDS)
        {
            cache->dummywindowms = nowms;
            cache->dummywindowcount = 0U;
        }
    }
}

static bool route_payload_control_header_valid(const aern_relay_payload_header* header, uint8_t ptype, uint32_t msglen)
{
    bool res;

    res = false;

    if (header != NULL)
    {
        if (header->sessionid != 0U && header->packetid == 0U && header->fragseq == 0U && header->fragcount == 0U &&
            header->payloadtype == ptype && header->reserved == 0U && header->flags == 0U && header->msglen == msglen)
        {
            res = true;
        }
    }

    return res;
}

static bool route_payload_data_header_valid(const aern_relay_payload_header* header, uint32_t bodylen)
{
    bool res;

    res = false;

    if (header != NULL)
    {
        if (header->sessionid != 0U && header->packetid != 0U && header->payloadtype == (uint8_t)aern_relay_payload_data &&
            header->reserved == 0U && header->msglen != 0U && header->msglen <= bodylen &&
            header->msglen <= AERN_RELAY_DATA_PAYLOAD_SIZE &&
            (header->flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND || header->flags == AERN_RELAY_PAYLOAD_FLAG_RETURN))
        {
            if ((header->fragseq == 0U && header->fragcount == 0U) ||
                (header->fragseq != 0U && header->fragcount != 0U && header->fragseq <= header->fragcount && header->fragcount <= AERN_MAX_FRAGMENTS))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool route_payload_dummy_header_valid(const aern_relay_payload_header* header, uint32_t bodylen)
{
    bool res;

    res = false;

    if (header != NULL)
    {
        if (header->payloadtype == (uint8_t)aern_relay_payload_dummy && header->reserved == 0U && header->flags == 0U && header->fragseq == 0U && 
            header->fragcount == 0U && header->msglen <= bodylen && header->msglen <= AERN_RELAY_DATA_PAYLOAD_SIZE)
        {
            res = true;
        }
    }

    return res;
}

static bool route_payload_header_valid(const aern_relay_payload_header* header, uint32_t bodylen)
{
    bool res;

    res = false;

    if (header != NULL)
    {
        switch ((aern_relay_payload_type)header->payloadtype)
        {
            case aern_relay_payload_session_open:
            {
                res = route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_session_open, AERN_RELAY_SESSION_OPEN_SIZE);
                break;
            }
            case aern_relay_payload_session_open_ack:
            {
                res = route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_session_open_ack, AERN_RELAY_SESSION_OPEN_ACK_SIZE);
                break;
            }
            case aern_relay_payload_session_close:
            {
                res = route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_session_close, 0U);
                break;
            }
            case aern_relay_payload_data:
            {
                res = route_payload_data_header_valid(header, bodylen);
                break;
            }
            case aern_relay_payload_dummy:
            {
                res = route_payload_dummy_header_valid(header, bodylen);
                break;
            }
            case aern_relay_payload_error:
            {
                res = route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_error, 0U);
                break;
            }
            default:
            {
                res = false;
                break;
            }
        }
    }

    return res;
}

static bool route_payload_header_read(aern_relay_payload_header* header, uint8_t* body, uint16_t actual)
{
    uint32_t bodylen;
    bool res;

    bodylen = 0U;
    res = false;

    if (header != NULL && body != NULL && actual >= AERN_RELAY_PAYLOAD_HEADER_SIZE)
    {
        bodylen = (uint32_t)actual - AERN_RELAY_PAYLOAD_HEADER_SIZE;
        aern_relay_payload_header_deserialize(header, body);
        res = route_payload_header_valid(header, bodylen);
    }

    return res;
}

static aern_protocol_errors route_plaintext_send(aern_forward_state* fwd, uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint8_t targethint)
{
    aern_topology_node_state nextnode = { 0 };
    qsc_socket nsock = { 0 };
    aern_network_packet pktout = { 0 };
    aern_route_map rm = { 0 };
    uint8_t outwire[AERN_RELAY_MTU] = { 0U };
    aern_connection_state* txcns;
    aern_protocol_errors res;
    size_t slen;
    uint8_t nexthint;

    txcns = NULL;
    nexthint = 0U;
    slen = 0U;
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && plaintext != NULL && fwd->topology != NULL && fwd->conn_table != NULL &&
        fwd->apscount >= AERN_ROUTE_MIN_HOPS)
    {
        if (targethint == 0U)
        {
            do
            {
                targethint = route_hint_from_index(rng_uint8_range(fwd->apscount));
            }
            while (targethint == 0U || targethint == fwd->ownhint);
        }

        res = aern_route_generate(&rm, fwd->apscount, fwd->ownhint, targethint);

        if (res == aern_protocol_error_none)
        {
            res = route_consume_next(&rm, fwd->apscount, &nexthint);
        }

        if (res == aern_protocol_error_none)
        {
            if (route_node_from_hint(fwd->topology, nexthint, &nextnode) == true)
            {
                txcns = aern_cipher_table_get_by_ip(fwd->conn_table, nextnode.address);

                if (txcns != NULL)
                {
                    aern_route_map_serialize(plaintext + AERN_LEN_PREFIX_SIZE, &rm);
                    pktout.pmessage = outwire + AERN_RELAY_HEADER_SIZE;
                    res = aern_encrypt_packet(txcns, &pktout, plaintext, AERN_RELAY_PLAINTEXT_SIZE);

                    if (res == aern_protocol_error_none)
                    {
                        pktout.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
                        aern_packet_header_serialize(&pktout, outwire);

                        if (aern_network_connect_to_device(&nsock, nextnode.address, aern_network_designation_aps) == qsc_socket_exception_success)
                        {
                            slen = qsc_socket_send(&nsock, outwire, AERN_RELAY_MTU, qsc_socket_send_flag_none);
                            aern_network_socket_dispose(&nsock);

                            if (slen == AERN_RELAY_MTU)
                            {
                                aern_relay_traffic_observe(fwd->relay_cache, AERN_RELAY_MTU, false);
                                res = aern_protocol_error_none;
                            }
                            else
                            {
                                res = aern_protocol_error_transmit_failure;
                            }
                        }
                        else
                        {
                            res = aern_protocol_error_connection_failure;
                        }
                    }
                }
                else
                {
                    res = aern_protocol_error_channel_down;
                }
            }
            else
            {
                res = aern_protocol_error_node_not_found;
            }
        }
    }

    qsc_memutils_secure_erase(outwire, sizeof(outwire));

    return res;
}

static aern_protocol_errors route_plaintext_delay_or_send(aern_forward_state* fwd, uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint64_t sessionid, uint64_t packetid, uint64_t expiry, uint8_t egresshint)
{
    aern_ingress_pending_item item = { 0 };
    uint64_t delay;
    aern_protocol_errors res;

    delay = 0U;
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && plaintext != NULL && fwd->relay_cache != NULL)
    {
        if (route_ingress_delay_enabled() == true)
        {
            delay = route_random_delay_milliseconds();

            if (delay != 0U)
            {
                if (route_pending_item_set_packet(&item, plaintext, AERN_RELAY_PLAINTEXT_SIZE, sessionid, packetid, expiry, qsc_timestamp_epochtime_milliseconds() + delay) == true && 
                    aern_relay_delay_push(fwd->relay_cache, &item) == true)
                {
                    res = aern_protocol_error_none;
                }
                else
                {
                    res = aern_protocol_error_memory_allocation;
                }
            }
            else
            {
                res = route_plaintext_send(fwd, plaintext, egresshint);
            }
        }
        else
        {
            res = route_plaintext_send(fwd, plaintext, egresshint);
        }
    }

    aern_relayqueue_item_dispose(&item);

    return res;
}

static aern_protocol_errors route_session_open_send(aern_forward_state* fwd, const aern_relay_session_cache_entry* session)
{
    aern_relay_payload_header header = { 0 };
    aern_relay_session_open open = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t* body;
    uint16_t actual;
    aern_protocol_errors res;

    actual = (uint16_t)(AERN_RELAY_PAYLOAD_HEADER_SIZE + AERN_RELAY_SESSION_OPEN_SIZE);
    body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && session != NULL)
    {
        header.sessionid = session->sessionid;
        header.packetid = 0U;
        header.fragseq = 0U;
        header.fragcount = 0U;
        header.msglen = AERN_RELAY_SESSION_OPEN_SIZE;
        header.payloadtype = (uint8_t)aern_relay_payload_session_open;
        header.reserved = session->reserved[0U];
        header.flags = 0U;

        open.sessionid = session->sessionid;
        open.ingresshint = session->ingresshint;
        open.egresshint = session->egresshint;
        open.port = session->port;
        open.reserved = session->reserved[0U];
        open.flags = session->flags;
        qsc_memutils_copy(open.destination, session->destination, AERN_CERTIFICATE_ADDRESS_SIZE);

        aern_packet_pad(plaintext, actual);
        aern_relay_payload_header_serialize(body, &header);
        aern_relay_session_open_serialize(body + AERN_RELAY_PAYLOAD_HEADER_SIZE, &open);
        res = route_plaintext_send(fwd, plaintext, session->egresshint);
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));

    return res;
}

static aern_protocol_errors route_session_ack_send(aern_forward_state* fwd, const aern_relay_session_cache_entry* session, uint8_t status)
{
    aern_relay_payload_header header = { 0 };
    aern_relay_session_open_ack ack = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t* body;
    uint16_t actual;
    aern_protocol_errors res;

    actual = (uint16_t)(AERN_RELAY_PAYLOAD_HEADER_SIZE + AERN_RELAY_SESSION_OPEN_ACK_SIZE);
    body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && session != NULL)
    {
        header.sessionid = session->sessionid;
        header.packetid = 0U;
        header.fragseq = 0U;
        header.fragcount = 0U;
        header.msglen = AERN_RELAY_SESSION_OPEN_ACK_SIZE;
        header.payloadtype = (uint8_t)aern_relay_payload_session_open_ack;
        header.reserved = session->reserved[0U];
        header.flags = 0U;

        ack.sessionid = session->sessionid;
        ack.status = status;
        ack.flags = 0U;
        ack.reserved = 0U;

        aern_packet_pad(plaintext, actual);
        aern_relay_payload_header_serialize(body, &header);
        aern_relay_session_open_ack_serialize(body + AERN_RELAY_PAYLOAD_HEADER_SIZE, &ack);
        res = route_plaintext_send(fwd, plaintext, session->ingresshint);
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));

    return res;
}

static aern_protocol_errors route_release_pending_session(aern_forward_state* fwd, uint64_t sessionid, uint8_t egresshint)
{
    aern_ingress_pending_item item = { 0 };
    uint64_t now;
    size_t count;
    size_t i;
    uint32_t released;
    aern_protocol_errors res;
    aern_protocol_errors sres;

    count = 0U;
    i = 0U;
    released = 0U;
    now = qsc_timestamp_datetime_utc();
    res = aern_protocol_error_none;
    sres = aern_protocol_error_none;

    if (fwd != NULL && fwd->relay_cache != NULL && sessionid != 0U && egresshint != 0U)
    {
        count = aern_relayqueue_count(&fwd->relay_cache->pendingqueue);

        for (i = 0U; i < count; ++i)
        {
            if (aern_relay_pending_pop(fwd->relay_cache, &item) == true)
            {
                if (route_pending_item_valid(&item, now) == true)
                {
                    if (item.sessionid == sessionid)
                    {
                        sres = route_plaintext_delay_or_send(fwd, item.packet, item.sessionid, item.packetid, item.expiry, egresshint);

                        if (sres == aern_protocol_error_none)
                        {
                            released += 1U;
                        }
                        else
                        {
                            res = sres;

                            if (aern_relay_pending_push(fwd->relay_cache, &item) == false)
                            {
                                fwd->relay_cache->pendingdropped += 1U;
                            }
                        }
                    }
                    else
                    {
                        if (aern_relay_pending_push(fwd->relay_cache, &item) == false)
                        {
                            fwd->relay_cache->pendingdropped += 1U;
                        }
                    }
                }
                else
                {
                    fwd->relay_cache->pendingdropped += 1U;
                }

                aern_relayqueue_item_dispose(&item);
            }
        }

        fwd->relay_cache->pendingreleased += (uint64_t)released;

        if (res == aern_protocol_error_none)
        {
            res = aern_ingress_delay_flush(fwd);
        }
    }
    else
    {
        res = aern_protocol_error_invalid_request;
    }

    return res;
}

static bool route_session_open_valid(const aern_forward_state* fwd, const aern_relay_payload_header* header, const aern_relay_session_open* open)
{
    bool res;

    res = false;

    if (fwd != NULL && header != NULL && open != NULL)
    {
        if (route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_session_open, AERN_RELAY_SESSION_OPEN_SIZE) == true &&
            open->sessionid == header->sessionid && open->reserved == 0U &&
            route_hint_in_range(open->ingresshint, fwd->apscount) == true && 
            route_hint_in_range(open->egresshint, fwd->apscount) == true)
        {
            res = true;
        }
    }

    return res;
}

static bool route_session_matches_open(const aern_relay_session_cache_entry* session, const aern_relay_session_open* open)
{
    bool res;

    res = false;

    if (session != NULL && open != NULL)
    {
        if (session->sessionid == open->sessionid && session->ingresshint == open->ingresshint &&
            session->egresshint == open->egresshint && session->port == open->port &&
            session->status == (uint8_t)aern_relay_session_status_active &&
            qsc_memutils_are_equal(session->destination, open->destination, AERN_CERTIFICATE_ADDRESS_SIZE) == true)
        {
            res = true;
        }
    }

    return res;
}

static aern_protocol_errors route_terminal_session_open(aern_forward_state* fwd, const aern_relay_payload_header* header, const uint8_t* body)
{
    aern_relay_session_cache_entry session = { 0 };
    aern_relay_session_open open = { 0 };
    uint64_t now;
    aern_protocol_errors res;
    bool found;

    found = false;
    now = qsc_timestamp_datetime_utc();
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && header != NULL && body != NULL && fwd->relay_cache != NULL)
    {
        aern_relay_session_open_deserialize(&open, body);

        if (route_session_open_valid(fwd, header, &open) == true)
        {
            found = aern_relay_session_find(fwd->relay_cache, &session, open.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS);

            if (found == true)
            {
                if (route_session_matches_open(&session, &open) == true)
                {
                    session.activity = now;
                    (void)aern_relay_session_add(fwd->relay_cache, &session);
                    res = route_session_ack_send(fwd, &session, 0U);
                }
            }
            else
            {
                session.sessionid = open.sessionid;
                session.created = now;
                session.activity = now;
                session.expiry = now + (uint64_t)AERN_RELAY_SESSION_TIMEOUT_SECONDS;
                session.ingresshint = open.ingresshint;
                session.egresshint = open.egresshint;
                session.port = open.port;
                session.reserved[0U] = open.reserved;
                session.status = (uint8_t)aern_relay_session_status_active;
                session.context = AERN_RELAY_SESSION_CONTEXT_EGRESS;
                session.flags = open.flags;
                session.transport = (uint8_t)aern_exit_transport_status_pending;
                session.txcount = 0U;
                session.rxcount = 0U;
                session.txfail = 0U;
                session.rxfail = 0U;

                qsc_memutils_copy(session.destination, open.destination, AERN_CERTIFICATE_ADDRESS_SIZE);

                if (aern_relay_session_add(fwd->relay_cache, &session) == true)
                {
                    res = route_session_ack_send(fwd, &session, 0U);
                }
                else
                {
                    res = aern_protocol_error_memory_allocation;
                }
            }
        }
    }

    return res;
}

static bool route_session_ack_valid(const aern_relay_payload_header* header, const aern_relay_session_open_ack* ack)
{
    bool res;

    res = false;

    if (header != NULL && ack != NULL)
    {
        if (route_payload_control_header_valid(header, (uint8_t)aern_relay_payload_session_open_ack, AERN_RELAY_SESSION_OPEN_ACK_SIZE) == true &&
            ack->sessionid == header->sessionid && ack->flags == 0U && ack->reserved == 0U)
        {
            res = true;
        }
    }

    return res;
}

static aern_protocol_errors route_terminal_session_ack(aern_forward_state* fwd, const aern_relay_payload_header* header, const uint8_t* body)
{
    aern_relay_session_cache_entry session = { 0 };
    aern_relay_session_open_ack ack = { 0 };
    uint32_t removed;
    aern_protocol_errors res;

    removed = 0U;
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && header != NULL && body != NULL && fwd->relay_cache != NULL)
    {
        aern_relay_session_open_ack_deserialize(&ack, body);

        if (route_session_ack_valid(header, &ack) == true)
        {
            if (aern_relay_session_find(fwd->relay_cache, &session, ack.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true)
            {
                if (ack.status == 0U)
                {
                    if (session.status == (uint8_t)aern_relay_session_status_pending)
                    {
                        session.status = (uint8_t)aern_relay_session_status_active;
                        session.activity = qsc_timestamp_datetime_utc();

                        if (aern_relay_session_add(fwd->relay_cache, &session) == true)
                        {
                            res = route_release_pending_session(fwd, ack.sessionid, session.egresshint);
                        }
                    }
                    else if (session.status == (uint8_t)aern_relay_session_status_active)
                    {
                        session.activity = qsc_timestamp_datetime_utc();
                        (void)aern_relay_session_add(fwd->relay_cache, &session);
                        res = aern_protocol_error_none;
                    }
                }
                else
                {
                    session.status = (uint8_t)aern_relay_session_status_closing;
                    session.activity = qsc_timestamp_datetime_utc();
                    (void)aern_relay_session_add(fwd->relay_cache, &session);
                    removed = aern_relay_pending_remove_session(fwd->relay_cache, ack.sessionid);
                    (void)removed;
                    res = aern_protocol_error_connection_failure;
                }
            }
        }
    }

    return res;
}

static bool route_exit_session_valid(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* data, size_t datalen)
{
    bool res;

    res = false;

    if (session != NULL && header != NULL && data != NULL)
    {
        if (session->status == (uint8_t)aern_relay_session_status_active && session->context == AERN_RELAY_SESSION_CONTEXT_EGRESS &&
            header->sessionid == session->sessionid && header->packetid != 0U && header->fragseq == 0U && header->fragcount == 0U &&
            header->msglen != 0U && (size_t)header->msglen == datalen && datalen <= AERN_FRAGMENT_CACHE_MEMORY_MAX &&
            header->payloadtype == (uint8_t)aern_relay_payload_data && header->reserved == 0U &&
            header->flags == AERN_RELAY_PAYLOAD_FLAG_OUTBOUND)
        {
            res = true;
        }
    }

    return res;
}

static bool route_ingress_session_valid(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* data, size_t datalen)
{
    bool res;

    res = false;

    if (session != NULL && header != NULL && data != NULL)
    {
        if (session->status == (uint8_t)aern_relay_session_status_active && session->context == AERN_RELAY_SESSION_CONTEXT_INGRESS &&
            header->sessionid == session->sessionid && header->packetid != 0U && header->fragseq == 0U && header->fragcount == 0U &&
            header->msglen != 0U && (size_t)header->msglen == datalen && datalen <= AERN_FRAGMENT_CACHE_MEMORY_MAX &&
            header->payloadtype == (uint8_t)aern_relay_payload_data && header->reserved == 0U &&
            header->flags == AERN_RELAY_PAYLOAD_FLAG_RETURN)
        {
            res = true;
        }
    }

    return res;
}

static aern_protocol_errors route_terminal_fragment_process(aern_forward_state* fwd, aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* data)
{
    aern_relay_payload_header hcopy = { 0 };
    uint8_t* assembled;
    aern_fragment_cache* fcache;
    size_t declaredlen;
    size_t before;
    size_t outlen;
    uint8_t direction;
    aern_protocol_errors res;
    bool complete;

    fcache = NULL;
    assembled = NULL;
    declaredlen = 0U;
    before = 0U;
    outlen = 0U;
    direction = aern_relay_fragment_direction_outbound;
    res = aern_protocol_error_invalid_request;
    complete = false;

    if (session != NULL && session->context == AERN_RELAY_SESSION_CONTEXT_INGRESS)
    {
        direction = aern_relay_fragment_direction_inbound;
    }

    if (fwd != NULL && session != NULL && header != NULL && data != NULL && fwd->relay_cache != NULL &&
        header->msglen != 0U && header->msglen <= AERN_RELAY_DATA_PAYLOAD_SIZE && header->fragseq != 0U &&
        header->fragcount != 0U && header->fragseq <= header->fragcount && header->fragcount <= AERN_MAX_FRAGMENTS)
    {
        declaredlen = (size_t)header->fragcount * (size_t)AERN_FRAG_CHUNK_SIZE;
        fcache = aern_fragment_table_get_or_add(&fwd->relay_cache->fragments, header->sessionid, header->packetid,
            direction, header->fragcount, qsc_timestamp_datetime_utc() + (uint64_t)AERN_RELAY_FRAGMENT_TIMEOUT_SECONDS, declaredlen);

        if (fcache != NULL && fcache->expiry >= qsc_timestamp_datetime_utc())
        {
            before = fcache->declared_length;
            complete = aern_fragment_cache_add_relay_fragment(fcache, header, data, (size_t)header->msglen, direction);

            if (before > fcache->declared_length && fwd->relay_cache->fragments.memoryused >= (before - fcache->declared_length))
            {
                fwd->relay_cache->fragments.memoryused -= (before - fcache->declared_length);
            }

            if (complete == true)
            {
                if (aern_fragment_cache_assemble_alloc(fcache, &assembled, &outlen) == true)
                {
                    hcopy = *header;
                    hcopy.fragseq = 0U;
                    hcopy.fragcount = 0U;
                    hcopy.msglen = (uint32_t)outlen;

                    if (session->context == AERN_RELAY_SESSION_CONTEXT_INGRESS)
                    {
                        res = aern_ingress_transport_send_serialized_packet(session, &hcopy, assembled, outlen);

                        if (res == aern_protocol_error_none)
                        {
                            session->rxcount += 1U;
                            session->rxfail = 0U;
                        }
                        else
                        {
                            session->rxfail += 1U;
                        }
                    }
                    else
                    {
                        res = aern_exit_transport_send_serialized_packet(session, &hcopy, assembled, outlen);

                        if (res == aern_protocol_error_none)
                        {
                            session->txcount += 1U;
                            session->txfail = 0U;
                            session->transport = (uint8_t)aern_exit_transport_status_active;
                        }
                        else
                        {
                            session->txfail += 1U;
                            session->transport = (uint8_t)aern_exit_transport_status_unimplemented;
                        }
                    }

                    session->activity = qsc_timestamp_datetime_utc();
                    (void)aern_relay_session_add(fwd->relay_cache, session);
                    qsc_memutils_secure_erase(assembled, outlen);
                    qsc_memutils_alloc_free(assembled);
                    aern_fragment_table_remove(&fwd->relay_cache->fragments, header->sessionid, header->packetid, direction);
                }
                else
                {
                    res = aern_protocol_error_memory_allocation;
                }
            }
            else
            {
                res = aern_protocol_error_none;
            }
        }
        else if (fcache != NULL)
        {
            aern_fragment_table_remove(&fwd->relay_cache->fragments, header->sessionid, header->packetid, direction);
            res = aern_protocol_error_message_time_invalid;
        }
    }

    return res;
}

static aern_protocol_errors route_terminal_data(aern_forward_state* fwd, const aern_relay_payload_header* header, const uint8_t* data)
{
    aern_relay_session_cache_entry session = { 0 };
    uint8_t context;
    aern_protocol_errors res;

    context = AERN_RELAY_SESSION_CONTEXT_EGRESS;
    res = aern_protocol_error_invalid_request;

    if (header != NULL && (header->flags & AERN_RELAY_PAYLOAD_FLAG_RETURN) != 0U)
    {
        context = AERN_RELAY_SESSION_CONTEXT_INGRESS;
    }

    if (fwd != NULL && header != NULL && data != NULL && fwd->relay_cache != NULL)
    {
        if (aern_relay_session_find(fwd->relay_cache, &session, header->sessionid, context) == true)
        {
            if (session.status == (uint8_t)aern_relay_session_status_active && header->msglen != 0U && header->msglen <= AERN_RELAY_DATA_PAYLOAD_SIZE)
            {
                session.activity = qsc_timestamp_datetime_utc();
                (void)aern_relay_session_add(fwd->relay_cache, &session);

                if (header->fragseq == 0U && header->fragcount == 0U)
                {
                    if (context == AERN_RELAY_SESSION_CONTEXT_INGRESS)
                    {
                        res = aern_ingress_transport_send_serialized_packet(&session, header, data, (size_t)header->msglen);

                        if (res == aern_protocol_error_none)
                        {
                            session.rxcount += 1U;
                            session.rxfail = 0U;
                        }
                        else
                        {
                            session.rxfail += 1U;
                        }
                    }
                    else
                    {
                        res = aern_exit_transport_send_serialized_packet(&session, header, data, (size_t)header->msglen);

                        if (res == aern_protocol_error_none)
                        {
                            session.txcount += 1U;
                            session.txfail = 0U;
                            session.transport = (uint8_t)aern_exit_transport_status_active;
                        }
                        else
                        {
                            session.txfail += 1U;
                            session.transport = (uint8_t)aern_exit_transport_status_unimplemented;
                        }
                    }

                    session.activity = qsc_timestamp_datetime_utc();
                    (void)aern_relay_session_add(fwd->relay_cache, &session);
                }
                else
                {
                    res = route_terminal_fragment_process(fwd, &session, header, data);
                }
            }
        }
        else
        {
            /* unknown-session terminal data can be dummy or stale data; drop without state mutation. */
            res = aern_protocol_error_none;
        }
    }

    return res;
}

static aern_protocol_errors route_terminal_payload_process(aern_forward_state* fwd, uint8_t* payload, uint16_t actual)
{
    aern_relay_payload_header header = { 0 };
    uint8_t* body;
    aern_protocol_errors res;

    body = payload + AERN_RELAY_PAYLOAD_HEADER_SIZE;
    res = aern_protocol_error_packet_header_invalid;

    if (route_payload_header_read(&header, payload, actual) == true)
    {
        switch ((aern_relay_payload_type)header.payloadtype)
        {
            case aern_relay_payload_session_open:
            {
                res = route_terminal_session_open(fwd, &header, body);
                break;
            }
            case aern_relay_payload_session_open_ack:
            {
                res = route_terminal_session_ack(fwd, &header, body);
                break;
            }
            case aern_relay_payload_data:
            {
                res = route_terminal_data(fwd, &header, body);
                break;
            }
            case aern_relay_payload_dummy:
            {
                if (fwd != NULL && fwd->relay_cache != NULL &&
                    fwd->relay_cache->initialized == true)
                {
                    ++fwd->relay_cache->dummydropped;
                }

                res = aern_protocol_error_none;
                break;
            }
            default:
            {
                res = aern_protocol_error_invalid_request;
                break;
            }
        }
    }

    return res;
}
void aern_relay_cache_initialize(aern_relay_cache_state* cache)
{
    uint64_t nowms;
    bool fragok;

    AERN_ASSERT(cache != NULL);

    nowms = qsc_timestamp_epochtime_milliseconds();
    fragok = false;

    if (cache != NULL)
    {
        qsc_memutils_clear(cache, sizeof(aern_relay_cache_state));

        aern_relaysession_initialize(&cache->sessions);
        aern_relayqueue_initialize(&cache->pendingqueue, AERN_INGRESS_PENDING_QUEUE_DEPTH);
        aern_relayqueue_initialize(&cache->delayqueue, AERN_INGRESS_DELAY_QUEUE_DEPTH);
        fragok = aern_fragment_table_initialize(&cache->fragments, AERN_FRAGMENT_TABLE_DEPTH, AERN_FRAGMENT_CACHE_MEMORY_MAX);

        if (cache->sessions.initialized == true && cache->pendingqueue.initialized == true &&
            cache->delayqueue.initialized == true && fragok == true)
        {
            cache->windowstartms = nowms;
            cache->dummywindowms = nowms;
            cache->nextdummyms = nowms;
            cache->initialized = true;
        }
        else
        {
            aern_relay_cache_dispose(cache);
        }
    }
}

void aern_relay_cache_dispose(aern_relay_cache_state* cache)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL)
    {
        aern_relaysession_dispose(&cache->sessions);
        aern_fragment_table_dispose(&cache->fragments);
        aern_relayqueue_dispose(&cache->pendingqueue);
        aern_relayqueue_dispose(&cache->delayqueue);
        qsc_memutils_secure_erase(cache, sizeof(aern_relay_cache_state));
    }
}

void aern_relay_cache_cleanup(aern_relay_cache_state* cache)
{
    uint64_t nowsec;
    uint64_t nowms;

    AERN_ASSERT(cache != NULL);

    nowsec = qsc_timestamp_datetime_utc();
    nowms = qsc_timestamp_epochtime_milliseconds();

    if ((cache != NULL) && (cache->initialized == true))
    {
        (void)aern_relaysession_cleanup_expired(&cache->sessions, nowsec);
        (void)aern_fragment_table_cleanup_expired(&cache->fragments, nowsec);
        (void)aern_relayqueue_cleanup_expired(&cache->pendingqueue, nowsec);
        (void)aern_relayqueue_cleanup_expired(&cache->delayqueue, nowsec);

        if ((cache->windowstartms == 0U) || ((nowms - cache->windowstartms) >= AERN_RELAY_TRAFFIC_WINDOW_MILLISECONDS))
        {
            cache->windowstartms = nowms;
            cache->relaytxbytes = 0U;
            cache->relayrxbytes = 0U;
        }

        if ((cache->dummywindowms == 0U) || ((nowms - cache->dummywindowms) >= AERN_RELAY_TRAFFIC_WINDOW_MILLISECONDS))
        {
            cache->dummywindowms = nowms;
            cache->dummywindowcount = 0U;
        }
    }
}

aern_protocol_errors aern_route_generate(aern_route_map* rm, uint8_t apscount, uint8_t originhint, uint8_t targethint)
{
    uint8_t hops;
    uint8_t pos;
    uint8_t candidate;
    uint8_t prevhint;
    uint8_t maxhops;
    uint8_t attempts;
    aern_protocol_errors res;

    hops = 0U;
    pos = 0U;
    candidate = 0U;
    prevhint = 0U;
    maxhops = 0U;
    attempts = 0U;
    res = aern_protocol_error_invalid_request;

    if (rm != NULL && apscount >= AERN_ROUTE_MIN_HOPS && route_hint_in_range(originhint, apscount) == true &&
        route_hint_in_range(targethint, apscount) == true && originhint != targethint)
    {
        qsc_memutils_clear(rm, sizeof(aern_route_map));

        maxhops = AERN_ROUTE_MAX_HOPS;

        if (maxhops > AERN_ROUTE_PATH_SIZE)
        {
            maxhops = AERN_ROUTE_PATH_SIZE;
        }

        if (maxhops > apscount)
        {
            maxhops = apscount;
        }

        hops = (uint8_t)(AERN_ROUTE_MIN_HOPS + rng_uint8_range((uint8_t)(maxhops - AERN_ROUTE_MIN_HOPS + 1U)));
        rm->path[0U] = originhint;
        prevhint = originhint;

        for (pos = 1U; pos < (uint8_t)(hops - 1U); ++pos)
        {
            attempts = 0U;

            while (true)
            {
                candidate = route_hint_from_index(rng_uint8_range(apscount));
                ++attempts;

                if (attempts > 64U)
                {
                    res = aern_protocol_error_node_not_found;
                    break;
                }

                if (candidate != 0U && candidate != originhint && candidate != targethint && candidate != prevhint)
                {
                    rm->path[pos] = candidate;
                    prevhint = candidate;
                    res = aern_protocol_error_none;
                    break;
                }
            }

            if (res != aern_protocol_error_none)
            {
                break;
            }
        }

        if (res == aern_protocol_error_none || pos == 1U)
        {
            if (prevhint != targethint)
            {
                rm->path[hops - 1U] = targethint;
                rm->hopcount = hops;
                res = aern_protocol_error_none;
            }
            else
            {
                res = aern_protocol_error_node_not_found;
            }
        }
    }

    return res;
}

void aern_route_map_serialize(uint8_t dst[AERN_ROUTEMAP_SIZE], const aern_route_map* rm)
{
    AERN_ASSERT(dst != NULL);
    AERN_ASSERT(rm  != NULL);

    if (dst != NULL && rm != NULL)
    {
        qsc_memutils_copy(dst, rm->path, AERN_ROUTEMAP_SIZE);
    }
}

void aern_route_map_deserialize(aern_route_map* rm, const uint8_t src[AERN_ROUTEMAP_SIZE])
{
    AERN_ASSERT(rm  != NULL);
    AERN_ASSERT(src != NULL);

    if (rm != NULL && src != NULL)
    {
        qsc_memutils_secure_erase(rm, sizeof(aern_route_map));
        qsc_memutils_copy(rm->path, src, AERN_ROUTEMAP_SIZE);
        rm->hopcount = 0U;
    }
}

void aern_relay_payload_header_serialize(uint8_t output[AERN_RELAY_PAYLOAD_HEADER_SIZE], const aern_relay_payload_header* header)
{
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(header != NULL);

    size_t pos;

    if (output != NULL && header != NULL)
    {
        qsc_memutils_clear(output, AERN_RELAY_PAYLOAD_HEADER_SIZE);

        qsc_intutils_le64to8(output, header->sessionid);
        pos = sizeof(uint64_t);
        qsc_intutils_le64to8(output + pos, header->packetid);
        pos += sizeof(uint64_t);
        qsc_intutils_le32to8(output + pos, header->fragseq);
        pos += sizeof(uint32_t);
        qsc_intutils_le32to8(output + pos, header->fragcount);
        pos += sizeof(uint32_t);
        qsc_intutils_le32to8(output + pos, header->msglen);
        pos += sizeof(uint32_t);
        output[pos] = header->payloadtype;
        pos += sizeof(uint8_t);
        output[pos] = header->reserved;
        pos += sizeof(uint8_t);
        qsc_intutils_le16to8(output + pos, header->flags);
    }
}

void aern_relay_payload_header_deserialize(aern_relay_payload_header* header, const uint8_t input[AERN_RELAY_PAYLOAD_HEADER_SIZE])
{
    AERN_ASSERT(header != NULL);
    AERN_ASSERT(input != NULL);

    size_t pos;

    if (header != NULL && input != NULL)
    {
        qsc_memutils_clear(header, sizeof(aern_relay_payload_header));

        header->sessionid = qsc_intutils_le8to64(input);
        pos = sizeof(uint64_t);
        header->packetid = qsc_intutils_le8to64(input + pos);
        pos += sizeof(uint64_t);
        header->fragseq = qsc_intutils_le8to32(input + pos);
        pos += sizeof(uint32_t);
        header->fragcount = qsc_intutils_le8to32(input + pos);
        pos += sizeof(uint32_t);
        header->msglen = qsc_intutils_le8to32(input + pos);
        pos += sizeof(uint32_t);
        header->payloadtype = input[pos];
        pos += sizeof(uint8_t);
        header->reserved = input[pos];
        pos += sizeof(uint8_t);
        header->flags = qsc_intutils_le8to16(input + pos);
    }
}

void aern_relay_session_open_serialize(uint8_t output[AERN_RELAY_SESSION_OPEN_SIZE], const aern_relay_session_open* state)
{
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(state != NULL);

    size_t pos;

    if (output != NULL && state != NULL)
    {
        qsc_memutils_clear(output, AERN_RELAY_SESSION_OPEN_SIZE);

        qsc_intutils_le64to8(output, state->sessionid);
        pos = sizeof(uint64_t);
        qsc_memutils_copy(output + pos, state->destination, AERN_CERTIFICATE_ADDRESS_SIZE);
        pos += AERN_CERTIFICATE_ADDRESS_SIZE;
        output[pos] = state->ingresshint;
        pos += sizeof(uint8_t);
        output[pos] = state->egresshint;
        pos += sizeof(uint8_t);
        qsc_intutils_le16to8(output + pos, state->port);
        pos += sizeof(uint16_t);
        output[pos] = state->reserved;
        pos += sizeof(uint8_t);
        output[pos] = state->flags;
    }
}

void aern_relay_session_open_deserialize(aern_relay_session_open* state, const uint8_t input[AERN_RELAY_SESSION_OPEN_SIZE])
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(input != NULL);

    size_t pos;

    if (state != NULL && input != NULL)
    {
        qsc_memutils_clear(state, sizeof(aern_relay_session_open));

        state->sessionid = qsc_intutils_le8to64(input);
        pos = sizeof(uint64_t);
        qsc_memutils_copy(state->destination, input + pos, AERN_CERTIFICATE_ADDRESS_SIZE);
        pos += AERN_CERTIFICATE_ADDRESS_SIZE;
        state->ingresshint = input[pos];
        pos += sizeof(uint8_t);
        state->egresshint = input[pos];
        pos += sizeof(uint8_t);
        state->port = qsc_intutils_le8to16(input + pos);
        pos += sizeof(uint16_t);
        state->reserved = input[pos];
        pos += sizeof(uint8_t);
        state->flags = input[pos];
    }
}

void aern_relay_session_open_ack_serialize(uint8_t output[AERN_RELAY_SESSION_OPEN_ACK_SIZE], const aern_relay_session_open_ack* state)
{
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(state != NULL);

    size_t pos;

    if (output != NULL && state != NULL)
    {
        qsc_memutils_clear(output, AERN_RELAY_SESSION_OPEN_ACK_SIZE);

        qsc_intutils_le64to8(output, state->sessionid);
        pos = sizeof(uint64_t);
        output[pos] = state->status;
        pos += sizeof(uint8_t);
        output[pos] = state->flags;
        pos += sizeof(uint8_t);
        qsc_intutils_le16to8(output + pos, state->reserved);
    }
}

void aern_relay_session_open_ack_deserialize(aern_relay_session_open_ack* state, const uint8_t input[AERN_RELAY_SESSION_OPEN_ACK_SIZE])
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(input != NULL);

    size_t pos;

    if (state != NULL && input != NULL)
    {
        qsc_memutils_clear(state, sizeof(aern_relay_session_open_ack));

        state->sessionid = qsc_intutils_le8to64(input);
        pos = sizeof(uint64_t);
        state->status = input[pos];
        pos += sizeof(uint8_t);
        state->flags = input[pos];
        pos += sizeof(uint8_t);
        state->reserved = qsc_intutils_le8to16(input + pos);
    }
}

void aern_packet_pad(uint8_t  plaintext[AERN_RELAY_PLAINTEXT_SIZE], uint16_t textlen)
{
    AERN_ASSERT(plaintext  != NULL);
    AERN_ASSERT(textlen <= AERN_MAX_USER_PAYLOAD);

    if (plaintext != NULL && textlen <= AERN_MAX_USER_PAYLOAD)
    {
        /* write the 2-byte LE length prefix */
        plaintext[0U] = (uint8_t)(textlen & 0xFFU);
        plaintext[1U] = (uint8_t)((textlen >> 8U) & 0xFFU);

        /* fill padding region with cryptographic random bytes */
        size_t pstart = (size_t)(AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE + textlen);
        size_t plen = AERN_RELAY_PLAINTEXT_SIZE - pstart;

        if (plen > 0U)
        {
            qsc_csp_generate(plaintext + pstart, plen);
        }
    }
}

uint16_t aern_packet_unpad(const uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE])
{
    AERN_ASSERT(plaintext != NULL);

    uint16_t len;

    len = 0U;

    if (plaintext != NULL)
    {
        len = (uint16_t)(plaintext[0U] | ((uint16_t)plaintext[1U] << 8U));

        if (len > AERN_MAX_USER_PAYLOAD)
        {
            return 0U;
        }
    }

    return len;
}

void aern_relay_session_key_create(uint8_t key[QSC_COLLECTION_KEY_WIDTH], uint64_t sessionid, uint8_t context)
{
    size_t i;

    AERN_ASSERT(key != NULL);

    if (key != NULL)
    {
        qsc_memutils_clear(key, QSC_COLLECTION_KEY_WIDTH);

        for (i = 0U; i < 8U; ++i)
        {
            key[i] = (uint8_t)((sessionid >> (i * 8U)) & 0xFFU);
        }

        key[8U] = context;
    }
}

bool aern_relay_session_add(aern_relay_cache_state* cache, const aern_relay_session_cache_entry* entry)
{
    bool res;

    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(entry != NULL);

    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true)
    {
        res = aern_relaysession_add(&cache->sessions, entry);
    }

    return res;
}

bool aern_relay_session_exists(const aern_relay_cache_state* cache, uint64_t sessionid, uint8_t context)
{
    bool res;

    AERN_ASSERT(cache != NULL);

    res = false;

    if (cache != NULL && cache->initialized == true)
    {
        res = aern_relaysession_exists(&cache->sessions, sessionid, context);
    }

    return res;
}

bool aern_relay_session_find(const aern_relay_cache_state* cache, aern_relay_session_cache_entry* entry, uint64_t sessionid, uint8_t context)
{
    bool res;

    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(entry != NULL);

    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true)
    {
        res = aern_relaysession_find(&cache->sessions, entry, sessionid, context);
    }

    return res;
}

void aern_relay_session_remove(aern_relay_cache_state* cache, uint64_t sessionid, uint8_t context)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL && cache->initialized == true)
    {
        aern_relaysession_remove(&cache->sessions, sessionid, context);
    }
}

bool route_dummy_traffic_allowed(aern_relay_cache_state* cache, uint32_t utilization, uint64_t nowms)
{
    bool res;

    res = false;

    if (cache != NULL && cache->initialized == true && AERN_DUMMY_TRAFFIC_ENABLED != 0U)
    {
        route_dummy_window_update(cache, nowms);

        if (utilization >= AERN_DUMMY_TRAFFIC_BANDWIDTH_CEILING_PERCENT)
        {
            cache->dummysuppressed = true;
        }
        else if (utilization <= AERN_DUMMY_TRAFFIC_BANDWIDTH_FLOOR_PERCENT)
        {
            cache->dummysuppressed = false;
        }

        if (cache->dummysuppressed == false && cache->dummywindowcount < AERN_DUMMY_TRAFFIC_MAXIMUM_PER_WINDOW)
        {
            if (cache->nextdummyms == 0U || nowms >= cache->nextdummyms)
            {
                res = true;
            }
        }
    }

    return res;
}

bool aern_relay_forward_state_is_valid(const aern_forward_state* fwd, bool requirecache)
{
    bool res;

    res = false;

    if (fwd != NULL)
    {
        if (fwd->conn_table != NULL && fwd->topology != NULL && fwd->apscount >= AERN_ROUTE_MINIMUM_HOPS && fwd->ownhint != 0U && fwd->ownhint <= fwd->apscount)
        {
            if (requirecache == false)
            {
                res = true;
            }
            else if (fwd->relay_cache != NULL && fwd->relay_cache->initialized == true)
            {
                res = true;
            }
        }
    }

    return res;
}

aern_protocol_errors aern_ingress_delay_flush(aern_forward_state* fwd)
{
    aern_ingress_pending_item item = { 0 };
    aern_relay_session_cache_entry session = { 0 };
    uint64_t nowms;
    uint64_t nowsec;
    size_t count;
    size_t i;
    aern_protocol_errors res;

    count = 0U;
    i = 0U;
    nowms = qsc_timestamp_epochtime_milliseconds();
    nowsec = qsc_timestamp_datetime_utc();
    res = aern_protocol_error_invalid_request;

    if (fwd != NULL && fwd->relay_cache != NULL && fwd->relay_cache->initialized == true)
    {
        res = aern_protocol_error_none;
        count = aern_relayqueue_count(&fwd->relay_cache->delayqueue);

        for (i = 0U; i < count; ++i)
        {
            if (aern_relay_delay_pop(fwd->relay_cache, &item) == true)
            {
                if (item.expiry != 0U && item.expiry < nowsec)
                {
                    aern_relayqueue_item_dispose(&item);
                }
                else if (item.delayuntil == 0U || item.delayuntil <= nowms)
                {
                    if (aern_relay_session_find(fwd->relay_cache, &session, item.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true &&
                        session.status == (uint8_t)aern_relay_session_status_active)
                    {
                        res = route_plaintext_send(fwd, item.packet, session.egresshint);
                    }
                    else
                    {
                        (void)aern_relay_delay_push(fwd->relay_cache, &item);
                    }
                }
                else
                {
                    (void)aern_relay_delay_push(fwd->relay_cache, &item);
                }

                aern_relayqueue_item_dispose(&item);
                qsc_memutils_secure_erase(&session, sizeof(session));
            }
        }
    }

    return res;
}

void aern_relay_traffic_observe(aern_relay_cache_state* cache, size_t pktlen, bool inbound)
{
    uint64_t nowms;

    nowms = qsc_timestamp_epochtime_milliseconds();

    if (cache != NULL && cache->initialized == true)
    {
        if (cache->windowstartms == 0U)
        {
            cache->windowstartms = nowms;
        }

        if (inbound == true)
        {
            cache->relayrxbytes += (uint64_t)pktlen;
        }
        else
        {
            cache->relaytxbytes += (uint64_t)pktlen;
        }
    }
}

uint32_t aern_relay_traffic_utilization(const aern_relay_cache_state* cache)
{
    uint64_t percent;
    uint64_t total;
    uint32_t res;

    res = 0U;
    total = 0U;
    percent = 0U;

    if (cache != NULL && cache->initialized == true && AERN_DUMMY_TRAFFIC_WINDOW_TARGET_BYTES != 0U)
    {
        total = cache->relayrxbytes + cache->relaytxbytes;
        percent = (total * 100U) / (uint64_t)AERN_DUMMY_TRAFFIC_WINDOW_TARGET_BYTES;

        if (percent > 100U)
        {
            res = 100U;
        }
        else
        {
            res = (uint32_t)percent;
        }
    }

    return res;
}

aern_protocol_errors aern_dummy_traffic_generate(aern_forward_state* fwd, uint32_t utilization)
{
    aern_relay_payload_header header = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t* body;
    uint8_t* data;
    uint64_t nowms;
    uint64_t delay;
    uint16_t actual;
    aern_protocol_errors res;

    actual = 0U;
    body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
    data = body + AERN_RELAY_PAYLOAD_HEADER_SIZE;
    delay = 0U;
    nowms = qsc_timestamp_epochtime_milliseconds();
    res = aern_protocol_error_invalid_request;

    if (aern_relay_forward_state_is_valid(fwd, true) == true)
    {
        aern_relay_cache_cleanup(fwd->relay_cache);
        res = aern_protocol_error_none;

        if (route_dummy_traffic_allowed(fwd->relay_cache, utilization, nowms) == true)
        {
            qsc_csp_generate(plaintext, sizeof(plaintext));
            qsc_memutils_clear(plaintext + AERN_LEN_PREFIX_SIZE, AERN_ROUTEMAP_SIZE);

            header.sessionid = route_random64();
            header.packetid = route_random64();
            header.fragseq = 0U;
            header.fragcount = 0U;
            header.msglen = (uint32_t)AERN_RELAY_DATA_PAYLOAD_SIZE;
            header.payloadtype = (uint8_t)aern_relay_payload_dummy;
            header.reserved = 0U;
            header.flags = 0U;

            aern_relay_payload_header_serialize(body, &header);
            qsc_csp_generate(data, AERN_RELAY_DATA_PAYLOAD_SIZE);
            actual = (uint16_t)AERN_MAX_USER_PAYLOAD;
            aern_packet_pad(plaintext, actual);

            res = route_plaintext_send(fwd, plaintext, 0U);

            delay = route_random_dummy_interval_milliseconds();

            if (delay == 0U)
            {
                delay = (uint64_t)AERN_DUMMY_TRAFFIC_INTERVAL_MAXIMUM_MILLISECONDS;
            }

            fwd->relay_cache->lastdummyms = nowms;
            fwd->relay_cache->nextdummyms = nowms + delay;

            if (res == aern_protocol_error_none)
            {
                ++fwd->relay_cache->dummysent;
                ++fwd->relay_cache->dummywindowcount;
            }
        }
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
    qsc_memutils_secure_erase(&header, sizeof(header));

    return res;
}

aern_protocol_errors aern_return_packet_send(aern_forward_state* fwd, aern_relay_session_cache_entry* session, const uint8_t* packet, size_t pktlen)
{
    aern_relay_payload_header header = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t* body;
    uint8_t* data;
    uint64_t packetid;
    uint64_t now;
    uint32_t fragcount;
    uint32_t fragseq;
    size_t offset;
    size_t remain;
    size_t clen;
    uint16_t actual;
    aern_protocol_errors res;
    bool valid;

    actual = 0U;
    body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
    clen = 0U;
    data = body + AERN_RELAY_PAYLOAD_HEADER_SIZE;
    fragcount = 0U;
    fragseq = 0U;
    now = 0U;
    offset = 0U;
    packetid = 0U;
    remain = 0U;
    res = aern_protocol_error_invalid_request;
    valid = false;

    if (aern_relay_forward_state_is_valid(fwd, true) == true && session != NULL && packet != NULL && 
        pktlen != 0U && session->status == (uint8_t)aern_relay_session_status_active && 
        session->context == AERN_RELAY_SESSION_CONTEXT_EGRESS && session->ingresshint != 0U && session->sessionid != 0U &&
        true && pktlen <= AERN_FRAGMENT_CACHE_MEMORY_MAX)
    {
        fragcount = (uint32_t)((pktlen + (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE - 1U) / (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE);

        if (fragcount != 0U && fragcount <= AERN_MAX_FRAGMENTS)
        {
            packetid = route_random64();
            valid = (packetid != 0U);
        }
    }

    if (valid == true)
    {
        res = aern_protocol_error_none;

        while (res == aern_protocol_error_none && offset < pktlen)
        {
            remain = pktlen - offset;
            clen = (remain > (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE) ? (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE : remain;

            qsc_memutils_clear(plaintext, sizeof(plaintext));
            qsc_memutils_clear(&header, sizeof(header));

            header.sessionid = session->sessionid;
            header.packetid = packetid;
            header.msglen = (uint32_t)clen;
            header.payloadtype = (uint8_t)aern_relay_payload_data;
            header.reserved = session->reserved[0U];
            header.flags = AERN_RELAY_PAYLOAD_FLAG_RETURN;

            if (fragcount > 1U)
            {
                fragseq += 1U;
                header.fragseq = fragseq;
                header.fragcount = fragcount;
            }
            else
            {
                header.fragseq = 0U;
                header.fragcount = 0U;
            }

            actual = (uint16_t)(AERN_RELAY_PAYLOAD_HEADER_SIZE + clen);
            aern_packet_pad(plaintext, actual);
            aern_relay_payload_header_serialize(body, &header);
            qsc_memutils_copy(data, packet + offset, clen);
            res = route_plaintext_send(fwd, plaintext, session->ingresshint);

            if (res == aern_protocol_error_none)
            {
                offset += clen;
            }
        }

        now = qsc_timestamp_datetime_utc();
        session->activity = now;

        if (res == aern_protocol_error_none && offset == pktlen && fragseq <= fragcount)
        {
            session->rxcount += 1U;
            session->rxfail = 0U;
            session->transport = (uint8_t)aern_exit_transport_status_active;
        }
        else
        {
            session->rxfail += 1U;

            if (session->transport == (uint8_t)aern_exit_transport_status_none)
            {
                session->transport = (uint8_t)aern_exit_transport_status_unimplemented;
            }
        }

        (void)aern_relay_session_add(fwd->relay_cache, session);
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
    qsc_memutils_secure_erase(&header, sizeof(header));

    return res;
}

void aern_exit_transport_set_callback(aern_exit_transport_send_callback callback, void* context)
{
    qsc_mutex mtx;

    mtx = route_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    m_exit_transport_callback = callback;
    m_exit_transport_context = context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }
}

void aern_ingress_transport_set_callback(aern_ingress_transport_send_callback callback, void* context)
{
    qsc_mutex mtx;

    mtx = route_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    m_ingress_transport_callback = callback;
    m_ingress_transport_context = context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }
}

aern_protocol_errors aern_exit_transport_send_serialized_packet(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen)
{
    AERN_ASSERT(session != NULL);
    AERN_ASSERT(header != NULL);
    AERN_ASSERT(packet != NULL);

    aern_exit_transport_send_callback cb;
    void* ctx;
    aern_protocol_errors res;

    qsc_mutex mtx;

    mtx = route_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    cb = m_exit_transport_callback;
    ctx = m_exit_transport_context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }

    res = aern_protocol_error_invalid_request;

    if (route_exit_session_valid(session, header, packet, pktlen) == true)
    {
        if (cb != NULL)
        {
            res = cb(session, header, packet, pktlen, ctx);
        }
        else
        {
            res = aern_protocol_error_operation_cancelled;
        }
    }

    return res;
}

aern_protocol_errors aern_exit_transport_return_serialized_packet(aern_forward_state* fwd, const aern_relay_session_cache_entry* session, const uint8_t* packet, size_t pktlen)
{
    AERN_ASSERT(session != NULL);
    AERN_ASSERT(packet != NULL);

    aern_relay_session_cache_entry scopy;
    aern_protocol_errors res;

    res = aern_protocol_error_invalid_request;
    qsc_memutils_clear(&scopy, sizeof(scopy));

    if (aern_relay_forward_state_is_valid(fwd, true) == true && session != NULL && packet != NULL && pktlen != 0U &&
        session->status == (uint8_t)aern_relay_session_status_active && session->context == AERN_RELAY_SESSION_CONTEXT_EGRESS &&
        session->sessionid != 0U && session->ingresshint != 0U && pktlen <= AERN_FRAGMENT_CACHE_MEMORY_MAX )
    {
        qsc_memutils_copy((uint8_t*)&scopy, (const uint8_t*)session, sizeof(scopy));
        res = aern_return_packet_send(fwd, &scopy, packet, pktlen);
    }

    qsc_memutils_secure_erase(&scopy, sizeof(scopy));

    return res;
}

aern_protocol_errors aern_ingress_transport_send_serialized_packet(const aern_relay_session_cache_entry* session, const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen)
{
    AERN_ASSERT(session != NULL);
    AERN_ASSERT(header != NULL);
    AERN_ASSERT(packet != NULL);

    aern_ingress_transport_send_callback cb;
    void* ctx;
    aern_protocol_errors res;

    qsc_mutex mtx;

    mtx = route_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    cb = m_ingress_transport_callback;
    ctx = m_ingress_transport_context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }

    res = aern_protocol_error_invalid_request;

    if (route_ingress_session_valid(session, header, packet, pktlen) == true)
    {
        if (cb != NULL)
        {
            res = cb(session, header, packet, pktlen, ctx);
        }
        else
        {
            res = aern_protocol_error_operation_cancelled;
        }
    }

    return res;
}

aern_protocol_errors aern_entry_packet_forward(aern_forward_state* fwd, uint8_t wire[AERN_RELAY_MTU], const char* srcip)
{
    AERN_ASSERT(fwd != NULL);
    AERN_ASSERT(wire != NULL);
    AERN_ASSERT(srcip != NULL);

    aern_network_packet pktin = { 0 };
    aern_route_map rm = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    aern_connection_state* rxcns;
    aern_protocol_errors res;
    size_t ptlen;

    rxcns = NULL;
    ptlen = 0U;
    res = aern_protocol_error_invalid_request;

    if (wire != NULL && srcip != NULL && aern_relay_forward_state_is_valid(fwd, true) == true)
    {
        if (fwd->relay_cache != NULL)
        {
            aern_relay_cache_cleanup(fwd->relay_cache);
            (void)aern_ingress_delay_flush(fwd);
        }

        rxcns = aern_cipher_table_get_by_ip(fwd->conn_table, srcip);

        if (rxcns != NULL)
        {
            aern_packet_header_deserialize(wire, &pktin);
            pktin.pmessage = wire + AERN_RELAY_HEADER_SIZE;

            if (route_relay_header_valid(&pktin) == true)
            {
                res = aern_decrypt_packet(rxcns, plaintext, &ptlen, &pktin);
            }
            else
            {
                res = aern_protocol_error_packet_header_invalid;
            }

            if (res == aern_protocol_error_none)
            {
                if (ptlen == AERN_RELAY_PLAINTEXT_SIZE)
                {
                    aern_relay_payload_header rhead = { 0 };
                    aern_relay_session_cache_entry rentry = { 0 };
                    aern_ingress_pending_item pitem = { 0 };
                    uint8_t* rbody;
                    uint16_t ractual;
                    uint8_t ownhint;
                    uint8_t targethint;
                    uint64_t now;

                    rbody = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
                    ownhint = fwd->ownhint;
                    targethint = 0U;
                    now = qsc_timestamp_datetime_utc();

                    if (route_entry_plaintext_valid(plaintext, &ractual) == true && route_payload_header_read(&rhead, rbody, ractual) == true &&
                        (rhead.payloadtype == (uint8_t)aern_relay_payload_data) && fwd->relay_cache != NULL)
                    {
                        if (rhead.packetid == 0U)
                        {
                            res = aern_protocol_error_packet_header_invalid;
                        }
                        else if (rhead.sessionid != 0U && aern_relay_session_find(fwd->relay_cache, &rentry, rhead.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS) == true)
                        {
                            if (rentry.status == (uint8_t)aern_relay_session_status_active)
                            {
                                res = route_plaintext_delay_or_send(fwd, plaintext, rhead.sessionid, rhead.packetid, rentry.expiry, rentry.egresshint);
                            }
                            else if (rentry.status == (uint8_t)aern_relay_session_status_pending)
                            {
                                if (route_pending_item_set_packet(&pitem, plaintext, AERN_RELAY_PLAINTEXT_SIZE, rentry.sessionid, rhead.packetid, rentry.expiry, 0U) == true &&
                                    aern_relay_pending_push(fwd->relay_cache, &pitem) == true)
                                {
                                    res = aern_protocol_error_none;
                                }
                                else
                                {
                                    res = aern_protocol_error_memory_allocation;
                                }
                            }
                            else
                            {
                                res = aern_protocol_error_invalid_request;
                            }
                        }
                        else
                        {
                            if (rhead.sessionid == 0U)
                            {
                                rhead.sessionid = route_random64();
                                aern_relay_payload_header_serialize(rbody, &rhead);
                            }

                            do
                            {
                                targethint = route_hint_from_index(rng_uint8_range(fwd->apscount));
                            }
                            while (targethint == 0U || targethint == ownhint);

                            res = aern_route_generate(&rm, fwd->apscount, ownhint, targethint);

                            if (res == aern_protocol_error_none)
                            {
                                rentry.sessionid = rhead.sessionid;
                                rentry.created = now;
                                rentry.activity = now;
                                rentry.expiry = now + (uint64_t)AERN_RELAY_SESSION_TIMEOUT_SECONDS;
                                rentry.ingresshint = ownhint;
                                rentry.egresshint = targethint;
                                rentry.reserved[0U] = rhead.reserved;
                                rentry.status = (uint8_t)aern_relay_session_status_pending;
                                rentry.context = AERN_RELAY_SESSION_CONTEXT_INGRESS;
                                rentry.flags = 0U;
                                rentry.transport = (uint8_t)aern_exit_transport_status_none;
                                rentry.txcount = 0U;
                                rentry.rxcount = 0U;
                                rentry.txfail = 0U;
                                rentry.rxfail = 0U;

                                if (aern_relay_session_add(fwd->relay_cache, &rentry) == true)
                                {
                                    if (route_pending_item_set_packet(&pitem, plaintext, AERN_RELAY_PLAINTEXT_SIZE, rentry.sessionid,
                                        rhead.packetid, rentry.expiry, 0U) == true &&
                                        aern_relay_pending_push(fwd->relay_cache, &pitem) == true)
                                    {
                                        res = route_session_open_send(fwd, &rentry);
                                    }
                                    else
                                    {
                                        aern_relay_session_remove(fwd->relay_cache, rentry.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS);
                                        res = aern_protocol_error_memory_allocation;
                                    }
                                }
                                else
                                {
                                    res = aern_protocol_error_memory_allocation;
                                }
                            }
                        }
                    }
                    else
                    {
                        res = aern_protocol_error_packet_header_invalid;
                    }

                    aern_relayqueue_item_dispose(&pitem);
                }
                else
                {
                    res = aern_protocol_error_packet_header_invalid;
                }
            }
        }
        else
        {
            res = aern_protocol_error_channel_down;
        }
    }

    return res;
}

aern_protocol_errors aern_packet_forward(aern_forward_state* fwd, uint8_t wire[AERN_RELAY_MTU], const char* src_ip)
{
    AERN_ASSERT(fwd != NULL);
    AERN_ASSERT(wire != NULL);
    AERN_ASSERT(src_ip != NULL);

    aern_topology_node_state nextnode = { 0 };
    qsc_socket nsock = { 0 };
    aern_network_packet pktin = { 0 };
    aern_network_packet pktout = { 0 };
    aern_route_map rm = { 0 };
    uint8_t outwire[AERN_RELAY_MTU] = { 0U };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    aern_connection_state* rxcns;
    aern_connection_state* txcns;
    size_t ptlen;
    size_t slen;
    uint16_t actual;
    uint8_t nexthint;
    aern_protocol_errors res;
    bool isexit;

    rxcns = NULL;
    txcns = NULL;
    actual = 0U;
    nexthint = 0U;
    ptlen = 0U;
    slen = 0U;
    isexit = false;
    res = aern_protocol_error_invalid_request;

    if (wire != NULL && src_ip != NULL && aern_relay_forward_state_is_valid(fwd, true) == true)
    {
        if (fwd->relay_cache != NULL)
        {
            aern_relay_cache_cleanup(fwd->relay_cache);
        }

        rxcns = aern_cipher_table_get_by_ip(fwd->conn_table, src_ip);

        if (rxcns != NULL)
        {
            aern_packet_header_deserialize(wire, &pktin);
            pktin.pmessage = wire + AERN_RELAY_HEADER_SIZE;

            if (route_relay_header_valid(&pktin) == true)
            {
                res = aern_decrypt_packet(rxcns, plaintext, &ptlen, &pktin);
            }
            else
            {
                res = aern_protocol_error_packet_header_invalid;
            }

            if (res == aern_protocol_error_none)
            {
                if (ptlen == AERN_RELAY_PLAINTEXT_SIZE && route_relay_plaintext_valid(plaintext, fwd->apscount, &rm, &actual) == true)
                {
                    isexit = (route_map_has_future(&rm) == false);

                    if (isexit == true)
                    {
                        res = route_terminal_payload_process(fwd, plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE, actual);
                    }
                    else
                    {
                        res = route_consume_next(&rm, fwd->apscount, &nexthint);

                            if (res == aern_protocol_error_none)
                            {
                                if (route_node_from_hint(fwd->topology, nexthint, &nextnode) == true)
                                {
                                    txcns = aern_cipher_table_get_by_ip(fwd->conn_table, nextnode.address);

                                    if (txcns != NULL)
                                    {
                                        aern_route_map_serialize(plaintext + AERN_LEN_PREFIX_SIZE, &rm);
                                        pktout.pmessage = outwire + AERN_RELAY_HEADER_SIZE;
                                        res = aern_encrypt_packet(txcns, &pktout, plaintext, AERN_RELAY_PLAINTEXT_SIZE);

                                        if (res == aern_protocol_error_none)
                                        {
                                            pktout.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
                                            aern_packet_header_serialize(&pktout, outwire);

                                            if (aern_network_connect_to_device(&nsock, nextnode.address, aern_network_designation_aps) == qsc_socket_exception_success)
                                            {
                                                slen = qsc_socket_send(&nsock, outwire, AERN_RELAY_MTU, qsc_socket_send_flag_none);
                                                aern_network_socket_dispose(&nsock);

                                                if (slen == AERN_RELAY_MTU)
                                                {
                                                    aern_relay_traffic_observe(fwd->relay_cache, AERN_RELAY_MTU, false);
                                                    res = aern_protocol_error_none;
                                                }
                                                else
                                                {
                                                    res = aern_protocol_error_transmit_failure;
                                                }
                                            }
                                            else
                                            {
                                                res = aern_protocol_error_connection_failure;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        res = aern_protocol_error_channel_down;
                                    }
                                }
                                else
                                {
                                    res = aern_protocol_error_node_not_found;
                                }
                            }
                        }
                    }
                    else
                    {
                        res = aern_protocol_error_packet_header_invalid;
                    }
                }
            }
        else
        {
            res = aern_protocol_error_key_unrecognized;
        }
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
    qsc_memutils_secure_erase(outwire, sizeof(outwire));

    return res;
}


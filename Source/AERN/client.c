#include "client.h"
#include "aern.h"
#include "certificate.h"
#include "commands.h"
#include "menu.h"
#include "network.h"
#include "fragment.h"
#include "mek.h"
#include "resources.h"
#include "route.h"
#include "server.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "memutils.h"
#include "socketclient.h"
#include "stringutils.h"
#include "timestamp.h"

static aern_client_transport_receive_callback m_client_transport_callback = NULL;
static void* m_client_transport_context = NULL;
static qsc_mutex m_clientcallbackmtx = NULL;
static volatile int32_t m_clientcallbackmtxstate = 0;
static aern_server_application_state m_client_application_state = { 0 };
static aern_child_certificate m_client_local_certificate = { 0 };
static aern_child_certificate m_client_entry_certificate = { 0 };
static aern_cipher_table m_client_cipher_table = { 0 };
static aern_relay_cache_state m_client_relay_cache = { 0 };
static aern_server_server_loop_status m_client_loop_status;
static char m_client_entry_address[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
static uint64_t m_client_session_id = 0U;
static uint64_t m_client_packet_id = 0U;
static uint64_t m_client_rx_count = 0U;
static uint64_t m_client_rx_fail = 0U;


static aern_protocol_errors client_aps_certificate_request(const aern_topology_node_state* rnode);
static bool client_aps_certificate_load(const aern_topology_node_state* rnode, aern_child_certificate* rcert);
static bool client_topology_certificate_match(const aern_topology_node_state* node, const aern_child_certificate* cert, const aern_root_certificate* root, aern_network_designations designation);
static bool client_cipher_table_entry_established(const aern_cipher_table* table, const aern_topology_node_state* entry);
static bool client_aps_certificate_matches_node(const aern_topology_node_state* rnode, const aern_child_certificate* rcert);
static aern_protocol_errors client_entry_connect(const char* address);
static aern_protocol_errors client_entry_connect_node(const aern_topology_node_state* rnode);
static bool client_entry_node_select(aern_topology_node_state* rnode);
static bool client_local_certificate_load(void);
static aern_protocol_errors client_relay_payload_process(uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE]);
static aern_protocol_errors client_relay_send(const uint8_t* message, size_t msglen);
static aern_protocol_errors client_return_fragment_process(const aern_relay_payload_header* header, const uint8_t* data);


static qsc_mutex client_transport_callback_mutex(void)
{
    qsc_mutex mtx;
    int32_t state;
    bool init;

    mtx = NULL;
    state = qsc_async_atomic_int32_load(&m_clientcallbackmtxstate);

    if (state != 2)
    {
        init = qsc_async_atomic_int32_compare_exchange(&m_clientcallbackmtxstate, 0, 1);

        if (init == true)
        {
            mtx = qsc_async_mutex_create();
            m_clientcallbackmtx = mtx;
            qsc_async_atomic_int32_store(&m_clientcallbackmtxstate, (mtx != NULL) ? 2 : -1);
        }
        else
        {
            do
            {
                qsc_async_thread_sleep(1U);
                state = qsc_async_atomic_int32_load(&m_clientcallbackmtxstate);
            }
            while (state == 1);
        }
    }

    if (qsc_async_atomic_int32_load(&m_clientcallbackmtxstate) == 2)
    {
        mtx = m_clientcallbackmtx;
    }

    return mtx;
}

static uint64_t client_random64(void)
{
    uint8_t rnd[sizeof(uint64_t)] = { 0U };
    uint64_t res;
    size_t pos;

    res = 0U;
    qsc_acp_generate(rnd, sizeof(rnd));

    for (pos = 0U; pos < sizeof(uint64_t); ++pos)
    {
        res |= ((uint64_t)rnd[pos] << (8U * pos));
    }

    if (res == 0U)
    {
        res = qsc_timestamp_datetime_utc();
    }

    qsc_memutils_secure_erase(rnd, sizeof(rnd));

    return res;
}

static bool client_topology_certificate_match(const aern_topology_node_state* node, const aern_child_certificate* cert, const aern_root_certificate* root, aern_network_designations designation)
{
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(cert != NULL);
	AERN_ASSERT(root != NULL);

	uint8_t chash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (node != NULL && cert != NULL && root != NULL)
	{
		if (node->designation == designation && cert->designation == designation &&
			aern_network_certificate_verify(cert, root) == aern_protocol_error_none)
		{
			aern_certificate_child_hash(chash, cert);

			if (qsc_memutils_are_equal(node->chash, chash, AERN_CERTIFICATE_HASH_SIZE) == true &&
				qsc_memutils_are_equal(node->serial, cert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
				qsc_stringutils_strings_equal(node->issuer, cert->issuer) == true &&
				node->expiration.from == cert->expiration.from &&
				node->expiration.to == cert->expiration.to)
			{
				res = true;
			}
		}
	}

    qsc_memutils_secure_erase(chash, sizeof(chash));

	return res;
}

static bool client_cipher_table_entry_established(const aern_cipher_table* table, const aern_topology_node_state* entry)
{
	AERN_ASSERT(table != NULL);
	AERN_ASSERT(entry != NULL);

	qsc_mutex mtx;
	size_t pos;
	bool res;

	mtx = NULL;
	pos = 0U;
	res = false;

	if (table != NULL && entry != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
		{
			if (table->slots[pos].used == true &&
				qsc_memutils_are_equal(table->slots[pos].serial, entry->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
				qsc_stringutils_strings_equal(table->slots[pos].address, entry->address) == true)
			{
				if (table->slots[pos].status == aern_mesh_peer_status_synchronized &&
					table->slots[pos].rekeypending == false &&
					table->slots[pos].cns.exflag == aern_network_flag_tunnel_session_established)
				{
					res = true;
				}

				break;
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_client_entry_context_is_valid(const aern_root_certificate* root, const aern_child_certificate* lcert, const aern_topology_list_state* topology, 
    const aern_topology_node_state* entry, const aern_child_certificate* entrycert, const aern_cipher_table* ctable)
{
	AERN_ASSERT(root != NULL);
	AERN_ASSERT(lcert != NULL);
	AERN_ASSERT(topology != NULL);
	AERN_ASSERT(entry != NULL);
	AERN_ASSERT(entrycert != NULL);
	AERN_ASSERT(ctable != NULL);

	aern_topology_node_state tnode = { 0 };
	bool res;

	res = false;

	if (root != NULL && lcert != NULL && topology != NULL && entry != NULL && entrycert != NULL && ctable != NULL)
	{
		if (aern_certificate_root_is_valid(root) == true &&
			aern_network_certificate_verify(lcert, root) == aern_protocol_error_none &&
			lcert->designation == aern_network_designation_client &&
			topology->count != 0U && topology->version != 0U &&
			entry->designation == aern_network_designation_aps &&
			aern_topology_node_find(topology, &tnode, entry->serial) == true)
		{
			if (qsc_memutils_are_equal(tnode.serial, entry->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
				qsc_stringutils_strings_equal(tnode.address, entry->address) == true &&
				client_topology_certificate_match(&tnode, entrycert, root, aern_network_designation_aps) == true &&
				client_cipher_table_entry_established(ctable, &tnode) == true)
			{
				res = true;
			}
		}
	}

    qsc_memutils_secure_erase(&tnode, sizeof(tnode));

	return res;
}

static bool client_aps_certificate_matches_node(const aern_topology_node_state* rnode, const aern_child_certificate* rcert)
{
    AERN_ASSERT(rnode != NULL);
    AERN_ASSERT(rcert != NULL);

    bool res;

    res = false;

    if (rnode != NULL && rcert != NULL)
    {
        res = client_topology_certificate_match(rnode, rcert, &m_client_application_state.root, aern_network_designation_aps);
    }

    return res;
}


static bool client_aps_node_count(uint16_t* count)
{
    AERN_ASSERT(count != NULL);

    aern_topology_node_state node = { 0 };
    size_t pos;
    bool res;

    res = false;

    if (count != NULL)
    {
        *count = 0U;
        res = true;

        for (pos = 0U; pos < m_client_application_state.tlist.count && res == true; ++pos)
        {
            qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

            if (aern_topology_list_item(&m_client_application_state.tlist, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps)
                {
                    if (*count < (uint16_t)~0U)
                    {
                        ++(*count);
                    }
                    else
                    {
                        res = false;
                    }
                }
            }
            else
            {
                res = false;
            }
        }
    }

    return res;
}

static bool client_aps_node_by_ordinal(aern_topology_node_state* rnode, uint16_t ordinal)
{
    AERN_ASSERT(rnode != NULL);

    aern_topology_node_state node = { 0 };
    size_t pos;
    uint16_t count;
    bool res;

    res = false;
    count = 0U;

    if (rnode != NULL)
    {
        for (pos = 0U; pos < m_client_application_state.tlist.count && res == false; ++pos)
        {
            qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

            if (aern_topology_list_item(&m_client_application_state.tlist, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps)
                {
                    if (count == ordinal)
                    {
                        qsc_memutils_copy((uint8_t*)rnode, (const uint8_t*)&node, sizeof(aern_topology_node_state));
                        res = true;
                    }

                    ++count;
                }
            }
        }
    }

    return res;
}

static bool client_entry_node_select(aern_topology_node_state* rnode)
{
    AERN_ASSERT(rnode != NULL);

    uint8_t rnd[2U] = { 0U };
    uint16_t count;
    uint16_t index;
    bool res;

    count = 0U;
    index = 0U;
    rnd[0U] = 0U;
    rnd[1U] = 0U;
    res = false;

    if (rnode != NULL)
    {
        if (client_aps_node_count(&count) == true && count != 0U)
        {
            qsc_acp_generate(rnd, sizeof(rnd));
            index = (uint16_t)((uint16_t)rnd[0] | ((uint16_t)rnd[1] << 8U));
            index = (uint16_t)(index % count);
            res = client_aps_node_by_ordinal(rnode, index);
        }
    }

    return res;
}

static bool client_aps_certificate_load(const aern_topology_node_state* rnode, aern_child_certificate* rcert)
{
    AERN_ASSERT(rnode != NULL);
    AERN_ASSERT(rcert != NULL);

    aern_protocol_errors merr;
    bool res;

    res = false;

    if (rnode != NULL && rcert != NULL)
    {
        qsc_memutils_clear(rcert, sizeof(aern_child_certificate));

        if (aern_server_child_certificate_from_serial(rcert, &m_client_application_state, rnode->serial) == true)
        {
            res = client_aps_certificate_matches_node(rnode, rcert);
        }

        if (res == false)
        {
            merr = client_aps_certificate_request(rnode);

            if (merr == aern_protocol_error_none)
            {
                qsc_memutils_clear(rcert, sizeof(aern_child_certificate));

                if (aern_server_child_certificate_from_serial(rcert, &m_client_application_state, rnode->serial) == true)
                {
                    res = client_aps_certificate_matches_node(rnode, rcert);
                }
            }
        }
    }

    return res;
}


void aern_client_transport_set_callback(aern_client_transport_receive_callback callback, void* context)
{
    qsc_mutex mtx;

    mtx = client_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    m_client_transport_callback = callback;
    m_client_transport_context = context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }
}

aern_protocol_errors aern_client_transport_receive_serialized_packet(const aern_relay_payload_header* header, const uint8_t* packet, size_t pktlen)
{
    AERN_ASSERT(header != NULL);
    AERN_ASSERT(packet != NULL);

    aern_client_transport_receive_callback cb;
    void* ctx;
    aern_protocol_errors res;

    qsc_mutex mtx;

    mtx = client_transport_callback_mutex();

    if (mtx != NULL)
    {
        qsc_async_mutex_lock(mtx);
    }

    cb = m_client_transport_callback;
    ctx = m_client_transport_context;

    if (mtx != NULL)
    {
        qsc_async_mutex_unlock(mtx);
    }

    res = aern_protocol_error_invalid_request;

    if (header != NULL && packet != NULL && pktlen != 0U)
    {
        if ((header->flags & AERN_RELAY_PAYLOAD_FLAG_RETURN) != 0U &&
            header->sessionid == m_client_session_id && header->msglen == pktlen &&
            (header->payloadtype == (uint8_t)aern_relay_payload_data))
        {
            if (cb != NULL)
            {
                res = cb(header, packet, pktlen, ctx);
            }
            else
            {
                res = aern_protocol_error_operation_cancelled;
            }
        }
    }

    return res;
}

static aern_protocol_errors client_return_fragment_process(const aern_relay_payload_header* header, const uint8_t* data)
{
    aern_relay_payload_header hcopy = { 0 };
    aern_fragment_cache* fcache;
    uint8_t* assembled;
    size_t declaredlen;
    size_t outlen;
    aern_protocol_errors res;
    bool complete;

    fcache = NULL;
    assembled = NULL;
    declaredlen = 0U;
    outlen = 0U;
    complete = false;
    res = aern_protocol_error_invalid_request;

    if (header != NULL && data != NULL && header->sessionid == m_client_session_id &&
        header->msglen != 0U && header->msglen <= AERN_RELAY_DATA_PAYLOAD_SIZE &&
        header->fragseq != 0U && header->fragcount != 0U &&
        header->fragseq <= header->fragcount && header->fragcount <= AERN_MAX_FRAGMENTS &&
        (header->flags & AERN_RELAY_PAYLOAD_FLAG_RETURN) != 0U)
    {
        declaredlen = (size_t)header->fragcount * (size_t)AERN_FRAG_CHUNK_SIZE;
        fcache = aern_fragment_table_get_or_add(&m_client_relay_cache.fragments, header->sessionid, header->packetid,
            (uint8_t)aern_relay_fragment_direction_inbound, header->fragcount,
            qsc_timestamp_datetime_utc() + (uint64_t)AERN_RELAY_FRAGMENT_TIMEOUT_SECONDS, declaredlen);

        if (fcache != NULL && fcache->expiry >= qsc_timestamp_datetime_utc())
        {
            complete = aern_fragment_cache_add_relay_fragment(fcache, header, data, (size_t)header->msglen,
                (uint8_t)aern_relay_fragment_direction_inbound);

            if (complete == true)
            {
                if (aern_fragment_cache_assemble_alloc(fcache, &assembled, &outlen) == true)
                {
                    hcopy = *header;
                    hcopy.fragseq = 0U;
                    hcopy.fragcount = 0U;
                    hcopy.msglen = (uint32_t)outlen;
                    res = aern_client_transport_receive_serialized_packet(&hcopy, assembled, outlen);

                    if (res == aern_protocol_error_none)
                    {
                        m_client_rx_count += 1U;
                        m_client_rx_fail = 0U;
                    }
                    else
                    {
                        m_client_rx_fail += 1U;
                    }

                    qsc_memutils_secure_erase(assembled, outlen);
                    qsc_memutils_alloc_free(assembled);
                    aern_fragment_table_remove(&m_client_relay_cache.fragments, header->sessionid, header->packetid, (uint8_t)aern_relay_fragment_direction_inbound);
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
            aern_fragment_table_remove(&m_client_relay_cache.fragments, header->sessionid, header->packetid, (uint8_t)aern_relay_fragment_direction_inbound);
            res = aern_protocol_error_message_time_invalid;
        }
    }

    return res;
}

static aern_protocol_errors client_relay_payload_process(uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE])
{
    aern_relay_payload_header header = { 0 };
    uint8_t* body;
    uint8_t* data;
    uint16_t actual;
    aern_protocol_errors res;

    actual = 0U;
    body = NULL;
    data = NULL;
    res = aern_protocol_error_packet_header_invalid;

    if (plaintext != NULL)
    {
        actual = aern_packet_unpad(plaintext);
        body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
        data = body + AERN_RELAY_PAYLOAD_HEADER_SIZE;
        aern_relay_payload_header_deserialize(&header, body);

        if (actual >= AERN_RELAY_PAYLOAD_HEADER_SIZE)
        {
            if ((header.flags & AERN_RELAY_PAYLOAD_FLAG_RETURN) != 0U &&
                header.sessionid == m_client_session_id &&
                header.msglen <= (uint32_t)(actual - AERN_RELAY_PAYLOAD_HEADER_SIZE) &&
                (header.payloadtype == (uint8_t)aern_relay_payload_data))
            {
                if (header.fragseq == 0U && header.fragcount == 0U)
                {
                    res = aern_client_transport_receive_serialized_packet(&header, data, (size_t)header.msglen);

                    if (res == aern_protocol_error_none)
                    {
                        m_client_rx_count += 1U;
                        m_client_rx_fail = 0U;
                    }
                    else
                    {
                        m_client_rx_fail += 1U;
                    }
                }
                else
                {
                    res = client_return_fragment_process(&header, data);
                }
            }
        }
    }

    return res;
}

aern_protocol_errors aern_client_receive_once(void)
{
    aern_network_packet pktin = { 0 };
    aern_connection_state* cns;
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t wire[AERN_RELAY_MTU] = { 0U };
    size_t ptlen;
    size_t rlen;
    aern_protocol_errors res;

    cns = NULL;
    ptlen = 0U;
    rlen = 0U;
    res = aern_protocol_error_invalid_request;

    if (m_client_entry_address[0] != 0 && m_client_session_id != 0U)
    {
        cns = aern_cipher_table_get_by_ip(&m_client_cipher_table, m_client_entry_address);

        if (cns != NULL)
        {
            rlen = qsc_socket_receive(&cns->target, wire, AERN_RELAY_MTU, qsc_socket_receive_flag_wait_all);

            if (rlen == AERN_RELAY_MTU)
            {
                aern_packet_header_deserialize(wire, &pktin);
                pktin.pmessage = wire + AERN_RELAY_HEADER_SIZE;

                if (pktin.flag == aern_network_flag_tunnel_encrypted_message && pktin.msglen == AERN_RELAY_CIPHERTEXT_SIZE)
                {
                    res = aern_decrypt_packet(cns, plaintext, &ptlen, &pktin);

                    if (res == aern_protocol_error_none && ptlen == AERN_RELAY_PLAINTEXT_SIZE)
                    {
                        res = client_relay_payload_process(plaintext);
                    }
                }
                else
                {
                    res = aern_protocol_error_packet_header_invalid;
                }
            }
            else
            {
                res = aern_protocol_error_receive_failure;
            }
        }
        else
        {
            res = aern_protocol_error_channel_down;
        }
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
    qsc_memutils_secure_erase(wire, sizeof(wire));

    aern_relay_cache_cleanup(&m_client_relay_cache);

    return res;
}

static aern_protocol_errors client_relay_send(const uint8_t* message, size_t msglen)
{
    aern_network_packet pktout = { 0 };
    aern_relay_payload_header header = { 0 };
    uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
    uint8_t wire[AERN_RELAY_MTU] = { 0U };
    uint8_t* body;
    aern_connection_state* cns;
    uint8_t* data;
    size_t sent;
    size_t offset;
    size_t remain;
    size_t clen;
    uint32_t fragcount;
    uint32_t fragseq;
    uint16_t actual;
    aern_protocol_errors merr;
    bool done;

    AERN_ASSERT(message != NULL);

    body = plaintext + AERN_LEN_PREFIX_SIZE + AERN_ROUTEMAP_SIZE;
    data = body + AERN_RELAY_PAYLOAD_HEADER_SIZE;
    cns = NULL;
    sent = 0U;
    offset = 0U;
    remain = 0U;
    clen = 0U;
    fragcount = 0U;
    fragseq = 0U;
    actual = 0U;
    done = false;
    merr = aern_protocol_error_invalid_request;

    aern_relay_cache_cleanup(&m_client_relay_cache);

    if (message != NULL && msglen != 0U && msglen <= AERN_FRAGMENT_CACHE_MEMORY_MAX)
    {
        if (m_client_entry_address[0] != 0)
        {
            cns = aern_cipher_table_get_by_ip(&m_client_cipher_table, m_client_entry_address);

            if (cns != NULL)
            {
                if (m_client_session_id == 0U)
                {
                    m_client_session_id = client_random64();
                    m_client_packet_id = 0U;
                }

                m_client_packet_id += 1U;
                fragcount = (uint32_t)((msglen + (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE - 1U) / (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE);

                if (fragcount != 0U && fragcount <= AERN_MAX_FRAGMENTS)
                {
                    merr = aern_protocol_error_none;
                }

                while (merr == aern_protocol_error_none && done == false && offset < msglen)
                {
                    remain = msglen - offset;
                    clen = (remain > (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE) ? (size_t)AERN_RELAY_DATA_PAYLOAD_SIZE : remain;
                    fragseq += 1U;

                    qsc_memutils_clear(&header, sizeof(header));
                    qsc_memutils_clear(&pktout, sizeof(aern_network_packet));
                    qsc_memutils_clear(plaintext, sizeof(plaintext));
                    qsc_memutils_clear(wire, sizeof(wire));

                    header.sessionid = m_client_session_id;
                    header.packetid = m_client_packet_id;
                    header.msglen = (uint32_t)clen;
                    header.payloadtype = (uint8_t)aern_relay_payload_data;
                    header.reserved = 0U;
                    header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

                    if (fragcount > 1U)
                    {
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
                    qsc_memutils_copy(data, message + offset, clen);

                    pktout.pmessage = wire + AERN_RELAY_HEADER_SIZE;
                    merr = aern_encrypt_packet(cns, &pktout, plaintext, AERN_RELAY_PLAINTEXT_SIZE);

                    if (merr == aern_protocol_error_none)
                    {
                        pktout.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
                        aern_packet_header_serialize(&pktout, wire);
                        sent = qsc_socket_send(&cns->target, wire, AERN_RELAY_MTU, qsc_socket_send_flag_none);

                        if (sent == AERN_RELAY_MTU)
                        {
                            offset += clen;
                        }
                        else
                        {
                            merr = aern_protocol_error_transmit_failure;
                            done = true;
                        }
                    }
                    else
                    {
                        done = true;
                    }
                }
            }
            else
            {
                merr = aern_protocol_error_channel_down;
            }
        }
        else
        {
            merr = aern_protocol_error_channel_down;
        }
    }

    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
    qsc_memutils_secure_erase(wire, sizeof(wire));

    return merr;
}


static aern_protocol_errors client_entry_connect_node(const aern_topology_node_state* rnode)
{
    AERN_ASSERT(rnode != NULL);

    aern_child_certificate rcert = { 0 };
    aern_connection_state cns = { 0 };
    aern_mek_request_state reqs = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (rnode != NULL)
    {
        if (rnode->designation == aern_network_designation_aps)
        {
            if (client_local_certificate_load() == true &&
                client_aps_certificate_load(rnode, &rcert) == true)
            {
                reqs.remote_address = rnode->address;
                reqs.lcert = &m_client_local_certificate;
                reqs.rcert = &rcert;
                reqs.root = &m_client_application_state.root;
                reqs.sigkey = m_client_application_state.sigkey;
                reqs.cns_out = &cns;

                merr = aern_mek_exchange_request(&reqs);

                if (merr == aern_protocol_error_none)
                {
                    merr = aern_cipher_table_add_peer(&m_client_cipher_table, rnode->address, rnode->serial, &cns, aern_mesh_peer_status_synchronized);

                    if (merr == aern_protocol_error_none)
                    {
                        qsc_memutils_copy((uint8_t*)&m_client_entry_certificate, (const uint8_t*)&rcert, sizeof(aern_child_certificate));
                        qsc_stringutils_copy_string(m_client_entry_address, sizeof(m_client_entry_address), rnode->address);

                        if (m_client_session_id == 0U)
                        {
                            m_client_session_id = client_random64();
                            m_client_packet_id = 0U;
                        }
                    }
                    else
                    {
                        aern_connection_close(&cns.target, aern_network_error_channel_down, false);
                        qsc_memutils_secure_erase(&cns, sizeof(aern_connection_state));
                    }
                }
            }
            else
            {
                merr = aern_protocol_error_certificate_not_found;
            }
        }
    }

    return merr;
}

static aern_protocol_errors client_entry_connect(const char* address)
{
    aern_topology_node_state rnode = { 0 };
    aern_protocol_errors merr;
    bool res;

    merr = aern_protocol_error_node_not_found;
    res = false;

    if (m_client_application_state.joined == true)
    {
        if (address != NULL && qsc_stringutils_string_size(address) != 0U)
        {
            res = aern_topology_node_find_address(&m_client_application_state.tlist, &rnode, address);
        }
        else
        {
            res = client_entry_node_select(&rnode);
        }

        if (res == true && rnode.designation == aern_network_designation_aps)
        {
            merr = client_entry_connect_node(&rnode);
        }
    }
    else
    {
        merr = aern_protocol_error_invalid_request;
    }

    return merr;
}

static bool client_local_certificate_load(void)
{
    bool res;

    res = false;

    if (aern_server_topology_local_fetch(&m_client_application_state, &m_client_local_certificate) == true)
    {
        if (m_client_local_certificate.designation == aern_network_designation_client)
        {
            if (aern_certificate_child_is_valid(&m_client_local_certificate) == true &&
                aern_certificate_root_signature_verify(&m_client_local_certificate, &m_client_application_state.root) == true)
            {
                res = true;
            }
        }
    }

    return res;
}

static aern_protocol_errors client_aps_certificate_store(const aern_child_certificate* rcert)
{
    AERN_ASSERT(rcert != NULL);

    char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (rcert != NULL)
    {
        aern_server_child_certificate_path_from_issuer(&m_client_application_state, fpath, sizeof(fpath), rcert->issuer);

        if (qsc_fileutils_exists(fpath) == true)
        {
            qsc_fileutils_delete(fpath);
        }

        if (aern_certificate_child_struct_to_file(fpath, rcert) == true)
        {
            merr = aern_protocol_error_none;
        }
        else
        {
            merr = aern_protocol_error_file_not_written;
        }
    }

    return merr;
}


static aern_protocol_errors client_aps_certificate_request(const aern_topology_node_state* rnode)
{
    AERN_ASSERT(rnode != NULL);

    aern_child_certificate rcert = { 0 };
    aern_network_incremental_update_request_state reqs = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (rnode != NULL)
    {
        if (rnode->designation == aern_network_designation_aps)
        {
            reqs.rnode = rnode;
            reqs.rcert = &rcert;
            reqs.root = &m_client_application_state.root;

            merr = aern_network_incremental_update_request(&reqs);

            if (merr == aern_protocol_error_none)
            {
                if (client_aps_certificate_matches_node(rnode, &rcert) == true)
                {
                    merr = client_aps_certificate_store(&rcert);
                }
                else
                {
                    merr = aern_protocol_error_authentication_failure;
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

static aern_protocol_errors client_aps_certificate_sync(void)
{
    aern_topology_node_state rnode = { 0 };
    aern_protocol_errors merr;
    size_t pos;

    merr = aern_protocol_error_none;

    for (pos = 0U; pos < m_client_application_state.tlist.count && merr == aern_protocol_error_none; ++pos)
    {
        if (aern_topology_list_item(&m_client_application_state.tlist, &rnode, pos) == true)
        {
            if (rnode.designation == aern_network_designation_aps)
            {
                merr = client_aps_certificate_request(&rnode);
            }
        }
        else
        {
            merr = aern_protocol_error_decoding_failure;
        }
    }

    return merr;
}

static aern_protocol_errors client_topology_merge_update(const aern_topology_list_state* ulist)
{
    AERN_ASSERT(ulist != NULL);

    aern_topology_node_state node = { 0 };
    size_t pos;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (ulist != NULL)
    {
        merr = aern_protocol_error_none;

        for (pos = 0U; pos < ulist->count && merr == aern_protocol_error_none; ++pos)
        {
            if (aern_topology_list_item(ulist, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps &&
                    aern_certificate_expiration_time_verify(&node.expiration) == true &&
                    qsc_memutils_zeroed(node.serial, AERN_CERTIFICATE_SERIAL_SIZE) == false &&
                    qsc_memutils_zeroed(node.chash, AERN_CERTIFICATE_HASH_SIZE) == false)
                {
                    if (aern_topology_node_exists(&m_client_application_state.tlist, node.serial) == true)
                    {
                        aern_topology_node_remove(&m_client_application_state.tlist, node.serial);
                    }

                    aern_topology_child_add_item(&m_client_application_state.tlist, &node);
                }
            }
            else
            {
                merr = aern_protocol_error_decoding_failure;
            }
        }
    }

    return merr;
}

static aern_protocol_errors client_register_update_request(const char* address)
{
    AERN_ASSERT(address != NULL);

    aern_network_register_update_request_state reqs = { 0 };
    aern_topology_list_state ulist = { 0 };
    char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
    qsc_mutex mtx;
    aern_protocol_errors merr;
    bool dres;

    dres = true;
    merr = aern_protocol_error_invalid_request;

    if (address != NULL)
    {
        if (aern_server_topology_root_exists(&m_client_application_state) == true)
        {
            if (aern_certificate_root_is_valid(&m_client_application_state.root) == false)
            {
                if (aern_server_root_certificate_load(&m_client_application_state, &m_client_application_state.root, &m_client_application_state.tlist) == true)
                {
                    merr = aern_protocol_error_none;
                }
                else
                {
                    merr = aern_protocol_error_certificate_not_found;
                }
            }
            else
            {
                merr = aern_protocol_error_none;
            }

            if (merr == aern_protocol_error_none)
            {
                if (client_local_certificate_load() == false)
                {
                    merr = aern_protocol_error_certificate_not_found;
                }
            }

            if (merr == aern_protocol_error_none)
            {
                if (m_client_application_state.joined == true && m_client_application_state.adc.designation == aern_network_designation_adc)
                {
                    dres = aern_menu_print_predefined_message_confirm(aern_application_register_existing,
                        m_client_application_state.mode, m_client_application_state.hostname);

                    if (dres == true)
                    {
                        aern_server_topology_purge_externals(&m_client_application_state);
                    }
                }

                if (dres == true)
                {
                    aern_topology_list_initialize(&ulist);
                    reqs.address = address;
                    reqs.lcert = &m_client_local_certificate;
                    reqs.list = &ulist;
                    reqs.rcert = &m_client_application_state.adc;
                    reqs.root = &m_client_application_state.root;
                    reqs.sigkey = m_client_application_state.sigkey;

                    merr = aern_network_register_update_request(&reqs);

                    if (merr == aern_protocol_error_none)
                    {
                        if (m_client_application_state.adc.designation == aern_network_designation_adc &&
                            aern_network_certificate_verify(&m_client_application_state.adc, &m_client_application_state.root) == aern_protocol_error_none)
                        {
                            mtx = qsc_async_mutex_lock_ex();

                            aern_topology_child_register(&m_client_application_state.tlist, &m_client_application_state.adc, address);
                            merr = client_topology_merge_update(&ulist);

                            if (merr == aern_protocol_error_none)
                            {
                                aern_server_child_certificate_path_from_issuer(&m_client_application_state, fpath, sizeof(fpath), m_client_application_state.adc.issuer);

                                if (qsc_fileutils_exists(fpath) == true)
                                {
                                    qsc_fileutils_delete(fpath);
                                }

                                if (aern_certificate_child_struct_to_file(fpath, &m_client_application_state.adc) == true)
                                {
                                    merr = client_aps_certificate_sync();

                                    if (merr == aern_protocol_error_none)
                                    {
                                        aern_server_topology_to_file(&m_client_application_state);
                                        m_client_application_state.joined = true;
                                    }
                                }
                                else
                                {
                                    merr = aern_protocol_error_file_not_written;
                                }
                            }

                            qsc_async_mutex_unlock_ex(mtx);
                        }
                        else
                        {
                            merr = aern_protocol_error_verification_failure;
                        }
                    }

                    aern_topology_list_dispose(&ulist);
                }
                else
                {
                    merr = aern_protocol_error_operation_cancelled;
                }
            }
        }
        else
        {
            merr = aern_protocol_error_certificate_not_found;
        }
    }

    return merr;
}

static void client_command_loop(char* command)
{
    AERN_ASSERT(command != NULL);

    const char* cmsg;
    aern_protocol_errors merr;

    m_client_loop_status = aern_server_loop_status_started;

    while (m_client_loop_status == aern_server_loop_status_started)
    {
        qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

        if (qsc_consoleutils_line_equals(command, "quit") || qsc_consoleutils_line_equals(command, "exit"))
        {
            aern_client_stop();
        }
        else if (qsc_consoleutils_line_contains(command, "list"))
        {
            aern_server_topology_print_list(&m_client_application_state);
        }
        else if (qsc_consoleutils_line_contains(command, "register "))
        {
            cmsg = qsc_stringutils_reverse_sub_string(command, " ");

            if (cmsg != NULL)
            {
                merr = client_register_update_request(cmsg);

                if (merr == aern_protocol_error_none)
                {
                    aern_menu_print_predefined_message(aern_application_register_success,
                        m_client_application_state.mode, m_client_application_state.hostname);
                }
                else
                {
                    aern_menu_print_predefined_message(aern_application_register_failure,
                        m_client_application_state.mode, m_client_application_state.hostname);
                }
            }
        }
        else if (qsc_consoleutils_line_equals(command, "connect"))
        {
            merr = client_entry_connect(NULL);

            if (merr == aern_protocol_error_none)
            {
                aern_menu_print_message("Client entry-node tunnel established.", m_client_application_state.mode, m_client_application_state.hostname);
            }
            else
            {
                aern_menu_print_message("Client entry-node tunnel failed.", m_client_application_state.mode, m_client_application_state.hostname);
            }
        }
        else if (qsc_consoleutils_line_contains(command, "connect "))
        {
            cmsg = qsc_stringutils_reverse_sub_string(command, " ");

            if (cmsg != NULL)
            {
                merr = client_entry_connect(cmsg);

                if (merr == aern_protocol_error_none)
                {
                    aern_menu_print_message("Client entry-node tunnel established.", m_client_application_state.mode, m_client_application_state.hostname);
                }
                else
                {
                    aern_menu_print_message("Client entry-node tunnel failed.", m_client_application_state.mode, m_client_application_state.hostname);
                }
            }
        }
        else if (qsc_consoleutils_line_equals(command, "receive") || qsc_consoleutils_line_equals(command, "recv"))
        {
            merr = aern_client_receive_once();

            if (merr == aern_protocol_error_none)
            {
                aern_menu_print_message("Client return packet received.", m_client_application_state.mode, m_client_application_state.hostname);
            }
            else
            {
                aern_menu_print_message("Client return packet unavailable or not delivered.", m_client_application_state.mode, m_client_application_state.hostname);
            }
        }
        else if (qsc_consoleutils_line_contains(command, "send "))
        {
            cmsg = qsc_stringutils_reverse_sub_string(command, " ");

            if (cmsg != NULL)
            {
                merr = client_relay_send((const uint8_t*)cmsg, qsc_stringutils_string_size(cmsg));

                if (merr == aern_protocol_error_none)
                {
                    aern_menu_print_message("Client relay packet sent.", m_client_application_state.mode, m_client_application_state.hostname);
                }
                else
                {
                    aern_menu_print_message("Client relay packet failed.", m_client_application_state.mode, m_client_application_state.hostname);
                }
            }
        }

        if (m_client_loop_status == aern_server_loop_status_started)
        {
            qsc_stringutils_clear_string(command);
            aern_menu_print_prompt(m_client_application_state.mode, m_client_application_state.hostname);
        }
    }
}

int32_t aern_client_start(void)
{
    char command[QSC_CONSOLE_MAX_LINE] = { 0 };
    int32_t ret;

    ret = 0;

    aern_server_state_initialize(&m_client_application_state, aern_network_designation_client);
    aern_cipher_table_initialize(&m_client_cipher_table);
    aern_relay_cache_initialize(&m_client_relay_cache);

    qsc_consoleutils_set_virtual_terminal();
    qsc_consoleutils_set_window_title(m_client_application_state.wtitle);

    aern_server_print_banner(&m_client_application_state);
    aern_menu_print_prompt(m_client_application_state.mode, m_client_application_state.hostname);

    client_command_loop(command);

    return ret;
}

void aern_client_stop(void)
{
    m_client_loop_status = aern_server_loop_status_stopped;
    aern_cipher_table_dispose(&m_client_cipher_table);
    aern_relay_cache_dispose(&m_client_relay_cache);
    m_client_session_id = 0U;
    m_client_packet_id = 0U;
    m_client_rx_count = 0U;
    m_client_rx_fail = 0U;
    qsc_memutils_secure_erase(&m_client_local_certificate, sizeof(aern_child_certificate));
    qsc_memutils_secure_erase(&m_client_entry_certificate, sizeof(aern_child_certificate));
    qsc_memutils_secure_erase((uint8_t*)m_client_entry_address, sizeof(m_client_entry_address));
    aern_server_state_unload(&m_client_application_state);
}


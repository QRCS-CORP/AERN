#include "aps.h"
#include "aern.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "network.h"
#include "mek.h"
#include "route.h"
#include "resources.h"
#include "server.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct aps_receive_state
{
    qsc_socket csock;
} aps_receive_state;
/** \endcond */

static aern_server_application_state m_aps_application_state = { 0 };
static aern_child_certificate m_aps_local_certificate = { 0 };
static aern_server_server_loop_status m_aps_command_loop_status;
static aern_server_server_loop_status m_aps_server_loop_status;
static qsc_socket m_aps_listener_socket = { 0 };
static aern_cipher_table m_aps_cipher_table = { 0 };
static aern_relay_cache_state m_aps_relay_cache = { 0 };
static uint64_t m_aps_idle_timer;

static void aps_server_listener_close(void)
{
    qsc_socket_close_socket(&m_aps_listener_socket);
    qsc_memutils_clear(&m_aps_listener_socket, sizeof(qsc_socket));
}

static uint16_t aps_topology_aps_count(void)
{
    aern_topology_node_state node = { 0 };
    size_t pos;
    uint16_t count;

    count = 0U;

    for (pos = 0U; pos < m_aps_application_state.tlist.count; ++pos)
    {
        qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

        if (aern_topology_list_item(&m_aps_application_state.tlist, &node, pos) == true)
        {
            if (node.designation == aern_network_designation_aps)
            {
                ++count;
            }
        }
    }

    return count;
}

static bool aps_topology_own_index(uint16_t* index)
{
    aern_topology_node_state node = { 0 };
    size_t pos;
    uint16_t apsidx;
    bool res;

    apsidx = 0U;
    res = false;

    if (index != NULL)
    {
        *index = 0U;

        for (pos = 0U; pos < m_aps_application_state.tlist.count; ++pos)
        {
            qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

            if (aern_topology_list_item(&m_aps_application_state.tlist, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps)
                {
                    if (qsc_memutils_are_equal(node.serial, m_aps_local_certificate.serial,
                        AERN_CERTIFICATE_SERIAL_SIZE) == true)
                    {
                        *index = apsidx;
                        res = true;
                        break;
                    }

                    ++apsidx;
                }
            }
        }
    }

    return res;
}


static bool aps_source_is_aps(const char* address)
{
    AERN_ASSERT(address != NULL);

    aern_topology_node_state node = { 0 };
    bool res;

    res = false;
    qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

    if (address != NULL)
    {
        if (aern_topology_node_find_address(&m_aps_application_state.tlist, &node, address) == true)
        {
            if (node.designation == aern_network_designation_aps)
            {
                res = true;
            }
        }
    }

    return res;
}

static aern_protocol_errors aps_relay_forward_response(uint8_t* packet, size_t packetlen, const char* source)
{
    aern_forward_state fwd = { 0 };
    uint16_t ownidx;
    uint16_t apscnt;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    ownidx = 0U;
    apscnt = 0U;
    qsc_memutils_clear(&fwd, sizeof(aern_forward_state));

    if (packet != NULL && source != NULL && packetlen == AERN_RELAY_MTU)
    {
        aern_relay_cache_cleanup(&m_aps_relay_cache);
        apscnt = aps_topology_aps_count();

        if (apscnt >= AERN_ROUTE_MINIMUM_HOPS && aps_topology_own_index(&ownidx) == true)
        {
            fwd.conn_table = &m_aps_cipher_table;
            fwd.relay_cache = &m_aps_relay_cache;
            fwd.topology = &m_aps_application_state.tlist;
            fwd.apscount = (uint8_t)apscnt;
            fwd.ownhint = (uint8_t)(ownidx + 1U);
            fwd.own_address = m_aps_application_state.localip;

            if (aern_relay_forward_state_is_valid(&fwd, true) == true)
            {
                aern_relay_traffic_observe(&m_aps_relay_cache, packetlen, true);
                merr = aern_packet_forward(&fwd, packet, source);
            }
            else
            {
                merr = aern_protocol_error_invalid_request;
            }
        }
        else
        {
            merr = aern_protocol_error_node_not_found;
        }
    }

    return merr;
}


static aern_protocol_errors aps_entry_relay_response(uint8_t* packet, size_t packetlen, const char* source)
{
    aern_forward_state fwd = { 0 };
    uint16_t ownidx;
    uint16_t apscnt;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    ownidx = 0U;
    apscnt = 0U;
    qsc_memutils_clear(&fwd, sizeof(aern_forward_state));

    if (packet != NULL && source != NULL && packetlen == AERN_RELAY_MTU)
    {
        aern_relay_cache_cleanup(&m_aps_relay_cache);
        apscnt = aps_topology_aps_count();

        if (apscnt >= AERN_ROUTE_MINIMUM_HOPS && aps_topology_own_index(&ownidx) == true)
        {
            fwd.conn_table = &m_aps_cipher_table;
            fwd.relay_cache = &m_aps_relay_cache;
            fwd.topology = &m_aps_application_state.tlist;
            fwd.apscount = (uint8_t)apscnt;
            fwd.ownhint = (uint8_t)(ownidx + 1U);
            fwd.own_address = m_aps_application_state.localip;

            if (aern_relay_forward_state_is_valid(&fwd, true) == true)
            {
                aern_relay_traffic_observe(&m_aps_relay_cache, packetlen, true);
                merr = aern_entry_packet_forward(&fwd, packet, source);
            }
            else
            {
                merr = aern_protocol_error_invalid_request;
            }
        }
        else
        {
            merr = aern_protocol_error_node_not_found;
        }
    }

    return merr;
}

static void aps_dummy_traffic_tick(void)
{
    aern_forward_state fwd = { 0 };
    uint32_t utilization;
    uint16_t ownidx;
    uint16_t apscnt;

    apscnt = 0U;
    ownidx = 0U;
    utilization = 0U;
    qsc_memutils_clear(&fwd, sizeof(aern_forward_state));

    if (m_aps_server_loop_status == aern_server_loop_status_started && AERN_DUMMY_TRAFFIC_ENABLED != 0U)
    {
        aern_relay_cache_cleanup(&m_aps_relay_cache);
        utilization = aern_relay_traffic_utilization(&m_aps_relay_cache);
        apscnt = aps_topology_aps_count();

        if (apscnt >= AERN_ROUTE_MINIMUM_HOPS && aps_topology_own_index(&ownidx) == true)
        {
            fwd.conn_table = &m_aps_cipher_table;
            fwd.relay_cache = &m_aps_relay_cache;
            fwd.topology = &m_aps_application_state.tlist;
            fwd.apscount = (uint8_t)apscnt;
            fwd.ownhint = (uint8_t)(ownidx + 1U);
            fwd.own_address = m_aps_application_state.localip;

            if (aern_relay_forward_state_is_valid(&fwd, true) == true)
            {
                (void)aern_dummy_traffic_generate(&fwd, utilization);
            }
        }
    }
}

static void aps_dummy_traffic_loop(void)
{
    while (m_aps_server_loop_status != aern_server_loop_status_stopped)
    {
        if (m_aps_server_loop_status == aern_server_loop_status_started)
        {
            aps_dummy_traffic_tick();
        }

        qsc_async_thread_sleep(AERN_DUMMY_TRAFFIC_INTERVAL_MAXIMUM_MILLISECONDS);
    }
}

static bool aps_local_certificate_load(void)
{
    bool res;

    res = false;

    if (aern_server_topology_local_fetch(&m_aps_application_state, &m_aps_local_certificate) == true)
    {
        if (m_aps_local_certificate.designation == aern_network_designation_aps)
        {
            if (aern_certificate_child_is_valid(&m_aps_local_certificate) == true &&
                aern_certificate_root_signature_verify(&m_aps_local_certificate, &m_aps_application_state.root) == true)
            {
                res = true;
            }
        }
    }

    return res;
}

static aern_protocol_errors aps_topology_merge_update(const aern_topology_list_state* ulist)
{
    AERN_ASSERT(ulist != NULL);

    aern_topology_node_state node = { 0 };
    size_t pos;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (ulist != NULL)
    {
        merr = aern_protocol_error_none;

        for (pos = 0U; pos < ulist->count; ++pos)
        {
            qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

            if (aern_topology_list_item(ulist, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps &&
                    aern_certificate_expiration_time_verify(&node.expiration) == true &&
                    qsc_memutils_zeroed(node.serial, AERN_CERTIFICATE_SERIAL_SIZE) == false &&
                    qsc_memutils_zeroed(node.chash, AERN_CERTIFICATE_HASH_SIZE) == false)
                {
                    if (qsc_memutils_are_equal(node.serial, m_aps_local_certificate.serial, AERN_CERTIFICATE_SERIAL_SIZE) == false)
                    {
                        if (aern_topology_node_exists(&m_aps_application_state.tlist, node.serial) == true)
                        {
                            aern_topology_node_remove(&m_aps_application_state.tlist, node.serial);
                        }

                        aern_topology_child_add_item(&m_aps_application_state.tlist, &node);
                    }
                }
            }
            else
            {
                merr = aern_protocol_error_decoding_failure;
                break;
            }
        }
    }

    return merr;
}

static bool aps_peer_certificate_matches_node(const aern_topology_node_state* rnode, const aern_child_certificate* rcert)
{
    AERN_ASSERT(rnode != NULL);
    AERN_ASSERT(rcert != NULL);

    uint8_t chash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
    bool res;

    res = false;

    if (rnode != NULL && rcert != NULL)
    {
        if (rnode->designation == aern_network_designation_aps &&
            rcert->designation == aern_network_designation_aps &&
            aern_network_certificate_verify(rcert, &m_aps_application_state.root) == aern_protocol_error_none)
        {
            qsc_memutils_clear(chash, sizeof(chash));
            aern_certificate_child_hash(chash, rcert);

            if (qsc_memutils_are_equal(rnode->chash, chash, AERN_CERTIFICATE_HASH_SIZE) == true &&
                qsc_memutils_are_equal(rnode->serial, rcert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
                qsc_stringutils_strings_equal(rnode->issuer, rcert->issuer) == true &&
                rnode->expiration.from == rcert->expiration.from &&
                rnode->expiration.to == rcert->expiration.to)
            {
                res = true;
            }
        }
    }

    return res;
}

static aern_protocol_errors aps_peer_certificate_store(const aern_child_certificate* rcert)
{
    AERN_ASSERT(rcert != NULL);

    char fpath[AERN_STORAGE_PATH_MAX] = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (rcert != NULL)
    {
        qsc_memutils_clear((uint8_t*)fpath, sizeof(fpath));
        aern_server_child_certificate_path_from_issuer(&m_aps_application_state, fpath, sizeof(fpath), rcert->issuer);

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

static aern_protocol_errors aps_peer_certificate_request(const aern_topology_node_state* rnode)
{
    AERN_ASSERT(rnode != NULL);

    aern_child_certificate rcert = { 0 };
    aern_network_incremental_update_request_state reqs = { 0 };
    qsc_mutex mtx;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (rnode != NULL)
    {
        if (rnode->designation == aern_network_designation_aps &&
            qsc_memutils_are_equal(rnode->serial, m_aps_local_certificate.serial, AERN_CERTIFICATE_SERIAL_SIZE) == false)
        {
            qsc_memutils_clear(&rcert, sizeof(aern_child_certificate));
            qsc_memutils_clear(&reqs, sizeof(aern_network_incremental_update_request_state));

            reqs.rnode = rnode;
            reqs.rcert = &rcert;
            reqs.root = &m_aps_application_state.root;

            merr = aern_network_incremental_update_request(&reqs);

            if (merr == aern_protocol_error_none)
            {
                if (aps_peer_certificate_matches_node(rnode, &rcert) == true)
                {
                    merr = aps_peer_certificate_store(&rcert);

                    if (merr == aern_protocol_error_none)
                    {
                        mtx = qsc_async_mutex_lock_ex();

                        if (aern_topology_node_exists(&m_aps_application_state.tlist, rnode->serial) == true)
                        {
                            aern_topology_node_remove(&m_aps_application_state.tlist, rnode->serial);
                        }

                        aern_topology_child_add_item(&m_aps_application_state.tlist, rnode);
                        aern_server_topology_to_file(&m_aps_application_state);

                        qsc_async_mutex_unlock_ex(mtx);
                    }
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

static aern_protocol_errors aps_peer_certificate_sync(void)
{
    aern_topology_node_state rnode = { 0 };
    size_t pos;
    aern_protocol_errors merr;

    merr = aern_protocol_error_none;

    for (pos = 0U; pos < m_aps_application_state.tlist.count && merr == aern_protocol_error_none; ++pos)
    {
        qsc_memutils_clear(&rnode, sizeof(aern_topology_node_state));

        if (aern_topology_list_item(&m_aps_application_state.tlist, &rnode, pos) == true)
        {
            if (rnode.designation == aern_network_designation_aps &&
                qsc_memutils_are_equal(rnode.serial, m_aps_local_certificate.serial, AERN_CERTIFICATE_SERIAL_SIZE) == false)
            {
                merr = aps_peer_certificate_request(&rnode);
            }
        }
        else
        {
            merr = aern_protocol_error_decoding_failure;
        }
    }

    return merr;
}


static aern_protocol_errors aps_mek_exchange_response(const qsc_socket* csock, const aern_network_packet* packetin, bool* sockkeep)
{
    AERN_ASSERT(csock != NULL);
    AERN_ASSERT(packetin != NULL);
    AERN_ASSERT(sockkeep != NULL);

    aern_child_certificate rcert = { 0 };
    aern_connection_state cns = { 0 };
    aern_mek_response_state resp = { 0 };
    aern_topology_node_state rnode = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (csock != NULL && packetin != NULL && sockkeep != NULL)
    {
        if (packetin->msglen == (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE +
            AERN_CERTIFICATE_SIGNED_HASH_SIZE))
        {
            resp.csock = (qsc_socket*)csock;
            resp.lcert = &m_aps_local_certificate;
            resp.rcert = &rcert;
            resp.root = &m_aps_application_state.root;
            resp.sigkey = m_aps_application_state.sigkey;
            resp.cns_out = &cns;

            merr = aern_mek_exchange_response(&resp, packetin);

            if (merr == aern_protocol_error_none)
            {
                if (aern_topology_node_find(&m_aps_application_state.tlist, &rnode, rcert.serial) == true && rnode.designation == aern_network_designation_aps)
                {
                    merr = aern_cipher_table_add_peer(&m_aps_cipher_table, rnode.address, rnode.serial, &cns, aern_mesh_peer_status_synchronized);

                    if (merr == aern_protocol_error_none)
                    {
                        *sockkeep = true;
                    }
                    else
                    {
                        aern_connection_state_dispose(&cns);
                    }
                }
                else
                {
                    aern_connection_state_dispose(&cns);
                    merr = aern_protocol_error_node_not_found;
                }
            }
            else
            {
                aern_connection_state_dispose(&cns);
            }
        }
        else
        {
            merr = aern_protocol_error_receive_failure;
        }
    }

    return merr;
}

static aern_protocol_errors aps_incremental_update_response(const qsc_socket* csock, const aern_network_packet* packetin)
{
    AERN_ASSERT(csock != NULL);
    AERN_ASSERT(packetin != NULL);

    aern_child_certificate rcert = { 0 };
    aern_network_incremental_update_response_state resp = { 0 };
    aern_topology_node_state rnode = { 0 };
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (csock != NULL && packetin != NULL)
    {
        if (aern_topology_node_find(&m_aps_application_state.tlist, &rnode, packetin->pmessage) == true)
        {
            if (rnode.designation == aern_network_designation_aps &&
                qsc_memutils_are_equal(rnode.serial, m_aps_local_certificate.serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
            {
                aern_certificate_child_copy(&rcert, &m_aps_local_certificate);
                merr = aern_protocol_error_none;
            }
            else if (rnode.designation == aern_network_designation_aps)
            {
                if (aern_server_child_certificate_from_issuer(&rcert, &m_aps_application_state, rnode.issuer) == true)
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
                merr = aern_protocol_error_invalid_request;
            }

            if (merr == aern_protocol_error_none)
            {
                qsc_memutils_clear(&resp, sizeof(aern_network_incremental_update_response_state));
                resp.csock = csock;
                resp.rcert = &rcert;
                resp.sigkey = m_aps_application_state.sigkey;

                merr = aern_network_incremental_update_response(&resp, packetin);
            }
        }
        else
        {
            merr = aern_protocol_error_node_not_found;
        }
    }

    return merr;
}

static aern_protocol_errors aps_register_update_request(const char* address)
{
    AERN_ASSERT(address != NULL);

    aern_network_register_update_request_state jrs = { 0 };
    aern_topology_list_state ulist = { 0 };
    char fpath[AERN_STORAGE_PATH_MAX] = { 0U };
    qsc_mutex mtx;
    aern_protocol_errors merr;
    bool dres;

    dres = true;
    merr = aern_protocol_error_invalid_request;

    if (address != NULL)
    {
        if (aern_server_topology_root_exists(&m_aps_application_state) == true)
        {
            if (aern_certificate_root_is_valid(&m_aps_application_state.root) == false)
            {
                if (aern_server_root_certificate_load(&m_aps_application_state, &m_aps_application_state.root, &m_aps_application_state.tlist) == true)
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
                if (aps_local_certificate_load() == false)
                {
                    merr = aern_protocol_error_certificate_not_found;
                }
            }

            if (merr == aern_protocol_error_none)
            {
                if (m_aps_application_state.joined == true && m_aps_application_state.adc.designation == aern_network_designation_adc)
                {
                    dres = aern_menu_print_predefined_message_confirm(aern_application_register_existing, m_aps_application_state.mode, m_aps_application_state.hostname);

                    if (dres == true)
                    {
                        aern_server_topology_purge_externals(&m_aps_application_state);
                    }
                }

                if (dres == true)
                {
                    aern_topology_list_initialize(&ulist);

                    qsc_memutils_clear(&jrs, sizeof(aern_network_register_update_request_state));
                    jrs.address = address;
                    jrs.lcert = &m_aps_local_certificate;
                    jrs.list = &ulist;
                    jrs.rcert = &m_aps_application_state.adc;
                    jrs.root = &m_aps_application_state.root;
                    jrs.sigkey = m_aps_application_state.sigkey;

                    merr = aern_network_register_update_request(&jrs);

                    if (merr == aern_protocol_error_none)
                    {
                        if (m_aps_application_state.adc.designation == aern_network_designation_adc &&
                            aern_network_certificate_verify(&m_aps_application_state.adc, &m_aps_application_state.root) == aern_protocol_error_none)
                        {
                            mtx = qsc_async_mutex_lock_ex();

                            aern_topology_child_register(&m_aps_application_state.tlist, &m_aps_application_state.adc, address);
                            merr = aps_topology_merge_update(&ulist);

                            if (merr == aern_protocol_error_none)
                            {
                                qsc_memutils_clear((uint8_t*)fpath, sizeof(fpath));
                                aern_server_child_certificate_path_from_issuer(&m_aps_application_state, fpath, sizeof(fpath), m_aps_application_state.adc.issuer);

                                if (qsc_fileutils_exists(fpath) == true)
                                {
                                    qsc_fileutils_delete(fpath);
                                }

                                if (aern_certificate_child_struct_to_file(fpath, &m_aps_application_state.adc) == true)
                                {
                                    merr = aps_peer_certificate_sync();

                                    if (merr == aern_protocol_error_none)
                                    {
                                        aern_server_topology_to_file(&m_aps_application_state);
                                        m_aps_application_state.joined = true;
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

static void aps_receive_loop(void* ras)
{
    AERN_ASSERT(ras != NULL);

    aern_network_packet pkt   = { 0 };
    aps_receive_state* pras;
    uint8_t* buff;
    size_t mlen;
    size_t plen;
    aern_protocol_errors merr;
    bool sockkeep;

    pras = (aps_receive_state*)ras;
    merr = aern_protocol_error_none;
    sockkeep = false;

    if (pras != NULL)
    {
        buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

        if (buff != NULL)
        {
            uint8_t hdr[AERN_PACKET_HEADER_SIZE] = { 0U };

            mlen = 0U;
            plen = qsc_socket_peek(&pras->csock, hdr, AERN_PACKET_HEADER_SIZE);

            if (plen == AERN_PACKET_HEADER_SIZE)
            {
                aern_packet_header_deserialize(hdr, &pkt);

                if (pkt.msglen > 0U && pkt.msglen <= AERN_MESSAGE_MAX_SIZE)
                {
                    plen = pkt.msglen + AERN_PACKET_HEADER_SIZE;
                    buff = (uint8_t*)qsc_memutils_realloc(buff, plen);

                    if (buff != NULL)
                    {
                        qsc_memutils_clear(buff, plen);
                        mlen = qsc_socket_receive(&pras->csock, buff, plen, qsc_socket_receive_flag_wait_all);
                    }
                    else
                    {
                        merr = aern_protocol_error_memory_allocation;
                    }
                }
                else if (pkt.msglen == 0U)
                {
                    /* header-only packet: read the header bytes from the socket */
                    mlen = qsc_socket_receive(&pras->csock, buff, AERN_PACKET_HEADER_SIZE, qsc_socket_receive_flag_wait_all);
                }

                if (mlen > 0U)
                {
                    pkt.pmessage = buff + AERN_PACKET_HEADER_SIZE;

                    switch ((aern_network_flags)pkt.flag)
                    {
                        /* topology announce from ADC */
                    case aern_network_flag_network_announce_broadcast:
                    {
                        aern_network_announce_response_state ars = 
                        {
                            .dcert = &m_aps_application_state.adc,
                            .rnode = NULL,   /* populated by response handler */
                            .root = &m_aps_application_state.root
                        };

                        merr = aern_network_announce_response(&ars, &pkt);
                        break;
                    }

                    /* register request from a client */
                    case aern_network_flag_register_request:
                    {
                        aern_child_certificate rcert = { 0 };

                        aern_network_register_response_state rrs = 
                        {
                            .csock = &pras->csock,
                            .lcert = &m_aps_local_certificate,
                            .rcert = &rcert,
                            .root = &m_aps_application_state.root,
                            .sigkey = m_aps_application_state.sigkey
                        };

                        merr = aern_network_register_response(&rrs, &pkt);
                        break;
                    }

                    /* incremental certificate update request from peer APS */
                    case aern_network_flag_incremental_update_request:
                    {
                        merr = aps_incremental_update_response(&pras->csock, &pkt);
                        break;
                    }

                    /* MEK exchange request from peer APS */
                    case aern_network_flag_mfk_request:
                    {
                        merr = aps_mek_exchange_response(&pras->csock, &pkt, &sockkeep);
                        break;
                    }

                    /* reserved obsolete fragment-control flags */
                    case aern_network_flag_fragment_collection_request:
                    case aern_network_flag_fragment_query_request:
                    {
                        merr = aern_protocol_error_invalid_request;
                        break;
                    }

                    /* resignation request from peer */
                    case aern_network_flag_network_resign_request:
                    {
                        aern_child_certificate rcert = { 0 };
                        aern_topology_node_state rnode = { 0 };

                        aern_network_resign_response_state rrs = 
                        {
                            .list = &m_aps_application_state.tlist,
                            .rcert = &rcert,
                            .rnode = &rnode,
                            .sigkey = m_aps_application_state.sigkey
                        };

                        merr = aern_network_resign_response(&rrs, &pkt);
                        break;
                    }

                    /* revocation broadcast from ADC */
                    case aern_network_flag_network_revocation_broadcast:
                    {
                        aern_topology_node_state rnode = { 0 };

                        aern_network_revoke_response_state rvs = 
                        {
                            .list = &m_aps_application_state.tlist,
                            .rnode = &rnode,
                            .dcert = &m_aps_application_state.adc
                        };

                        merr = aern_network_revoke_response(&rvs, &pkt);

                        if (merr == aern_protocol_error_none)
                        {
                            if (rnode.designation == aern_network_designation_aps)
                            {
                                (void)aern_cipher_table_remove(&m_aps_cipher_table, rnode.address);
                            }

                            aern_topology_node_remove(&m_aps_application_state.tlist, rnode.serial);
                            aern_server_topology_to_file(&m_aps_application_state);
                        }

                        break;
                    }


                    /* encrypted relay packet from synchronized APS peer or client */
                    case aern_network_flag_tunnel_encrypted_message:
                    {
                        if (aps_source_is_aps((const char*)pras->csock.address) == true)
                        {
                            merr = aps_relay_forward_response(buff, mlen, (const char*)pras->csock.address);
                        }
                        else
                        {
                            merr = aps_entry_relay_response(buff, mlen, (const char*)pras->csock.address);
                        }

                        break;
                    }
                    case aern_network_flag_system_error_condition:
                    {
                        aern_network_send_error(&pras->csock, aern_protocol_error_none);
                        break;
                    }

                    default:
                    {
                        aern_network_send_error(&pras->csock,
                            aern_protocol_error_invalid_request);
                        merr = aern_protocol_error_invalid_request;
                        break;
                    }
                    }

                    if (merr != aern_protocol_error_none)
                    {
                        /* report error code only */
                        const char* estr = aern_protocol_error_to_string(merr);
                        aern_server_log_write_message(&m_aps_application_state, aern_application_log_receive_failure, estr, qsc_stringutils_string_size(estr));
                    }
                }
            }

            qsc_memutils_alloc_free(buff);
        }

        if (sockkeep == false)
        {
            aern_network_socket_dispose(&pras->csock);
        }
        else
        {
            qsc_memutils_clear(&pras->csock, sizeof(qsc_socket));
        }
    }

    qsc_memutils_alloc_free(pras);
}

#if defined(AERN_NETWORK_PROTOCOL_IPV6)
static void aps_ipv6_server_start(void)
{
    qsc_ipinfo_ipv6_address addt = { 0 };
    qsc_socket_exceptions serr;

    addt = qsc_ipinfo_ipv6_address_from_string(m_aps_application_state.localip);

    if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
    {
        aps_server_listener_close();
        qsc_socket_server_initialize(&m_aps_listener_socket);
        serr = qsc_socket_create(&m_aps_listener_socket, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

        if (serr == qsc_socket_exception_success)
        {
            serr = qsc_socket_bind_ipv6(&m_aps_listener_socket, &addt, AERN_APPLICATION_APS_PORT);

            if (serr == qsc_socket_exception_success)
            {
                serr = qsc_socket_listen(&m_aps_listener_socket, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

                if (serr == qsc_socket_exception_success)
                {
                    while (m_aps_server_loop_status != aern_server_loop_status_stopped)
                    {
                        aps_receive_state* ras;

                        if (m_aps_server_loop_status == aern_server_loop_status_paused)
                        {
                            qsc_async_thread_sleep(AERN_STORAGE_SERVER_PAUSE_INTERVAL);
                        }
                        else
                        {
                            ras = (aps_receive_state*)qsc_memutils_malloc(sizeof(aps_receive_state));

                            if (ras != NULL)
                            {
                                qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
                                serr = qsc_socket_accept(&m_aps_listener_socket, &ras->csock);

                                if (serr == qsc_socket_exception_success)
                                {
                                    ras->csock.connection_status = qsc_socket_state_connected;
                                    qsc_async_thread_create(&aps_receive_loop, ras);
                                }
                                else
                                {
                                    qsc_memutils_alloc_free(ras);
                                }
                            }
                            else
                            {
                                m_aps_server_loop_status = aern_server_loop_status_stopped;
                            }
                        }
                    }
                }
            }
        }
    }
}
#else
static void aps_ipv4_server_start(void)
{
    qsc_ipinfo_ipv4_address addt = { 0 };
    qsc_socket_exceptions serr;

    addt = qsc_ipinfo_ipv4_address_from_string(m_aps_application_state.localip);

    if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
    {
        aps_server_listener_close();
        qsc_socket_server_initialize(&m_aps_listener_socket);
        serr = qsc_socket_create(&m_aps_listener_socket, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

        if (serr == qsc_socket_exception_success)
        {
            serr = qsc_socket_bind_ipv4(&m_aps_listener_socket, &addt, AERN_APPLICATION_APS_PORT);

            if (serr == qsc_socket_exception_success)
            {
                serr = qsc_socket_listen(&m_aps_listener_socket, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

                if (serr == qsc_socket_exception_success)
                {
                    while (m_aps_server_loop_status != aern_server_loop_status_stopped)
                    {
                        aps_receive_state* ras;

                        if (m_aps_server_loop_status == aern_server_loop_status_paused)
                        {
                            qsc_async_thread_sleep(AERN_STORAGE_SERVER_PAUSE_INTERVAL);
                        }
                        else
                        {
                            ras = (aps_receive_state*)qsc_memutils_malloc(sizeof(aps_receive_state));

                            if (ras != NULL)
                            {
                                qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
                                serr = qsc_socket_accept(&m_aps_listener_socket, &ras->csock);

                                if (serr == qsc_socket_exception_success)
                                {
                                    ras->csock.connection_status = qsc_socket_state_connected;
                                    qsc_async_thread_create(&aps_receive_loop, ras);
                                }
                                else
                                {
                                    qsc_memutils_alloc_free(ras);
                                }
                            }
                            else
                            {
                                m_aps_server_loop_status = aern_server_loop_status_stopped;
                            }
                        }
                    }
                }
            }
        }
    }
}
#endif

static bool aps_server_service_start(void)
{
    bool res;

    res = false;

    if (m_aps_server_loop_status != aern_server_loop_status_started)
    {
        aern_cipher_table_initialize(&m_aps_cipher_table);
        aern_relay_cache_initialize(&m_aps_relay_cache);
        m_aps_server_loop_status = aern_server_loop_status_started;

#if defined(AERN_NETWORK_PROTOCOL_IPV6)
        res = qsc_async_thread_create_noargs(&aps_ipv6_server_start);
#else
        res = qsc_async_thread_create_noargs(&aps_ipv4_server_start);
#endif

        if (res == false)
        {
            m_aps_server_loop_status = aern_server_loop_status_stopped;
        }
        else
        {
            (void)qsc_async_thread_create_noargs(&aps_dummy_traffic_loop);
        }
    }
    else
    {
        res = true;
    }

    return res;
}

static void aps_idle_timer(void)
{
    const uint32_t MMSEC = 60U * 1000U;

    while (true)
    {
        qsc_async_thread_sleep(MMSEC);
        qsc_mutex mtx = qsc_async_mutex_lock_ex();

        if (m_aps_application_state.mode != aern_console_mode_user)
        {
            ++m_aps_idle_timer;

            if (m_aps_idle_timer >= m_aps_application_state.timeout)
            {
                aern_server_user_logout(&m_aps_application_state);
                m_aps_idle_timer = 0U;
                qsc_consoleutils_print_line("");
                aern_menu_print_predefined_message(aern_application_console_timeout_expired, m_aps_application_state.mode, m_aps_application_state.hostname);
                aern_menu_print_prompt(m_aps_application_state.mode, m_aps_application_state.hostname);
            }
        }

        qsc_async_mutex_unlock_ex(mtx);
    }
}

static void aps_server_dispose(void)
{
    aps_server_listener_close();
    aern_cipher_table_dispose(&m_aps_cipher_table);
    aern_relay_cache_dispose(&m_aps_relay_cache);
    aern_server_state_initialize(&m_aps_application_state, aern_network_designation_aps);
    aern_cipher_table_initialize(&m_aps_cipher_table);
    qsc_memutils_clear(&m_aps_local_certificate, sizeof(aern_child_certificate));
    m_aps_command_loop_status = aern_server_loop_status_stopped;
    m_aps_server_loop_status  = aern_server_loop_status_stopped;
    m_aps_idle_timer = 0U;
}

static void aps_command_loop(char* command)
{
    AERN_ASSERT(command != NULL);

    m_aps_command_loop_status = aern_server_loop_status_started;

    while (true)
    {
        qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

        qsc_mutex mtx = qsc_async_mutex_lock_ex();
        m_aps_idle_timer = 0U;
        qsc_async_mutex_unlock_ex(mtx);

        /*
         * APS uses the same command/mode/action architecture as ARS and ADC.
         * The full command dispatch (certificate, server, config, enable, user
         * modes) will be wired here in Phase-2.  For Phase-1 only the quit/
         * start-service commands are active.
         */
        if (qsc_consoleutils_line_equals(command, "quit") || qsc_consoleutils_line_equals(command, "exit"))
        {
            m_aps_command_loop_status = aern_server_loop_status_stopped;
            aern_server_state_unload(&m_aps_application_state);
            aern_menu_print_predefined_message(aern_application_application_quit, m_aps_application_state.mode, m_aps_application_state.hostname);
        }
        else if (qsc_consoleutils_line_contains(command, "service start"))
        {
            if (m_aps_server_loop_status != aern_server_loop_status_started)
            {
                if (aps_server_service_start() == true)
                {
                    aern_menu_print_predefined_message(aern_application_server_service_start_success, m_aps_application_state.mode, m_aps_application_state.hostname);
                }
                else
                {
                    aern_menu_print_predefined_message(aern_application_server_service_start_failure, m_aps_application_state.mode, m_aps_application_state.hostname);
                }
            }
        }
        else if (qsc_consoleutils_line_contains(command, "service stop"))
        {
            m_aps_server_loop_status = aern_server_loop_status_stopped;
            aps_server_listener_close();
        }
        else if (qsc_consoleutils_line_contains(command, "service pause"))
        {
            m_aps_server_loop_status = aern_server_loop_status_paused;
        }
        else if (qsc_consoleutils_line_contains(command, "service resume"))
        {
            m_aps_server_loop_status = aern_server_loop_status_started;
        }
        else if (qsc_consoleutils_line_contains(command, "list"))
        {
            aern_server_topology_print_list(&m_aps_application_state);
        }
        else if (qsc_consoleutils_line_contains(command, "register "))
        {
            const char* cmsg;
            aern_protocol_errors merr;

            cmsg = qsc_stringutils_reverse_sub_string(command, " ");

            if (cmsg != NULL)
            {
                if (m_aps_server_loop_status == aern_server_loop_status_started)
                {
                    merr = aps_register_update_request(cmsg);

                    if (merr == aern_protocol_error_none)
                    {
                        aern_menu_print_predefined_message(aern_application_register_success, m_aps_application_state.mode, m_aps_application_state.hostname);
                    }
                    else
                    {
                        aern_menu_print_predefined_message(aern_application_register_failure, m_aps_application_state.mode, m_aps_application_state.hostname);
                    }
                }
                else
                {
                    aern_menu_print_predefined_message(aern_application_server_service_not_started, m_aps_application_state.mode, m_aps_application_state.hostname);
                }
            }
        }

        aern_menu_print_prompt(m_aps_application_state.mode, m_aps_application_state.hostname);
        qsc_stringutils_clear_string(command);

        if (m_aps_command_loop_status == aern_server_loop_status_stopped)
        {
            break;
        }
    }

    aps_server_dispose();
}

void aern_aps_pause_server(void)
{
    m_aps_command_loop_status = aern_server_loop_status_paused;
}

int32_t aern_aps_start_server(void)
{
    char command[QSC_CONSOLE_MAX_LINE] = { 0 };
    qsc_thread idle;

    aern_server_state_initialize(&m_aps_application_state, aern_network_designation_aps);
    aern_cipher_table_initialize(&m_aps_cipher_table);
    aern_relay_cache_initialize(&m_aps_relay_cache);

    qsc_consoleutils_set_virtual_terminal();
    qsc_consoleutils_set_window_size(1000, 600);
    qsc_consoleutils_set_window_title(m_aps_application_state.wtitle);

    aern_server_print_banner(&m_aps_application_state);

    aern_menu_print_prompt(m_aps_application_state.mode, m_aps_application_state.hostname);

    m_aps_idle_timer = 0U;
    idle = qsc_async_thread_create_noargs(&aps_idle_timer);

    if (idle)
    {
        aps_command_loop(command);
    }

    return 0;
}

void aern_aps_stop_server(void)
{
    m_aps_command_loop_status = aern_server_loop_status_stopped;
    m_aps_server_loop_status = aern_server_loop_status_stopped;
    aps_server_listener_close();
}


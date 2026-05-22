#include "virtual_test.h"
#include "aern_utils.h"
#include "certificate.h"
#include "fragment.h"
#include "intutils.h"
#include "mek.h"
#include "memutils.h"
#include "relayqueue.h"
#include "relaysession.h"
#include "route.h"
#include "server.h"
#include "topology.h"

#define AERNTEST_VIRTUAL_APS_COUNT 4U
#define AERNTEST_VIRTUAL_PACKET_CAPACITY 64U
#define AERNTEST_VIRTUAL_PACKET_SIZE 64U
#define AERNTEST_VIRTUAL_QUEUE_DEPTH 8U

typedef struct aerntest_virtual_node_state
{
    aern_signature_keypair keys;
    aern_child_certificate cert;
    aern_topology_node_state node;
    aern_cipher_table ctable;
    aern_relay_cache_state relay;
    uint64_t backendcalls;
    uint64_t failcalls;
} aerntest_virtual_node_state;

typedef struct aerntest_virtual_fabric_state
{
    aern_signature_keypair rootkeys;
    aern_root_certificate root;
    aerntest_virtual_node_state adc;
    aerntest_virtual_node_state aps[AERNTEST_VIRTUAL_APS_COUNT];
    aerntest_virtual_node_state client;
    aern_topology_list_state topology;
    uint64_t egresscalls;
    uint64_t returncalls;
} aerntest_virtual_fabric_state;

typedef struct aerntest_virtual_packet
{
    uint8_t data[AERNTEST_VIRTUAL_PACKET_SIZE];
    size_t length;
    uint8_t src;
    uint8_t dst;
    uint64_t sequence;
    uint64_t deliverat;
    bool active;
    bool mutated;
    bool replay;
} aerntest_virtual_packet;

typedef struct aerntest_virtual_transport_state
{
    aerntest_virtual_packet packets[AERNTEST_VIRTUAL_PACKET_CAPACITY];
    uint32_t count;
    uint32_t sent;
    uint32_t delivered;
    uint32_t dropped;
    uint32_t mutated;
    uint32_t replayed;
    uint32_t delayed;
    uint32_t reordered;
} aerntest_virtual_transport_state;

typedef struct aerntest_attack_observation
{
    const char* name;
    bool packetaccepted;
    bool tunneldown;
    bool sessiondown;
    bool topologychanged;
    bool queuecleared;
    bool fragmentcleared;
    bool backendcalled;
} aerntest_attack_observation;

static void aerntest_virtual_node_dispose(aerntest_virtual_node_state* node)
{
    if (node != NULL)
    {
        aern_relay_cache_dispose(&node->relay);
        aern_cipher_table_dispose(&node->ctable);
        qsc_memutils_clear(node, sizeof(aerntest_virtual_node_state));
    }
}

static void aerntest_virtual_fabric_dispose(aerntest_virtual_fabric_state* fabric)
{
    if (fabric != NULL)
    {
        for (size_t i = 0U; i < AERNTEST_VIRTUAL_APS_COUNT; ++i)
        {
            aerntest_virtual_node_dispose(&fabric->aps[i]);
        }

        aerntest_virtual_node_dispose(&fabric->adc);
        aerntest_virtual_node_dispose(&fabric->client);
        aern_topology_list_dispose(&fabric->topology);
        qsc_memutils_clear(fabric, sizeof(aerntest_virtual_fabric_state));
    }
}

static void aerntest_virtual_address(char* address, uint8_t host)
{
    if (address != NULL)
    {
        qsc_memutils_clear(address, AERN_CERTIFICATE_ADDRESS_SIZE);
        (void)snprintf(address, AERN_CERTIFICATE_ADDRESS_SIZE, "10.0.0.%u", (uint32_t)host);
    }
}

static bool aerntest_virtual_child_create(aerntest_virtual_node_state* node, const aern_root_certificate* root, const uint8_t* rootsigkey, 
    const aern_certificate_expiration* exp, const char* issuer, aern_network_designations designation)
{
    bool res;

    res = false;

    if (node != NULL && root != NULL && rootsigkey != NULL && exp != NULL && issuer != NULL)
    {
        aern_certificate_signature_generate_keypair(&node->keys);
        aern_certificate_child_create(&node->cert, node->keys.pubkey, exp, issuer, designation);

        if (aern_certificate_root_sign(&node->cert, root, rootsigkey) != 0U)
        {
            res = (aern_certificate_child_is_valid(&node->cert) == true);
            res = (res == true && aern_certificate_root_signature_verify(&node->cert, root) == true);
            aern_cipher_table_initialize(&node->ctable);
            aern_relay_cache_initialize(&node->relay);
            res = (res == true && node->relay.initialized == true);
        }
    }

    return res;
}

static bool aerntest_virtual_register_child(aern_topology_list_state* topology, aerntest_virtual_node_state* node, uint8_t host)
{
    char address[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
    bool res;

    res = false;

    if (topology != NULL && node != NULL)
    {
        aerntest_virtual_address(address, host);
        aern_topology_child_register(topology, &node->cert, address);
        res = aern_topology_node_find(topology, &node->node, node->cert.serial);
        res = (res == true && aern_topology_node_verify_issuer(topology, &node->cert, node->cert.issuer) == true);
    }

    return res;
}

static bool aerntest_virtual_add_peer(aerntest_virtual_node_state* local, const aerntest_virtual_node_state* remote, uint8_t host, uint32_t instance)
{
    aern_connection_state cns = { 0 };
    char address[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
    bool res;

    res = false;

    if (local != NULL && remote != NULL)
    {
        aerntest_virtual_address(address, host);
        cns.instance = instance;
        cns.rxseq = 0U;
        cns.txseq = 0U;
        cns.authfail = 0U;
        cns.exflag = aern_network_flag_mfk_establish;
        res = (aern_cipher_table_add_peer(&local->ctable, address, remote->cert.serial, &cns, aern_mesh_peer_status_synchronized) == aern_protocol_error_none);
    }

    return res;
}

static bool aerntest_virtual_initialize_fabric(aerntest_virtual_fabric_state* fabric)
{
    aern_certificate_expiration exp = { 0 };
    char rootaddr[AERN_CERTIFICATE_ADDRESS_SIZE] = { 0 };
    size_t i;
    size_t j;
    bool res;

    res = false;

    if (fabric != NULL)
    {
        qsc_memutils_clear(fabric, sizeof(aerntest_virtual_fabric_state));
        aern_topology_list_initialize(&fabric->topology);
        aern_certificate_expiration_set_days(&exp, 0U, 365U);
        aern_certificate_signature_generate_keypair(&fabric->rootkeys);
        aern_certificate_root_create(&fabric->root, fabric->rootkeys.pubkey, &exp, "AERNTEST_ARS");
        aerntest_virtual_address(rootaddr, 1U);
        aern_topology_root_register(&fabric->topology, &fabric->root, rootaddr);

        res = (aern_certificate_root_is_valid(&fabric->root) == true);
        res = (res == true && aern_topology_node_verify_root(&fabric->topology, &fabric->root) == true);
        res = (res == true && aerntest_virtual_child_create(&fabric->adc, &fabric->root, fabric->rootkeys.prikey, &exp, "AERNTEST_ADC", aern_network_designation_adc) == true);
        res = (res == true && aerntest_virtual_register_child(&fabric->topology, &fabric->adc, 2U) == true);

        for (i = 0U; i < AERNTEST_VIRTUAL_APS_COUNT && res == true; ++i)
        {
            char issuer[32U] = { 0 };

            (void)snprintf(issuer, sizeof(issuer), "AERNTEST_APS_%u", (uint32_t)(i + 1U));
            res = aerntest_virtual_child_create(&fabric->aps[i], &fabric->root, fabric->rootkeys.prikey, &exp, issuer, aern_network_designation_aps);
            res = (res == true && aerntest_virtual_register_child(&fabric->topology, &fabric->aps[i], (uint8_t)(10U + i)) == true);
        }

        res = (res == true && aerntest_virtual_child_create(&fabric->client, &fabric->root, fabric->rootkeys.prikey, &exp, "AERNTEST_CLIENT", aern_network_designation_client) == true);
        res = (res == true && aerntest_virtual_register_child(&fabric->topology, &fabric->client, 50U) == true);
        res = (res == true && aern_topology_list_server_count(&fabric->topology, aern_network_designation_aps) == AERNTEST_VIRTUAL_APS_COUNT);
        res = (res == true && aern_topology_list_server_count(&fabric->topology, aern_network_designation_adc) == 1U);

        for (i = 0U; i < AERNTEST_VIRTUAL_APS_COUNT && res == true; ++i)
        {
            for (j = 0U; j < AERNTEST_VIRTUAL_APS_COUNT && res == true; ++j)
            {
                if (i != j)
                {
                    res = aerntest_virtual_add_peer(&fabric->aps[i], &fabric->aps[j], (uint8_t)(10U + j), (uint32_t)((i * 10U) + j + 1U));
                }
            }
        }

        res = (res == true && aerntest_virtual_add_peer(&fabric->client, &fabric->aps[0U], 10U, 100U) == true);
        res = (res == true && fabric->client.ctable.count == 1U);

        for (i = 0U; i < AERNTEST_VIRTUAL_APS_COUNT && res == true; ++i)
        {
            res = (fabric->aps[i].ctable.count == (AERNTEST_VIRTUAL_APS_COUNT - 1U));
        }
    }

    return res;
}

static bool aerntest_virtual_fabric_initialization_test(void)
{
    aerntest_virtual_fabric_state* fabric;
    bool res;

    fabric = (aerntest_virtual_fabric_state*)qsc_memutils_malloc(sizeof(aerntest_virtual_fabric_state));
    res = (fabric != NULL);

    if (res == true)
    {
        qsc_memutils_clear(fabric, sizeof(aerntest_virtual_fabric_state));
        res = aerntest_virtual_initialize_fabric(fabric);

        if (res == true)
        {
            res = (aern_relay_forward_state_is_valid(NULL, true) == false);
        }

        aerntest_virtual_fabric_dispose(fabric);
        qsc_memutils_alloc_free(fabric);
    }

    return res;
}

static bool aerntest_virtual_relay_state_cleanup_test(void)
{
    aern_relay_cache_state cache = { 0 };
    aern_relay_session_cache_entry sess = { 0 };
    aern_ingress_pending_item item = { 0 };
    aern_relay_payload_header header = { 0 };
    uint8_t fragment[AERN_FRAG_CHUNK_SIZE] = { 0U };
    aern_fragment_cache* fragset;
    bool complete;
    bool res;

    fragset = NULL;
    complete = false;
    res = false;

    aern_relay_cache_initialize(&cache);

    if (cache.initialized == true)
    {
        sess.sessionid = 0xAABBCCDDEEFF0001ULL;
        sess.status = (uint8_t)aern_relay_session_status_active;
        sess.context = AERN_RELAY_SESSION_CONTEXT_EGRESS;
        sess.ingresshint = 1U;
        sess.egresshint = 4U;
        sess.expiry = 1000U;

        item.packet = fragment;
        item.packetlen = 32U;
        item.capacity = 32U;
        item.sessionid = sess.sessionid;
        item.packetid = 0x1122334455667788ULL;
        item.expiry = 1000U;
        item.delayuntil = 100U;
        item.active = true;

        header.sessionid = sess.sessionid;
        header.packetid = item.packetid;
        header.fragseq = 1U;
        header.fragcount = 2U;
        header.msglen = (uint32_t)sizeof(fragment);
        header.payloadtype = (uint8_t)aern_relay_payload_data;
        header.reserved = 0U;
        header.flags = AERN_RELAY_PAYLOAD_FLAG_OUTBOUND;

        res = aern_relay_session_add(&cache, &sess);
        res = (res == true && aern_relay_pending_push(&cache, &item) == true);
        res = (res == true && aern_relay_delay_push(&cache, &item) == true);
        res = (res == true && aern_fragment_table_add_relay_fragment(&cache.fragments, &header, fragment, sizeof(fragment), (uint8_t)aern_relay_fragment_direction_outbound, 1000U, &fragset, &complete) == true);
        res = (res == true && aern_relaysession_count(&cache.sessions) == 1U);
        res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 1U);
        res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 1U);
        res = (res == true && aern_fragment_table_count(&cache.fragments) == 1U);

        if (res == true)
        {
            aern_relay_session_remove(&cache, sess.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS);
            (void)aern_relay_pending_remove_session(&cache, sess.sessionid);
            (void)aern_relayqueue_remove_session(&cache.delayqueue, sess.sessionid, 0U);
            (void)aern_fragment_table_remove_session(&cache.fragments, sess.sessionid);

            res = (aern_relaysession_count(&cache.sessions) == 0U);
            res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 0U);
            res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 0U);
            res = (res == true && aern_fragment_table_count(&cache.fragments) == 0U);
        }
    }

    aern_relay_cache_dispose(&cache);

    return res;
}

static void aerntest_virtual_transport_init(aerntest_virtual_transport_state* trans)
{
    if (trans != NULL)
    {
        qsc_memutils_clear(trans, sizeof(aerntest_virtual_transport_state));
    }
}

static bool aerntest_virtual_transport_send(aerntest_virtual_transport_state* trans, uint8_t src, uint8_t dst, uint64_t sequence, const uint8_t* data, size_t length, uint64_t deliverat)
{
    bool res;

    res = false;

    if (trans != NULL && data != NULL && length <= AERNTEST_VIRTUAL_PACKET_SIZE && trans->count < AERNTEST_VIRTUAL_PACKET_CAPACITY)
    {
        aerntest_virtual_packet* pkt;

        pkt = &trans->packets[trans->count];
        qsc_memutils_clear(pkt, sizeof(aerntest_virtual_packet));
        qsc_memutils_copy(pkt->data, data, length);
        pkt->length = length;
        pkt->src = src;
        pkt->dst = dst;
        pkt->sequence = sequence;
        pkt->deliverat = deliverat;
        pkt->active = true;
        ++trans->count;
        ++trans->sent;
        res = true;
    }

    return res;
}

static bool aerntest_virtual_transport_drop(aerntest_virtual_transport_state* trans, uint64_t sequence)
{
    bool res;

    res = false;

    if (trans != NULL)
    {
        for (uint32_t i = 0U; i < trans->count; ++i)
        {
            if (trans->packets[i].active == true && trans->packets[i].sequence == sequence)
            {
                trans->packets[i].active = false;
                ++trans->dropped;
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool aerntest_virtual_transport_mutate(aerntest_virtual_transport_state* trans, uint64_t sequence)
{
    bool res;

    res = false;

    if (trans != NULL)
    {
        for (uint32_t i = 0U; i < trans->count; ++i)
        {
            if (trans->packets[i].active == true && trans->packets[i].sequence == sequence && trans->packets[i].length != 0U)
            {
                trans->packets[i].data[0U] ^= 0x5AU;
                trans->packets[i].mutated = true;
                ++trans->mutated;
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool aerntest_virtual_transport_replay(aerntest_virtual_transport_state* trans, uint64_t sequence)
{
    bool res;

    res = false;

    if (trans != NULL && trans->count < AERNTEST_VIRTUAL_PACKET_CAPACITY)
    {
        for (uint32_t i = 0U; i < trans->count; ++i)
        {
            if (trans->packets[i].active == true && trans->packets[i].sequence == sequence)
            {
                trans->packets[trans->count] = trans->packets[i];
                trans->packets[trans->count].replay = true;
                ++trans->count;
                ++trans->replayed;
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool aerntest_virtual_transport_reorder(aerntest_virtual_transport_state* trans, uint32_t a, uint32_t b)
{
    aerntest_virtual_packet tmp = { 0 };
    bool res;

    res = false;

    if (trans != NULL && a < trans->count && b < trans->count)
    {
        tmp = trans->packets[a];
        trans->packets[a] = trans->packets[b];
        trans->packets[b] = tmp;
        ++trans->reordered;
        res = true;
    }

    return res;
}

static uint32_t aerntest_virtual_transport_deliver_ready(aerntest_virtual_transport_state* trans, uint64_t now)
{
    uint32_t delivered;

    delivered = 0U;

    if (trans != NULL)
    {
        for (uint32_t i = 0U; i < trans->count; ++i)
        {
            if (trans->packets[i].active == true && trans->packets[i].deliverat <= now)
            {
                trans->packets[i].active = false;
                ++trans->delivered;
                ++delivered;
            }
            else if (trans->packets[i].active == true)
            {
                ++trans->delayed;
            }
            else
            {
                /* Inactive packets have already been dropped or delivered. */
            }
        }
    }

    return delivered;
}

static bool aerntest_virtual_transport_scheduler_test(void)
{
    aerntest_virtual_transport_state trans = { 0 };
    uint8_t msg[AERNTEST_VIRTUAL_PACKET_SIZE] = { 0 };
    uint32_t delivered;
    bool res;

    aerntest_virtual_transport_init(&trans);
    msg[0U] = 0xA0U;

    res = aerntest_virtual_transport_send(&trans, 1U, 2U, 1U, msg, 16U, 10U);
    msg[0U] = 0xB0U;
    res = (res == true && aerntest_virtual_transport_send(&trans, 1U, 3U, 2U, msg, 16U, 50U) == true);
    msg[0U] = 0xC0U;
    res = (res == true && aerntest_virtual_transport_send(&trans, 2U, 4U, 3U, msg, 16U, 10U) == true);
    res = (res == true && aerntest_virtual_transport_mutate(&trans, 3U) == true);
    res = (res == true && aerntest_virtual_transport_replay(&trans, 1U) == true);
    res = (res == true && aerntest_virtual_transport_drop(&trans, 2U) == true);
    res = (res == true && aerntest_virtual_transport_reorder(&trans, 0U, 2U) == true);

    delivered = aerntest_virtual_transport_deliver_ready(&trans, 25U);
    res = (res == true && delivered == 3U);
    res = (res == true && trans.sent == 3U && trans.count == 4U && trans.dropped == 1U);
    res = (res == true && trans.mutated == 1U && trans.replayed == 1U && trans.reordered == 1U);
    res = (res == true && trans.delivered == 3U && trans.delayed == 0U);

    return res;
}


static bool aerntest_virtual_transport_queue_pressure_test(void)
{
    aerntest_virtual_transport_state trans = { 0 };
    uint8_t msg[AERNTEST_VIRTUAL_PACKET_SIZE] = { 0U };
    uint32_t delivered;
    bool res;

    aerntest_virtual_transport_init(&trans);
    res = true;

    for (uint32_t i = 0U; i < AERNTEST_VIRTUAL_PACKET_CAPACITY && res == true; ++i)
    {
        msg[0U] = (uint8_t)i;
        res = aerntest_virtual_transport_send(&trans, 1U, 2U, (uint64_t)(i + 1U), msg, 16U, (uint64_t)(i * 10U));
    }

    msg[0U] = 0xFFU;
    res = (res == true && aerntest_virtual_transport_send(&trans, 1U, 2U, 1000U, msg, 16U, 1000U) == false);
    delivered = aerntest_virtual_transport_deliver_ready(&trans, 150U);
    res = (res == true && delivered == 16U);
    res = (res == true && trans.delivered == 16U && trans.delayed == (AERNTEST_VIRTUAL_PACKET_CAPACITY - 16U));
    delivered = aerntest_virtual_transport_deliver_ready(&trans, 1000U);
    res = (res == true && delivered == (AERNTEST_VIRTUAL_PACKET_CAPACITY - 16U));
    res = (res == true && trans.delivered == AERNTEST_VIRTUAL_PACKET_CAPACITY);

    return res;
}

static bool aerntest_virtual_fabric_scheduler_load_test(void)
{
    aerntest_virtual_transport_state trans = { 0 };
    uint8_t msg[AERNTEST_VIRTUAL_PACKET_SIZE] = { 0U };
    aerntest_virtual_fabric_state* fabric;
    uint32_t delivered;
    uint32_t i;
    bool res;

    fabric = (aerntest_virtual_fabric_state*)qsc_memutils_malloc(sizeof(aerntest_virtual_fabric_state));
    res = (fabric != NULL);
    aerntest_virtual_transport_init(&trans);

    if (res == true)
    {
        qsc_memutils_clear(fabric, sizeof(aerntest_virtual_fabric_state));
        res = aerntest_virtual_initialize_fabric(fabric);

        for (i = 0U; i < 32U && res == true; ++i)
        {
            msg[0U] = (uint8_t)i;
            msg[1U] = (uint8_t)(i ^ 0xA5U);
            res = aerntest_virtual_transport_send(&trans, 50U, 10U, (uint64_t)(i + 1U), msg, 32U, (uint64_t)(i % 4U));
        }

        res = (res == true && fabric->client.ctable.count == 1U);
        res = (res == true && fabric->aps[0U].ctable.count == (AERNTEST_VIRTUAL_APS_COUNT - 1U));
        delivered = aerntest_virtual_transport_deliver_ready(&trans, 3U);
        res = (res == true && delivered == 32U);
        res = (res == true && trans.sent == 32U && trans.delivered == 32U && trans.dropped == 0U);

        aerntest_virtual_fabric_dispose(fabric);
        qsc_memutils_alloc_free(fabric);
    }

    return res;
}


static bool aerntest_virtual_fabric_mixed_flow_scheduler_test(void)
{
    aerntest_virtual_transport_state trans = { 0 };
    uint8_t msg[AERNTEST_VIRTUAL_PACKET_SIZE] = { 0U };
    aerntest_virtual_fabric_state* fabric;
    uint32_t delivered;
    uint32_t outbound;
    uint32_t returned;
    uint32_t delayed;
    uint32_t i;
    bool res;

    fabric = (aerntest_virtual_fabric_state*)qsc_memutils_malloc(sizeof(aerntest_virtual_fabric_state));
    res = (fabric != NULL);
    aerntest_virtual_transport_init(&trans);
    outbound = 0U;
    returned = 0U;
    delayed = 0U;

    if (res == true)
    {
        qsc_memutils_clear(fabric, sizeof(aerntest_virtual_fabric_state));
        res = aerntest_virtual_initialize_fabric(fabric);

        for (i = 0U; i < 48U && res == true; ++i)
        {
            msg[0U] = (uint8_t)(0x40U + i);
            msg[1U] = (uint8_t)(i ^ 0x5AU);

            if ((i & 1U) == 0U)
            {
                ++outbound;
                res = aerntest_virtual_transport_send(&trans, 50U, 13U, (uint64_t)(i + 1U), msg, 32U, (uint64_t)(i % 6U));
            }
            else
            {
                ++returned;
                res = aerntest_virtual_transport_send(&trans, 13U, 50U, (uint64_t)(i + 1U), msg, 32U, (uint64_t)(i % 6U));
            }
        }

        res = (res == true && outbound == 24U && returned == 24U);
        res = (res == true && fabric->client.ctable.count == 1U);
        res = (res == true && fabric->aps[3U].ctable.count == (AERNTEST_VIRTUAL_APS_COUNT - 1U));

        delivered = aerntest_virtual_transport_deliver_ready(&trans, 2U);
        delayed = trans.delayed;
        res = (res == true && delivered == 24U);
        res = (res == true && delayed == 24U);

        delivered = aerntest_virtual_transport_deliver_ready(&trans, 6U);
        res = (res == true && delivered == 24U);
        res = (res == true && trans.sent == 48U && trans.delivered == 48U && trans.dropped == 0U);
        res = (res == true && trans.count == 48U);

        aerntest_virtual_fabric_dispose(fabric);
        qsc_memutils_alloc_free(fabric);
    }

    return res;
}

static bool aerntest_virtual_revocation_idle_active_cleanup_test(void)
{
    aern_relay_cache_state cache = { 0 };
    aern_relay_session_cache_entry idle = { 0 };
    aern_relay_session_cache_entry active = { 0 };
    aern_ingress_pending_item item = { 0 };
    uint8_t packet[AERNTEST_VIRTUAL_PACKET_SIZE] = { 0U };
    bool res;

    res = false;

    aern_relay_cache_initialize(&cache);

    if (cache.initialized == true)
    {
        idle.sessionid = 0x0102030405060708ULL;
        idle.status = (uint8_t)aern_relay_session_status_pending;
        idle.context = AERN_RELAY_SESSION_CONTEXT_INGRESS;
        idle.ingresshint = 1U;
        idle.egresshint = 2U;
        idle.expiry = 1000U;

        active.sessionid = 0x1112131415161718ULL;
        active.status = (uint8_t)aern_relay_session_status_active;
        active.context = AERN_RELAY_SESSION_CONTEXT_EGRESS;
        active.ingresshint = 1U;
        active.egresshint = 3U;
        active.expiry = 1000U;

        item.packet = packet;
        item.packetlen = 16U;
        item.capacity = sizeof(packet);
        item.sessionid = idle.sessionid;
        item.packetid = 1U;
        item.expiry = 1000U;
        item.delayuntil = 100U;
        item.active = true;

        res = aern_relay_session_add(&cache, &idle);
        res = (res == true && aern_relay_session_add(&cache, &active) == true);
        res = (res == true && aern_relay_pending_push(&cache, &item) == true);
        item.sessionid = active.sessionid;
        res = (res == true && aern_relay_delay_push(&cache, &item) == true);
        res = (res == true && aern_relaysession_count(&cache.sessions) == 2U);
        res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 1U);
        res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 1U);

        if (res == true)
        {
            aern_relay_session_remove(&cache, idle.sessionid, AERN_RELAY_SESSION_CONTEXT_INGRESS);
            (void)aern_relay_pending_remove_session(&cache, idle.sessionid);
            (void)aern_relayqueue_remove_session(&cache.delayqueue, idle.sessionid, 0U);

            res = (aern_relaysession_count(&cache.sessions) == 1U);
            res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 0U);
            res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 1U);
        }

        if (res == true)
        {
            aern_relay_session_remove(&cache, active.sessionid, AERN_RELAY_SESSION_CONTEXT_EGRESS);
            (void)aern_relay_pending_remove_session(&cache, active.sessionid);
            (void)aern_relayqueue_remove_session(&cache.delayqueue, active.sessionid, 0U);

            res = (aern_relaysession_count(&cache.sessions) == 0U);
            res = (res == true && aern_relayqueue_count(&cache.pendingqueue) == 0U);
            res = (res == true && aern_relayqueue_count(&cache.delayqueue) == 0U);
        }
    }

    aern_relay_cache_dispose(&cache);

    return res;
}

static bool aerntest_virtual_attack_observation_matrix_test(void)
{
    aerntest_attack_observation obs[5U] = { 0 };
    bool res;

    obs[0U].name = "replay";
    obs[0U].packetaccepted = false;
    obs[0U].tunneldown = false;
    obs[0U].sessiondown = false;
    obs[0U].topologychanged = false;
    obs[0U].queuecleared = false;
    obs[0U].fragmentcleared = false;
    obs[0U].backendcalled = false;

    obs[1U].name = "modified-authenticated-header";
    obs[1U].packetaccepted = false;
    obs[1U].tunneldown = false;
    obs[1U].sessiondown = false;
    obs[1U].topologychanged = false;
    obs[1U].queuecleared = false;
    obs[1U].fragmentcleared = false;
    obs[1U].backendcalled = false;

    obs[2U].name = "backend-failure";
    obs[2U].packetaccepted = true;
    obs[2U].tunneldown = false;
    obs[2U].sessiondown = false;
    obs[2U].topologychanged = false;
    obs[2U].queuecleared = false;
    obs[2U].fragmentcleared = false;
    obs[2U].backendcalled = true;

    obs[3U].name = "revocation-active-session";
    obs[3U].packetaccepted = false;
    obs[3U].tunneldown = true;
    obs[3U].sessiondown = true;
    obs[3U].topologychanged = true;
    obs[3U].queuecleared = true;
    obs[3U].fragmentcleared = true;
    obs[3U].backendcalled = false;

    obs[4U].name = "dummy-terminal";
    obs[4U].packetaccepted = true;
    obs[4U].tunneldown = false;
    obs[4U].sessiondown = false;
    obs[4U].topologychanged = false;
    obs[4U].queuecleared = false;
    obs[4U].fragmentcleared = false;
    obs[4U].backendcalled = false;

    res = (obs[0U].name != NULL && obs[1U].name != NULL && obs[2U].name != NULL && obs[3U].name != NULL && obs[4U].name != NULL);
    res = (res == true && obs[0U].packetaccepted == false && obs[0U].backendcalled == false && obs[0U].topologychanged == false);
    res = (res == true && obs[1U].packetaccepted == false && obs[1U].backendcalled == false && obs[1U].tunneldown == false);
    res = (res == true && obs[2U].packetaccepted == true && obs[2U].backendcalled == true && obs[2U].sessiondown == false);
    res = (res == true && obs[3U].tunneldown == true && obs[3U].sessiondown == true && obs[3U].queuecleared == true && obs[3U].fragmentcleared == true);
    res = (res == true && obs[4U].packetaccepted == true && obs[4U].backendcalled == false);

    return res;
}

bool aerntest_virtual_run(void)
{
    bool res;

    res = true;

    if (aerntest_virtual_fabric_initialization_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual fabric initialization test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual fabric initialization test.");
        res = false;
    }

    if (aerntest_virtual_transport_scheduler_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual transport scheduler mutation/drop/replay test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual transport scheduler mutation/drop/replay test.");
        res = false;
    }

    if (aerntest_virtual_relay_state_cleanup_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual revocation relay-state cleanup test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual revocation relay-state cleanup test.");
        res = false;
    }

    if (aerntest_virtual_transport_queue_pressure_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual transport queue-pressure flush test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual transport queue-pressure flush test.");
        res = false;
    }

    if (aerntest_virtual_fabric_scheduler_load_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual fabric scheduler load test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual fabric scheduler load test.");
        res = false;
    }

    if (aerntest_virtual_revocation_idle_active_cleanup_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual revocation idle-active cleanup test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual revocation idle-active cleanup test.");
        res = false;
    }

    if (aerntest_virtual_fabric_mixed_flow_scheduler_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual fabric mixed-flow scheduler test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual fabric mixed-flow scheduler test.");
        res = false;
    }

    if (aerntest_virtual_attack_observation_matrix_test() == true)
    {
        aerntest_print_line("[PASS] AERN virtual attack observation matrix test.");
    }
    else
    {
        aerntest_print_line("[FAIL] AERN virtual attack observation matrix test.");
        res = false;
    }

    return res;
}

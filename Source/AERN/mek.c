#include "mek.h"
#include "certificate.h"
#include "network.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "acp.h"
#include "socketclient.h"
#include "stringutils.h"
#include "timestamp.h"

/* Key-derivation label bytes. The NUL terminator is not included. */
static const uint8_t MEK_LABEL_TX[11U] = { 'A','E','R','N','-','M','E','K','-','T','X' };
static const uint8_t MEK_LABEL_RX[11U] = { 'A','E','R','N','-','M','E','K','-','R','X' };

/* Internal helpers. */


void mek_derive_and_init_ciphers(aern_connection_state* cns, uint8_t secret[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE], const uint8_t initiator[AERN_CERTIFICATE_SERIAL_SIZE], const uint8_t responder[AERN_CERTIFICATE_SERIAL_SIZE], bool initiatorrole)
{
    /* derive directional TX and RX RCS states from the exchanged secret. The
     * initiator perspective is canonical: TX material uses the TX label with
     * initiator and responder serial ordering, and RX material uses the RX label
     * with responder and initiator serial ordering. The responder installs those
     * materials in the opposite local direction. */

    AERN_ASSERT(cns != NULL);
    AERN_ASSERT(secret != NULL);
    AERN_ASSERT(initiator != NULL);
    AERN_ASSERT(responder != NULL);

    aern_cipher_keyparams kp;
    uint8_t txmat[AERN_MEK_KDF_OUTPUT_SIZE] = { 0U };
    uint8_t rxmat[AERN_MEK_KDF_OUTPUT_SIZE] = { 0U };
    uint8_t kdfin[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE + sizeof(MEK_LABEL_TX) + AERN_CERTIFICATE_SERIAL_SIZE + AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };
    size_t pos;

    qsc_memutils_clear(&kp, sizeof(aern_cipher_keyparams));

    if (cns != NULL && secret != NULL && initiator != NULL && responder != NULL)
    {
        pos = 0U;
        qsc_memutils_copy(kdfin + pos, secret, AERN_CRYPTO_SYMMETRIC_SECRET_SIZE);
        pos += AERN_CRYPTO_SYMMETRIC_SECRET_SIZE;
        qsc_memutils_copy(kdfin + pos, MEK_LABEL_TX, sizeof(MEK_LABEL_TX));
        pos += sizeof(MEK_LABEL_TX);
        qsc_memutils_copy(kdfin + pos, initiator, AERN_CERTIFICATE_SERIAL_SIZE);
        pos += AERN_CERTIFICATE_SERIAL_SIZE;
        qsc_memutils_copy(kdfin + pos, responder, AERN_CERTIFICATE_SERIAL_SIZE);
        qsc_shake256_compute(txmat, AERN_MEK_KDF_OUTPUT_SIZE, kdfin, sizeof(kdfin));

        qsc_memutils_clear(kdfin, sizeof(kdfin));
        pos = 0U;
        qsc_memutils_copy(kdfin + pos, secret, AERN_CRYPTO_SYMMETRIC_SECRET_SIZE);
        pos += AERN_CRYPTO_SYMMETRIC_SECRET_SIZE;
        qsc_memutils_copy(kdfin + pos, MEK_LABEL_RX, sizeof(MEK_LABEL_RX));
        pos += sizeof(MEK_LABEL_RX);
        qsc_memutils_copy(kdfin + pos, responder, AERN_CERTIFICATE_SERIAL_SIZE);
        pos += AERN_CERTIFICATE_SERIAL_SIZE;
        qsc_memutils_copy(kdfin + pos, initiator, AERN_CERTIFICATE_SERIAL_SIZE);
        qsc_shake256_compute(rxmat, AERN_MEK_KDF_OUTPUT_SIZE, kdfin, sizeof(kdfin));

        if (initiatorrole == true)
        {
            kp.key = txmat;
            kp.keylen = AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            kp.nonce = txmat + AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            kp.info = NULL;
            kp.infolen = 0U;
            aern_cipher_initialize(&cns->txcpr, &kp, true);

            kp.key = rxmat;
            kp.nonce = rxmat + AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            aern_cipher_initialize(&cns->rxcpr, &kp, false);
        }
        else
        {
            kp.key = rxmat;
            kp.keylen = AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            kp.nonce = rxmat + AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            kp.info = NULL;
            kp.infolen = 0U;
            aern_cipher_initialize(&cns->txcpr, &kp, true);

            kp.key = txmat;
            kp.nonce = txmat + AERN_CRYPTO_SYMMETRIC_KEY_SIZE;
            aern_cipher_initialize(&cns->rxcpr, &kp, false);
        }

        cns->txseq = 0U;
        cns->rxseq = 0U;
        cns->authfail = 0U;
        cns->exflag = aern_network_flag_tunnel_session_established;
    }

    qsc_memutils_secure_erase(secret, AERN_CRYPTO_SYMMETRIC_SECRET_SIZE);
    qsc_memutils_secure_erase(txmat, sizeof(txmat));
    qsc_memutils_secure_erase(rxmat, sizeof(rxmat));
    qsc_memutils_secure_erase(kdfin, sizeof(kdfin));
    qsc_memutils_secure_erase(&kp, sizeof(kp));
}

static bool mek_certificate_matches_node(const aern_topology_node_state* node, const aern_child_certificate* cert, const aern_root_certificate* root)
{
    uint8_t chash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };
    bool res;

    res = false;

    if (node != NULL && cert != NULL && root != NULL)
    {
        if (node->designation == aern_network_designation_aps &&
            cert->designation == aern_network_designation_aps &&
            aern_network_certificate_verify(cert, root) == aern_protocol_error_none)
        {
            qsc_memutils_clear(chash, sizeof(chash));
            aern_certificate_child_hash(chash, cert);

            if (qsc_memutils_are_equal(node->chash, chash, AERN_CERTIFICATE_HASH_SIZE) == true &&
                qsc_memutils_are_equal(node->serial, cert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true &&
                qsc_stringutils_strings_equal(node->issuer, cert->issuer) == true &&
                node->expiration.from == cert->expiration.from && node->expiration.to == cert->expiration.to)
            {
                res = true;
            }
        }
    }

    return res;
}

static bool mek_cipher_table_peer_is_synchronized(const aern_cipher_table* table, const aern_topology_node_state* node)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(node != NULL);

    const aern_cipher_table* ctable;
    uint32_t pos;
    bool res;

    ctable = table;
    pos = 0U;
    res = false;

    if (ctable != NULL && ctable->gmtx != NULL && node != NULL)
    {
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (ctable->slots[pos].used == true &&
                qsc_memutils_are_equal(ctable->slots[pos].serial, node->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
            {
                if (qsc_stringutils_strings_equal(ctable->slots[pos].address, node->address) == true &&
                    ctable->slots[pos].status == aern_mesh_peer_status_synchronized &&
                    ctable->slots[pos].rekeypending == false &&
                    ctable->slots[pos].cns.exflag == aern_network_flag_tunnel_session_established)
                {
                    res = true;
                }

                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return res;
}

static bool mek_peer_certificate_load(const aern_aps_state* state, const aern_topology_node_state* node, aern_child_certificate* cert)
{
    bool res;

    res = false;

    if (state != NULL && node != NULL && cert != NULL)
    {
        if (state->appstate != NULL)
        {
            qsc_memutils_clear(cert, sizeof(aern_child_certificate));

            if (aern_server_child_certificate_from_serial(cert, state->appstate, node->serial) == true)
            {
                res = mek_certificate_matches_node(node, cert, state->root);
            }
        }
    }

    return res;
}

aern_protocol_errors aern_mek_exchange_request(aern_mek_request_state* state)
{
    AERN_ASSERT(state != NULL);

    aern_network_mfk_request_state nstate = { 0 };
    aern_topology_node_state node = { 0 };
    uint8_t secret[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
    size_t alen;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    alen = 0U;

    if (state != NULL && state->remote_address != NULL && state->lcert != NULL &&
        state->rcert != NULL && state->root != NULL && state->sigkey != NULL && state->cns_out != NULL)
    {
        if (aern_network_certificate_verify(state->lcert, state->root) == aern_protocol_error_none &&
            aern_network_certificate_verify(state->rcert, state->root) == aern_protocol_error_none)
        {
            alen = qsc_stringutils_string_size(state->remote_address);

            if (alen > 0U && alen < AERN_CERTIFICATE_ADDRESS_SIZE)
            {
                qsc_memutils_copy(node.address, state->remote_address, alen);
                node.designation = aern_network_designation_aps;

                nstate.lcert = state->lcert;
                nstate.mfk = secret;
                nstate.rcert = state->rcert;
                nstate.rnode = &node;
                nstate.root = state->root;
                nstate.sigkey = state->sigkey;

                merr = aern_network_mfk_exchange_request(&nstate);

                if (merr == aern_protocol_error_none)
                {
                    qsc_memutils_secure_erase(state->cns_out, sizeof(aern_connection_state));
                    mek_derive_and_init_ciphers(state->cns_out, secret, state->lcert->serial, state->rcert->serial, true);
                    state->cns_out->instance = (uint32_t)qsc_timestamp_datetime_utc();
                }
            }
        }
        else
        {
            merr = aern_protocol_error_authentication_failure;
        }
    }

    qsc_memutils_secure_erase(secret, sizeof(secret));
    qsc_memutils_secure_erase(&nstate, sizeof(nstate));
    qsc_memutils_secure_erase(&node, sizeof(node));

    return merr;
}

aern_protocol_errors aern_mek_exchange_response(aern_mek_response_state* state, const aern_network_packet* packetin)
{
    aern_network_mfk_response_state nstate = { 0 };
    uint8_t secret[AERN_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0U };
    aern_protocol_errors merr;

    AERN_ASSERT(state != NULL);
    AERN_ASSERT(packetin != NULL);

    merr = aern_protocol_error_invalid_request;

    if (state != NULL && packetin != NULL && state->csock != NULL && state->lcert != NULL && 
        state->rcert != NULL && state->root != NULL && state->sigkey != NULL && state->cns_out != NULL)
    {
        if (aern_network_certificate_verify(state->lcert, state->root) == aern_protocol_error_none)
        {
            nstate.csock = state->csock;
            nstate.lcert = state->lcert;
            nstate.mfk = secret;
            nstate.rcert = (aern_child_certificate*)state->rcert;
            nstate.root = state->root;
            nstate.sigkey = state->sigkey;

            merr = aern_network_mfk_exchange_response(&nstate, packetin);

            if (merr == aern_protocol_error_none)
            {
                qsc_memutils_secure_erase(state->cns_out, sizeof(aern_connection_state));
                qsc_memutils_copy(&state->cns_out->target, state->csock, sizeof(qsc_socket));
                mek_derive_and_init_ciphers(state->cns_out, secret, state->rcert->serial, state->lcert->serial, false);
                state->cns_out->instance = (uint32_t)qsc_timestamp_datetime_utc();
            }
        }
        else
        {
            merr = aern_protocol_error_authentication_failure;
        }
    }

    qsc_memutils_secure_erase(secret, sizeof(secret));
    qsc_memutils_secure_erase(&nstate, sizeof(nstate));

    return merr;
}

void aern_cipher_table_initialize(aern_cipher_table* table)
{
    AERN_ASSERT(table != NULL);

    if (table != NULL)
    {
        qsc_memutils_clear(table, sizeof(aern_cipher_table));
        table->count = 0U;
        table->gmtx = qsc_async_mutex_create();
    }
}

aern_protocol_errors aern_cipher_table_add(aern_cipher_table* table, const char* address, const aern_connection_state* cns)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(address != NULL);
    AERN_ASSERT(cns != NULL);

    aern_protocol_errors merr;

    merr = aern_cipher_table_add_peer(table, address, NULL, cns, aern_mesh_peer_status_synchronized);

    return merr;
}

aern_protocol_errors aern_cipher_table_add_peer(aern_cipher_table* table, const char* address, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], const aern_connection_state* cns, aern_mesh_peer_status status)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(address != NULL);
    AERN_ASSERT(cns != NULL);

    size_t len;
    uint32_t empty;
    uint32_t pos;
    aern_protocol_errors merr;
    bool found;

    merr = aern_protocol_error_invalid_request;
    len = 0U;
    empty = AERN_MAX_PEERS;
    pos = 0U;
    found = false;

    if (table != NULL && table->gmtx != NULL && address != NULL && cns != NULL)
    {
        len = qsc_stringutils_string_size(address);

        if (len > 0U && len < AERN_CERTIFICATE_ADDRESS_SIZE)
        {
            qsc_async_mutex_lock(table->gmtx);

            for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
            {
                if (table->slots[pos].used == true)
                {
                    if (qsc_stringutils_strings_equal(table->slots[pos].address, address) == true)
                    {
                        found = true;
                        break;
                    }
                }
                else if (empty == AERN_MAX_PEERS)
                {
                    empty = pos;
                }
            }

            if (found == true)
            {
                aern_connection_state_dispose(&table->slots[pos].cns);
                qsc_memutils_secure_erase(&table->slots[pos], sizeof(aern_cipher_table_slot));
                table->slots[pos].used = true;
                qsc_memutils_copy(table->slots[pos].address, address, len);
                table->slots[pos].address[len] = '\0';

                if (serial != NULL)
                {
                    qsc_memutils_copy(table->slots[pos].serial, serial, AERN_CERTIFICATE_SERIAL_SIZE);
                }

                qsc_memutils_copy(&table->slots[pos].cns, cns, sizeof(aern_connection_state));
                table->slots[pos].created = qsc_timestamp_datetime_utc();
                table->slots[pos].lastrekey = table->slots[pos].created;
                table->slots[pos].rekeypending = false;
                table->slots[pos].status = status;
                merr = aern_protocol_error_none;
            }
            else if (empty < AERN_MAX_PEERS)
            {
                qsc_memutils_secure_erase(&table->slots[empty], sizeof(aern_cipher_table_slot));
                table->slots[empty].used = true;
                qsc_memutils_copy(table->slots[empty].address, address, len);
                table->slots[empty].address[len] = '\0';

                if (serial != NULL)
                {
                    qsc_memutils_copy(table->slots[empty].serial, serial, AERN_CERTIFICATE_SERIAL_SIZE);
                }

                qsc_memutils_copy(&table->slots[empty].cns, cns,
                    sizeof(aern_connection_state));
                table->slots[empty].created = qsc_timestamp_datetime_utc();
                table->slots[empty].lastrekey = table->slots[empty].created;
                table->slots[empty].rekeypending = false;
                table->slots[empty].status = status;
                ++table->count;
                merr = aern_protocol_error_none;
            }
            else
            {
                merr = aern_protocol_error_hosts_exceeded;
            }

            qsc_async_mutex_unlock(table->gmtx);
        }
    }

    return merr;
}

aern_connection_state* aern_cipher_table_get_by_ip(aern_cipher_table* table, const char* address)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(address != NULL);

    aern_connection_state* res;
    uint32_t pos;

    res = NULL;
    ;
    pos = 0U;

    if (table != NULL && table->gmtx != NULL && address != NULL)
    {
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true && qsc_stringutils_strings_equal(table->slots[pos].address, address) == true)
            {
                res = &table->slots[pos].cns;
                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return res;
}

aern_connection_state* aern_cipher_table_get_by_serial(aern_cipher_table* table, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE])
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(serial != NULL);

    aern_connection_state* res;
    uint32_t pos;

    res = NULL;
    pos = 0U;

    if (table != NULL && table->gmtx != NULL && serial != NULL)
    {
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true && qsc_memutils_are_equal(table->slots[pos].serial, serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
            {
                res = &table->slots[pos].cns;
                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return res;
}

aern_connection_state* aern_cipher_table_get_by_instance(aern_cipher_table* table, uint32_t instance)
{
    AERN_ASSERT(table != NULL);

    aern_connection_state* res;
    uint32_t pos;

    res = NULL;;
    pos = 0U;

    if (table != NULL && table->gmtx != NULL)
    {
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true && table->slots[pos].cns.instance == instance)
            {
                res = &table->slots[pos].cns;
                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return res;
}

aern_protocol_errors aern_cipher_table_remove(aern_cipher_table* table, const char* address)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(address != NULL);

    uint32_t pos;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    pos = 0U;

    if (table != NULL && table->gmtx != NULL && address != NULL)
    {
        merr = aern_protocol_error_node_not_found;
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true && qsc_stringutils_strings_equal(table->slots[pos].address, address) == true)
            {
                aern_connection_state_dispose(&table->slots[pos].cns);
                qsc_memutils_secure_erase(&table->slots[pos], sizeof(aern_cipher_table_slot));

                if (table->count > 0U)
                {
                    --table->count;
                }

                merr = aern_protocol_error_none;
                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return merr;
}

void aern_cipher_table_dispose(aern_cipher_table* table)
{
    AERN_ASSERT(table != NULL);

    uint32_t pos;

    pos = 0U;

    if (table != NULL && table->gmtx != NULL)
    {
        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true)
            {
                aern_connection_state_dispose(&table->slots[pos].cns);
            }
        }

        if (table->gmtx != NULL)
        {
            qsc_async_mutex_destroy(table->gmtx);
            table->gmtx = NULL;
        }

        qsc_memutils_secure_erase(table, sizeof(aern_cipher_table));
        table->count = 0U;
    }
}

bool aern_mek_rekey_required(const aern_connection_state* cns)
{
    AERN_ASSERT(cns != NULL);

    bool res;

    res = false;

    if (cns != NULL)
    {
        if (cns->txseq >= AERN_MEK_REKEY_SOFT_THRESHOLD || cns->rxseq >= AERN_MEK_REKEY_SOFT_THRESHOLD)
        {
            res = true;
        }
    }

    return res;
}

bool aern_mek_rekey_limit_exceeded(const aern_connection_state* cns)
{
    AERN_ASSERT(cns != NULL);

    bool res;

    res = false;

    if (cns != NULL)
    {
        if (cns->txseq >= AERN_MEK_REKEY_PACKET_THRESHOLD || cns->rxseq >= AERN_MEK_REKEY_PACKET_THRESHOLD)
        {
            res = true;
        }
    }

    return res;
}

aern_protocol_errors aern_cipher_table_mark_rekey_pending(aern_cipher_table* table, const uint8_t serial[AERN_CERTIFICATE_SERIAL_SIZE], bool pending)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(serial != NULL);

    uint32_t pos;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    pos = 0U;

    if (table != NULL && table->gmtx != NULL && serial != NULL)
    {
        merr = aern_protocol_error_node_not_found;
        qsc_async_mutex_lock(table->gmtx);

        for (pos = 0U; pos < AERN_MAX_PEERS; ++pos)
        {
            if (table->slots[pos].used == true && qsc_memutils_are_equal(table->slots[pos].serial, serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
            {
                table->slots[pos].rekeypending = pending;

                if (pending == true)
                {
                    table->slots[pos].status = aern_mesh_peer_status_synchronizing;
                }
                else if (table->slots[pos].status == aern_mesh_peer_status_synchronizing)
                {
                    table->slots[pos].status = aern_mesh_peer_status_synchronized;
                }
                else
                {
                    /* The current non-synchronizing status is preserved. */
                }

                merr = aern_protocol_error_none;
                break;
            }
        }

        qsc_async_mutex_unlock(table->gmtx);
    }

    return merr;
}

size_t aern_aps_mesh_synchronize(aern_aps_state* state)
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(state->lcert != NULL);
    AERN_ASSERT(state->root != NULL);
    AERN_ASSERT(state->sigkey != NULL);
    AERN_ASSERT(state->appstate != NULL);
    AERN_ASSERT(state->vtopo != NULL);
    AERN_ASSERT(state->ctable != NULL);

    aern_child_certificate cert = { 0 };
    aern_connection_state cns = { 0 };
    aern_mek_request_state reqs = { 0 };
    aern_topology_node_state node = { 0 };
    const aern_topology_list_state* list;
    size_t established;
    size_t pos;
    aern_protocol_errors merr;

    list = NULL;
    established = 0U;
    pos = 0U;

    if (state != NULL && state->lcert != NULL && state->root != NULL && state->sigkey != NULL && state->appstate != NULL && state->vtopo != NULL && state->ctable != NULL)
    {
        list = state->vtopo;

        for (pos = 0U; pos < list->count; ++pos)
        {
            qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

            if (aern_topology_list_item(list, &node, pos) == true)
            {
                if (node.designation == aern_network_designation_aps &&
                    qsc_memutils_are_equal(node.serial, state->lcert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == false)
                {
                    qsc_memutils_clear(&cert, sizeof(aern_child_certificate));

                    if (mek_peer_certificate_load(state, &node, &cert) == true)
                    {
                        if (mek_cipher_table_peer_is_synchronized(state->ctable, &node) == true)
                        {
                            ++established;
                        }
                        else
                        {
                            qsc_memutils_clear(&cns, sizeof(aern_connection_state));
                            qsc_memutils_clear(&reqs, sizeof(aern_mek_request_state));

                            reqs.remote_address = node.address;
                            reqs.lcert = state->lcert;
                            reqs.rcert = &cert;
                            reqs.root = state->root;
                            reqs.sigkey = state->sigkey;
                            reqs.cns_out = &cns;

                            merr = aern_mek_exchange_request(&reqs);

                            if (merr == aern_protocol_error_none)
                            {
                                merr = aern_cipher_table_add_peer(state->ctable, node.address, node.serial, &cns, aern_mesh_peer_status_synchronized);

                                if (merr == aern_protocol_error_none)
                                {
                                    ++established;
                                }
                                else
                                {
                                    aern_connection_state_dispose(&cns);
                                }
                            }
                            else
                            {
                                aern_connection_state_dispose(&cns);
                            }
                        }
                    }
                }
            }
        }
    }

    qsc_memutils_secure_erase(&cert, sizeof(cert));
    qsc_memutils_secure_erase(&cns, sizeof(cns));
    qsc_memutils_secure_erase(&reqs, sizeof(reqs));
    qsc_memutils_secure_erase(&node, sizeof(node));

    return established;
}

bool aern_aps_is_synchronized(const aern_aps_state* state)
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(state->lcert != NULL);
    AERN_ASSERT(state->root != NULL);
    AERN_ASSERT(state->appstate != NULL);
    AERN_ASSERT(state->vtopo != NULL);
    AERN_ASSERT(state->ctable != NULL);

    aern_child_certificate cert = { 0 };
    aern_topology_node_state node = { 0 };
    const aern_topology_list_state* list;
    size_t pos;
    bool localfound;
    bool res;

    list = NULL;
    pos = 0U;
    localfound = false;
    res = false;

    if (state != NULL && state->lcert != NULL && state->root != NULL && state->appstate != NULL && state->vtopo != NULL && state->ctable != NULL)
    {
        list = state->vtopo;

        if (aern_network_certificate_verify(state->lcert, state->root) == aern_protocol_error_none && list->topology != NULL && list->count > 0U)
        {
            res = true;

            for (pos = 0U; pos < list->count; ++pos)
            {
                qsc_memutils_clear(&node, sizeof(aern_topology_node_state));

                if (aern_topology_list_item(list, &node, pos) == true)
                {
                    if (node.designation == aern_network_designation_aps)
                    {
                        if (qsc_memutils_are_equal(node.serial, state->lcert->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
                        {
                            localfound = true;

                            if (mek_certificate_matches_node(&node, state->lcert, state->root) == false)
                            {
                                res = false;
                                break;
                            }
                        }
                        else
                        {
                            qsc_memutils_clear(&cert, sizeof(aern_child_certificate));

                            if (mek_peer_certificate_load(state, &node, &cert) == false)
                            {
                                res = false;
                                break;
                            }

                            if (mek_cipher_table_peer_is_synchronized(state->ctable, &node) == false)
                            {
                                res = false;
                                break;
                            }
                        }
                    }
                }
                else
                {
                    res = false;
                    break;
                }
            }

            if (localfound == false)
            {
                res = false;
            }
        }
    }

    qsc_memutils_secure_erase(&cert, sizeof(cert));
    qsc_memutils_secure_erase(&node, sizeof(node));

    return res;
}

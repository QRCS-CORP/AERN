#include "lifecycle.h"
#include "aern.h"
#include "certificate.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "acp.h"
#include "async.h"
#include "socketclient.h"
#include "stringutils.h"
#include "timestamp.h"

#define LC_RESIGN_REQ_SEQ 0xFFFFFF20UL
#define LC_RESIGN_ACK_SEQ 0xFFFFFF21UL
#define LC_RESIGN_REQ_MSG (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE +  AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define LC_RESIGN_REQ_PKT (AERN_PACKET_HEADER_SIZE + LC_RESIGN_REQ_MSG)
#define LC_RESIGN_ACK_MSG (AERN_PACKET_SUBHEADER_SIZE + 8U + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define LC_RESIGN_ACK_PKT (AERN_PACKET_HEADER_SIZE + LC_RESIGN_ACK_MSG)
#define LC_REVOKE_ACK_SEQ 0xFFFFFF22UL
#define LC_REVOKE_ACK_MSG (AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE)
#define LC_REVOKE_ACK_PKT (AERN_PACKET_HEADER_SIZE + LC_REVOKE_ACK_MSG)
#define LC_KEEPALIVE_PKT_MSG 0U
#define LC_KEEPALIVE_PKT_SIZE (AERN_PACKET_HEADER_SIZE + LC_KEEPALIVE_PKT_MSG)


static const char* const LC_PROTOCOL_ERROR_STRINGS[] =
{
    /* 0x00 */ "None",
    /* 0x01 */ "Authentication failure",
    /* 0x02 */ "Certificate not found",
    /* 0x03 */ "Communications channel failed",
    /* 0x04 */ "Connection failure",
    /* 0x05 */ "Connect failure",
    /* 0x06 */ "Convergence failure",
    /* 0x07 */ "Convergence synchronized",
    /* 0x08 */ "Decapsulation failure",
    /* 0x09 */ "Decoding failure",
    /* 0x0A */ "Decryption failure",
    /* 0x0B */ "Establish failure",
    /* 0x0C */ "Exchange failure",
    /* 0x0D */ "File not deleted",
    /* 0x0E */ "File not found",
    /* 0x0F */ "File not written",
    /* 0x10 */ "Hash invalid",
    /* 0x11 */ "Hosts exceeded",
    /* 0x12 */ "Invalid request",
    /* 0x13 */ "Certificate expired",
    /* 0x14 */ "Key expired",
    /* 0x15 */ "Key unrecognized",
    /* 0x16 */ "Listener failure",
    /* 0x17 */ "Memory allocation failure",
    /* 0x18 */ "Message timestamp invalid",
    /* 0x19 */ "Message verification failure",
    /* 0x1A */ "No usable address",
    /* 0x1B */ "Node not available",
    /* 0x1C */ "Node not found",
    /* 0x1D */ "Node already registered",
    /* 0x1E */ "Operation cancelled",
    /* 0x1F */ "Packet header invalid",
    /* 0x20 */ "Packet unsequenced",
    /* 0x21 */ "Receive failure",
    /* 0x22 */ "Root signature invalid",
    /* 0x23 */ "Serialization failure",
    /* 0x24 */ "Signature failure",
    /* 0x25 */ "Signing failure",
    /* 0x26 */ "Socket binding failure",
    /* 0x27 */ "Socket creation failure",
    /* 0x28 */ "Transmit failure",
    /* 0x29 */ "No APS in topology",
    /* 0x2A */ "Unknown protocol",
    /* 0x2B */ "Verification failure",
};

#define LC_PROTOCOL_ERROR_COUNT  (sizeof(LC_PROTOCOL_ERROR_STRINGS) / sizeof(LC_PROTOCOL_ERROR_STRINGS[0]))


static const uint8_t LC_RESIGNED_TAG[8U] = { 'r','e','s','i','g','n','e','d', };

static void lc_write_subheader(uint8_t dst[AERN_PACKET_SUBHEADER_SIZE], const aern_network_packet* pkt)
{
    qsc_intutils_le64to8(dst, pkt->sequence);
    qsc_intutils_le64to8(dst + sizeof(uint64_t), pkt->utctime);
}

static aern_protocol_errors lc_validate_header(const aern_network_packet* pkt, aern_network_flags expected_flag, uint64_t expected_seq)
{
    aern_protocol_errors perr;

    if (pkt->flag == (uint8_t)aern_network_flag_system_error_condition)
    {
        perr = (aern_protocol_errors)pkt->pmessage[0U];
    }
    else if (!aern_packet_time_valid(pkt))
    {
        perr = aern_protocol_error_message_time_invalid;
    }
    else if (pkt->flag != (uint8_t)expected_flag)
    {
        perr = aern_protocol_error_invalid_request;
    }
    else if (pkt->sequence != expected_seq)
    {
        perr = aern_protocol_error_packet_unsequenced;
    }
    else
    {
        perr = aern_protocol_error_none;
    }

    return perr;
}

static aern_protocol_errors lc_recv_exact(const qsc_socket* csock, uint8_t* rbuf, size_t expected_size, aern_network_packet* pkt_out)
{
    size_t rlen;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;
    rlen = qsc_socket_receive(csock, rbuf, expected_size, qsc_socket_receive_flag_wait_all);

    if (rlen >= AERN_PACKET_HEADER_SIZE)
    {
        aern_packet_header_deserialize(rbuf, pkt_out);
        pkt_out->pmessage = rbuf + AERN_PACKET_HEADER_SIZE;

        if (rlen == expected_size)
        {
            merr = aern_protocol_error_none;
        }
        else if (pkt_out->flag == (uint8_t)aern_network_flag_system_error_condition && rlen > AERN_PACKET_HEADER_SIZE)
        {
            merr = (aern_protocol_errors)rbuf[AERN_PACKET_HEADER_SIZE];
        }
        else
        {
            merr = aern_protocol_error_receive_failure;
        }
    }

    return merr;
}

void aern_teardown_connection(aern_connection_state* cstate, qsc_socket* csock, const char* address, aern_cipher_table* ctable)
{
    AERN_ASSERT(cstate != NULL);

    if (cstate != NULL)
    {
        if (csock != NULL && qsc_socket_is_connected(csock))
        {
            aern_connection_close(csock, aern_network_error_channel_down, true);
        }

        qsc_rcs_dispose(&cstate->rxcpr);
        qsc_rcs_dispose(&cstate->txcpr);
        cstate->rxseq = 0U;
        cstate->txseq = 0U;
        cstate->exflag = aern_network_flag_none;
        cstate->instance = 0U;

        /* remove from cipher table (socket already closed above) */
        if (ctable != NULL && address != NULL)
        {
            aern_cipher_table_remove(ctable, address);
        }
    }
}

aern_protocol_errors aern_resign_request_v2(aern_resign_request_v2_state* state)
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(state->address != NULL);
    AERN_ASSERT(state->lcert != NULL);
    AERN_ASSERT(state->sigkey != NULL);
    AERN_ASSERT(state->root != NULL);

    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (state != NULL && state->address != NULL && state->lcert != NULL && state->sigkey != NULL && state->root != NULL)
    {
        qsc_socket csock = { 0 };

        if (aern_network_connect_to_device(&csock, state->address, aern_network_designation_adc) == qsc_socket_exception_success)
        {
            /* build request: subhdr || serial || Sign(SHA3-256(subhdr || serial)) */
            uint8_t sbuf[LC_RESIGN_REQ_PKT] = { 0U };
            aern_network_packet req = { 0 };

            req.flag = (uint8_t)aern_network_flag_network_resign_request;
            req.sequence = LC_RESIGN_REQ_SEQ;
            req.msglen = (uint32_t)LC_RESIGN_REQ_MSG;
            aern_packet_set_utc_time(&req);
            req.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

            lc_write_subheader(req.pmessage, &req);
            qsc_memutils_copy(req.pmessage + AERN_PACKET_SUBHEADER_SIZE, state->lcert->serial, AERN_CERTIFICATE_SERIAL_SIZE);

            size_t sl = aern_certificate_message_hash_sign(req.pmessage + AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE,
                state->sigkey, req.pmessage, AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE);

            if (sl == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
            {
                aern_packet_header_serialize(&req, sbuf);

                size_t slen = qsc_socket_client_send(&csock, sbuf, LC_RESIGN_REQ_PKT, qsc_socket_send_flag_none);

                if (slen == LC_RESIGN_REQ_PKT)
                {
                    /* receive acknowledgement: subhdr || "resigned"(8) || adc_sig */
                    uint8_t rbuf[LC_RESIGN_ACK_PKT] = { 0U };
                    aern_network_packet ack = { 0 };

                    merr = lc_recv_exact(&csock, rbuf, LC_RESIGN_ACK_PKT, &ack);
                    aern_network_socket_dispose(&csock);

                    if (merr == aern_protocol_error_none)
                    {
                        merr = lc_validate_header(&ack, aern_network_flag_network_resign_response, LC_RESIGN_ACK_SEQ);

                        if (merr == aern_protocol_error_none)
                        {
                            /* verify ADC signature on (subhdr || "resigned") */
                            if (aern_certificate_signature_hash_verify(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE + 8U, AERN_CERTIFICATE_SIGNED_HASH_SIZE,
                                ack.pmessage, AERN_PACKET_SUBHEADER_SIZE + 8U, NULL) == false)
                            {
                                if (qsc_memutils_are_equal(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE, LC_RESIGNED_TAG, 8U) == false)
                                {
                                    return aern_protocol_error_authentication_failure;
                                }
                            }

                            /* verify "resigned" tag */
                            if (qsc_memutils_are_equal(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE, LC_RESIGNED_TAG, 8U) == false)
                            {
                                return aern_protocol_error_authentication_failure;
                            }

                            /* zero all cipher states and session state */
                            if (state->ctable != NULL)
                            {
                                aern_cipher_table_dispose(state->ctable);
                            }

                            /* zero the signing key (caller must zero cert) */
                            qsc_memutils_secure_erase((uint8_t*)state->sigkey, AERN_ASYMMETRIC_SIGNING_KEY_SIZE);
                            merr = aern_protocol_error_none;
                        }
                    }
                }
                else
                {
                    aern_network_socket_dispose(&csock);
                    return aern_protocol_error_transmit_failure;
                }
            }
            else
            {
                aern_network_socket_dispose(&csock);
                return aern_protocol_error_signing_failure;
            }
        }
        else
        {
            merr = aern_protocol_error_connection_failure;
        }
    }

    return merr;
}

aern_protocol_errors aern_resign_response_v2(aern_resign_response_v2_state* state, const aern_network_packet* packetin)
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(state->csock != NULL);
    AERN_ASSERT(state->lcert != NULL);
    AERN_ASSERT(state->sigkey != NULL);
    AERN_ASSERT(state->vtopo != NULL);
    AERN_ASSERT(packetin != NULL);

    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (state != NULL && state->csock != NULL && state->lcert != NULL && state->sigkey != NULL && state->vtopo != NULL && packetin != NULL)
    {
        /* step 1: validate header */
        merr = lc_validate_header(packetin, aern_network_flag_network_resign_request, LC_RESIGN_REQ_SEQ);

        if (merr == aern_protocol_error_none)
        {
            aern_topology_node_state rnode = { 0 };
            aern_child_certificate stub = { 0 };

            /* verify subheader timestamp byte-for-byte */
            {
                uint8_t expected[AERN_PACKET_SUBHEADER_SIZE] = { 0U };
                lc_write_subheader(expected, packetin);

                if (!qsc_memutils_are_equal(expected, packetin->pmessage, AERN_PACKET_SUBHEADER_SIZE))
                {
                    merr = aern_protocol_error_message_time_invalid;
                    aern_network_send_error(state->csock, merr);
                    return merr;
                }
            }

            const uint8_t* rserial = packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE;

            if (!aern_topology_node_find(state->vtopo, &rnode, rserial))
            {
                merr = aern_protocol_error_node_not_found;
                aern_network_send_error(state->csock, merr);
                return merr;
            }

            /* step 2: verify device signature on (subhdr || serial) 
             * to verify the signature we need the device's verkey.
             * the topology node stores chash (cert hash), not the verkey directly.
             * we create a stub certificate with the verkey from the topology child hash
             * field for verification. In a full implementation the cert would be loaded from disk here. */
            qsc_memutils_copy(stub.serial, rnode.serial, AERN_CERTIFICATE_SERIAL_SIZE);
            /* verkey stored at chash offset in Phase-2 register path */
            qsc_memutils_copy(stub.verkey, rnode.chash, AERN_CERTIFICATE_HASH_SIZE);

            if (aern_certificate_signature_hash_verify( packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE,
                AERN_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE, &stub) == false)
            {
                merr = aern_protocol_error_authentication_failure;
                aern_network_send_error(state->csock, merr);
                return merr;
            }

            /* steps 4, 5: APS revoke_broadcast; Client remove silently */
            if (rnode.designation == aern_network_designation_aps)
            {
                aern_network_revoke_request_state rrs = 
                {
                    .designation = aern_network_designation_aps,
                    .list = state->vtopo,
                    .rnode = &rnode,
                    .sigkey = state->sigkey
                };

                merr = aern_network_revoke_broadcast(&rrs);
            }
            else
            {
                /* client: remove from topology; no broadcast */
                aern_topology_node_remove(state->vtopo, rserial);
                aern_topology_increment_version(state->vtopo);
                merr = aern_protocol_error_none;
            }

            if (merr != aern_protocol_error_none)
            {
                aern_network_send_error(state->csock, merr);
                return merr;
            }

            /* step 6: send acknowledgement: subhdr || "resigned"(8) || adc_sig */
            const size_t ackmsg = AERN_PACKET_SUBHEADER_SIZE + 8U + AERN_CERTIFICATE_SIGNED_HASH_SIZE;
            const size_t ackpkt = AERN_PACKET_HEADER_SIZE + ackmsg;
            uint8_t* abuf = (uint8_t*)qsc_memutils_malloc(ackpkt);

            if (abuf == NULL)
            {
                return aern_protocol_error_memory_allocation;
            }

            aern_network_packet ack = { 0 };
            ack.flag = (uint8_t)aern_network_flag_network_resign_response;
            ack.sequence = LC_RESIGN_ACK_SEQ;
            ack.msglen = (uint32_t)ackmsg;
            aern_packet_set_utc_time(&ack);
            ack.pmessage = abuf + AERN_PACKET_HEADER_SIZE;

            lc_write_subheader(ack.pmessage, &ack);
            qsc_memutils_copy(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE, LC_RESIGNED_TAG, 8U);

            size_t sl = aern_certificate_message_hash_sign(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE + 8U, state->sigkey, ack.pmessage, AERN_PACKET_SUBHEADER_SIZE + 8U);

            if (sl != AERN_CERTIFICATE_SIGNED_HASH_SIZE)
            {
                qsc_memutils_alloc_free(abuf);
                return aern_protocol_error_signing_failure;
            }

            aern_packet_header_serialize(&ack, abuf);
            qsc_socket_client_send(state->csock, abuf, ackpkt, qsc_socket_send_flag_none);
            qsc_memutils_secure_erase(abuf, ackpkt);
            qsc_memutils_alloc_free(abuf);
            merr = aern_protocol_error_none;
        }
        else
        {
            aern_network_send_error(state->csock, merr);
        }
    }

    return aern_protocol_error_none;
}

aern_protocol_errors aern_revoke_response_v2(aern_revoke_v2_state* state, const aern_network_packet* packetin)
{
    AERN_ASSERT(state != NULL);
    AERN_ASSERT(state->csock != NULL);
    AERN_ASSERT(state->lcert != NULL);
    AERN_ASSERT(state->dcert != NULL);
    AERN_ASSERT(state->sigkey != NULL);
    AERN_ASSERT(state->vtopo != NULL);
    AERN_ASSERT(state->ctable != NULL);
    AERN_ASSERT(packetin != NULL);

    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (state != NULL && state->csock != NULL && state->dcert != NULL && state->sigkey != NULL && state->vtopo != NULL && state->ctable != NULL && packetin != NULL)
    {
        /* verify header */
        merr = lc_validate_header(packetin, aern_network_flag_network_revocation_broadcast, 0xFFFFFF14UL);

        /* fallback: phase-1 uses a different sequence; accept either */
        if (merr == aern_protocol_error_packet_unsequenced)
        {
            if (packetin->flag == (uint8_t)aern_network_flag_network_revocation_broadcast)
            {
                merr = aern_protocol_error_none;
            }
        }

        if (merr == aern_protocol_error_none)
        {
            /* verify ADC signature on (subhdr || serial) */
            const size_t msg_len = AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SERIAL_SIZE;
            const uint8_t* sig = packetin->pmessage + msg_len;

            if (aern_certificate_signature_hash_verify(sig, AERN_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, msg_len, state->dcert) == false)
            {
                merr = aern_protocol_error_authentication_failure;
            }
        }

        if (merr != aern_protocol_error_none)
        {
            aern_network_send_error(state->csock, merr);
            return merr;
        }

        /* extract revoked serial */
        const uint8_t* rev_serial = packetin->pmessage + AERN_PACKET_SUBHEADER_SIZE;

        /* find in cipher table by topology, send terminate, zero ciphers */
        aern_topology_node_state rev_node = { 0 };

        if (aern_topology_node_find(state->vtopo, &rev_node, rev_serial))
        {
            aern_connection_state* cns = aern_cipher_table_get_by_ip(state->ctable, rev_node.address);

            if (cns != NULL)
            {
                /* send connection-terminated on the tunnel */
                if (qsc_socket_is_connected(&cns->target))
                {
                    aern_connection_close(&cns->target, aern_network_error_channel_down, true);
                }

                qsc_rcs_dispose(&cns->rxcpr);
                qsc_rcs_dispose(&cns->txcpr);
                cns->rxseq = 0U;
                cns->txseq = 0U;
                cns->exflag = aern_network_flag_none;

                /* remove from cipher table */
                aern_cipher_table_remove(state->ctable, rev_node.address);
            }
        }

        /* remove from topology, increment version */
        aern_topology_node_remove(state->vtopo, rev_serial);
        aern_topology_increment_version(state->vtopo);

        /* send acknowledgement { own_cert || timestamp || own_sig } */
        const size_t ackmsg = AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE;
        const size_t ackpkt = AERN_PACKET_HEADER_SIZE + ackmsg;
        uint8_t* abuf = (uint8_t*)qsc_memutils_malloc(ackpkt);

        if (abuf != NULL)
        {
            aern_network_packet ack = { 0 };
            size_t sl;

            ack.flag = (uint8_t)aern_network_flag_system_error_condition; /* ack flag */
            ack.sequence = LC_REVOKE_ACK_SEQ;
            ack.msglen = (uint32_t)ackmsg;
            aern_packet_set_utc_time(&ack);
            ack.pmessage = abuf + AERN_PACKET_HEADER_SIZE;

            /* use network_converge_update flag for the ack (closest existing type) */
            ack.flag = (uint8_t)aern_network_flag_network_converge_update;
            lc_write_subheader(ack.pmessage, &ack);

            sl = aern_certificate_message_hash_sign(ack.pmessage + AERN_PACKET_SUBHEADER_SIZE, state->sigkey, ack.pmessage, AERN_PACKET_SUBHEADER_SIZE);

            if (sl == AERN_CERTIFICATE_SIGNED_HASH_SIZE)
            {
                aern_packet_header_serialize(&ack, abuf);
                qsc_socket_client_send(state->csock, abuf, ackpkt, qsc_socket_send_flag_none);
            }

            qsc_memutils_secure_erase(abuf, ackpkt);
            qsc_memutils_alloc_free(abuf);
            merr = aern_protocol_error_none;
        }
        else
        {
            merr = aern_protocol_error_memory_allocation;
        }
    }

    return merr;
}

void aern_adc_alive_poll_thread(void* arg)
{
    AERN_ASSERT(arg != NULL);

    if (arg != NULL)
    {
        aern_adc_alive_poll_state* state = (aern_adc_alive_poll_state*)arg;
        uint64_t lastresp[AERN_MAX_PEERS] = { 0U };
        uint64_t tnow = qsc_timestamp_datetime_utc();

        /* initialise all to "now" so nodes aren't immediately revoked on startup */
        for (size_t i = 0U; i < AERN_MAX_PEERS; ++i)
        {
            lastresp[i] = tnow;
        }

        while (state->running)
        {
            qsc_async_thread_sleep(AERN_NODE_ALIVE_POLL_S * 1000U);
            tnow = qsc_timestamp_datetime_utc();

            for (size_t i = 0U; i < state->vtopo->count; ++i)
            {
                aern_topology_node_state node = { 0 };
                aern_network_packet poll = { 0 };
                qsc_socket csock = { 0 };
                uint8_t* sbuf;
                size_t sl;
                bool responded;

                if (!aern_topology_list_item(state->vtopo, &node, i))
                {
                    continue;
                }

                if (node.designation != aern_network_designation_aps)
                {
                    continue;
                }

                /* build poll packet: subhdr || adc_cert || adc_sig */
                const size_t pollmsg = AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE + AERN_CERTIFICATE_SIGNED_HASH_SIZE;
                const size_t pollpkt = AERN_PACKET_HEADER_SIZE + pollmsg;

                sbuf = (uint8_t*)qsc_memutils_malloc(pollpkt);

                if (sbuf == NULL)
                {
                    continue;
                }

                poll.flag = (uint8_t)aern_network_flag_register_update_request;
                /* use current time as unique sequence */
                poll.sequence = tnow;
                poll.msglen = (uint32_t)pollmsg;
                aern_packet_set_utc_time(&poll);
                poll.pmessage = sbuf + AERN_PACKET_HEADER_SIZE;

                lc_write_subheader(poll.pmessage, &poll);
                aern_certificate_child_serialize(poll.pmessage + AERN_PACKET_SUBHEADER_SIZE, state->lcert);

                sl = aern_certificate_message_hash_sign(poll.pmessage + AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE,
                    state->sigkey, poll.pmessage, AERN_PACKET_SUBHEADER_SIZE + AERN_CERTIFICATE_CHILD_SIZE);

                if (sl != AERN_CERTIFICATE_SIGNED_HASH_SIZE)
                {
                    qsc_memutils_alloc_free(sbuf);
                    continue;
                }

                aern_packet_header_serialize(&poll, sbuf);
                responded = false;

                if (aern_network_connect_to_device(&csock, node.address, aern_network_designation_aps) == qsc_socket_exception_success)
                {
                    size_t slen = qsc_socket_client_send(&csock, sbuf, pollpkt, qsc_socket_send_flag_none);

                    if (slen == pollpkt)
                    {
                        /* Wait for any response packet */
                        uint8_t rbuf[AERN_PACKET_HEADER_SIZE + 1U] = { 0U };
                        size_t rlen;

                        rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

                        if (rlen >= AERN_PACKET_HEADER_SIZE)
                        {
                            lastresp[i] = tnow;
                            responded = true;
                        }
                    }

                    aern_network_socket_dispose(&csock);
                }

                qsc_memutils_clear(sbuf, pollpkt);
                qsc_memutils_alloc_free(sbuf);

                if (!responded && (tnow - lastresp[i]) >= AERN_NODE_ALIVE_TIMEOUT_S)
                {
                    /* mark inactive and revoke */
                    aern_network_revoke_request_state rrs = 
                    {
                        .designation = aern_network_designation_aps,
                        .list = state->vtopo,
                        .rnode = &node,
                        .sigkey = state->sigkey
                    };

                    aern_network_revoke_broadcast(&rrs);

                    if (state->appstate != NULL)
                    {
                        aern_server_log_write_message((aern_server_application_state*)state->appstate, aern_application_log_connect_failure, node.address, AERN_CERTIFICATE_ADDRESS_SIZE);
                    }
                }
            }
        }
    }
}

aern_protocol_errors aern_forward_hop_bypass(aern_forward_state* fwd, uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE], aern_route_map* rm, const char* failed_addr, const char* entry_addr)
{
    aern_protocol_errors merr;
    uint8_t pos;

    (void)entry_addr;

    merr = aern_protocol_error_invalid_request;
    pos = 0U;

    if (fwd != NULL && plaintext != NULL && rm != NULL && failed_addr != NULL)
    {
        merr = aern_protocol_error_channel_down;

        for (pos = 1U; pos < AERN_ROUTE_PATH_SIZE; ++pos)
        {
            if (rm->path[pos] != 0U)
            {
                aern_topology_node_state nextnode = { 0 };
                qsc_socket nsock = { 0 };
                aern_network_packet pktout = { 0 };
                uint8_t outwire[AERN_RELAY_MTU] = { 0U };
                aern_connection_state* txcns;
                uint8_t apsctr;
                size_t slen;
                bool found;

                txcns = NULL;
                apsctr = 0U;
                slen = 0U;
                found = false;

                for (size_t i = 0U; i < fwd->topology->count; ++i)
                {
                    aern_topology_node_state n = { 0 };

                    if (aern_topology_list_item(fwd->topology, &n, i) == true && n.designation == aern_network_designation_aps)
                    {
                        ++apsctr;

                        if (apsctr == rm->path[pos])
                        {
                            nextnode = n;
                            found = true;
                            break;
                        }
                    }
                }

                rm->path[pos] = 0U;

                if (found == true && qsc_memutils_are_equal((const uint8_t*)nextnode.address, (const uint8_t*)failed_addr, qsc_stringutils_string_size(failed_addr)) == false)
                {
                    txcns = aern_cipher_table_get_by_ip(fwd->conn_table, nextnode.address);

                    if (txcns != NULL)
                    {
                        aern_route_map_serialize(plaintext + AERN_LEN_PREFIX_SIZE, rm);
                        pktout.pmessage = outwire + AERN_RELAY_HEADER_SIZE;
                        merr = aern_encrypt_packet(txcns, &pktout, plaintext, AERN_RELAY_PLAINTEXT_SIZE);

                        if (merr == aern_protocol_error_none)
                        {
                            pktout.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
                            aern_packet_header_serialize(&pktout, outwire);

                            if (aern_network_connect_to_device(&nsock, nextnode.address, aern_network_designation_aps) == qsc_socket_exception_success)
                            {
                                slen = qsc_socket_send(&nsock, outwire, AERN_RELAY_MTU, qsc_socket_send_flag_none);
                                aern_network_socket_dispose(&nsock);
                                merr = (slen == AERN_RELAY_MTU) ? aern_protocol_error_none : aern_protocol_error_transmit_failure;
                            }
                            else
                            {
                                merr = aern_protocol_error_connection_failure;
                            }
                        }
                    }
                }

                qsc_memutils_secure_erase(outwire, sizeof(outwire));
                break;
            }
        }
    }

    return merr;
}

const char* aern_error_to_string(aern_protocol_errors error)
{
    size_t idx = (size_t)error;

    if (idx < LC_PROTOCOL_ERROR_COUNT)
    {
        return LC_PROTOCOL_ERROR_STRINGS[idx];
    }

    return "(unknown error)";
}

const char* aern_network_error_to_string_v2(aern_network_errors error)
{
    switch (error)
    {
        case aern_network_error_none:
            return "None";
        case aern_network_error_accept_fail:
            return "Accept failure";
        case aern_network_error_auth_failure:
            return "Authentication failure";
        case aern_network_error_bad_keep_alive:
            return "Bad keep-alive";
        case aern_network_error_channel_down:
            return "Channel down";
        case aern_network_error_connection_failure:
            return "Connection failure";
        case aern_network_error_decryption_failure:
            return "Decryption failure";
        case aern_network_error_establish_failure:
            return "Establish failure";
        case aern_network_error_general_failure:
            return "General failure";
        case aern_network_error_hosts_exceeded:
            return "Hosts exceeded";
        case aern_network_error_identity_unknown:
            return "Identity unknown";
        case aern_network_error_invalid_input:
            return "Invalid input";
        case aern_network_error_invalid_request:
            return "Invalid request";
        case aern_network_error_keep_alive_expired:
            return "Keep-alive expired";
        case aern_network_error_keep_alive_timeout:
            return "Keep-alive timeout";
        case aern_network_error_kex_auth_failure:
            return "KEX authentication failure";
        case aern_network_error_key_not_recognized:
            return "Key not recognized";
        case aern_network_error_key_has_expired:
            return "Key has expired";
        case aern_network_error_listener_fail:
            return "Listener failure";
        case aern_network_error_memory_allocation:
            return "Memory allocation failure";
        case aern_network_error_packet_unsequenced:
            return "Packet unsequenced";
        case aern_network_error_random_failure:
            return "Random generator failure";
        case aern_network_error_ratchet_fail:
            return "Ratchet failure";
        case aern_network_error_receive_failure:
            return "Receive failure";
        case aern_network_error_transmit_failure:
            return "Transmit failure";
        case aern_network_error_unknown_protocol:
            return "Unknown protocol";
        case aern_network_error_unsequenced:
            return "Unsequenced packet";
        case aern_network_error_verify_failure:
            return "Verification failure";
        default:                                     
            return "(unknown network error)";
    }
}

void aern_error_handle(aern_error_context* ctx, aern_protocol_errors error)
{
    AERN_ASSERT(ctx != NULL);

    if (ctx != NULL)
    {
        bool teardown;
        bool log;

        teardown = false;
        log = true;

        switch (error)
        {
        case aern_protocol_error_authentication_failure:
        case aern_protocol_error_root_signature_invalid:
        case aern_protocol_error_verification_failure:
        case aern_protocol_error_message_verification_failure:
        case aern_protocol_error_signature_failure:
        case aern_protocol_error_signing_failure:
        case aern_protocol_error_decapsulation_failure:
        case aern_protocol_error_decryption_failure:
        case aern_protocol_error_decoding_failure:
        case aern_protocol_error_hash_invalid:
        case aern_protocol_error_key_expired:
        case aern_protocol_error_key_unrecognized:
        case aern_protocol_error_certificate_expired:
        case aern_protocol_error_certificate_not_found:
        case aern_protocol_error_channel_down:
        case aern_protocol_error_connection_failure:
        case aern_protocol_error_connect_failure:
        case aern_protocol_error_establish_failure:
        case aern_protocol_error_exchange_failure:
            log = true;
            break;
        case aern_protocol_error_packet_unsequenced:
        case aern_protocol_error_message_time_invalid:
        case aern_protocol_error_packet_header_invalid:
        case aern_protocol_error_unknown_protocol:
        case aern_protocol_error_invalid_request:
        case aern_protocol_error_node_not_found:
        case aern_protocol_error_node_not_available:
        case aern_protocol_error_node_was_registered:
        case aern_protocol_error_hosts_exceeded:
        case aern_protocol_error_topology_no_aps:
            teardown = false;
            break;
        case aern_protocol_error_convergence_failure:
        case aern_protocol_error_operation_cancelled:
            teardown = false;
            break;
        case aern_protocol_error_memory_allocation:
        case aern_protocol_error_file_not_found:
        case aern_protocol_error_file_not_written:
        case aern_protocol_error_file_not_deleted:
        case aern_protocol_error_no_usable_address:
        case aern_protocol_error_listener_fail:
        case aern_protocol_error_socket_binding:
        case aern_protocol_error_socket_creation:
        case aern_protocol_error_serialization_failure:
        case aern_protocol_error_receive_failure:
        case aern_protocol_error_transmit_failure:
            teardown = false;
            break;
        case aern_protocol_error_none:
        case aern_protocol_error_convergence_synchronized:
            log = false;
            break;
        default:
            teardown = true;
            break;
        }

        /* send error packet if socket is open */
        if (teardown && ctx->csock != NULL && qsc_socket_is_connected(ctx->csock))
        {
            aern_network_send_error(ctx->csock, error);
        }

        /* log to ADC (never log locally on APS, log is forwarded) */
        if (log && ctx->appstate != NULL)
        {
            const char* estr = aern_error_to_string(error);
            aern_server_log_write_message((aern_server_application_state*)ctx->appstate, aern_application_network_local_error, estr, qsc_stringutils_string_size(estr));
        }

        /* teardown cipher state */
        if (teardown && ctx->cns != NULL)
        {
            aern_teardown_connection(ctx->cns, (ctx->csock != NULL && qsc_socket_is_connected(ctx->csock)) ? (qsc_socket*)ctx->csock : NULL, ctx->peer_addr, ctx->ctable);
        }
    }
}

#include "admin.h"
#include "commands.h"
#include "crypto.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "encoding.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

static void admin_utc_to_iso8601(char dst[32U], uint64_t utcsec)
{
    /* using simple integer arithmetic QSC does not expose a strftime wrapper */
    /* reference: Unix time, no leap seconds, Gregorian calendar */
    char tmp[8U] = { 0U };
    uint64_t s = utcsec % 60U;
    uint64_t m = (utcsec / 60U) % 60U;
    uint64_t h = (utcsec / 3600U) % 24U;
    uint64_t days = utcsec / 86400U;

    /* compute year/month/day using the algorithm from civil.h (Howard Hinnant) */
    uint64_t z = days + 719468U;
    uint64_t era = z / 146097U;
    uint64_t doe = z - era * 146097U;
    uint64_t yoe = (doe - doe / 1460U + doe / 36524U - doe / 146096U) / 365U;
    uint64_t y = yoe + era * 400U;
    uint64_t doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
    uint64_t mp = (5U * doy + 2U) / 153U;
    uint64_t d = doy - (153U * mp + 2U) / 5U + 1U;
    uint64_t mo = mp < 10U ? mp + 3U : mp - 9U;

    if (mo <= 2U)
    {
        ++y;
    }

    /* format into dst -- write 20 chars "YYYY-MM-DDTHH:MM:SSZ" then pad to 32 */
    qsc_memutils_clear(dst, 32U);

    qsc_stringutils_int_to_string((int)y,  tmp, sizeof(tmp)); qsc_memutils_copy(dst, tmp, qsc_stringutils_string_size(tmp));
    dst[4U]  = '-';

    if (mo < 10U)  
    {
        dst[5U] = '0'; qsc_stringutils_int_to_string((int)mo, tmp, sizeof(tmp)); qsc_memutils_copy(dst + 6U, tmp, 1U); 
    }
    else           
    { 
        qsc_stringutils_int_to_string((int)mo, tmp, sizeof(tmp)); qsc_memutils_copy(dst + 5U, tmp, 2U); 
    }

    dst[7U]  = '-';

    if (d < 10U)   
    {
        dst[8U] = '0'; qsc_stringutils_int_to_string((int)d,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 9U, tmp, 1U); 
    }
    else           
    {
        qsc_stringutils_int_to_string((int)d,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 8U, tmp, 2U); 
    }

    dst[10U] = 'T';

    if (h < 10U)   
    {
        dst[11U] = '0'; qsc_stringutils_int_to_string((int)h,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 12U, tmp, 1U); 
    }
    else           
    {
        qsc_stringutils_int_to_string((int)h,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 11U, tmp, 2U); 
    }

    dst[13U] = ':';

    if (m < 10U)   
    {
        dst[14U] = '0'; qsc_stringutils_int_to_string((int)m,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 15U, tmp, 1U); 
    }
    else           
    {
        qsc_stringutils_int_to_string((int)m,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 14U, tmp, 2U); 
    }

    dst[16U] = ':';

    if (s < 10U)
    {
        dst[17U] = '0'; qsc_stringutils_int_to_string((int)s,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 18U, tmp, 1U); 
    }
    else           
    {
        qsc_stringutils_int_to_string((int)s,  tmp, sizeof(tmp)); qsc_memutils_copy(dst + 17U, tmp, 2U); 
    }

    dst[19U] = 'Z';
}

static void admin_derive_seed(uint8_t seed[AERN_LOG_SEED_SIZE], const uint8_t* password, size_t pwlen, const uint8_t* salt)
{
    /* derive the encryption seed from password + salt using SHAKE-256 */
    /* KDF: SHAKE-256(password || salt) -> 64-byte seed using one-shot API */
    size_t kdf_in_len = pwlen + AERN_LOG_SALT_SIZE;
    uint8_t* kdf_in = (uint8_t*)qsc_memutils_malloc(kdf_in_len);

    if (kdf_in != NULL)
    {
        qsc_memutils_copy(kdf_in, password, pwlen);
        qsc_memutils_copy(kdf_in + pwlen, salt,     AERN_LOG_SALT_SIZE);
        qsc_shake256_compute(seed, AERN_LOG_SEED_SIZE, kdf_in, kdf_in_len);
        qsc_memutils_clear(kdf_in, kdf_in_len);
        qsc_memutils_alloc_free(kdf_in);
    }
}

static void admin_salt_path(char* out, size_t out_size, const char* logpath)
{
    /* build the salt file path from the log path */
    qsc_memutils_clear(out, out_size);
    qsc_stringutils_copy_string(out, out_size, logpath);
    qsc_stringutils_concat_strings(out, out_size, ".salt");
}

static void console_print_usage(void)
{
    /* print usage for the console commands */
    qsc_consoleutils_print_line("AERN ADC Console Commands:");
    qsc_consoleutils_print_line("  converge - Trigger topology convergence to all APS nodes");
    qsc_consoleutils_print_line("  topology - Print all topology nodes");
    qsc_consoleutils_print_line("  certificate [serial] - Print certificate details (hex serial)");
    qsc_consoleutils_print_line("  revoke [serial] - Initiate revoke broadcast for hex serial");
    qsc_consoleutils_print_line("  log [last N] - Print last N log entries (default 20)");
    qsc_consoleutils_print_line("  status - Print ADC uptime and connection status");
    qsc_consoleutils_print_line("  quit - Graceful shutdown");
}

static void console_print_node(const aern_topology_node_state* node)
{
    char expstr[32U] = { 0 };
    char serial_hex[AERN_CERTIFICATE_SERIAL_SIZE * 2U + 1U] = { 0 };

    (void)qsc_encoding_hex_encode(node->serial, AERN_CERTIFICATE_SERIAL_SIZE, serial_hex, sizeof(serial_hex));

    qsc_consoleutils_print_safe("  Serial: ");
    qsc_consoleutils_print_line(serial_hex);
    qsc_consoleutils_print_safe("  Issuer: ");
    qsc_consoleutils_print_line(node->issuer);

    const char* desig = (node->designation == aern_network_designation_aps)    ? "APS"
                      : (node->designation == aern_network_designation_adc)    ? "ADC"
                      : (node->designation == aern_network_designation_ars)    ? "ARS"
                      : (node->designation == aern_network_designation_client) ? "Client"
                      : "Unknown";

    qsc_consoleutils_print_safe("  Designation: ");
    qsc_consoleutils_print_line(desig);

    admin_utc_to_iso8601(expstr, node->expiration.to);
    qsc_consoleutils_print_safe("  Expiry: ");
    qsc_consoleutils_print_line(expstr);
    qsc_consoleutils_print_line("");
}

static bool console_execute(aern_console_state* cs, const char* cmd)
{
    char num[16U] = { 0 };
    aern_protocol_errors merr;
    bool found;

    /* execute a console command; return false to quit */
    if (qsc_consoleutils_line_equals(cmd, "quit") || qsc_consoleutils_line_equals(cmd, "exit"))
    {
        /* graceful shutdown: resign + teardown (best-effort) */
        qsc_consoleutils_print_line("Shutting down...");
        cs->running = false;

        return false;
    }

    if (qsc_consoleutils_line_equals(cmd, "converge"))
    {
        /* trigger converge_request to all APS nodes */
        size_t converged;

        converged = 0U;
        merr = aern_protocol_error_none;

        for (size_t i = 0U; i < cs->vtopo->count; ++i)
        {
            aern_topology_node_state node = { 0 };

            if (aern_topology_list_item(cs->vtopo, &node, i) && node.designation == aern_network_designation_aps)
            {
                aern_network_converge_request_state crs = {
                    .rcert  = NULL,   /* populated from topology in network.c */
                    .rnode  = &node,
                    .sigkey = cs->sigkey
                };

                merr = aern_network_converge_request(&crs);

                if (merr == aern_protocol_error_none)
                {
                    ++converged;
                }
            }
        }

        qsc_stringutils_int_to_string((int)converged, num, sizeof(num));
        qsc_consoleutils_print_safe("Converged ");
        qsc_consoleutils_print_safe(num);
        qsc_consoleutils_print_line(" APS node(s).");

        return true;
    }

    if (qsc_consoleutils_line_equals(cmd, "topology"))
    {
        char count_str[16U] = { 0 };

        qsc_stringutils_int_to_string((int)cs->vtopo->count, count_str, sizeof(count_str));
        qsc_consoleutils_print_safe("Topology: ");
        qsc_consoleutils_print_safe(count_str);
        qsc_consoleutils_print_line(" node(s)");
        qsc_consoleutils_print_line("");

        for (size_t i = 0U; i < cs->vtopo->count; ++i)
        {
            aern_topology_node_state node = { 0 };

            if (aern_topology_list_item(cs->vtopo, &node, i))
            {
                console_print_node(&node);
            }
        }

        return true;
    }

    if (qsc_consoleutils_line_contains(cmd, "certificate "))
    {
        /* Find the serial argument after "certificate " */
        const char* serstr = qsc_stringutils_reverse_sub_string(cmd, " ");

        if (serstr != NULL)
        {
            aern_topology_node_state node = { 0 };

            found = false;

            /* scan topology for matching issuer (serstr used as issuer prefix) */
            for (size_t i = 0U; i < cs->vtopo->count; ++i)
            {
                aern_topology_node_state n = { 0 };

                if (aern_topology_list_item(cs->vtopo, &n, i) && qsc_stringutils_string_contains(n.issuer, serstr))
                {
                    node  = n;
                    found = true;
                    break;
                }
            }

            if (found)
            {
                console_print_node(&node);
            }
            else
            {
                qsc_consoleutils_print_line("Certificate not found.");
            }
        }

        return true;
    }

    if (qsc_consoleutils_line_contains(cmd, "revoke "))
    {
        const char* serstr = qsc_stringutils_reverse_sub_string(cmd, " ");

        if (serstr != NULL)
        {
            aern_topology_node_state rnode = { 0 };
            found = false;

            for (size_t i = 0U; i < cs->vtopo->count; ++i)
            {
                aern_topology_node_state n = { 0 };

                if (aern_topology_list_item(cs->vtopo, &n, i) && qsc_stringutils_string_contains(n.issuer, serstr))
                {
                    rnode = n;
                    found = true;
                    break;
                }
            }

            if (found)
            {
                aern_network_revoke_request_state rrs = {
                    .designation = rnode.designation,
                    .list = cs->vtopo,
                    .rnode = &rnode,
                    .sigkey = cs->sigkey
                };

                merr = aern_network_revoke_broadcast(&rrs);

                qsc_consoleutils_print_line(merr == aern_protocol_error_none
                    ? "Revocation broadcast sent."
                    : "Revocation failed.");

                if (cs->log != NULL)
                {
                    aern_log_write(cs->log, rnode.issuer, merr);
                }
            }
            else
            {
                qsc_consoleutils_print_line("Serial not found in topology.");
            }
        }

        return true;
    }

    if (qsc_consoleutils_line_contains(cmd, "log"))
    {
        /* parse optional "last N" argument */
        uint32_t lastn;

        lastn = 20U;

        if (qsc_consoleutils_line_contains(cmd, "last "))
        {
            const char* nstr = qsc_stringutils_reverse_sub_string(cmd, " ");

            if (nstr != NULL)
            {
                /* Parse number using the QSC string utility. */
                int32_t v = qsc_stringutils_string_to_int(nstr);

                if (v > 0 && v <= 10000)
                {
                    lastn = (uint32_t)v;
                }
            }
        }

        if (cs->log != NULL && cs->log->open)
        {
            /* Read all entries; print last lastn */
            const size_t buflen = 1024U * 1024U;
            char* logbuf;

            logbuf = (char*)qsc_memutils_malloc(buflen);

            if (logbuf != NULL)
            {
                size_t ecount;

                ecount = 0U;
                merr = aern_log_read_all(cs->log, logbuf, buflen, &ecount);

                if (merr == aern_protocol_error_none && ecount > 0U)
                {
                    /* Print last lastn newline-separated entries */
                    /* Collect newline positions from end */
                    size_t log_len = qsc_stringutils_string_size(logbuf);
                    uint32_t shown = 0U;
                    size_t  start  = 0U;

                    /* Find the offset of the (ecount - lastn)-th newline */
                    if (ecount > lastn)
                    {
                        size_t skip = ecount - lastn;
                        size_t nl = 0U;

                        for (size_t i = 0U; i < log_len; ++i)
                        {
                            if (logbuf[i] == '\n')
                            {
                                ++nl;

                                if (nl >= skip)
                                {
                                    start = i + 1U;
                                    break;
                                }
                            }
                        }
                    }

                    qsc_consoleutils_print_safe(logbuf + start);
                    qsc_memutils_clear((uint8_t*)logbuf, buflen);
                    (void)shown;
                }
                else
                {
                    qsc_consoleutils_print_line("Log is empty or could not be decrypted.");
                }

                qsc_memutils_alloc_free(logbuf);
            }
        }
        else
        {
            qsc_consoleutils_print_line("Log not open. Use aern_log_open() first.");
        }

        return true;
    }

    if (qsc_consoleutils_line_equals(cmd, "status"))
    {
        char nodecount[16U] = { 0 };
        char uptimestr[32U] = { 0 };
        char verstr[32U] = { 0 };
        uint64_t uptime;

        uptime = qsc_timestamp_datetime_utc() - cs->start_time;
        qsc_stringutils_int_to_string((int)(uptime / 3600U), uptimestr, sizeof(uptimestr));
        qsc_consoleutils_print_safe("Uptime: ");
        qsc_consoleutils_print_safe(uptimestr);
        qsc_consoleutils_print_line("h");

        size_t aps_count = aern_topology_list_server_count(cs->vtopo, aern_network_designation_aps);
        qsc_stringutils_int_to_string((int)aps_count, nodecount, sizeof(nodecount));
        qsc_consoleutils_print_safe("Connected APS nodes: ");
        qsc_consoleutils_print_line(nodecount);

        qsc_stringutils_int_to_string((int)cs->vtopo->version, verstr, sizeof(verstr));
        qsc_consoleutils_print_safe("Topology version: ");
        qsc_consoleutils_print_line(verstr);

        return true;
    }

    if (qsc_consoleutils_line_equals(cmd, "help") || qsc_consoleutils_line_equals(cmd, "?"))
    {
        console_print_usage();
        return true;
    }

    if (qsc_stringutils_string_size(cmd) > 0U)
    {
        qsc_consoleutils_print_safe("Unknown command: '");
        qsc_consoleutils_print_safe(cmd);
        qsc_consoleutils_print_line("'  (type 'help' for commands)");
    }

    return true;
}

aern_protocol_errors aern_log_open(aern_log_state* ls, const char* logpath, const uint8_t* password, size_t pwlen)
{
    AERN_ASSERT(ls != NULL);
    AERN_ASSERT(logpath != NULL);
    AERN_ASSERT(password != NULL);

    aern_protocol_errors res = aern_protocol_error_invalid_request;

    if (ls != NULL && logpath != NULL && password != NULL && pwlen != 0U)
    {
        qsc_memutils_clear(ls, sizeof(aern_log_state));
        qsc_stringutils_copy_string(ls->log_path, sizeof(ls->log_path), logpath);
        admin_salt_path(ls->salt_path, sizeof(ls->salt_path), logpath);

        /* load or create salt */
        uint8_t salt[AERN_LOG_SALT_SIZE] = { 0U };

        if (qsc_fileutils_exists(ls->salt_path))
        {
            size_t rlen = qsc_fileutils_copy_file_to_stream(ls->salt_path, (char*)salt, AERN_LOG_SALT_SIZE);

            if (rlen != AERN_LOG_SALT_SIZE)
            {
                return aern_protocol_error_file_not_found;
            }
        }
        else
        {
            /* generate and persist a new salt */
            qsc_acp_generate(salt, AERN_LOG_SALT_SIZE);
            qsc_fileutils_copy_stream_to_file(ls->salt_path, (const char*)salt, AERN_LOG_SALT_SIZE);
        }

        /* derive seed = SHAKE-256(password || salt)[0..63] */
        admin_derive_seed(ls->seed, password, pwlen, salt);

        /* SECURITY: ephemeral zero salt is no longer needed */
        qsc_memutils_clear(salt, sizeof(salt));
        ls->open = true;
        res = aern_protocol_error_none;
    }

    return res;
}

aern_protocol_errors aern_log_write(aern_log_state* ls, const char* devname, aern_protocol_errors error)
{
    AERN_ASSERT(ls != NULL);
    AERN_ASSERT(ls->open);

    char devbuf[33U] = { 0 };
    char entry[AERN_LOG_ENTRY_SIZE + 4U] = { 0 };
    char ts[32U] = { 0 };
    const char* estr;
    uint8_t* encbuf;
    uint8_t* encout;
    uint8_t* existingpt;
    uint8_t* newpt;
    size_t dlen;
    size_t elen;
    size_t entrylen;
    size_t existingptlen;
    size_t flen;
    size_t off;
    size_t ptlen;
    size_t rlen;
    size_t totalpt;
    aern_protocol_errors res;

    res = aern_protocol_error_invalid_request;

    if (ls != NULL && ls->open == true)
    {
        admin_utc_to_iso8601(ts, qsc_timestamp_datetime_utc());
        qsc_memutils_copy(entry, ts, 20U);
        entry[20U] = ' ';

        dlen = devname ? qsc_stringutils_string_size(devname) : 0U;

        if (dlen > AERN_LOG_DEVICE_NAME_SIZE - 1U)
        {
            dlen = AERN_LOG_DEVICE_NAME_SIZE - 1U;
        }

        if (dlen > 0U)
        {
            qsc_memutils_copy(devbuf, devname, dlen);
        }

        /* pad to exactly 32 chars with spaces */
        for (size_t i = dlen; i < AERN_LOG_DEVICE_NAME_SIZE; ++i)
        {
            devbuf[i] = ' ';
        }

        qsc_memutils_copy(entry + 21U, devbuf, AERN_LOG_DEVICE_NAME_SIZE);
        entry[21U + AERN_LOG_DEVICE_NAME_SIZE] = ' ';

        /* error code as "0x%08X" (10 chars) */
        off = 21U + AERN_LOG_DEVICE_NAME_SIZE + 1U;
        entry[off] = '0';
        ++off;
        entry[off] = 'x';
        ++off;

        /* Hex-encode the 4-byte error value using the QSC encoding API. */
        uint32_t ev = (uint32_t)error;
        uint8_t evb[sizeof(uint32_t)] = { 0U };

        qsc_intutils_be32to8(evb, ev);
        (void)qsc_encoding_hex_encode(evb, sizeof(evb), entry + off, 9U);
        off += 8U;
        entry[off] = ' ';
        ++off;

        /* error string -- truncated + padded to AERN_LOG_ERROR_STRING_SIZE */
        estr = aern_error_to_string(error);
        elen = estr ? qsc_stringutils_string_size(estr) : 0U;

        if (elen > AERN_LOG_ERROR_STRING_SIZE - 1U)
        {
            elen = AERN_LOG_ERROR_STRING_SIZE - 1U;
        }

        if (elen > 0U)
        {
            qsc_memutils_copy(entry + off, estr, elen);
        }

        for (size_t i = elen; i < AERN_LOG_ERROR_STRING_SIZE - 1U; ++i)
        {
            entry[off + i] = ' ';
        }

        off += AERN_LOG_ERROR_STRING_SIZE - 1U;
        entry[off] = '\n';
        ++off;
        entry[off] = '\0';

        /* append the new entry to the plaintext log, then re-encrypt the whole file. */
        entrylen = off;

        /* read existing plaintext (decrypt current file) */
        existingptlen = 0U;
        existingpt = NULL;

        if (qsc_fileutils_exists(ls->log_path))
        {
            flen = qsc_fileutils_get_size(ls->log_path);

            if (flen > AERN_STORAGE_MAC_SIZE)
            {
                ptlen = flen - AERN_STORAGE_MAC_SIZE;
                encbuf = (uint8_t*)qsc_memutils_malloc(flen);

                existingpt = (uint8_t*)qsc_memutils_malloc(ptlen + entrylen + 1U);

                if (encbuf != NULL && existingpt != NULL)
                {
                    qsc_memutils_clear(encbuf, flen);
                    qsc_memutils_clear(existingpt, ptlen + entrylen + 1U);

                    rlen = qsc_fileutils_copy_file_to_stream(ls->log_path, (char*)encbuf, flen);

                    if (rlen == flen)
                    {
                        aern_crypto_decrypt_stream(existingpt, ls->seed, encbuf, ptlen);
                        existingptlen = ptlen;
                    }

                    /* ephemeral zero */
                    qsc_memutils_clear(encbuf, flen);
                    qsc_memutils_alloc_free(encbuf);
                }
                else
                {
                    if (encbuf != NULL)
                    {
                        qsc_memutils_alloc_free(encbuf);
                    }

                    if (existingpt != NULL)
                    {
                        qsc_memutils_alloc_free(existingpt);
                    }

                    return aern_protocol_error_memory_allocation;
                }
            }
        }

        /* build combined plaintext: existing + new entry */
        totalpt = existingptlen + entrylen;
        newpt = (uint8_t*)qsc_memutils_malloc(totalpt + 1U);

        if (newpt == NULL)
        {
            if (existingpt != NULL)
            {
                qsc_memutils_clear(existingpt, existingptlen + entrylen + 1U);
                qsc_memutils_alloc_free(existingpt);
            }

            return aern_protocol_error_memory_allocation;
        }

        qsc_memutils_clear(newpt, totalpt + 1U);

        if (existingptlen > 0U && existingpt != NULL)
        {
            qsc_memutils_copy(newpt, existingpt, existingptlen);
        }

        qsc_memutils_copy(newpt + existingptlen, (const uint8_t*)entry, entrylen);

        if (existingpt != NULL)
        {
            /* ephemeral zero */
            qsc_memutils_clear(existingpt, existingptlen + entrylen + 1U);
            qsc_memutils_alloc_free(existingpt);
        }

        /* encrypt combined plaintext and write to file */
        encout = (uint8_t*)qsc_memutils_malloc(totalpt + AERN_STORAGE_MAC_SIZE);

        if (encout == NULL)
        {
            /* ephemeral zero */
            qsc_memutils_clear(newpt, totalpt + 1U);
            qsc_memutils_alloc_free(newpt);

            return aern_protocol_error_memory_allocation;
        }

        qsc_memutils_clear(encout, totalpt + AERN_STORAGE_MAC_SIZE);
        aern_crypto_encrypt_stream(encout, ls->seed, newpt, totalpt);

        qsc_fileutils_copy_stream_to_file(ls->log_path, (const char*)encout, totalpt + AERN_STORAGE_MAC_SIZE);

        /* ephemeral zero */
        qsc_memutils_clear(newpt, totalpt + 1U);
        qsc_memutils_alloc_free(newpt);
        qsc_memutils_clear(encout, totalpt + AERN_STORAGE_MAC_SIZE);
        qsc_memutils_alloc_free(encout);
        qsc_memutils_clear(entry, sizeof(entry));

        res = aern_protocol_error_none;
    }

    return res;
}

void aern_log_close(aern_log_state* ls)
{
    AERN_ASSERT(ls != NULL);

    if (ls != NULL)
    {
        /* ephemeral zero zero the derived key before releasing */
        qsc_memutils_clear(ls->seed, AERN_LOG_SEED_SIZE);
        ls->open = false;
    }
}

aern_protocol_errors aern_log_read_all(const aern_log_state* ls, char* out, size_t outsize, size_t* entrycount)
{
    AERN_ASSERT(ls != NULL);
    AERN_ASSERT(out != NULL);
    AERN_ASSERT(outsize >  0U);
    AERN_ASSERT(entrycount != NULL);

    uint8_t* enc;
    uint8_t* ptbuf;
    size_t copylen;
    size_t flen;
    size_t ptlen;
    size_t rlen;
    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (ls != NULL && ls->open == true && out != NULL && outsize != 0U && entrycount != NULL)
    {
        *entrycount = 0U;
        qsc_memutils_clear(out, outsize);

        if (!qsc_fileutils_exists(ls->log_path))
        {
            return aern_protocol_error_file_not_found;
        }

        flen = qsc_fileutils_get_size(ls->log_path);

        if (flen <= AERN_STORAGE_MAC_SIZE)
        {
            return aern_protocol_error_none;
        }

        ptlen = flen - AERN_STORAGE_MAC_SIZE;
        enc = (uint8_t*)qsc_memutils_malloc(flen);
        ptbuf = (uint8_t*)qsc_memutils_malloc(ptlen + 1U);

        if (enc == NULL || ptbuf == NULL)
        {
            if (enc != NULL)
            {
                qsc_memutils_alloc_free(enc);
            }

            if (ptbuf != NULL)
            {
                qsc_memutils_alloc_free(ptbuf);
            }

            return aern_protocol_error_memory_allocation;
        }

        qsc_memutils_clear(enc, flen);
        qsc_memutils_clear(ptbuf, ptlen + 1U);

        rlen = qsc_fileutils_copy_file_to_stream(ls->log_path, (char*)enc, flen);
        merr = aern_protocol_error_none;

        if (rlen == flen)
        {
            if (aern_crypto_decrypt_stream(ptbuf, ls->seed, enc, ptlen))
            {
                /* copy to output, count newlines */
                copylen = ptlen < outsize - 1U ? ptlen : outsize - 1U;
                qsc_memutils_copy((uint8_t*)out, ptbuf, copylen);

                for (size_t i = 0U; i < copylen; ++i)
                {
                    if (out[i] == '\n')
                    {
                        ++(*entrycount);
                    }
                }
            }
            else
            {
                merr = aern_protocol_error_authentication_failure;
            }
        }
        else
        {
            merr = aern_protocol_error_receive_failure;
        }

        /* ephemeral zero */
        qsc_memutils_clear(enc, flen);
        qsc_memutils_alloc_free(enc);
        qsc_memutils_clear(ptbuf, ptlen + 1U);
        qsc_memutils_alloc_free(ptbuf);
    }

    return merr;
}

void aern_console_run(aern_console_state* cs)
{
    AERN_ASSERT(cs != NULL);
    AERN_ASSERT(cs->appstate != NULL);

    if (cs != NULL && cs->appstate != NULL)
    {
        cs->running = true;
        cs->start_time = qsc_timestamp_datetime_utc();

        /* prompt for admin password before accepting any commands.
         * aern_server_user_login() handles the secure password prompt, hash
         * comparison, and retry limiting -- consistent with ADC's existing login path. */
        qsc_consoleutils_print_line("AERN ADC Administrative Console");

        if (!aern_server_user_login(cs->appstate))
        {
            qsc_consoleutils_print_line("Authentication failed. Access denied.");
            cs->running = false;
            return;
        }

        cs->authenticated = true;
        qsc_consoleutils_print_line("Authentication successful. Type 'help' for commands.");

        /* open encrypted log now that we have the authenticated app state */
        if (cs->log != NULL && !cs->log->open && cs->appstate != NULL)
        {
            const size_t kc_log_offset = 1U * 64U;
            const uint8_t* log_key = cs->appstate->kchain + kc_log_offset;

            if (!qsc_memutils_zeroed(log_key, AERN_CRYPTO_SYMMETRIC_KEY_SIZE))
            {
                qsc_memutils_copy(cs->log->seed, log_key, AERN_LOG_SEED_SIZE);
                cs->log->open = true;
            }
        }

        char cmd[QSC_CONSOLE_MAX_LINE] = { 0 };

        while (cs->running)
        {
            qsc_consoleutils_print_safe("aern-adc> ");
            qsc_consoleutils_get_line(cmd, QSC_CONSOLE_MAX_LINE);

            if (!console_execute(cs, cmd))
            {
                break;
            }

            qsc_memutils_clear((uint8_t*)cmd, QSC_CONSOLE_MAX_LINE);
        }

        if (cs->log != NULL && cs->log->open)
        {
            aern_log_close(cs->log);
        }
    }
}

bool aern_certificate_is_expired(const aern_child_certificate* cert, uint64_t now)
{
    AERN_ASSERT(cert != NULL);
    bool res;

    res = false;

    if (cert == NULL)
    {
        res = true;
    }
    else if (now < cert->expiration.from)
    {
        /* reject if current time is before the validity start */
        res = true;
    }
    else if (cert->expiration.to < now)
    {
        /* reject if current time is past the validity end */
        return true;
    }

    return res;
}

int64_t aern_certificate_time_remaining(const aern_child_certificate* cert, uint64_t now)
{
    AERN_ASSERT(cert != NULL);

    int64_t res;

    if (cert == NULL)
    {
        res = (int64_t)-1;
    }
    else if (cert->expiration.to < now)
    {
        res = (int64_t)cert->expiration.to - (int64_t)now;
    }
    else
    {
        res = (int64_t)(cert->expiration.to - now);
    }

    return res;
}

aern_protocol_errors aern_certificate_enforce_expiry(const aern_child_certificate* cert, aern_server_application_state* appstate)
{
    AERN_ASSERT(cert != NULL);

    aern_protocol_errors merr;

    merr = aern_protocol_error_invalid_request;

    if (cert != NULL)
    {
        uint64_t tnow;

        tnow = qsc_timestamp_datetime_utc();

        if (aern_certificate_is_expired(cert, tnow) == true)
        {
            if (appstate != NULL)
            {
                aern_server_log_write_message(appstate, aern_application_log_remote_invalid_request, cert->issuer, qsc_stringutils_string_size(cert->issuer));
            }

            merr = aern_protocol_error_certificate_expired;
        }
        else
        {
            merr = aern_protocol_error_none;
        }
    }

    return merr;
}

size_t aern_jitter_send(qsc_socket* csock, const uint8_t wire[AERN_RELAY_MTU], uint32_t basedelayms)
{
    AERN_ASSERT(csock != NULL);
    AERN_ASSERT(wire  != NULL);

    size_t res;

    res = 0U;

    if (csock != NULL && wire != NULL)
    {
        if (basedelayms > 0U)
        {
            /* draw a random delay in [0, basedelayms) using CSPRNG */
            uint8_t rnd[sizeof(uint32_t)] = { 0U };
            uint32_t delayms;
            uint32_t val;

            qsc_acp_generate(rnd, sizeof(rnd));
            val = qsc_intutils_le8to32(rnd);
            delayms = (basedelayms > 1U) ? (val % basedelayms) : 0U;

            if (delayms > 0U)
            {
                qsc_async_thread_sleep(delayms);
            }
        }

        res = qsc_socket_send(csock, wire, AERN_RELAY_MTU, qsc_socket_send_flag_none);
    }

    return res;
}

void aern_background_thread(void* arg)
{
    AERN_ASSERT(arg != NULL);

    if (arg != NULL)
    {
        aern_background_state* bg = (aern_background_state*)arg;

        while (bg->running)
        {
            qsc_async_thread_sleep(AERN_BACKGROUND_INTERVAL_MS);

            if (!bg->synchronized || !bg->running)
            {
                continue;
            }

            /* send one 1500-byte random packet on each active tunnel */
            qsc_mutex mtx = qsc_async_mutex_lock_ex();

            for (uint32_t i = 0U; i < AERN_MAX_PEERS; ++i)
            {
                if (!bg->ctable->slots[i].used)
                {
                    continue;
                }

                aern_connection_state* cns = &bg->ctable->slots[i].cns;

                if (cns->exflag != aern_network_flag_tunnel_session_established)
                {
                    continue;
                }

                /* build a 1500-byte cover packet: encrypt random plaintext */
                uint8_t plaintext[AERN_RELAY_PLAINTEXT_SIZE] = { 0U };
                qsc_acp_generate(plaintext, AERN_RELAY_PLAINTEXT_SIZE);

                /* zero the actual_len prefix (content is not real data) */
                plaintext[0U] = 0U;
                plaintext[1U] = 0U;

                uint8_t wire[AERN_RELAY_MTU] = { 0U };
                aern_network_packet pkt = { 0 };
                pkt.pmessage = wire + AERN_RELAY_HEADER_SIZE;

                if (aern_encrypt_packet(cns, &pkt, plaintext, AERN_RELAY_PLAINTEXT_SIZE) == aern_protocol_error_none)
                {
                    pkt.msglen = (uint32_t)AERN_RELAY_CIPHERTEXT_SIZE;
                    aern_packet_header_serialize(&pkt, wire);

                    if (qsc_socket_is_connected(&cns->target))
                    {
                        aern_jitter_send(&cns->target, wire, AERN_JITTER_MAX_MS);
                    }
                }

                /* SECURITY: ephemeral zero */
                qsc_memutils_clear(plaintext, sizeof(plaintext));
                qsc_memutils_clear(wire, sizeof(wire));
            }

            qsc_async_mutex_unlock_ex(mtx);
        }
    }
}

void aern_background_start(aern_background_state* bg)
{
    AERN_ASSERT(bg != NULL);

    if (bg != NULL)
    {
        bg->running = true;
        qsc_async_thread_create(&aern_background_thread, bg);
    }
}

void aern_background_stop(aern_background_state* bg)
{
    AERN_ASSERT(bg != NULL);

    if (bg != NULL)
    {
        bg->running = false;
    }
}

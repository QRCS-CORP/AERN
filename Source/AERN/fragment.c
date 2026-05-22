#include "fragment.h"
#include "memutils.h"

static bool fragment_cache_match(const aern_fragment_cache* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    bool res;

    res = false;

    if (cache != NULL)
    {
        res = (cache->sessionid == sessionid && cache->packetid == packetid && cache->direction == direction);
    }

    return res;
}

static bool fragment_cache_is_empty(const aern_fragment_cache* cache)
{
    bool res;

    res = true;

    if (cache != NULL)
    {
        res = (cache->parts == NULL && cache->sessionid == 0U && cache->packetid == 0U);
    }

    return res;
}

void aern_fragment_part_dispose(aern_fragment_part_state* part)
{
    AERN_ASSERT(part != NULL);

    if (part != NULL)
    {
        if (part->data != NULL)
        {
            if (part->capacity != 0U)
            {
                qsc_memutils_secure_erase(part->data, part->capacity);
            }

            qsc_memutils_alloc_free(part->data);
        }

        qsc_memutils_secure_erase(part, sizeof(aern_fragment_part_state));
    }
}

void aern_fragment_cache_initialize(aern_fragment_cache* cache)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL)
    {
        qsc_memutils_secure_erase(cache, sizeof(aern_fragment_cache));
    }
}

bool aern_fragment_cache_allocate(aern_fragment_cache* cache, uint32_t fragcount, size_t declaredlen)
{
    AERN_ASSERT(cache != NULL);

    bool res;

    res = false;

    if (cache != NULL && fragcount != 0U && fragcount <= AERN_MAX_FRAGMENTS && declaredlen != 0U)
    {
        if (cache->parts == NULL)
        {
            cache->parts = (aern_fragment_part_state*)qsc_memutils_malloc((size_t)fragcount * sizeof(aern_fragment_part_state));

            if (cache->parts != NULL)
            {
                qsc_memutils_clear(cache->parts, (size_t)fragcount * sizeof(aern_fragment_part_state));
                cache->partscap = (size_t)fragcount;
                cache->total_frags = fragcount;
                cache->declared_length = declaredlen;
                res = true;
            }
        }
        else if (cache->partscap == (size_t)fragcount && cache->total_frags == fragcount && cache->declared_length == declaredlen)
        {
            res = true;
        }
    }

    return res;
}

void aern_fragment_cache_dispose(aern_fragment_cache* cache)
{
    AERN_ASSERT(cache != NULL);

    size_t i;

    if (cache != NULL)
    {
        if (cache->parts != NULL)
        {
            for (i = 0U; i < cache->partscap; ++i)
            {
                aern_fragment_part_dispose(&cache->parts[i]);
            }

            qsc_memutils_alloc_free(cache->parts);
        }

        qsc_memutils_secure_erase(cache, sizeof(aern_fragment_cache));
    }
}

void aern_fragment_cache_clear(aern_fragment_cache* cache)
{
    aern_fragment_cache_dispose(cache);
}

void aern_fragment_cache_set_key(aern_fragment_cache* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction, uint64_t expiry)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL)
    {
        cache->sessionid = sessionid;
        cache->packetid = packetid;
        cache->direction = direction;
        cache->expiry = expiry;
        cache->metaset = true;
    }
}

static bool fragment_cache_add_raw(aern_fragment_cache* cache, const uint8_t* data, size_t dlen, uint32_t fragseq, uint32_t fragcount)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(data != NULL);

    aern_fragment_part_state* part;
    size_t declaredlen;
    size_t exactlen;
    size_t index;
    bool res;

    part = NULL;
    declaredlen = 0U;
    exactlen = 0U;
    index = 0U;
    res = false;

    if (cache != NULL && data != NULL && dlen != 0U && fragseq != 0U && fragcount != 0U &&
        fragseq <= fragcount && fragcount <= AERN_MAX_FRAGMENTS && dlen <= AERN_FRAG_CHUNK_SIZE)
    {
        if (fragseq < fragcount && dlen != AERN_FRAG_CHUNK_SIZE)
        {
            res = false;
        }
        else
        {
            declaredlen = (size_t)fragcount * AERN_FRAG_CHUNK_SIZE;

            if (fragseq == fragcount)
            {
                exactlen = ((size_t)(fragcount - 1U) * AERN_FRAG_CHUNK_SIZE) + dlen;
                declaredlen = exactlen;

                if (cache->declared_length == 0U || cache->declared_length > declaredlen)
                {
                    cache->declared_length = declaredlen;
                }
            }
            else if (cache->declared_length != 0U)
            {
                declaredlen = cache->declared_length;
            }

            if (declaredlen >= dlen && aern_fragment_cache_allocate(cache, fragcount, declaredlen) == true)
            {
                index = (size_t)(fragseq - 1U);
                part = &cache->parts[index];

                if (part->received == false)
                {
                    if (cache->total_bytes <= cache->declared_length && dlen <= (cache->declared_length - cache->total_bytes))
                    {
                        part->data = (uint8_t*)qsc_memutils_malloc(dlen);

                        if (part->data != NULL)
                        {
                            qsc_memutils_copy(part->data, data, dlen);
                            part->datalen = dlen;
                            part->capacity = dlen;
                            part->received = true;
                            ++cache->received_count;
                            cache->total_bytes += dlen;
                            res = true;
                        }
                    }
                }
                else if (part->datalen == dlen)
                {
                    res = qsc_memutils_are_equal(part->data, data, dlen);
                }

                if (cache->received_count == cache->total_frags && cache->total_bytes == cache->declared_length)
                {
                    cache->complete = true;
                }
            }
        }
    }

    return res;
}

bool aern_fragment_cache_add_fragment(aern_fragment_cache* cache, const aern_relay_payload_header* header, const uint8_t* data, size_t dlen, uint8_t direction, bool* complete)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(data != NULL);
    AERN_ASSERT(header != NULL);

    bool res;

    res = false;

    if (complete != NULL)
    {
        *complete = false;
    }

    if (cache != NULL && header != NULL && data != NULL && complete != NULL && header->reserved == 0U &&
        header->fragseq > 0U && header->fragcount > 0U && header->fragseq <= header->fragcount &&
        header->fragcount <= AERN_MAX_FRAGMENTS && header->msglen == dlen && dlen != 0U &&
        dlen <= AERN_FRAG_CHUNK_SIZE && header->sessionid == cache->sessionid &&
        header->packetid == cache->packetid && direction == cache->direction)
    {
        if (cache->metaset == false || cache->received_count == 0U)
        {
            cache->payloadtype = header->payloadtype;
            cache->reserved = header->reserved;
            cache->flags = header->flags;
            cache->metaset = true;
        }

        if (cache->payloadtype == header->payloadtype && cache->reserved == header->reserved && cache->flags == header->flags)
        {
            res = fragment_cache_add_raw(cache, data, dlen, header->fragseq, header->fragcount);
            *complete = cache->complete;
        }
    }

    return res;
}

bool aern_fragment_cache_add(aern_fragment_cache* cache, const uint8_t* data, size_t dlen, uint32_t seq)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(data != NULL);

    uint32_t fragseq;
    uint32_t fragcount;
    bool res;

    res = false;
    fragseq = seq;
    fragcount = 0U;

    if (cache != NULL)
    {
        fragcount = (cache->total_frags != 0U) ? cache->total_frags : 1U;

        if (seq == UINT32_MAX)
        {
            fragseq = fragcount;
        }

        res = fragment_cache_add_raw(cache, data, dlen, fragseq, fragcount);
    }

    return res;
}

bool aern_fragment_cache_add_relay_fragment(aern_fragment_cache* cache, const aern_relay_payload_header* header, const uint8_t* fragment, size_t fraglen, uint8_t direction)
{
    bool complete;
    bool res;

    complete = false;
    res = aern_fragment_cache_add_fragment(cache, header, fragment, fraglen, direction, &complete);

    return (res == true && complete == true);
}

bool aern_fragment_cache_assemble_alloc(const aern_fragment_cache* cache, uint8_t** output, size_t* msglen)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(msglen != NULL);

    size_t offset;
    size_t i;
    bool res;

    offset = 0U;
    res = false;

    if (output != NULL)
    {
        *output = NULL;
    }

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if (cache != NULL && output != NULL && msglen != NULL && cache->complete == true && cache->parts != NULL && cache->total_bytes != 0U && cache->total_bytes <= cache->declared_length)
    {
        *output = (uint8_t*)qsc_memutils_malloc(cache->total_bytes);

        if (*output != NULL)
        {
            for (i = 0U; i < cache->partscap; ++i)
            {
                if (cache->parts[i].received == false || cache->parts[i].data == NULL)
                {
                    break;
                }

                qsc_memutils_copy(*output + offset, cache->parts[i].data, cache->parts[i].datalen);
                offset += cache->parts[i].datalen;
            }

            if (i == cache->partscap && offset == cache->total_bytes)
            {
                *msglen = offset;
                res = true;
            }
            else
            {
                qsc_memutils_secure_erase(*output, cache->total_bytes);
                qsc_memutils_alloc_free(*output);
                *output = NULL;
            }
        }
    }

    return res;
}

bool aern_fragment_cache_assemble_packet(const aern_fragment_cache* cache, uint8_t* output, size_t outlen, size_t* msglen)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(msglen != NULL);

    size_t offset;
    size_t i;
    bool res;

    offset = 0U;
    res = false;

    if (msglen != NULL)
    {
        *msglen = 0U;
    }

    if (cache != NULL && output != NULL && msglen != NULL && cache->complete == true && cache->parts != NULL && outlen >= cache->total_bytes)
    {
        for (i = 0U; i < cache->partscap; ++i)
        {
            if (cache->parts[i].received == false || cache->parts[i].data == NULL)
            {
                break;
            }

            qsc_memutils_copy(output + offset, cache->parts[i].data, cache->parts[i].datalen);
            offset += cache->parts[i].datalen;
        }

        if (i == cache->partscap && offset == cache->total_bytes)
        {
            *msglen = offset;
            res = true;
        }
    }

    return res;
}

void aern_fragment_cache_assemble(const aern_fragment_cache* cache, uint8_t* output, size_t* outlen)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(output != NULL);
    AERN_ASSERT(outlen != NULL);

    size_t cap;

    cap = 0U;

    if (outlen != NULL)
    {
        cap = *outlen;
        (void)aern_fragment_cache_assemble_packet(cache, output, cap, outlen);
    }
}

bool aern_fragment_table_initialize(aern_fragment_table* table, size_t setscap, size_t memorymax)
{
    AERN_ASSERT(table != NULL);

    bool res;

    res = false;

    if (table != NULL && setscap != 0U && memorymax != 0U)
    {
        qsc_memutils_clear(table, sizeof(aern_fragment_table));
        table->sets = (aern_fragment_cache*)qsc_memutils_malloc(setscap * sizeof(aern_fragment_cache));

        if (table->sets != NULL)
        {
            qsc_memutils_clear(table->sets, setscap * sizeof(aern_fragment_cache));
            table->setscap = setscap;
            table->memorymax = memorymax;
            table->initialized = true;
            res = true;
        }
    }

    return res;
}

void aern_fragment_table_dispose(aern_fragment_table* table)
{
    AERN_ASSERT(table != NULL);

    size_t i;

    if (table != NULL)
    {
        if (table->sets != NULL)
        {
            for (i = 0U; i < table->setscap; ++i)
            {
                aern_fragment_cache_dispose(&table->sets[i]);
            }

            qsc_memutils_alloc_free(table->sets);
        }

        qsc_memutils_secure_erase(table, sizeof(aern_fragment_table));
    }
}

void aern_fragment_table_clear(aern_fragment_table* table)
{
    AERN_ASSERT(table != NULL);

    size_t setscap;
    size_t memorymax;

    if (table != NULL)
    {
        setscap = table->setscap;
        memorymax = table->memorymax;
        aern_fragment_table_dispose(table);
        (void)aern_fragment_table_initialize(table, setscap, memorymax);
    }
}

aern_fragment_cache* aern_fragment_table_find(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(table != NULL);

    aern_fragment_cache* res;
    size_t i;

    res = NULL;

    if (table != NULL && table->initialized == true && sessionid != 0U && packetid != 0U)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (fragment_cache_match(&table->sets[i], sessionid, packetid, direction) == true)
            {
                res = &table->sets[i];
                break;
            }
        }
    }

    return res;
}

const aern_fragment_cache* aern_fragment_table_find_const(const aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(table != NULL);

    const aern_fragment_cache* res;
    size_t i;

    res = NULL;

    if (table != NULL && table->initialized == true && sessionid != 0U && packetid != 0U)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (fragment_cache_match(&table->sets[i], sessionid, packetid, direction) == true)
            {
                res = &table->sets[i];
                break;
            }
        }
    }

    return res;
}

aern_fragment_cache* aern_fragment_table_get_or_add(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction, uint32_t fragcount, uint64_t expiry, size_t declaredlen)
{
    AERN_ASSERT(table != NULL);

    aern_fragment_cache* res;
    size_t empty;
    size_t i;

    empty = 0U;
    res = aern_fragment_table_find(table, sessionid, packetid, direction);

    if (res == NULL && table != NULL && table->initialized == true && sessionid != 0U && packetid != 0U && fragcount != 0U && declaredlen != 0U)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (fragment_cache_is_empty(&table->sets[i]) == true)
            {
                empty = i;
                break;
            }
        }

        if (i < table->setscap && declaredlen <= table->memorymax && table->memoryused <= (table->memorymax - declaredlen))
        {
            res = &table->sets[empty];
            aern_fragment_cache_initialize(res);
            aern_fragment_cache_set_key(res, sessionid, packetid, direction, expiry);

            if (aern_fragment_cache_allocate(res, fragcount, declaredlen) == true)
            {
                res->created = 0U;
                table->memoryused += declaredlen;
                ++table->setscount;
            }
            else
            {
                aern_fragment_cache_dispose(res);
                res = NULL;
            }
        }
    }

    return res;
}

bool aern_fragment_table_add_relay_fragment(aern_fragment_table* table, const aern_relay_payload_header* header, const uint8_t* fragment, size_t fraglen, uint8_t direction, uint64_t expiry, aern_fragment_cache** set, bool* complete)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(header != NULL);
    AERN_ASSERT(fragment != NULL);

    aern_fragment_cache* entry;
    size_t before;
    size_t reserve;
    bool res;

    entry = NULL;
    before = 0U;
    reserve = 0U;
    res = false;

    if (set != NULL)
    {
        *set = NULL;
    }

    if (complete != NULL)
    {
        *complete = false;
    }

    if (table != NULL && header != NULL && fragment != NULL && set != NULL && complete != NULL &&
        header->reserved == 0U && header->sessionid != 0U && header->packetid != 0U &&
        header->fragseq != 0U && header->fragcount != 0U && header->fragseq <= header->fragcount &&
        header->fragcount <= AERN_MAX_FRAGMENTS && header->msglen == fraglen &&
        fraglen != 0U && fraglen <= AERN_FRAG_CHUNK_SIZE)
    {
        if ((header->fragseq == header->fragcount) || (fraglen == AERN_FRAG_CHUNK_SIZE))
        {
            reserve = (size_t)header->fragcount * (size_t)AERN_FRAG_CHUNK_SIZE;

            if (reserve != 0U && reserve <= table->memorymax)
            {
                entry = aern_fragment_table_get_or_add(table, header->sessionid, header->packetid, direction,
                    header->fragcount, expiry, reserve);

                if (entry != NULL)
                {
                    before = entry->declared_length;
                    res = aern_fragment_cache_add_fragment(entry, header, fragment, fraglen, direction, complete);

                    if (res == true)
                    {
                        if (before > entry->declared_length && table->memoryused >= (before - entry->declared_length))
                        {
                            table->memoryused -= (before - entry->declared_length);
                        }

                        *set = entry;
                    }
                }
            }
        }
    }

    return res;
}

void aern_fragment_table_remove(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(table != NULL);

    size_t i;

    if (table != NULL && table->initialized == true)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (fragment_cache_match(&table->sets[i], sessionid, packetid, direction) == true)
            {
                if (table->memoryused >= table->sets[i].declared_length)
                {
                    table->memoryused -= table->sets[i].declared_length;
                }
                else
                {
                    table->memoryused = 0U;
                }

                aern_fragment_cache_dispose(&table->sets[i]);

                if (table->setscount != 0U)
                {
                    --table->setscount;
                }

                break;
            }
        }
    }
}

uint32_t aern_fragment_table_remove_session(aern_fragment_table* table, uint64_t sessionid)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;
    size_t i;

    count = 0U;

    if (table != NULL && table->initialized == true && sessionid != 0U)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (table->sets[i].sessionid == sessionid)
            {
                if (table->memoryused >= table->sets[i].declared_length)
                {
                    table->memoryused -= table->sets[i].declared_length;
                }
                else
                {
                    table->memoryused = 0U;
                }

                aern_fragment_cache_dispose(&table->sets[i]);
                ++count;

                if (table->setscount != 0U)
                {
                    --table->setscount;
                }
            }
        }
    }

    return count;
}

uint32_t aern_fragment_table_cleanup_expired(aern_fragment_table* table, uint64_t now)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;
    size_t i;

    count = 0U;

    if (table != NULL && table->initialized == true)
    {
        for (i = 0U; i < table->setscap; ++i)
        {
            if (table->sets[i].expiry != 0U && table->sets[i].expiry <= now)
            {
                if (table->memoryused >= table->sets[i].declared_length)
                {
                    table->memoryused -= table->sets[i].declared_length;
                }
                else
                {
                    table->memoryused = 0U;
                }

                aern_fragment_cache_dispose(&table->sets[i]);
                ++count;

                if (table->setscount != 0U)
                {
                    --table->setscount;
                }
            }
        }
    }

    return count;
}

uint32_t aern_fragment_table_count(const aern_fragment_table* table)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;

    count = 0U;

    if (table != NULL && table->initialized == true)
    {
        count = (uint32_t)table->setscount;
    }

    return count;
}

void aern_relay_fragment_key_create(uint8_t key[QSC_COLLECTION_KEY_WIDTH], uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    size_t i;

    if (key != NULL)
    {
        qsc_memutils_clear(key, QSC_COLLECTION_KEY_WIDTH);

        for (i = 0U; i < 8U; ++i)
        {
            key[i] = (uint8_t)((sessionid >> (i * 8U)) & 0xFFU);
        }

        for (i = 0U; i < 7U; ++i)
        {
            key[8U + i] = (uint8_t)((packetid >> (i * 8U)) & 0xFFU);
        }

        key[15U] = direction;
    }
}

bool aern_relay_fragment_set_add(aern_relay_cache_state* cache, const aern_relay_fragment_set_entry* entry)
{
    AERN_ASSERT(cache != NULL);

    aern_fragment_cache* set;
    size_t declaredlen;
    bool res;

    set = NULL;
    declaredlen = 0U;
    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true && entry->sessionid != 0U &&
        entry->packetid != 0U && entry->fragcount != 0U)
    {
        declaredlen = (entry->totalsize != 0U) ? (size_t)entry->totalsize : ((size_t)entry->fragcount * (size_t)AERN_FRAG_CHUNK_SIZE);
        set = aern_fragment_table_get_or_add(&cache->fragments, entry->sessionid, entry->packetid, entry->direction,
            entry->fragcount, entry->expiry, declaredlen);

        if (set != NULL)
        {
            set->created = entry->created;
            set->expiry = entry->expiry;
            res = true;
        }
    }

    return res;
}

bool aern_relay_fragment_set_find(const aern_relay_cache_state* cache, aern_relay_fragment_set_entry* entry, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(entry != NULL);

    const aern_fragment_cache* set;
    bool res;

    set = NULL;
    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true)
    {
        set = aern_fragment_table_find_const(&cache->fragments, sessionid, packetid, direction);

        if (set != NULL)
        {
            qsc_memutils_clear(entry, sizeof(aern_relay_fragment_set_entry));
            entry->sessionid = set->sessionid;
            entry->packetid = set->packetid;
            entry->created = set->created;
            entry->expiry = set->expiry;
            entry->fragcount = set->total_frags;
            entry->received = set->received_count;
            entry->totalsize = (uint32_t)set->total_bytes;
            entry->direction = set->direction;
            entry->complete = (set->complete == true) ? 1U : 0U;
            res = true;
        }
    }

    return res;
}

void aern_relay_fragment_set_remove(aern_relay_cache_state* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL && cache->initialized == true)
    {
        aern_fragment_table_remove(&cache->fragments, sessionid, packetid, direction);
    }
}

bool aern_relay_fragment_cache_add(aern_relay_cache_state* cache, const aern_fragment_cache* entry)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(entry != NULL);

    aern_fragment_cache* set;
    size_t i;
    bool res;

    set = NULL;
    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true && entry->sessionid != 0U &&
        entry->packetid != 0U && entry->total_frags != 0U && entry->declared_length != 0U)
    {
        aern_fragment_table_remove(&cache->fragments, entry->sessionid, entry->packetid, entry->direction);
        set = aern_fragment_table_get_or_add(&cache->fragments, entry->sessionid, entry->packetid, entry->direction, entry->total_frags, entry->expiry, entry->declared_length);

        if (set != NULL)
        {
            set->created = entry->created;
            set->payloadtype = entry->payloadtype;
            set->reserved = entry->reserved;
            set->flags = entry->flags;
            set->metaset = entry->metaset;

            for (i = 0U; i < entry->partscap; ++i)
            {
                if (entry->parts[i].received == true && entry->parts[i].data != NULL && entry->parts[i].datalen != 0U)
                {
                    (void)fragment_cache_add_raw(set, entry->parts[i].data, entry->parts[i].datalen, (uint32_t)(i + 1U), entry->total_frags);
                }
            }

            res = true;
        }
    }

    return res;
}

bool aern_relay_fragment_cache_find(const aern_relay_cache_state* cache, aern_fragment_cache* entry, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(entry != NULL);

    const aern_fragment_cache* set;
    size_t i;
    bool res;

    set = NULL;
    res = false;

    if (cache != NULL && entry != NULL && cache->initialized == true)
    {
        set = aern_fragment_table_find_const(&cache->fragments, sessionid, packetid, direction);

        if (set != NULL)
        {
            aern_fragment_cache_dispose(entry);
            aern_fragment_cache_set_key(entry, set->sessionid, set->packetid, set->direction, set->expiry);
            entry->created = set->created;
            entry->payloadtype = set->payloadtype;
            entry->reserved = set->reserved;
            entry->flags = set->flags;
            entry->metaset = set->metaset;

            if (aern_fragment_cache_allocate(entry, set->total_frags, set->declared_length) == true)
            {
                for (i = 0U; i < set->partscap; ++i)
                {
                    if (set->parts[i].received == true && set->parts[i].data != NULL && set->parts[i].datalen != 0U)
                    {
                        (void)fragment_cache_add_raw(entry, set->parts[i].data, set->parts[i].datalen, (uint32_t)(i + 1U), set->total_frags);
                    }
                }

                res = true;
            }
        }
    }

    return res;
}

void aern_relay_fragment_cache_remove(aern_relay_cache_state* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction)
{
    AERN_ASSERT(cache != NULL);

    if (cache != NULL && cache->initialized == true)
    {
        aern_fragment_table_remove(&cache->fragments, sessionid, packetid, direction);
    }
}

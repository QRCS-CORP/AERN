#include "relaysession.h"
#include "memutils.h"

static bool relaysession_match(const aern_relay_session_cache_entry* entry, uint64_t sessionid, uint8_t context)
{
    bool res;

    res = false;

    if (entry != NULL)
    {
        res = (entry->sessionid == sessionid && entry->context == context);
    }

    return res;
}

void aern_relaysession_initialize(aern_relaysession_table* table)
{
    AERN_ASSERT(table != NULL);

    if (table != NULL)
    {
        qsc_memutils_clear(table, sizeof(aern_relaysession_table));
        table->initialized = true;
    }
}

void aern_relaysession_dispose(aern_relaysession_table* table)
{
    AERN_ASSERT(table != NULL);

    if (table != NULL)
    {
        qsc_memutils_secure_erase(table, sizeof(aern_relaysession_table));
    }
}

void aern_relaysession_clear(aern_relaysession_table* table)
{
    AERN_ASSERT(table != NULL);

    if (table != NULL)
    {
        qsc_memutils_secure_erase(table->entries, sizeof(table->entries));
        qsc_memutils_secure_erase(table->active, sizeof(table->active));
        table->initialized = true;
    }
}

bool aern_relaysession_add(aern_relaysession_table* table, const aern_relay_session_cache_entry* entry)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(entry != NULL);

    size_t empty;
    size_t i;
    bool res;

    empty = AERN_RELAYSESSION_TABLE_DEPTH;
    res = false;

    if (table != NULL && entry != NULL && table->initialized == true && entry->sessionid != 0U)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true)
            {
                if (relaysession_match(&table->entries[i], entry->sessionid, entry->context) == true)
                {
                    table->entries[i] = *entry;
                    res = true;
                    break;
                }
            }
            else if (empty == AERN_RELAYSESSION_TABLE_DEPTH)
            {
                empty = i;
            }
        }

        if (res == false && empty < AERN_RELAYSESSION_TABLE_DEPTH)
        {
            table->entries[empty] = *entry;
            table->active[empty] = true;
            res = true;
        }
    }

    return res;
}

bool aern_relaysession_exists(const aern_relaysession_table* table, uint64_t sessionid, uint8_t context)
{
    AERN_ASSERT(table != NULL);

    bool res;

    res = (aern_relaysession_find_const(table, sessionid, context) != NULL);

    return res;
}

bool aern_relaysession_find(const aern_relaysession_table* table, aern_relay_session_cache_entry* entry, uint64_t sessionid, uint8_t context)
{
    AERN_ASSERT(table != NULL);
    AERN_ASSERT(entry != NULL);

    const aern_relay_session_cache_entry* found;
    bool res;

    res = false;
    found = aern_relaysession_find_const(table, sessionid, context);

    if (entry != NULL && found != NULL)
    {
        *entry = *found;
        res = true;
    }

    return res;
}

const aern_relay_session_cache_entry* aern_relaysession_find_const(const aern_relaysession_table* table, uint64_t sessionid, uint8_t context)
{
    AERN_ASSERT(table != NULL);

    const aern_relay_session_cache_entry* res;
    size_t i;

    res = NULL;

    if (table != NULL && table->initialized == true && sessionid != 0U)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true && relaysession_match(&table->entries[i], sessionid, context) == true)
            {
                res = &table->entries[i];
                break;
            }
        }
    }

    return res;
}

void aern_relaysession_remove(aern_relaysession_table* table, uint64_t sessionid, uint8_t context)
{
    AERN_ASSERT(table != NULL);

    size_t i;

    if (table != NULL && table->initialized == true && sessionid != 0U)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true && relaysession_match(&table->entries[i], sessionid, context) == true)
            {
                qsc_memutils_secure_erase(&table->entries[i], sizeof(aern_relay_session_cache_entry));
                table->active[i] = false;
                break;
            }
        }
    }
}

uint32_t aern_relaysession_remove_session(aern_relaysession_table* table, uint64_t sessionid)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;
    size_t i;

    count = 0U;

    if (table != NULL && table->initialized == true && sessionid != 0U)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true && table->entries[i].sessionid == sessionid)
            {
                qsc_memutils_secure_erase(&table->entries[i], sizeof(aern_relay_session_cache_entry));
                table->active[i] = false;
                ++count;
            }
        }
    }

    return count;
}

uint32_t aern_relaysession_cleanup_expired(aern_relaysession_table* table, uint64_t now)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;
    size_t i;

    count = 0U;

    if (table != NULL && table->initialized == true)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true && table->entries[i].expiry != 0U && table->entries[i].expiry <= now)
            {
                qsc_memutils_secure_erase(&table->entries[i], sizeof(aern_relay_session_cache_entry));
                table->active[i] = false;
                ++count;
            }
        }
    }

    return count;
}

uint32_t aern_relaysession_count(const aern_relaysession_table* table)
{
    AERN_ASSERT(table != NULL);

    uint32_t count;
    size_t i;

    count = 0U;

    if (table != NULL && table->initialized == true)
    {
        for (i = 0U; i < AERN_RELAYSESSION_TABLE_DEPTH; ++i)
        {
            if (table->active[i] == true)
            {
                ++count;
            }
        }
    }

    return count;
}

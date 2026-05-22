#include "relayqueue.h"
#include "route.h"
#include "memutils.h"
#include "timestamp.h"

static bool relayqueue_item_is_valid(const aern_ingress_pending_item* item)
{
    bool res;

    res = false;

    if (item != NULL && item->packet != NULL && item->packetlen != 0U &&
        item->capacity >= item->packetlen && item->packetlen <= AERN_MAX_RELAY_PACKET_SIZE &&
        item->sessionid != 0U && item->packetid != 0U)
    {
        res = true;
    }

    return res;
}

static void relayqueue_item_copy_clear(aern_ingress_pending_item* item)
{
    if (item != NULL)
    {
        qsc_memutils_clear(item, sizeof(aern_ingress_pending_item));
    }
}

void aern_relayqueue_item_dispose(aern_ingress_pending_item* item)
{
    AERN_ASSERT(item != NULL);

    if (item != NULL)
    {
        if (item->packet != NULL)
        {
            if (item->capacity != 0U)
            {
                qsc_memutils_secure_erase(item->packet, item->capacity);
            }

            qsc_memutils_alloc_free(item->packet);
        }

        relayqueue_item_copy_clear(item);
    }
}

void aern_relayqueue_initialize(aern_relayqueue_state* queue, size_t depth)
{
    AERN_ASSERT(queue != NULL);

    if (queue != NULL)
    {
        qsc_memutils_clear(queue, sizeof(aern_relayqueue_state));

        if (depth != 0U && depth <= (SIZE_MAX / sizeof(aern_ingress_pending_item)))
        {
            queue->items = (aern_ingress_pending_item*)qsc_memutils_malloc(depth * sizeof(aern_ingress_pending_item));

            if (queue->items != NULL)
            {
                qsc_memutils_clear(queue->items, depth * sizeof(aern_ingress_pending_item));
                queue->depth = depth;
                queue->initialized = true;
            }
        }
    }
}

void aern_relayqueue_dispose(aern_relayqueue_state* queue)
{
    AERN_ASSERT(queue != NULL);

    if (queue != NULL)
    {
        if (queue->items != NULL)
        {
            for (size_t i = 0U; i < queue->depth; ++i)
            {
                aern_relayqueue_item_dispose(&queue->items[i]);
            }

            qsc_memutils_alloc_free(queue->items);
        }

        qsc_memutils_clear(queue, sizeof(aern_relayqueue_state));
    }
}

void aern_relayqueue_clear(aern_relayqueue_state* queue)
{
    AERN_ASSERT(queue != NULL);

    size_t depth;

    if (queue != NULL)
    {
        depth = queue->depth;
        aern_relayqueue_dispose(queue);
        aern_relayqueue_initialize(queue, depth);
    }
}

bool aern_relayqueue_push(aern_relayqueue_state* queue, const aern_ingress_pending_item* item)
{
    AERN_ASSERT(queue != NULL);
    AERN_ASSERT(item != NULL);

    aern_ingress_pending_item* dst;
    bool res;

    res = false;

    if (queue != NULL && queue->initialized == true && queue->items != NULL && queue->depth != 0U &&
        queue->tail < queue->depth && queue->count < queue->depth && relayqueue_item_is_valid(item) == true)
    {
        dst = &queue->items[queue->tail];

        if (dst->active == false && dst->packet == NULL)
        {
            dst->packet = (uint8_t*)qsc_memutils_malloc(item->packetlen);

            if (dst->packet != NULL)
            {
                qsc_memutils_copy(dst->packet, item->packet, item->packetlen);
                dst->packetlen = item->packetlen;
                dst->capacity = item->packetlen;
                dst->sessionid = item->sessionid;
                dst->packetid = item->packetid;
                dst->expiry = item->expiry;
                dst->delayuntil = item->delayuntil;
                dst->active = true;

                queue->tail = (queue->tail + 1U) % queue->depth;
                ++queue->count;
                res = true;
            }
        }
    }

    return res;
}

bool aern_relayqueue_pop(aern_relayqueue_state* queue, aern_ingress_pending_item* item)
{
    AERN_ASSERT(queue != NULL);
    AERN_ASSERT(item != NULL);

    aern_ingress_pending_item* src;
    bool res;

    res = false;

    if (queue != NULL && item != NULL && queue->initialized == true && queue->items != NULL &&
        queue->depth != 0U && queue->head < queue->depth && queue->count != 0U)
    {
        src = &queue->items[queue->head];

        if (src->active == true && relayqueue_item_is_valid(src) == true)
        {
            aern_relayqueue_item_dispose(item);
            *item = *src;
            relayqueue_item_copy_clear(src);
            queue->head = (queue->head + 1U) % queue->depth;
            --queue->count;
            res = true;
        }
    }

    return res;
}

uint32_t aern_relayqueue_remove_session(aern_relayqueue_state* queue, uint64_t sessionid, uint64_t tnow)
{
    AERN_ASSERT(queue != NULL);
    
    aern_ingress_pending_item item;
    size_t count;
    size_t i;
    uint32_t removed;

    (void)tnow;
    count = 0U;
    removed = 0U;
    relayqueue_item_copy_clear(&item);

    if (queue != NULL && queue->initialized == true)
    {
        count = queue->count;

        for (i = 0U; i < count; ++i)
        {
            if (aern_relayqueue_pop(queue, &item) == true)
            {
                if (item.sessionid == sessionid)
                {
                    aern_relayqueue_item_dispose(&item);
                    ++removed;
                }
                else
                {
                    if (aern_relayqueue_push(queue, &item) == false)
                    {
                        ++removed;
                    }

                    aern_relayqueue_item_dispose(&item);
                }
            }
        }
    }

    return removed;
}

uint32_t aern_relayqueue_cleanup_expired(aern_relayqueue_state* queue, uint64_t tnow)
{
    AERN_ASSERT(queue != NULL);

    aern_ingress_pending_item item = { 0 };
    size_t count;
    size_t i;
    uint32_t removed;

    count = 0U;
    removed = 0U;
    relayqueue_item_copy_clear(&item);

    if (queue != NULL && queue->initialized == true)
    {
        count = queue->count;

        for (i = 0U; i < count; ++i)
        {
            if (aern_relayqueue_pop(queue, &item) == true)
            {
                if (item.expiry != 0U && item.expiry <= tnow)
                {
                    aern_relayqueue_item_dispose(&item);
                    ++removed;
                }
                else
                {
                    if (aern_relayqueue_push(queue, &item) == false)
                    {
                        ++removed;
                    }

                    aern_relayqueue_item_dispose(&item);
                }
            }
        }
    }

    return removed;
}

uint32_t aern_relayqueue_count(const aern_relayqueue_state* queue)
{
    AERN_ASSERT(queue != NULL);
    
    uint32_t count;

    count = 0U;

    if (queue != NULL && queue->initialized == true)
    {
        count = (uint32_t)queue->count;
    }

    return count;
}

bool aern_relayqueue_is_empty(const aern_relayqueue_state* queue)
{
    AERN_ASSERT(queue != NULL);

    bool res;

    res = true;

    if (queue != NULL && queue->initialized == true)
    {
        res = (queue->count == 0U);
    }

    return res;
}

bool aern_relayqueue_is_full(const aern_relayqueue_state* queue)
{
    AERN_ASSERT(queue != NULL);

    bool res;

    res = false;

    if (queue != NULL && queue->initialized == true)
    {
        res = (queue->count >= queue->depth);
    }

    return res;
}

bool aern_relay_delay_push(aern_relay_cache_state* cache, const aern_ingress_pending_item* item)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(item != NULL);
    
    bool res;

    res = false;

    if (cache != NULL && item != NULL && cache->initialized == true)
    {
        res = aern_relayqueue_push(&cache->delayqueue, item);

        if (res == false)
        {
            ++cache->pendingoverflow;
        }
    }

    return res;
}

bool aern_relay_delay_pop(aern_relay_cache_state* cache, aern_ingress_pending_item* item)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(item != NULL);

    bool res;

    res = false;

    if (cache != NULL && item != NULL && cache->initialized == true)
    {
        res = aern_relayqueue_pop(&cache->delayqueue, item);
    }

    return res;
}

bool aern_relay_pending_push(aern_relay_cache_state* cache, const aern_ingress_pending_item* item)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(item != NULL);

    bool res;

    res = false;

    if (cache != NULL && item != NULL && cache->initialized == true)
    {
        res = aern_relayqueue_push(&cache->pendingqueue, item);

        if (res == false)
        {
            ++cache->pendingoverflow;
        }
    }

    return res;
}

bool aern_relay_pending_pop(aern_relay_cache_state* cache, aern_ingress_pending_item* item)
{
    AERN_ASSERT(cache != NULL);
    AERN_ASSERT(item != NULL);

    bool res;

    res = false;

    if (cache != NULL && item != NULL && cache->initialized == true)
    {
        res = aern_relayqueue_pop(&cache->pendingqueue, item);
    }

    return res;
}

uint32_t aern_relay_pending_remove_session(aern_relay_cache_state* cache, uint64_t sessionid)
{
    AERN_ASSERT(cache != NULL);

    uint32_t removed;
    uint64_t nowsec;

    removed = 0U;
    nowsec = qsc_timestamp_datetime_utc();

    if (cache != NULL && cache->initialized == true)
    {
        removed = aern_relayqueue_remove_session(&cache->pendingqueue, sessionid, nowsec);
        removed += aern_relayqueue_remove_session(&cache->delayqueue, sessionid, nowsec);
        cache->pendingdropped += (uint64_t)removed;
    }

    return removed;
}


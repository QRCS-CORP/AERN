#ifndef AERN_RELAYQUEUE_H
#define AERN_RELAYQUEUE_H

#include "aern.h"

/**
 * \file relayqueue.h
 * \brief Relay pending and delay queue interface.
 *
 * \details
 * This header defines the bounded relay queue used by the AERN route engine for
 * packets that are waiting for session establishment or delayed ingress release.
 * The queue stores a fixed number of item slots, while each queued packet is
 * held in heap-backed storage owned by the queue entry. The queue does not use
 * qsc_queue_state and does not expose internal ring indexes to callers.
 *
 * Queue ownership rules:
 * - Push copies the caller-provided packet into queue-owned storage.
 * - Pop transfers the queue-owned packet storage to the caller-owned item.
 * - Remove, cleanup, clear, and dispose securely erase and release all owned
 *   packet storage before clearing queue state.
 *
 * Callers that receive an item through a successful pop operation must release
 * the transferred packet storage with aern_relayqueue_item_dispose().
 */

/*!
 * \struct aern_ingress_pending_item
 * \brief Relay packet queued while an ingress session waits for egress acknowledgement or delay expiry.
 */
typedef struct aern_ingress_pending_item
{
    uint8_t* packet;                                /*!< Heap-backed relay packet bytes */
    size_t packetlen;                               /*!< Number of valid packet bytes */
    size_t capacity;                                /*!< Allocated packet capacity in bytes */
    uint64_t sessionid;                             /*!< Logical session identifier */
    uint64_t packetid;                              /*!< Packet identifier */
    uint64_t expiry;                                /*!< UTC expiry time in seconds */
    uint64_t delayuntil;                            /*!< UTC release time in milliseconds, or zero */
    bool active;                                    /*!< True when the item owns packet storage */
} aern_ingress_pending_item;

/*!
 * \struct aern_relayqueue_state
 * \brief Fixed-slot relay queue with heap-backed packet storage.
 */
typedef struct aern_relayqueue_state
{
    aern_ingress_pending_item* items;               /*!< Heap-backed queue item slots */
    size_t depth;                                   /*!< Maximum number of queue slots */
    size_t head;                                    /*!< Index of the next item to pop */
    size_t tail;                                    /*!< Index of the next item to push */
    size_t count;                                   /*!< Number of active queue items */
    bool initialized;                               /*!< True when the queue owns the item array */
} aern_relayqueue_state;

/**
 * \brief Dispose of a relay queue item and release owned packet storage.
 *
 * \details
 * This function securely erases the packet buffer when present, releases it
 * through the QSC memory allocator, and clears the item metadata. It is safe to
 * call on a zeroed or inactive item.
 *
 * \param item: [aern_ingress_pending_item*] The queue item to dispose.
 */
AERN_EXPORT_API void aern_relayqueue_item_dispose(aern_ingress_pending_item* item);

/**
 * \brief Initialize a relay queue with a fixed number of item slots.
 *
 * \details
 * This function allocates the queue slot array and initializes the ring state.
 * Packet payload storage is not allocated until items are pushed.
 *
 * \param queue: [aern_relayqueue_state*] The queue state to initialize.
 * \param depth: [size_t] The maximum number of queue items.
 */
AERN_EXPORT_API void aern_relayqueue_initialize(aern_relayqueue_state* queue, size_t depth);

/**
 * \brief Dispose of a relay queue.
 *
 * \details
 * This function securely disposes all active queue items, releases the queue
 * slot array, and clears the queue state.
 *
 * \param queue: [aern_relayqueue_state*] The queue state to dispose.
 */
AERN_EXPORT_API void aern_relayqueue_dispose(aern_relayqueue_state* queue);

/**
 * \brief Clear all active items from a relay queue.
 *
 * \details
 * This function securely disposes all active items and resets the queue ring
 * indexes while preserving the allocated slot array.
 *
 * \param queue: [aern_relayqueue_state*] The queue state to clear.
 */
AERN_EXPORT_API void aern_relayqueue_clear(aern_relayqueue_state* queue);

/**
 * \brief Push a relay packet item into the queue.
 *
 * \details
 * The queue copies item->packet into newly allocated queue-owned storage. The
 * caller retains ownership of the input item and may dispose or reuse it after
 * this function returns. The queue rejects inactive, oversized, empty, or
 * malformed packet items.
 *
 * \param queue: [aern_relayqueue_state*] The queue to receive the item.
 * \param item: [const aern_ingress_pending_item*] The item metadata and packet
 * buffer to copy into the queue.
 *
 * \return [bool] Returns true if the item was copied into the queue; otherwise false.
 */
AERN_EXPORT_API bool aern_relayqueue_push(aern_relayqueue_state* queue, const aern_ingress_pending_item* item);

/**
 * \brief Pop the oldest relay packet item from the queue.
 *
 * \details
 * On success, this function transfers the queue-owned packet buffer to the
 * caller-provided output item. The caller is responsible for releasing the
 * transferred buffer by calling aern_relayqueue_item_dispose().
 *
 * \param queue: [aern_relayqueue_state*] The queue to remove an item from.
 * \param item: [aern_ingress_pending_item*] The output item that receives the
 * transferred packet ownership.
 *
 * \return [bool] Returns true if an item was removed; otherwise false.
 */
AERN_EXPORT_API bool aern_relayqueue_pop(aern_relayqueue_state* queue, aern_ingress_pending_item* item);

/**
 * \brief Remove all queued items that belong to a relay session.
 *
 * \details
 * This function removes and securely disposes each active queue item whose
 * session identifier matches the supplied value. The current time value is used
 * by the implementation when reinserting retained items through cleanup logic.
 *
 * \param queue: [aern_relayqueue_state*] The queue to scan.
 * \param sessionid: [uint64_t] The relay session identifier to remove.
 * \param tnow: [uint64_t] The current UTC time in seconds or milliseconds,
 * according to the caller's queue policy.
 *
 * \return [uint32_t] Returns the number of removed items.
 */
AERN_EXPORT_API uint32_t aern_relayqueue_remove_session(aern_relayqueue_state* queue, uint64_t sessionid, uint64_t tnow);

/**
 * \brief Remove expired relay queue items.
 *
 * \details
 * This function removes and securely disposes all active items whose expiry has
 * elapsed. Non-expired items remain queued in FIFO order.
 *
 * \param queue: [aern_relayqueue_state*] The queue to clean.
 * \param tnow: [uint64_t] The current UTC time in seconds.
 *
 * \return [uint32_t] Returns the number of expired items removed.
 */
AERN_EXPORT_API uint32_t aern_relayqueue_cleanup_expired(aern_relayqueue_state* queue, uint64_t tnow);

/**
 * \brief Get the number of active items in a relay queue.
 *
 * \param queue: [const aern_relayqueue_state*] The queue to query.
 *
 * \return [uint32_t] Returns the number of active items.
 */
AERN_EXPORT_API uint32_t aern_relayqueue_count(const aern_relayqueue_state* queue);

/**
 * \brief Test whether a relay queue is empty.
 *
 * \param queue: [const aern_relayqueue_state*] The queue to query.
 *
 * \return [bool] Returns true if the queue has no active items.
 */
AERN_EXPORT_API bool aern_relayqueue_is_empty(const aern_relayqueue_state* queue);

/**
 * \brief Test whether a relay queue is full.
 *
 * \param queue: [const aern_relayqueue_state*] The queue to query.
 *
 * \return [bool] Returns true if the queue has no available item slots.
 */
AERN_EXPORT_API bool aern_relayqueue_is_full(const aern_relayqueue_state* queue);

#endif

#ifndef AERN_FRAGMENT_H
#define AERN_FRAGMENT_H

#include "route.h"

/**
 * \def AERN_FRAGMENT_TABLE_DEPTH
 * \brief The default number of fragment cache entries maintained by a fragment table.
 */
#ifndef AERN_FRAGMENT_TABLE_DEPTH
#   define AERN_FRAGMENT_TABLE_DEPTH 16U
#endif

/**
 * \def AERN_FRAGMENT_CACHE_MEMORY_MAX
 * \brief The default maximum number of bytes available to a fragment table for cached fragment data.
 */
#ifndef AERN_FRAGMENT_CACHE_MEMORY_MAX
#   define AERN_FRAGMENT_CACHE_MEMORY_MAX (16U * 1024U * 1024U)
#endif

/**
 * \brief Dispose of a fragment part state.
 *
 * \param part: [aern_fragment_part_state*] The fragment part state to dispose.
 */
AERN_EXPORT_API void aern_fragment_part_dispose(aern_fragment_part_state* part);

/**
 * \brief Initialize a fragment cache state.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state to initialize.
 */
AERN_EXPORT_API void aern_fragment_cache_initialize(aern_fragment_cache* cache);

/**
 * \brief Allocate storage for a fragment cache.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state to allocate.
 * \param fragcount: [uint32_t] The number of fragments expected in the fragment set.
 * \param declaredlen: [size_t] The declared total message length represented by the fragment set.
 *
 * \return [bool] Returns true if the fragment cache was allocated successfully; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_allocate(aern_fragment_cache* cache, uint32_t fragcount, size_t declaredlen);

/**
 * \brief Dispose of a fragment cache state and release all owned fragment storage.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state to dispose.
 */
AERN_EXPORT_API void aern_fragment_cache_dispose(aern_fragment_cache* cache);

/**
 * \brief Clear a fragment cache state without releasing the cache object itself.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state to clear.
 */
AERN_EXPORT_API void aern_fragment_cache_clear(aern_fragment_cache* cache);

/**
 * \brief Add a raw fragment buffer to a fragment cache.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state that receives the fragment.
 * \param data: [const uint8_t*] The fragment data buffer to add.
 * \param dlen: [size_t] The number of bytes in the fragment data buffer.
 * \param seq: [uint32_t] The fragment sequence number.
 *
 * \return [bool] Returns true if the fragment was accepted by the cache; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_add(aern_fragment_cache* cache, const uint8_t* data, size_t dlen, uint32_t seq);

/**
 * \brief Add a relay payload fragment to a fragment cache using its encrypted relay payload header metadata.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state that receives the fragment.
 * \param header: [const aern_relay_payload_header*] The relay payload header associated with the fragment.
 * \param data: [const uint8_t*] The fragment data buffer to add.
 * \param dlen: [size_t] The number of bytes in the fragment data buffer.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 * \param complete: [bool*] The output flag set to true when the fragment set is complete.
 *
 * \return [bool] Returns true if the fragment was accepted by the cache; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_add_fragment(aern_fragment_cache* cache, const aern_relay_payload_header* header, const uint8_t* data, size_t dlen, uint8_t direction, bool* complete);

/**
 * \brief Add a relay fragment to a fragment cache and update the cache completion state.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state that receives the fragment.
 * \param header: [const aern_relay_payload_header*] The relay payload header associated with the fragment.
 * \param fragment: [const uint8_t*] The fragment data buffer to add.
 * \param fraglen: [size_t] The number of bytes in the fragment data buffer.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 *
 * \return [bool] Returns true if the relay fragment was accepted by the cache; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_add_relay_fragment(aern_fragment_cache* cache, const aern_relay_payload_header* header, const uint8_t* fragment, size_t fraglen, uint8_t direction);

/**
 * \brief Set the identity key and expiration time for a fragment cache.
 *
 * \param cache: [aern_fragment_cache*] The fragment cache state to update.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment set.
 * \param packetid: [uint64_t] The relay packet identifier associated with the fragment set.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 * \param expiry: [uint64_t] The expiration time for the fragment cache entry.
 */
AERN_EXPORT_API void aern_fragment_cache_set_key(aern_fragment_cache* cache, uint64_t sessionid, uint64_t packetid, uint8_t direction, uint64_t expiry);

/**
 * \brief Allocate and assemble a completed fragment cache into a contiguous message buffer.
 *
 * \param cache: [const aern_fragment_cache*] The completed fragment cache to assemble.
 * \param output: [uint8_t**] The output pointer that receives the allocated message buffer.
 * \param msglen: [size_t*] The output parameter that receives the assembled message length.
 *
 * \return [bool] Returns true if the message was assembled and allocated successfully; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_assemble_alloc(const aern_fragment_cache* cache, uint8_t** output, size_t* msglen);

/**
 * \brief Assemble a completed fragment cache into a caller-provided packet buffer.
 *
 * \param cache: [const aern_fragment_cache*] The completed fragment cache to assemble.
 * \param output: [uint8_t*] The output buffer that receives the assembled message.
 * \param outlen: [size_t] The capacity in bytes of the output buffer.
 * \param msglen: [size_t*] The output parameter that receives the assembled message length.
 *
 * \return [bool] Returns true if the message was assembled successfully; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_cache_assemble_packet(const aern_fragment_cache* cache, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Assemble a completed fragment cache into a caller-provided output buffer.
 *
 * \param cache: [const aern_fragment_cache*] The completed fragment cache to assemble.
 * \param out: [uint8_t*] The output buffer that receives the assembled message.
 * \param outlen: [size_t*] The input buffer capacity and output assembled message length.
 */
AERN_EXPORT_API void aern_fragment_cache_assemble(const aern_fragment_cache* cache, uint8_t* out, size_t* outlen);

/**
 * \brief Initialize a fragment table.
 *
 * \param table: [aern_fragment_table*] The fragment table state to initialize.
 * \param setscap: [size_t] The maximum number of fragment cache sets supported by the table.
 * \param memorymax: [size_t] The maximum number of bytes available for cached fragment data.
 *
 * \return [bool] Returns true if the fragment table was initialized successfully; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_table_initialize(aern_fragment_table* table, size_t setscap, size_t memorymax);

/**
 * \brief Dispose of a fragment table and all fragment cache entries owned by the table.
 *
 * \param table: [aern_fragment_table*] The fragment table state to dispose.
 */
AERN_EXPORT_API void aern_fragment_table_dispose(aern_fragment_table* table);

/**
 * \brief Clear all fragment cache entries from a fragment table.
 *
 * \param table: [aern_fragment_table*] The fragment table state to clear.
 */
AERN_EXPORT_API void aern_fragment_table_clear(aern_fragment_table* table);

/**
 * \brief Find a mutable fragment cache entry by session, packet, and direction.
 *
 * \param table: [aern_fragment_table*] The fragment table to search.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment set.
 * \param packetid: [uint64_t] The relay packet identifier associated with the fragment set.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 *
 * \return [aern_fragment_cache*] Returns a pointer to the matching fragment cache entry, or NULL if no entry exists.
 */
AERN_EXPORT_API aern_fragment_cache* aern_fragment_table_find(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Find a constant fragment cache entry by session, packet, and direction.
 *
 * \param table: [const aern_fragment_table*] The fragment table to search.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment set.
 * \param packetid: [uint64_t] The relay packet identifier associated with the fragment set.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 *
 * \return [const aern_fragment_cache*] Returns a pointer to the matching fragment cache entry, or NULL if no entry exists.
 */
AERN_EXPORT_API const aern_fragment_cache* aern_fragment_table_find_const(const aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Find an existing fragment cache entry or create a new one.
 *
 * \param table: [aern_fragment_table*] The fragment table to search or update.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment set.
 * \param packetid: [uint64_t] The relay packet identifier associated with the fragment set.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 * \param fragcount: [uint32_t] The number of fragments expected in the fragment set.
 * \param expiry: [uint64_t] The expiration time for the fragment cache entry.
 * \param declaredlen: [size_t] The declared total message length represented by the fragment set.
 *
 * \return [aern_fragment_cache*] Returns a pointer to the fragment cache entry, or NULL on failure.
 */
AERN_EXPORT_API aern_fragment_cache* aern_fragment_table_get_or_add(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction, uint32_t fragcount, uint64_t expiry, size_t declaredlen);

/**
 * \brief Add a relay fragment to a fragment table and return the active fragment cache entry.
 *
 * \param table: [aern_fragment_table*] The fragment table that receives the fragment.
 * \param header: [const aern_relay_payload_header*] The relay payload header associated with the fragment.
 * \param fragment: [const uint8_t*] The fragment data buffer to add.
 * \param fraglen: [size_t] The number of bytes in the fragment data buffer.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 * \param expiry: [uint64_t] The expiration time for a newly-created fragment cache entry.
 * \param set: [aern_fragment_cache**] The output pointer that receives the fragment cache entry used for the fragment.
 * \param complete: [bool*] The output flag set to true when the fragment set is complete.
 *
 * \return [bool] Returns true if the relay fragment was accepted by the table; otherwise, false.
 */
AERN_EXPORT_API bool aern_fragment_table_add_relay_fragment(aern_fragment_table* table, const aern_relay_payload_header* header, const uint8_t* fragment, size_t fraglen, uint8_t direction, uint64_t expiry, aern_fragment_cache** set, bool* complete);

/**
 * \brief Remove a fragment cache entry from a fragment table.
 *
 * \param table: [aern_fragment_table*] The fragment table to update.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment set.
 * \param packetid: [uint64_t] The relay packet identifier associated with the fragment set.
 * \param direction: [uint8_t] The relay direction associated with the fragment set.
 */
AERN_EXPORT_API void aern_fragment_table_remove(aern_fragment_table* table, uint64_t sessionid, uint64_t packetid, uint8_t direction);

/**
 * \brief Remove all fragment cache entries associated with a relay session.
 *
 * \param table: [aern_fragment_table*] The fragment table to update.
 * \param sessionid: [uint64_t] The relay session identifier associated with the fragment entries to remove.
 *
 * \return [uint32_t] Returns the number of fragment cache entries removed from the table.
 */
AERN_EXPORT_API uint32_t aern_fragment_table_remove_session(aern_fragment_table* table, uint64_t sessionid);

/**
 * \brief Remove expired fragment cache entries from a fragment table.
 *
 * \param table: [aern_fragment_table*] The fragment table to update.
 * \param now: [uint64_t] The current time value used to compare against fragment cache expiration times.
 *
 * \return [uint32_t] Returns the number of expired fragment cache entries removed from the table.
 */
AERN_EXPORT_API uint32_t aern_fragment_table_cleanup_expired(aern_fragment_table* table, uint64_t now);

/**
 * \brief Get the number of active fragment cache entries in a fragment table.
 *
 * \param table: [const aern_fragment_table*] The fragment table state to query.
 *
 * \return [uint32_t] Returns the number of active fragment cache entries in the table.
 */
AERN_EXPORT_API uint32_t aern_fragment_table_count(const aern_fragment_table* table);

#endif

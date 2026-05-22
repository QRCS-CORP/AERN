#ifndef AERN_RELAYSESSION_H
#define AERN_RELAYSESSION_H

#include "route.h"

/**
 * \brief Initialize a relay-session table.
 *
 * This function clears the relay-session table and marks it as initialized. The
 * table must be initialized before relay-session entries can be added, queried,
 * removed, or expired.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to initialize.
 */
AERN_EXPORT_API void aern_relaysession_initialize(aern_relaysession_table* table);

/**
 * \brief Dispose of a relay-session table.
 *
 * This function clears all session entries, active-slot markers, and the
 * initialization state of the relay-session table.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to dispose.
 */
AERN_EXPORT_API void aern_relaysession_dispose(aern_relaysession_table* table);

/**
 * \brief Clear all entries from a relay-session table.
 *
 * This function removes every active relay-session entry from the table while
 * leaving the table in the initialized state.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to clear.
 */
AERN_EXPORT_API void aern_relaysession_clear(aern_relaysession_table* table);

/**
 * \brief Add or replace a relay-session entry.
 *
 * This function stores a relay-session cache entry in the first available table
 * slot. If an active entry already exists with the same session identifier and
 * context, the existing entry is replaced.
 *
 * \param table: [aern_relaysession_table*] The initialized relay-session table.
 * \param entry: [const aern_relay_session_cache_entry*] The relay-session entry to store.
 *
 * \return Returns true if the entry was added or replaced; otherwise, returns false.
 */
AERN_EXPORT_API bool aern_relaysession_add(aern_relaysession_table* table, const aern_relay_session_cache_entry* entry);

/**
 * \brief Test whether a relay session exists.
 *
 * This function searches the relay-session table for an active entry matching the
 * specified session identifier and session context.
 *
 * \param table: [const aern_relaysession_table*] The relay-session table to search.
 * \param sessionid: [uint64_t] The logical relay-session identifier.
 * \param context: [uint8_t] The relay-session context value.
 *
 * \return Returns true if a matching active entry exists; otherwise, returns false.
 */
AERN_EXPORT_API bool aern_relaysession_exists(const aern_relaysession_table* table, uint64_t sessionid, uint8_t context);

/**
 * \brief Find and copy a relay-session entry.
 *
 * This function searches for an active relay-session entry matching the specified
 * session identifier and context. When found, the entry is copied to the output
 * structure.
 *
 * \param table: [const aern_relaysession_table*] The relay-session table to search.
 * \param entry: [aern_relay_session_cache_entry*] The output structure that receives the matching entry.
 * \param sessionid: [uint64_t] The logical relay-session identifier.
 * \param context: [uint8_t] The relay-session context value.
 *
 * \return Returns true if a matching active entry was found and copied; otherwise, returns false.
 */
AERN_EXPORT_API bool aern_relaysession_find(const aern_relaysession_table* table, aern_relay_session_cache_entry* entry, uint64_t sessionid, uint8_t context);

/**
 * \brief Find a relay-session entry by reference.
 *
 * This function searches for an active relay-session entry matching the specified
 * session identifier and context, and returns a constant pointer to the stored
 * table entry.
 *
 * \param table: [const aern_relaysession_table*] The relay-session table to search.
 * \param sessionid: [uint64_t] The logical relay-session identifier.
 * \param context: [uint8_t] The relay-session context value.
 *
 * \return Returns a constant pointer to the matching entry, or NULL if no matching entry exists.
 */
AERN_EXPORT_API const aern_relay_session_cache_entry* aern_relaysession_find_const(const aern_relaysession_table* table, uint64_t sessionid, uint8_t context);

/**
 * \brief Remove a relay-session entry.
 *
 * This function removes the active relay-session entry matching the specified
 * session identifier and context. The entry storage is cleared before the slot is
 * marked inactive.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to modify.
 * \param sessionid: [uint64_t] The logical relay-session identifier.
 * \param context: [uint8_t] The relay-session context value.
 */
AERN_EXPORT_API void aern_relaysession_remove(aern_relaysession_table* table, uint64_t sessionid, uint8_t context);

/**
 * \brief Remove all entries for a relay-session identifier.
 *
 * This function removes every active relay-session entry matching the specified
 * session identifier, regardless of session context. Each removed entry is
 * cleared before its slot is marked inactive.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to modify.
 * \param sessionid: [uint64_t] The logical relay-session identifier.
 *
 * \return Returns the number of entries removed from the table.
 */
AERN_EXPORT_API uint32_t aern_relaysession_remove_session(aern_relaysession_table* table, uint64_t sessionid);

/**
 * \brief Remove expired relay-session entries.
 *
 * This function removes active relay-session entries whose expiry time is nonzero
 * and less than or equal to the supplied current time. Each expired entry is
 * cleared before its slot is marked inactive.
 *
 * \param table: [aern_relaysession_table*] The relay-session table to modify.
 * \param now: [uint64_t] The current UTC time in seconds.
 *
 * \return Returns the number of expired entries removed from the table.
 */
AERN_EXPORT_API uint32_t aern_relaysession_cleanup_expired(aern_relaysession_table* table, uint64_t now);

/**
 * \brief Count active relay-session entries.
 *
 * This function counts the number of active entries currently stored in an
 * initialized relay-session table.
 *
 * \param table: [const aern_relaysession_table*] The relay-session table to inspect.
 *
 * \return Returns the number of active relay-session entries.
 */
AERN_EXPORT_API uint32_t aern_relaysession_count(const aern_relaysession_table* table);

#endif

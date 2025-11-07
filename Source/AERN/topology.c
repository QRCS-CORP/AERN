#include "topology.h"
#include "async.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#if defined(AERN_DEBUG_MODE)
#	include "acp.h"
#endif

void aern_topology_address_from_issuer(char* address, const char* issuer, const aern_topology_list_state* list)
{
	AERN_ASSERT(address != NULL);
	AERN_ASSERT(issuer != NULL);
	AERN_ASSERT(list != NULL);

	size_t clen;

	if (address != NULL && issuer != NULL && list != NULL && list->topology != NULL && list->count > 0U)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			clen = qsc_stringutils_string_size(issuer);

			if (clen > 0U)
			{
				aern_topology_node_state node = { 0 };

				if (aern_topology_list_item(list, &node, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)node.issuer, (const uint8_t*)issuer, clen) == true)
					{
						qsc_memutils_copy(address, node.address, AERN_CERTIFICATE_ADDRESS_SIZE);
						break;
					}
				}
			}
		}
	}
}

uint8_t* aern_topology_child_add_empty_node(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	uint8_t* nptr;
	uint8_t* ttmp;
	size_t nctx;

	nptr = NULL;
	ttmp = NULL;

	if (list != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nctx = list->count + 1U;

		if (list->topology != NULL)
		{
			ttmp = qsc_memutils_realloc(list->topology, nctx * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ttmp != NULL)
			{
				list->topology = ttmp;
			}
		}
		else
		{
			list->topology = qsc_memutils_malloc(nctx * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		}

		nptr = (uint8_t*)(list->topology + (list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE));

		qsc_memutils_clear(nptr, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		++list->count;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return nptr;
}

void aern_topology_child_add_item(aern_topology_list_state* list, const aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	uint8_t* nptr;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		aern_topology_node_remove_duplicate(list, node->issuer);

		nptr = aern_topology_child_add_empty_node(list);
		aern_topology_node_serialize(nptr, node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool aern_topology_canonical_to_issuer_name(char* issuer, size_t isslen, const char* domain, const char* cname)
{
	AERN_ASSERT(issuer != NULL);
	AERN_ASSERT(isslen != 0U);
	AERN_ASSERT(domain != NULL);
	AERN_ASSERT(cname != NULL);

	size_t len;
	int64_t pos;
	bool res;

	const char EXT[] = ".ccert";
	const char SEP[] = "_";

	res = false;

	if (issuer != NULL && isslen != 0 && domain != NULL && cname != NULL)
	{
		len = qsc_stringutils_string_size(cname) + 
			qsc_stringutils_string_size(domain) + 
			qsc_stringutils_string_size(EXT) +
			qsc_stringutils_string_size(SEP);

		if (isslen >= len)
		{
			pos = qsc_stringutils_string_size(domain);
			qsc_stringutils_copy_substring(issuer, isslen, domain, pos);
			qsc_stringutils_concat_strings(issuer, isslen, SEP);
			qsc_stringutils_concat_strings(issuer, isslen, cname);
			qsc_stringutils_to_uppercase(issuer);
			qsc_stringutils_concat_strings(issuer, isslen, EXT);
			res = true;
		}
	}

	return res;
}

bool aern_topology_issuer_to_canonical_name(char* cname, size_t namelen, const char* issuer)
{
	AERN_ASSERT(cname != NULL);
	AERN_ASSERT(namelen != 0U);
	AERN_ASSERT(issuer != NULL);

	size_t len;
	int64_t pos;
	bool res;

	res = false;

	if (cname != NULL && namelen != 0U && issuer != NULL)
	{
		len = qsc_stringutils_string_size(issuer);

		if (len < namelen)
		{
			pos = qsc_stringutils_find_string(issuer, "_");

			if (pos > 0)
			{
				qsc_stringutils_copy_substring(cname, namelen, issuer, pos);
				qsc_stringutils_concat_strings(cname, namelen, ".");
				len = qsc_stringutils_find_string(issuer, ".");

				if (len > 0U)
				{
					++pos;
					qsc_stringutils_copy_substring(cname + pos, namelen, issuer + pos, len - pos);
					qsc_stringutils_to_lowercase(cname);
					res = true;
				}
			}
		}
	}

	return res;
}

void aern_topology_child_register(aern_topology_list_state* list, const aern_child_certificate* ccert, const char* address)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(address != NULL);

	aern_topology_node_state node = { 0 };
	uint8_t* nptr;

	nptr = NULL;

	if (list != NULL && ccert != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		aern_topology_node_remove_duplicate(list, ccert->issuer);

		qsc_memutils_copy(node.issuer, ccert->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, ccert->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, AERN_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(&node.expiration, &ccert->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		node.designation = ccert->designation;
		aern_certificate_child_hash(node.chash, ccert);

		nptr = aern_topology_child_add_empty_node(list);
		aern_topology_node_serialize(nptr, &node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

void aern_topology_list_clone(const aern_topology_list_state* tlist, aern_topology_list_state* tcopy)
{
	for (size_t i = 0U; i < tlist->count; ++i)
	{
		aern_topology_node_state node = { 0 };
		uint8_t* nptr;

		if (aern_topology_list_item(tlist, &node, i) == true)
		{
			nptr = aern_topology_child_add_empty_node(tcopy);
			aern_topology_node_serialize(nptr, &node);
		}
	}
}

void aern_topology_list_deserialize(aern_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	if (list != NULL && input != NULL)
	{
		cnt = (size_t)qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);

		for (size_t i = 0U; i < cnt; ++i)
		{
			aern_topology_node_state node = { 0 };
			uint8_t* nptr;

			if (pos >= inplen)
			{
				break;
			}

			aern_topology_node_deserialize(&node, input + pos);
			nptr = aern_topology_child_add_empty_node(list);
			aern_topology_node_serialize(nptr, &node);

			pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}
}
 
void aern_topology_list_dispose(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	if (list != NULL)
	{
		if (list->topology != NULL)
		{
			qsc_memutils_clear(list->topology, list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
			qsc_memutils_alloc_free(list->topology);
			list->topology = NULL;
			list->count = 0U;
		}
	}
}

void aern_topology_list_initialize(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	if (list != NULL)
	{
		list->count = 0U;
		list->topology = NULL;
	}
}

bool aern_topology_list_item(const aern_topology_list_state* list, aern_topology_node_state* node, size_t index)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && index < list->count)
	{
		const uint8_t* nptr;
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nptr = (uint8_t*)(list->topology + (index * AERN_NETWORK_TOPOLOGY_NODE_SIZE));
		aern_topology_node_deserialize(node, nptr);
		res = true;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

size_t aern_topology_list_remove_duplicates(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	uint8_t* np1;
	uint8_t* np2;
	uint8_t* ntop;
	size_t ctr;
	size_t len;
	size_t pos;
	qsc_mutex mtx;

	ctr = 0U;

	if (list != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		pos = 0U;
		len = list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE;
		ntop = (uint8_t*)qsc_memutils_malloc(len);

		if (ntop != NULL)
		{
			uint8_t* ptmp;

			qsc_memutils_clear(ntop, len);

			for (size_t i = 0U; i < list->count; ++i)
			{
				bool res;

				np1 = (uint8_t*)(list->topology + (i * AERN_NETWORK_TOPOLOGY_NODE_SIZE));
				np2 = NULL;
				res = false;

				for (size_t j = i + 1U; j < list->count; ++j)
				{
					np2 = (uint8_t*)(list->topology + (j * AERN_NETWORK_TOPOLOGY_NODE_SIZE));

					if (qsc_memutils_are_equal(np1, np2, AERN_NETWORK_TOPOLOGY_NODE_SIZE) == true)
					{
						res = true;
						break;
					}
				}

				if (res == false)
				{
					qsc_memutils_copy(ntop + pos, np1, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
					pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
					++ctr;
				}
			}

			ptmp = qsc_memutils_realloc(list->topology, ctr * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ptmp != NULL)
			{
				list->topology = ptmp;
				qsc_memutils_copy(list->topology, ntop, ctr * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count = (uint32_t)ctr;
			}

			qsc_memutils_alloc_free(ntop);
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return ctr;
}

size_t aern_topology_list_server_count(const aern_topology_list_state* list, aern_network_designations ntype)
{
	AERN_ASSERT(list != NULL);

	size_t cnt;

	cnt = 0U;

	if (list != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype)
				{
					++cnt;
				}
			}
		}
	}

	return cnt;
}

size_t aern_topology_list_serialize(uint8_t* output, const aern_topology_list_state* list)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(list != NULL);

	size_t pos;

	pos = 0U;

	if (output != NULL && list != NULL)
	{
		qsc_intutils_le32to8(output, list->count);
		pos += sizeof(uint32_t);

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state node = { 0 };

			if (aern_topology_list_item(list, &node, i) == true)
			{
				aern_topology_node_serialize(output + pos, &node);
				pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
			}
		}
	}

	return pos;
}

size_t aern_topology_list_size(const aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	size_t rlen;

	rlen = 0U;

	if (list != NULL)
	{
		if (list->count > 0U)
		{
			rlen = sizeof(uint32_t) + (list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		}
	}

	return rlen;
}

size_t aern_topology_list_update_pack(uint8_t* output, const aern_topology_list_state* list, aern_network_designations ntype)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(list != NULL);

	size_t pos;

	pos = 0U;

	if (output != NULL && list != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype || ntype == aern_network_designation_all)
				{
					aern_topology_node_serialize(output + pos, &ntmp);
					pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
				}
			}
		}
	}

	return pos;
}

size_t aern_topology_list_update_unpack(aern_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	cnt = 0U;

	if (list != NULL && input != NULL && inplen >= AERN_NETWORK_TOPOLOGY_NODE_SIZE)
	{
		pos = 0U;
		cnt = inplen / AERN_NETWORK_TOPOLOGY_NODE_SIZE;

		for (size_t i = 0U; i < cnt; ++i)
		{
			aern_topology_node_state node = { 0 };
			uint8_t* nptr;

			aern_topology_node_deserialize(&node, input + pos);
			nptr = aern_topology_child_add_empty_node(list);
			aern_topology_node_serialize(nptr, &node);
			pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}

	return cnt;
}

size_t aern_topology_ordered_server_list(aern_topology_list_state* olist, const aern_topology_list_state* tlist, aern_network_designations ntype)
{
	AERN_ASSERT(olist != NULL);
	AERN_ASSERT(tlist != NULL);

	size_t dcnt;
	size_t scnt;

	scnt = 0U;

	if (olist != NULL && tlist != NULL)
	{
		qsc_list_state slst = { 0 };
		aern_topology_node_state node = { 0 };

		dcnt = aern_topology_list_server_count(tlist, ntype);

		if (dcnt > 0U)
		{
			/* iterate through the topology list and add nodes of the device type */
			qsc_list_initialize(&slst, AERN_CERTIFICATE_SERIAL_SIZE);

			for (size_t i = 0U; i < tlist->count; ++i)
			{
				aern_topology_list_item(tlist, &node, i);

				if (node.designation == ntype || ntype == aern_network_designation_all)
				{
					qsc_list_add(&slst, node.serial);
				}
			}

			if (slst.count > 0U)
			{
				uint8_t sern[AERN_CERTIFICATE_SERIAL_SIZE] = { 0U };

				scnt = slst.count;

				/* sort the list of serial numbers */
				qsc_list_sort(&slst);

				/* fill the output topology state with nodes ordered by serial number  */
				for (size_t i = 0U; i < slst.count; ++i)
				{
					qsc_list_item(&slst, sern, i);

					if (aern_topology_node_find(tlist, &node, sern) == true)
					{
						aern_topology_child_add_item(olist, &node);
					}
				}
			}
		}
	}

	return scnt;
}

void aern_topology_node_add_alias(aern_topology_node_state* node, const char* alias)
{
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(alias != NULL);

	size_t apos;
	size_t ilen;

	if (node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= AERN_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		ilen = qsc_stringutils_string_size(node->issuer);

		if (ilen >= AERN_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			apos = qsc_stringutils_find_string(node->issuer, AERN_TOPOLOGY_ALIAS_DELIMITER);

			if (apos > 0U)
			{
				qsc_memutils_clear(node->issuer + apos, ilen - apos);
				qsc_stringutils_concat_strings(node->issuer, AERN_CERTIFICATE_ISSUER_SIZE, AERN_TOPOLOGY_ALIAS_DELIMITER);
			}
		}

		qsc_stringutils_concat_strings(node->issuer, AERN_CERTIFICATE_ISSUER_SIZE, alias);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool aern_topology_nodes_are_equal(const aern_topology_node_state* a, const aern_topology_node_state* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (qsc_memutils_are_equal((const uint8_t*)a->address, (const uint8_t*)b->address, AERN_CERTIFICATE_ADDRESS_SIZE) == true)
		{
			if (qsc_memutils_are_equal(a->chash, b->chash, AERN_CERTIFICATE_HASH_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, AERN_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, AERN_CERTIFICATE_ISSUER_SIZE) == true)
					{
						if (a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
						{
							if (a->designation == b->designation)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	return res;
}

void aern_topology_node_clear(aern_topology_node_state* node)
{
	AERN_ASSERT(node != NULL);

	if (node != NULL)
	{
		qsc_memutils_clear(node->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(node->address, AERN_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_clear(node->chash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_clear(node->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		node->expiration.from = 0U;
		node->expiration.to = 0U;
		node->designation = aern_network_designation_none;
	}
}

void aern_topology_node_copy(const aern_topology_node_state* source, aern_topology_node_state* destination)
{
	AERN_ASSERT(source != NULL);
	AERN_ASSERT(destination != NULL);

	if (source != NULL && destination != NULL)
	{
		qsc_memutils_copy(destination->issuer, source->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(destination->address, source->address, AERN_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(destination->chash, source->chash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_copy(destination->serial, source->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		destination->expiration.from = source->expiration.from;
		destination->expiration.to = source->expiration.to;
		destination->designation = source->designation;
	}
}

void aern_topology_node_deserialize(aern_topology_node_state* node, const uint8_t* input)
{
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(input != NULL);

	size_t pos;
	
	if (node != NULL && input != NULL)
	{
		qsc_memutils_copy(node->issuer, input, AERN_CERTIFICATE_ISSUER_SIZE);
		pos = AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(node->serial, input + pos, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(node->address, input + pos, AERN_CERTIFICATE_ADDRESS_SIZE);
		pos += AERN_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(node->chash, input + pos, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += AERN_CRYPTO_SYMMETRIC_HASH_SIZE;
		node->expiration.from = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->expiration.to = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->designation = input[pos];
	}
}

bool aern_topology_node_find(const aern_topology_list_state* list, aern_topology_node_state* node, const uint8_t* serial)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && serial != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_find_address(const aern_topology_list_state* list, aern_topology_node_state* node, const char* address)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(address != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128((const uint8_t*)ntmp.address, (const uint8_t*)address) == true)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}
		
		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_find_alias(const aern_topology_list_state* list, aern_topology_node_state* node, const char* alias)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(alias != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= AERN_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_stringutils_string_contains(ntmp.issuer, alias) == true)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_find_ads(const aern_topology_list_state* list, aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == aern_network_designation_ads)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_find_issuer(const aern_topology_list_state* list, aern_topology_node_state* node, const char* issuer)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);
	AERN_ASSERT(issuer != NULL);

	size_t clen;
	bool res;

	res = false;

	if (list != NULL && node != NULL && issuer != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();
		clen = qsc_stringutils_string_size(issuer);

		if (clen >= AERN_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			int64_t nlen;

			nlen = qsc_stringutils_find_string(issuer, AERN_TOPOLOGY_ALIAS_DELIMITER);
			clen = (nlen > 0 && nlen < (int64_t)clen) ? (size_t)nlen : clen;

			for (size_t i = 0U; i < list->count; ++i)
			{
				aern_topology_node_state ntmp = { 0 };

				if (aern_topology_list_item(list, &ntmp, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)ntmp.issuer, (const uint8_t*)issuer, clen) == true)
					{
						aern_topology_node_copy(&ntmp, node);
						res = true;
						break;
					}
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_find_root(const aern_topology_list_state* list, aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);
	
	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == aern_network_designation_ars)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool aern_topology_node_exists(const aern_topology_list_state* list, const uint8_t* serial)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && serial != NULL)
	{
		res = (aern_topology_node_get_index(list, serial) != AERN_TOPOLOGY_NODE_NOT_FOUND);
	}

	return res;
}

int32_t aern_topology_node_get_index(const aern_topology_list_state* list, const uint8_t* serial)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(serial != NULL);

	int32_t res;

	res = AERN_TOPOLOGY_NODE_NOT_FOUND;

	if (list != NULL && serial != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					res = (int32_t)i;
					break;
				}
			}
		}
	}

	return res;
}

void aern_topology_node_remove(aern_topology_list_state* list, const uint8_t* serial)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(serial != NULL);

	int32_t lpos;
	int32_t npos;

	if (list != NULL && serial != NULL)
	{
		if (list->count > 0U)
		{
			npos = aern_topology_node_get_index(list, serial);

			if (npos >= 0)
			{
				uint8_t* ttmp;

				lpos = list->count - 1;

				if (npos != lpos && lpos > 0)
				{
					qsc_memutils_copy(list->topology + (npos * AERN_NETWORK_TOPOLOGY_NODE_SIZE), list->topology + (lpos * AERN_NETWORK_TOPOLOGY_NODE_SIZE), AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				}

				qsc_memutils_clear(list->topology + (lpos * AERN_NETWORK_TOPOLOGY_NODE_SIZE), AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count -= 1U;

				if (list->count > 0U)
				{
					/* resize the array */
					ttmp = qsc_memutils_realloc(list->topology, list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				}
				else
				{
					/* array placeholder */
					ttmp = qsc_memutils_realloc(list->topology, sizeof(uint8_t));
				}

				if (ttmp != NULL)
				{
					list->topology = ttmp;
				}
			}
		}
	}
}

void aern_topology_node_remove_duplicate(aern_topology_list_state* list, const char* issuer)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(issuer != NULL);

	if (list != NULL && issuer != NULL)
	{
		aern_topology_node_state rnode = { 0 };

		if (aern_topology_node_find_issuer(list, &rnode, issuer) == true)
		{
			/* delete the node from the database */
			aern_topology_node_remove(list, rnode.serial);
		}
	}
}

size_t aern_topology_node_serialize(uint8_t* output, const aern_topology_node_state* node)
{
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(node != NULL);

	size_t pos;
	
	pos = 0U;

	if (output != NULL && node != NULL)
	{
		qsc_memutils_copy(output, node->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		pos = AERN_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, node->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		pos += AERN_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, node->address, AERN_CERTIFICATE_ADDRESS_SIZE);
		pos += AERN_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(output + pos, node->chash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += AERN_CRYPTO_SYMMETRIC_HASH_SIZE;
		qsc_intutils_le64to8(output + pos, node->expiration.from);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(output + pos, node->expiration.to);
		pos += sizeof(uint64_t);
		output[pos] = (uint8_t)node->designation;
		pos += sizeof(uint8_t);
	}

	return pos;
}

bool aern_topology_node_verify_ads(const aern_topology_list_state* list, const aern_child_certificate* ccert)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(ccert != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_ads(list, &node) == true)
		{
			uint8_t lhash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

			aern_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, AERN_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool aern_topology_node_verify_issuer(const aern_topology_list_state* list, const aern_child_certificate* ccert, const char* issuer)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(ccert != NULL);
	AERN_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL && issuer != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_issuer(list, &node, issuer) == true)
		{
			uint8_t lhash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

			aern_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, AERN_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool aern_topology_node_verify_root(const aern_topology_list_state* list, const aern_root_certificate* rcert)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(rcert != NULL);

	bool res; 

	res = false;

	if (list != NULL && rcert != NULL)
	{
		aern_topology_node_state node = { 0 };

		if (aern_topology_node_find_root(list, &node) == true)
		{
			uint8_t lhash[AERN_CERTIFICATE_HASH_SIZE] = { 0U };

			aern_certificate_root_hash(lhash, rcert);
			res = (qsc_memutils_are_equal(lhash, node.chash, AERN_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

void aern_topology_root_register(aern_topology_list_state* list, const aern_root_certificate* rcert, const char* address)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(rcert != NULL);
	AERN_ASSERT(address != NULL);

	aern_topology_node_state node = { 0 };
	uint8_t* nptr;
	
	if (list != NULL && rcert != NULL && address != NULL)
	{
		qsc_memutils_copy(node.issuer, rcert->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, rcert->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, AERN_CERTIFICATE_ADDRESS_SIZE);
		aern_certificate_root_hash(node.chash, rcert);
		qsc_memutils_copy(&node.expiration, &rcert->expiration, sizeof(aern_certificate_expiration));
		node.designation = aern_network_designation_ars;

		nptr = aern_topology_child_add_empty_node(list);
		aern_topology_node_serialize(nptr, &node);
	}
}

size_t aern_topology_list_to_string(const aern_topology_list_state* list, char* output, size_t outlen)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(output != NULL);
	AERN_ASSERT(outlen != 0);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (list != NULL && output != NULL && outlen != 0U)
	{
		if (list->count * AERN_TOPOLOGY_NODE_ENCODED_SIZE <= outlen)
		{
			for (size_t i = 0U; i < list->count; ++i)
			{
				aern_topology_node_state ntmp = { 0 };

				aern_topology_list_item(list, &ntmp, i);
				slen = aern_topology_node_encode(&ntmp, output + spos);
				spos += slen;
			}
		}
	}

	return spos;
}

size_t aern_topology_node_encode(const aern_topology_node_state* node, char output[AERN_TOPOLOGY_NODE_ENCODED_SIZE])
{
	size_t slen;
	size_t spos;

	spos = 0U;

	if (node != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy(output, AERN_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(node->issuer);
		qsc_memutils_copy(output + spos, node->issuer, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		qsc_memutils_copy(output + spos, AERN_CHILD_CERTIFICATE_ADDRESS_PREFIX, slen);
		spos += slen;

		if (qsc_ipinfo_get_address_type(node->address) == qsc_ipinfo_address_type_ipv4)
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, (uint8_t*)node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}
		else
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}

		slen = qsc_stringutils_string_size(AERN_ROOT_CERTIFICATE_HASH_PREFIX);
		qsc_memutils_copy(output + spos, AERN_ROOT_CERTIFICATE_HASH_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->chash, output + spos, AERN_CERTIFICATE_HASH_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = AERN_CERTIFICATE_HASH_SIZE * 2U;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy(output + spos, AERN_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->serial, output + spos, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = AERN_CERTIFICATE_SERIAL_SIZE * 2U;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy(output + spos, AERN_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += aern_certificate_designation_encode(output + spos, node->designation);
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy(output + spos, AERN_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy(output + spos, AERN_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;
	}

	return spos;
}

void aern_topology_from_file(const char* fpath, aern_topology_list_state* list)
{
	AERN_ASSERT(fpath != NULL);
	AERN_ASSERT(list != NULL);

	uint8_t* lbuf;
	size_t flen;

	if (fpath != NULL && list != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0U)
			{
				lbuf = (uint8_t*)qsc_memutils_malloc(flen);

				if (lbuf != NULL)
				{
					qsc_fileutils_copy_file_to_stream(fpath, (char*)lbuf, flen);
					aern_topology_list_deserialize(list, lbuf, flen);
					qsc_memutils_alloc_free(lbuf);
				}
			}
		}
	}
}

void aern_topology_to_file(const aern_topology_list_state* list, const char* fpath)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(fpath != NULL);

	uint8_t* pbuf;
	size_t flen;

	if (list != NULL && fpath != NULL)
	{
		flen = sizeof(uint32_t) + (list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		pbuf = (uint8_t*)qsc_memutils_malloc(flen);

		if (pbuf != NULL)
		{
			aern_topology_list_serialize(pbuf, list);
			qsc_fileutils_copy_stream_to_file(fpath, (const char*)pbuf, flen);
			qsc_memutils_alloc_free(pbuf);
		}
	}
}

#if defined(AERN_DEBUG_MODE)
typedef struct topology_device_package
{
	aern_signature_keypair akp;
	aern_signature_keypair ckp;
	aern_signature_keypair dkp;
	aern_signature_keypair mkp;
	aern_signature_keypair rkp;
	aern_child_certificate acrt;
	aern_child_certificate ccrt;
	aern_child_certificate dcrt;
	aern_child_certificate mcrt;
	aern_root_certificate root;
	aern_topology_node_state ande;
	aern_topology_node_state and2;
	aern_topology_node_state and3;
	aern_topology_node_state and4;
	aern_topology_node_state and5;
	aern_topology_node_state and6;
	aern_topology_node_state and7;
	aern_topology_node_state and8;
	aern_topology_node_state cnde;
	aern_topology_node_state dnde;
	aern_topology_node_state mnde;
	aern_topology_list_state list;
} topology_device_package;

static void topology_load_child_node(aern_topology_list_state* list, aern_topology_node_state* node, const aern_child_certificate* ccert)
{
	uint8_t ipa[AERN_CERTIFICATE_ADDRESS_SIZE] = { 192U, 168U, 1U };

	qsc_acp_generate(ipa + 3U, 1U);
	aern_topology_child_register(list, ccert, ipa);
	aern_topology_node_find(list, node, (const uint8_t*)ccert->serial);
}

static void topology_device_destroy(topology_device_package* spkg)
{
	aern_topology_list_dispose(&spkg->list);
}

static void topology_device_instantiate(topology_device_package* spkg)
{
	aern_certificate_expiration exp = { 0 };

	/* generate the root certificate */
	aern_certificate_signature_generate_keypair(&spkg->rkp);
	aern_certificate_expiration_set_days(&exp, 0U, 30U);
	aern_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ/ARS-1:rds1.xyz.com");
	
	/* create the aps responder */
	aern_certificate_signature_generate_keypair(&spkg->akp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-1:aps1.xyz.com", aern_network_designation_aps);
	aern_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->ande, &spkg->acrt);

	/* aps copies for list test */
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-2:aps2.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and2, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-3:aps3.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and3, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-4:aps4.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and4, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-5:aps5.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and5, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-6:aps6.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and6, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-7:aps7.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and7, &spkg->acrt);
	aern_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-8:aps8.xyz.com", aern_network_designation_aps);
	topology_load_child_node(&spkg->list, &spkg->and8, &spkg->acrt);

	/* create a client */
	aern_certificate_signature_generate_keypair(&spkg->ckp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ/Client-1:client1.xyz.com", aern_network_designation_client);
	aern_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->cnde, &spkg->ccrt);

	/* create the ads */
	aern_certificate_signature_generate_keypair(&spkg->dkp);
	aern_certificate_expiration_set_days(&exp, 0U, 100U);
	aern_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ/ADC-1:ads1.xyz.com", aern_network_designation_ads);
	aern_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->dnde, &spkg->dcrt);
}

static bool topology_find_test(topology_device_package* spkg)
{
	aern_topology_node_state tand = { 0 };
	aern_topology_node_state tmnd = { 0 };
	bool res;

	res = false;

	if (spkg != NULL)
	{
		/* test find related functions */
		aern_topology_node_find(&spkg->list, &tand, spkg->ande.serial);

		if (aern_topology_nodes_are_equal(&tand, &spkg->ande) == true)
		{
			aern_topology_node_find_alias(&spkg->list, &tmnd, "mas1.xyz.com");

			if (aern_topology_nodes_are_equal(&tmnd, &spkg->mnde) == true)
			{
				aern_topology_node_find_issuer(&spkg->list, &tand, spkg->ande.issuer);

				if (aern_topology_nodes_are_equal(&tand, &spkg->ande) == true)
				{
					aern_topology_node_add_alias(&spkg->cnde, "client.xyz.com");

					if (qsc_stringutils_string_contains(spkg->cnde.issuer, "client.xyz.com") == true)
					{
						res = true;
					}
				}
			}
		}
	}

	return res;
}

static bool topology_serialization_test(topology_device_package* spkg)
{
	aern_topology_list_state lstc = { 0 };
	aern_topology_node_state itma;
	aern_topology_node_state itmb;
	uint8_t* lbuf;
	size_t mlen;
	bool res;
	
	res = false;

	if (spkg != NULL)
	{
		mlen = sizeof(uint32_t) + (spkg->list.count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		lbuf = (uint8_t*)qsc_memutils_malloc(mlen);

		if (lbuf != NULL)
		{
			aern_topology_list_serialize(lbuf, &spkg->list);
			aern_topology_list_initialize(&lstc);
			aern_topology_list_deserialize(&lstc, lbuf, mlen);
			qsc_memutils_alloc_free(lbuf);
			res = true;

			for (size_t i = 0; i < lstc.count; ++i)
			{
				if (aern_topology_list_item(&lstc, &itma, i) == true)
				{
					if (aern_topology_list_item(&spkg->list, &itmb, i) == true)
					{
						if (aern_topology_nodes_are_equal(&itma, &itmb) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			if (res == true)
			{
				aern_topology_node_state ncpy = { 0 };
				uint8_t nser[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

				for (size_t i = 0U; i < lstc.count; ++i)
				{
					if (aern_topology_list_item(&lstc, &itma, i) == true)
					{
						aern_topology_node_serialize(nser, &itma);
						aern_topology_node_deserialize(&ncpy, nser);

						if (aern_topology_nodes_are_equal(&itma, &ncpy) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			aern_topology_list_dispose(&lstc);
		}
	}

	return res;
}

static bool topology_sorted_list_test(topology_device_package* spkg)
{
	aern_topology_list_state olst = { 0 };
	aern_topology_node_state itma;
	aern_topology_node_state itmb;
	size_t acnt;
	size_t ncnt;
	bool res;

	/* test the count */
	acnt = aern_topology_list_server_count(&spkg->list, aern_network_designation_aps);
	ncnt = aern_topology_ordered_server_list(&olst, &spkg->list, aern_network_designation_aps);

	res = (acnt == ncnt);

	if (res == true)
	{
		/* test the sort */
		for (size_t i = 0U; i < olst.count - 1U; ++i)
		{
			aern_topology_list_item(&olst, &itma, i);
			aern_topology_list_item(&olst, &itmb, i + 1U);

			if (qsc_memutils_greater_than_le128(itma.serial, itmb.serial) == false)
			{
				res = false;
				break;
			}
		}

		aern_topology_list_dispose(&olst);
	}

	return res;
}

bool aern_topology_functions_test(void)
{
	topology_device_package spkg = { 0 };
	bool res;

	res = false;
	topology_device_instantiate(&spkg);

	/* test the find functions */
	if (topology_find_test(&spkg) == true)
	{
		/* test add, remove, and serialization functions */
		if (topology_serialization_test(&spkg) == true)
		{
			/* test sort and ordered list */
			if (topology_sorted_list_test(&spkg) == true)
			{
				res = true;
			}
		}
	}

	topology_device_destroy(&spkg);

	return res;
}
#endif

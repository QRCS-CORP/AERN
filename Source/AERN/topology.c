#include "topology.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#if defined(AERN_DEBUG_MODE)
#	include "acp.h"
#endif

static int32_t topology_node_serial_compare(const uint8_t* a, const uint8_t* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	const uint8_t* aser;
	const uint8_t* bser;
	int32_t res;

	res = 0;

	if (a != NULL && b != NULL)
	{
		aser = a + AERN_CERTIFICATE_ISSUER_SIZE;
		bser = b + AERN_CERTIFICATE_ISSUER_SIZE;

		if (qsc_memutils_are_equal_128(aser, bser) == false)
		{
			res = (qsc_memutils_greater_than_le128(aser, bser) == true) ? 1 : -1;
		}
	}

	return res;
}

static void topology_node_swap(uint8_t* a, uint8_t* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	uint8_t tmp[AERN_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

	if (a != NULL && b != NULL)
	{
		qsc_memutils_copy(tmp, a, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		qsc_memutils_copy(a, b, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		qsc_memutils_copy(b, tmp, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		qsc_memutils_secure_erase(tmp, sizeof(tmp));
	}
}

static void topology_sort_by_serial(uint8_t* nodes, uint32_t count)
{
	AERN_ASSERT(nodes != NULL);

	size_t i;
	size_t j;
	uint8_t* left;
	uint8_t* right;

	if (nodes != NULL && count > 1U)
	{
		for (i = 0U; i < (size_t)count - 1U; ++i)
		{
			left = nodes + (i * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

			for (j = i + 1U; j < (size_t)count; ++j)
			{
				right = nodes + (j * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

				if (topology_node_serial_compare(left, right) > 0)
				{
					topology_node_swap(left, right);
				}
			}
		}
	}
}

static size_t topology_designation_count(const aern_topology_list_state* list, aern_network_designations designation)
{
	AERN_ASSERT(list != NULL);

	aern_topology_node_state node = { 0 };
	size_t cnt;

	cnt = 0U;

	if (list != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			qsc_memutils_clear(&node, sizeof(node));

			if (aern_topology_list_item(list, &node, i) == true && node.designation == designation)
			{
				++cnt;
			}
		}
	}

	return cnt;
}

static bool topology_issuer_matches(const char* a, const char* b)
{
	AERN_ASSERT(a != NULL);
	AERN_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = qsc_memutils_are_equal((const uint8_t*)a, (const uint8_t*)b, AERN_CERTIFICATE_ISSUER_SIZE);
	}

	return res;
}

static bool topology_node_can_insert(const aern_topology_list_state* list, const aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	aern_topology_node_state exnode = { 0 };
	bool replacing;
	bool res;

	replacing = false;
	res = false;

	if (list != NULL && node != NULL)
	{
		replacing = aern_topology_node_find_issuer(list, &exnode, node->issuer);

		if (list->count < AERN_NETWORK_TOPOLOGY_MAX_SIZE || replacing == true)
		{
			qsc_memutils_clear(&exnode, sizeof(exnode));
			res = true;

			if (aern_topology_node_find(list, &exnode, node->serial) == true &&
				topology_issuer_matches(exnode.issuer, node->issuer) == false)
			{
				res = false;
			}
			else if (node->designation == aern_network_designation_aps && replacing == false &&
				topology_designation_count(list, aern_network_designation_aps) >= 255U)
			{
				res = false;
			}
		}
	}

	return res;
}

void aern_topology_add(aern_topology_list_state* list, const aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	uint32_t count;

	if (list != NULL && node != NULL)
	{
		count = list->count;
		aern_topology_child_add_item(list, node);

		if (list->count != count)
		{
			(void)aern_topology_increment_version(list);
		}
	}
}

void aern_topology_hash(const aern_topology_list_state* list, uint8_t hash[AERN_CERTIFICATE_HASH_SIZE])
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(hash != NULL);

	uint8_t* scratch;
	size_t len;

	scratch = NULL;
	len = 0U;

	if (hash != NULL)
	{
		qsc_memutils_clear(hash, AERN_CERTIFICATE_HASH_SIZE);
	}

	if (list != NULL && hash != NULL)
	{
		if (list->topology != NULL && list->count > 0U)
		{
			len = (size_t)list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE;
			scratch = qsc_memutils_malloc(len);

			if (scratch != NULL)
			{
				qsc_memutils_copy(scratch, list->topology, len);
				topology_sort_by_serial(scratch, list->count);
				qsc_shake256_compute(hash, AERN_CERTIFICATE_HASH_SIZE, scratch, len);
				qsc_memutils_secure_erase(scratch, len);
				qsc_memutils_alloc_free(scratch);
			}
		}
		else
		{
			qsc_shake256_compute(hash, AERN_CERTIFICATE_HASH_SIZE, (const uint8_t*)"aern-empty-topology", 19U);
		}
	}
}

uint64_t aern_topology_increment_version(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	uint64_t res;

	res = 0U;

	if (list != NULL)
	{
		qsc_async_mutex_lock(list->gmtx);

		if (list->version == 0U)
		{
			list->version = 1U;
		}
		else
		{
			++list->version;

			if (list->version == 0U)
			{
				list->version = 1U;
			}
		}

		res = list->version;
		qsc_async_mutex_unlock(list->gmtx);
	}

	return res;
}

void aern_topology_remove(aern_topology_list_state* list, const uint8_t* serial)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(serial != NULL);

	if (list != NULL && serial != NULL)
	{
		if (aern_topology_node_exists(list, serial) == true)
		{
			aern_topology_node_remove(list, serial);
			(void)aern_topology_increment_version(list);
		}
	}
}

aern_protocol_errors aern_topology_update(aern_topology_list_state* list, const aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	aern_protocol_errors res;

	res = aern_protocol_error_invalid_request;

	if (list != NULL && node != NULL)
	{
		if (aern_topology_node_exists(list, node->serial) == true)
		{
			aern_topology_node_remove(list, node->serial);
			aern_topology_child_add_item(list, node);
			(void)aern_topology_increment_version(list);
			res = aern_protocol_error_none;
		}
		else
		{
			res = aern_protocol_error_node_not_found;
		}
	}

	return res;
}

aern_protocol_errors aern_topology_version_verify(const aern_topology_list_state* list, uint64_t incomingver)
{
	AERN_ASSERT(list != NULL);

	aern_protocol_errors res;

	res = aern_protocol_error_invalid_request;

	if (list != NULL)
	{
		if (incomingver > list->version)
		{
			res = aern_protocol_error_none;
		}
	}

	return res;
}

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

	if (list != NULL && list->count < AERN_NETWORK_TOPOLOGY_MAX_SIZE)
	{
		nctx = list->count + 1U;

		if (list->topology != NULL)
		{
			ttmp = qsc_memutils_realloc(list->topology, nctx * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		}
		else
		{
			ttmp = qsc_memutils_malloc(nctx * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
		}

		if (ttmp != NULL)
		{
			list->topology = ttmp;
			nptr = list->topology + ((size_t)list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
			qsc_memutils_secure_erase(nptr, AERN_NETWORK_TOPOLOGY_NODE_SIZE);
			++list->count;
		}
	}

	return nptr;
}

void aern_topology_child_add_item(aern_topology_list_state* list, const aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	uint8_t* nptr;

	if (list != NULL && node != NULL && topology_node_can_insert(list, node) == true)
	{
		qsc_async_mutex_lock(list->gmtx);

		aern_topology_node_remove_duplicate(list, node->issuer);
		nptr = aern_topology_child_add_empty_node(list);

		if (nptr != NULL)
		{
			aern_topology_node_serialize(nptr, node);
			topology_sort_by_serial(list->topology, list->count);
		}

		qsc_async_mutex_unlock(list->gmtx);
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
		qsc_memutils_copy(node.issuer, ccert->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, ccert->serial, AERN_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, AERN_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(&node.expiration, &ccert->expiration, AERN_CERTIFICATE_EXPIRATION_SIZE);
		node.designation = ccert->designation;
		aern_certificate_child_hash(node.chash, ccert);

		if (topology_node_can_insert(list, &node) == true)
		{
			qsc_async_mutex_lock(list->gmtx);

			aern_topology_node_remove_duplicate(list, ccert->issuer);
			nptr = aern_topology_child_add_empty_node(list);

			if (nptr != NULL)
			{
				aern_topology_node_serialize(nptr, &node);
				topology_sort_by_serial(list->topology, list->count);
			}

			qsc_async_mutex_unlock(list->gmtx);
		}
	}
}

void aern_topology_list_clone(const aern_topology_list_state* tlist, aern_topology_list_state* tcopy)
{
	AERN_ASSERT(tlist != NULL);
	AERN_ASSERT(tcopy != NULL);

	if (tlist != NULL && tcopy != NULL)
	{
		tcopy->version = tlist->version;

		for (size_t i = 0U; i < tlist->count; ++i)
		{
			aern_topology_node_state node = { 0 };
			uint8_t* nptr;

			if (aern_topology_list_item(tlist, &node, i) == true)
			{
				nptr = aern_topology_child_add_empty_node(tcopy);

				if (nptr != NULL)
				{
					aern_topology_node_serialize(nptr, &node);
				}
			}
		}

		if (tcopy->topology != NULL && tcopy->count > 1U)
		{
			topology_sort_by_serial(tcopy->topology, tcopy->count);
		}
	}
}

void aern_topology_list_deserialize(aern_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;
	size_t rlen;

	if (list != NULL && input != NULL && inplen >= sizeof(uint32_t))
	{
		cnt = (size_t)qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);
		rlen = pos + (cnt * AERN_NETWORK_TOPOLOGY_NODE_SIZE);

		if (cnt <= AERN_NETWORK_TOPOLOGY_MAX_SIZE && rlen >= pos && rlen == inplen)
		{
			for (size_t i = 0U; i < cnt; ++i)
			{
				aern_topology_node_state node = { 0 };
				uint8_t* nptr;

				aern_topology_node_deserialize(&node, input + pos);
				nptr = aern_topology_child_add_empty_node(list);

				if (nptr != NULL)
				{
					aern_topology_node_serialize(nptr, &node);
				}

				pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
			}

			if (list->topology != NULL && list->count > 1U)
			{
				topology_sort_by_serial(list->topology, list->count);
			}

			if (list->version == 0U)
			{
				list->version = 1U;
			}
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
			if (list->count != 0U)
			{
				qsc_memutils_secure_erase(list->topology, list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
			}

			qsc_memutils_alloc_free(list->topology);
			list->topology = NULL;
			list->count = 0U;

			if (list->gmtx != NULL)
			{
				qsc_async_mutex_destroy(list->gmtx);
			}
		}

		list->version = 0U;
	}
}

void aern_topology_list_initialize(aern_topology_list_state* list)
{
	AERN_ASSERT(list != NULL);

	if (list != NULL)
	{
		list->count = 0U;
		list->topology = NULL;
		list->version = 1U;
		list->gmtx = qsc_async_mutex_create();
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

		nptr = (uint8_t*)(list->topology + (index * AERN_NETWORK_TOPOLOGY_NODE_SIZE));
		aern_topology_node_deserialize(node, nptr);
		res = true;
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

	ctr = 0U;

	if (list != NULL)
	{
		qsc_async_mutex_lock(list->gmtx);

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

		qsc_async_mutex_unlock(list->gmtx);
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

	if (list != NULL && input != NULL &&
		inplen >= AERN_NETWORK_TOPOLOGY_NODE_SIZE &&
		(inplen % AERN_NETWORK_TOPOLOGY_NODE_SIZE) == 0U)
	{
		pos = 0U;
		cnt = inplen / AERN_NETWORK_TOPOLOGY_NODE_SIZE;

		if (cnt <= AERN_NETWORK_TOPOLOGY_MAX_SIZE && list->count <= AERN_NETWORK_TOPOLOGY_MAX_SIZE - cnt)
		{
			for (size_t i = 0U; i < cnt; ++i)
			{
				aern_topology_node_state node = { 0 };
				uint8_t* nptr;

				aern_topology_node_deserialize(&node, input + pos);
				nptr = aern_topology_child_add_empty_node(list);

				if (nptr != NULL)
				{
					aern_topology_node_serialize(nptr, &node);
				}

				pos += AERN_NETWORK_TOPOLOGY_NODE_SIZE;
			}

			if (list->topology != NULL && list->count > 1U)
			{
				topology_sort_by_serial(list->topology, list->count);
			}

			if (list->version == 0U)
			{
				list->version = 1U;
			}
		}
		else
		{
			cnt = 0U;
		}
	}

	return cnt;
}

size_t aern_topology_ordered_server_list(aern_topology_list_state* olist, const aern_topology_list_state* tlist, aern_network_designations ntype)
{
	AERN_ASSERT(olist != NULL);
	AERN_ASSERT(tlist != NULL);

	aern_topology_node_state node;
	uint8_t* scratch;
	uint8_t* nptr;
	size_t dcnt;
	size_t i;
	size_t scnt;
	size_t slen;

	scratch = NULL;
	scnt = 0U;

	if (olist != NULL && tlist != NULL)
	{
		aern_topology_list_dispose(olist);
		aern_topology_list_initialize(olist);

		dcnt = aern_topology_list_server_count(tlist, ntype);

		if (dcnt > 0U && dcnt <= tlist->count)
		{
			slen = dcnt * AERN_NETWORK_TOPOLOGY_NODE_SIZE;

			if (slen / AERN_NETWORK_TOPOLOGY_NODE_SIZE == dcnt)
			{
				scratch = qsc_memutils_malloc(slen);
			}

			if (scratch != NULL)
			{
				qsc_memutils_clear(scratch, slen);

				for (i = 0U; i < tlist->count; ++i)
				{
					if (aern_topology_list_item(tlist, &node, i) == true &&
						(node.designation == ntype || ntype == aern_network_designation_all))
					{
						nptr = scratch + (scnt * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
						aern_topology_node_serialize(nptr, &node);
						++scnt;
					}
				}

				if (scnt > 1U)
				{
					topology_sort_by_serial(scratch, (uint32_t)scnt);
				}

				for (i = 0U; i < scnt; ++i)
				{
					nptr = scratch + (i * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
					aern_topology_node_deserialize(&node, nptr);
					aern_topology_child_add_item(olist, &node);
				}

				qsc_memutils_secure_erase(scratch, slen);
				qsc_memutils_alloc_free(scratch);
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
		qsc_memutils_secure_erase(node->issuer, AERN_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_secure_erase(node->address, AERN_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_secure_erase(node->chash, AERN_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_secure_erase(node->serial, AERN_CERTIFICATE_SERIAL_SIZE);
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

		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal((const uint8_t*)ntmp.address, (const uint8_t*)address, AERN_CERTIFICATE_ADDRESS_SIZE) == true)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}
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
		for (size_t i = 0U; i < list->count; ++i)
		{
			aern_topology_node_state ntmp = { 0 };

			if (aern_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == aern_network_designation_adc)
				{
					aern_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}
	}

	return res;
}

bool aern_topology_node_find_adc(const aern_topology_list_state* list, aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	aern_topology_node_state ntmp = { 0 };
	size_t pos;
	bool res;

	pos = 0U;
	res = false;

	if (list != NULL && node != NULL)
	{
		for (pos = 0U; pos < list->count; ++pos)
		{
			qsc_memutils_clear(&ntmp, sizeof(ntmp));

			if (aern_topology_list_item(list, &ntmp, pos) == true &&
				ntmp.designation == aern_network_designation_adc)
			{
				aern_topology_node_copy(&ntmp, node);
				res = true;
				break;
			}
		}
	}

	return res;
}

bool aern_topology_node_find_aps(const aern_topology_list_state* list, aern_topology_node_state* node)
{
	AERN_ASSERT(list != NULL);
	AERN_ASSERT(node != NULL);

	aern_topology_node_state ntmp = { 0 };
	size_t pos;
	bool res;

	pos = 0U;
	res = false;

	if (list != NULL && node != NULL)
	{
		for (pos = 0U; pos < list->count; ++pos)
		{
			qsc_memutils_clear(&ntmp, sizeof(ntmp));

			if (aern_topology_list_item(list, &ntmp, pos) == true &&
				ntmp.designation == aern_network_designation_aps)
			{
				aern_topology_node_copy(&ntmp, node);
				res = true;
				break;
			}
		}
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

				lpos = (int32_t)list->count - 1;

				for (int32_t i = npos; i < lpos; ++i)
				{
					qsc_memutils_copy(list->topology + ((size_t)i * AERN_NETWORK_TOPOLOGY_NODE_SIZE), list->topology + (((size_t)i + 1U) * AERN_NETWORK_TOPOLOGY_NODE_SIZE), AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				}

				qsc_memutils_secure_erase(list->topology + ((size_t)lpos * AERN_NETWORK_TOPOLOGY_NODE_SIZE), AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count -= 1U;

				if (list->count > 0U)
				{
					ttmp = qsc_memutils_realloc(list->topology, (size_t)list->count * AERN_NETWORK_TOPOLOGY_NODE_SIZE);
				}
				else
				{
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

bool aern_topology_node_verify_adc(const aern_topology_list_state* list, const aern_child_certificate* ccert)
{
	return aern_topology_node_verify_ads(list, ccert);
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

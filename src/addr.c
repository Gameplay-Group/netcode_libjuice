/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "addr.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef XLINK_SOCKADDR_IN __sockaddr_in;
typedef XLINK_SOCKADDR_IN6 __sockaddr_in6;




socklen_t addr_get_len(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(__sockaddr_in);
	case AF_INET6:
		return sizeof(__sockaddr_in6);
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return 0;
	}
}

uint16_t addr_get_port(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs(((__sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return ntohs(((__sockaddr_in6 *)sa)->sin6_port);
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return 0;
	}
}

int addr_set_port(struct sockaddr *sa, uint16_t port) {
	switch (sa->sa_family) {
	case AF_INET:
		((__sockaddr_in *)sa)->sin_port = htons(port);
		return 0;
	case AF_INET6:
		((__sockaddr_in6 *)sa)->sin6_port = htons(port);
		return 0;
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return -1;
	}
}

bool addr_is_any(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		const uint8_t *b = (const uint8_t *)&sin->sin_addr;
		for (int i = 0; i < 4; ++i)
			if (b[i] != 0)
				return false;

		return true;
	}
	case AF_INET6: {
		const __sockaddr_in6 *sin6 = (const __sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			const uint8_t *b = (const uint8_t *)&sin6->sin6_addr + 12;
			for (int i = 0; i < 4; ++i)
				if (b[i] != 0)
					return false;
		} else {
			const uint8_t *b = (const uint8_t *)&sin6->sin6_addr;
			for (int i = 0; i < 16; ++i)
				if (b[i] != 0)
					return false;
		}
		return true;
	}
	default:
		return false;
	}
}

bool addr_is_local(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		const uint8_t *b = (const uint8_t *)&sin->sin_addr;
		if (b[0] == 127) // loopback
			return true;
		if (b[0] == 169 && b[1] == 254) // link-local
			return true;
		return false;
	}
	case AF_INET6: {
		const __sockaddr_in6 *sin6 = (const __sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
			return true;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			return true;
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			const uint8_t *b = (const uint8_t *)&sin6->sin6_addr + 12;
			if (b[0] == 127) // loopback
				return true;
			if (b[0] == 169 && b[1] == 254) // link-local
				return true;
			return false;
		}
		return false;
	}
	default:
		return false;
	}
}

bool addr_unmap_inet6_v4mapped(struct sockaddr *sa, socklen_t *len) {
	if (sa->sa_family != AF_INET6)
		return false;

	const __sockaddr_in6 *sin6 = (const __sockaddr_in6 *)sa;
	if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return false;

	__sockaddr_in6 copy = *sin6;
	sin6 = &copy;

	__sockaddr_in *sin = (__sockaddr_in *)sa;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	memcpy(&sin->sin_addr, ((const uint8_t *)&sin6->sin6_addr) + 12, 4);
	*len = sizeof(*sin);
	return true;
}

bool addr_map_inet6_v4mapped(struct sockaddr_storage *ss, socklen_t *len) {
	if (ss->ss_family != AF_INET)
		return false;

	const __sockaddr_in *sin = (const __sockaddr_in *)ss;
	__sockaddr_in copy = *sin;
	sin = &copy;

	__sockaddr_in6 *sin6 = (__sockaddr_in6 *)ss;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	uint8_t *b = (uint8_t *)&sin6->sin6_addr;
	memset(b, 0, 10);
	memset(b + 10, 0xFF, 2);
	memcpy(b + 12, (const uint8_t *)&sin->sin_addr, 4);
	*len = sizeof(*sin6);
	return true;
}

bool addr_is_equal(const struct sockaddr *a, const struct sockaddr *b, bool compare_ports) {
	if (a->sa_family != b->sa_family)
		return false;

	switch (a->sa_family) {
	case AF_INET: {
		const __sockaddr_in *ain = (const __sockaddr_in *)a;
		const __sockaddr_in *bin = (const __sockaddr_in *)b;
		if (memcmp(&ain->sin_addr, &bin->sin_addr, 4) != 0)
			return false;
		if (compare_ports && ain->sin_port != bin->sin_port)
			return false;
		break;
	}
	case AF_INET6: {
		const __sockaddr_in6 *ain6 = (const __sockaddr_in6 *)a;
		const __sockaddr_in6 *bin6 = (const __sockaddr_in6 *)b;
		if (memcmp(&ain6->sin6_addr, &bin6->sin6_addr, 16) != 0)
			return false;
		if (compare_ports && ain6->sin6_port != bin6->sin6_port)
			return false;
		break;
	}
	default:
		return false;
	}

	return true;
}

#ifndef EAI_FAMILY
#define EAI_FAMILY -6
#endif
#ifndef EAI_NONAME
#define EAI_NONAME -2
#endif
#ifndef EAI_OVERFLOW
#define EAI_OVERFLOW -12
#endif
#ifndef EAI_MEMORY
#define EAI_MEMORY -10
#endif

// always safe: callers only ever hand this a binary sockaddr they already hold (a bound local address, or a candidate we already parsed), so there is no hostname to look up -- it only formats, it never resolves.
// return code is largely irrelevant -- just return 0 on success and nonzero on failure
int juice_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen,
                      char *serv, socklen_t servlen, int flags) {
	(void)salen;
	(void)flags;
	if (!sa)
		return EAI_FAMILY;

	if (serv && servlen > 0) {
		uint16_t port;
		switch (sa->sa_family) {
		case AF_INET:
			port = ntohs(((const __sockaddr_in *)sa)->sin_port);
			break;
		case AF_INET6:
			port = ntohs(((const __sockaddr_in6 *)sa)->sin6_port);
			break;
		default:
			return EAI_FAMILY;
		}
		int n = snprintf(serv, servlen, "%u", (unsigned)port);
		if (n < 0 || (socklen_t)n >= servlen)
			return EAI_OVERFLOW;
	}

	if (host && hostlen > 0) {
		char tmp[64];
		switch (sa->sa_family) {
		case AF_INET:
			if (!inet_ntop(AF_INET, &((const __sockaddr_in *)sa)->sin_addr, tmp, sizeof(tmp)))
				return EAI_OVERFLOW;
			break;
		case AF_INET6: {
			const __sockaddr_in6 *sin6 = (const __sockaddr_in6 *)sa;
			if (!inet_ntop(AF_INET6, &sin6->sin6_addr, tmp, sizeof(tmp)))
				return EAI_OVERFLOW;
			const uint8_t *b = (const uint8_t *)&sin6->sin6_addr;
			if (sin6->sin6_scope_id != 0 && b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
				size_t l = strlen(tmp);
				snprintf(tmp + l, sizeof(tmp) - l, "%%%u", (unsigned)sin6->sin6_scope_id);
			}
			break;
		}
		default:
			return EAI_FAMILY;
		}
		size_t need = strlen(tmp) + 1;
		if (need > (size_t)hostlen)
			return EAI_OVERFLOW;
		memcpy(host, tmp, need);
	}

	if ((!host || hostlen == 0) && (!serv || servlen == 0))
		return EAI_NONAME;

	return 0;
}

// Numeric-only getaddrinfo replacement: parses literal IPv4/IPv6 + numeric port, never does DNS, and returns a single calloc'd result for juice_freeaddrinfo.
// we ONLY need to return one result from here because we never do DNS lookup, so there can only be a single host name
// safe in production because nothing that needs a DNS lookup ever reaches it: local candidates are formatted from bound socket addresses (numeric), and remote candidates are resolved under AI_NUMERICHOST (ice_resolve_candidate / SIMPLE mode) 
// so a non-numeric one from a malicious or mDNS peer is rejected here exactly as the system resolver would reject it -- it is never silently looked up.
// the only input that could legitimately be a hostname is the STUN/TURN server (addr_resolve, no AI_NUMERICHOST), which we keep numeric by config (home server defaults to 127.0.0.1) 
// -- a DNS name configured there would fail to resolve rather than be looked up.
// return code is largely irrelevant -- just return 0 on success and nonzero on failure
int juice_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                      struct addrinfo **res) {
	if (!res)
		return EAI_NONAME;
	*res = NULL;

	int family = hints ? hints->ai_family : AF_UNSPEC;
	int socktype = hints ? hints->ai_socktype : 0;
	int protocol = hints ? hints->ai_protocol : 0;
	int flags = hints ? hints->ai_flags : 0;

	// Service must be a decimal port in [0,65535]; anything else (or a name) is rejected since we never consult /etc/services.
	uint16_t port = 0;
	if (service && *service) {
		char *end = NULL;
		unsigned long value = strtoul(service, &end, 10);
		if (end == service || *end != '\0' || value > 0xFFFFu)
			return EAI_NONAME;
		port = (uint16_t)value;
	}

	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t addrlen = 0;
	int resolved_family = AF_UNSPEC;

	if (node == NULL) {
		// No host: AI_PASSIVE wants the wildcard (left zeroed), otherwise loopback.
		int fam = (family == AF_INET6) ? AF_INET6 : AF_INET;
		// ipv4 case
		if (fam != AF_INET6) {
			__sockaddr_in *s4 = (__sockaddr_in *)&ss;
			s4->sin_family         = AF_INET;
			s4->sin_port           = htons(port);
			s4->sin_addr.s_addr    = (flags & AI_PASSIVE) ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);
			addrlen                = sizeof(*s4);
		} else {
			__sockaddr_in6 *s6 = (__sockaddr_in6 *)&ss;
			s6->sin6_family         = AF_INET6;
			s6->sin6_port           = htons(port);
			if (!(flags & AI_PASSIVE))
				((uint8_t *)&s6->sin6_addr)[15] = 1; // ::1
			addrlen = sizeof(*s6);
		}
		resolved_family = fam;
	} else {
		int ok = 0;
		// Try IPv4 first (unless the caller pinned AF_INET6).
		if (family == AF_INET || family == AF_UNSPEC) {
			__sockaddr_in *s4 = (__sockaddr_in *)&ss;
			if (inet_pton(AF_INET, node, &s4->sin_addr) == 1) {
				s4->sin_family  = AF_INET;
				s4->sin_port    = htons(port);
				addrlen         = sizeof( *s4 );
				resolved_family = AF_INET;
				ok              = 1;
			}
		}
		// IPV6 case -- much more of a pain in the ass
		if (!ok && (family == AF_INET6 || family == AF_UNSPEC)) {
			// Split off a "%scope" suffix (numeric only) before handing the address to inet_pton.
			char addrbuf[ADDR_MAX_NUMERICHOST_LEN];
			const char *addrpart = node;
			uint32_t scope = 0;
			const char *pct = strchr(node, '%');
			if (pct) {
				size_t n = (size_t)( pct - node );
				if ( n >= sizeof( addrbuf ) )
					return EAI_NONAME;
				memcpy(addrbuf, node, n);
				addrbuf[n]         = '\0';
				addrpart           = addrbuf;
				char*         send = NULL;
				unsigned long sv   = strtoul(pct + 1, &send, 10);
				if ( send == pct + 1 || *send != '\0' )
					return EAI_NONAME;
				scope = (uint32_t)sv;
			}
			__sockaddr_in6 *s6 = (__sockaddr_in6 *)&ss;
			if (inet_pton(AF_INET6, addrpart, &s6->sin6_addr) == 1) {
				s6->sin6_family   = AF_INET6;
				s6->sin6_port     = htons(port);
				s6->sin6_scope_id = scope;
				addrlen           = sizeof( *s6 );
				resolved_family   = AF_INET6;
				ok                = 1;
			}
		}
		if (!ok)
			return EAI_NONAME; // not a numeric literal, and we never fall back to DNS
	}

	// One block holds the addrinfo and its sockaddr so juice_freeaddrinfo can free the whole node with a single free().
	struct addrinfo *ai =
	    (struct addrinfo *)calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_storage));
	if (!ai)
		return EAI_MEMORY;
	struct sockaddr *sa = (struct sockaddr *)(ai + 1);
	memcpy(sa, &ss, (size_t)addrlen);
	ai->ai_flags = flags;
	ai->ai_family = resolved_family;
	ai->ai_socktype = socktype;
	ai->ai_protocol = protocol;
	ai->ai_addrlen = addrlen;
	ai->ai_addr = sa;
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;
	*res = ai;
	return 0;
}

// Frees the chain returned by juice_getaddrinfo; each node is a single allocation (sockaddr is embedded).
void juice_freeaddrinfo(struct addrinfo *res) {
	while (res) {
		struct addrinfo *next = res->ai_next;
		free(res);
		res = next;
	}
}

int addr_to_string(const struct sockaddr *sa, char *buffer, size_t size) {
	socklen_t salen = addr_get_len(sa);
	if (salen == 0)
		goto error;

	char host[ADDR_MAX_NUMERICHOST_LEN];
	char service[ADDR_MAX_NUMERICSERV_LEN];
	if (getnameinfo(sa, salen, host, ADDR_MAX_NUMERICHOST_LEN, service, ADDR_MAX_NUMERICSERV_LEN,
	                NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM)) {
		JLOG_ERROR("getnameinfo failed, errno=%d", sockerrno);
		goto error;
	}

	int len = snprintf(buffer, size, "%s:%s", host, service);
	if (len < 0 || (size_t)len >= size)
		goto error;

	return len;

error:
	// Make sure we still write a valid null-terminated string
	snprintf(buffer, size, "?");
	return -1;
}

// djb2 hash function
#define DJB2_INIT 5381
static void djb2(unsigned long *hash, int i) {
	*hash = ((*hash << 5) + *hash) + i; // hash * 33 + i
}

unsigned long addr_hash(const struct sockaddr *sa, bool with_port) {
	unsigned long hash = DJB2_INIT;

	djb2(&hash, sa->sa_family);
	switch (sa->sa_family) {
	case AF_INET: {
		const __sockaddr_in *sin = (const __sockaddr_in *)sa;
		const uint8_t *b = (const uint8_t *)&sin->sin_addr;
		for (int i = 0; i < 4; ++i)
			djb2(&hash, b[i]);
		if (with_port) {
			djb2(&hash, sin->sin_port >> 8);
			djb2(&hash, sin->sin_port & 0xFF);
		}
		break;
	}
	case AF_INET6: {
		const __sockaddr_in6 *sin6 = (const __sockaddr_in6 *)sa;
		const uint8_t *b = (const uint8_t *)&sin6->sin6_addr;
		for (int i = 0; i < 16; ++i)
			djb2(&hash, b[i]);
		if (with_port) {
			djb2(&hash, sin6->sin6_port >> 8);
			djb2(&hash, sin6->sin6_port & 0xFF);
		}
		break;
	}
	default:
		break;
	}

	return hash;
}


int addr_resolve(const char *hostname, const char *service, int socktype, addr_record_t *records,
                 size_t count) {
	addr_record_t *end = records + count;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_protocol = socktype == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
#ifdef AI_ADDRCONFIG
	hints.ai_flags = AI_ADDRCONFIG;
#endif
	struct addrinfo *ai_list = NULL;
	if (getaddrinfo(hostname, service, &hints, &ai_list)) {
		JLOG_WARN("Address resolution failed for %s:%s", hostname, service);
		return -1;
	}

	int ret = 0;
	for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
			++ret;
			if (records != end) {
				memcpy(&records->addr, ai->ai_addr, ai->ai_addrlen);
				records->len = (socklen_t)ai->ai_addrlen;
				records->socktype = socktype;
				++records;
			}
		}
	}

	freeaddrinfo(ai_list);
	return ret;
}

bool addr_is_numeric_hostname(const char *hostname) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	struct addrinfo *ai_list = NULL;
	if (getaddrinfo(hostname, "9", &hints, &ai_list))
		return false;

	freeaddrinfo(ai_list);
	return true;
}

bool addr_record_is_equal(const addr_record_t *a, const addr_record_t *b, bool compare_ports) {
	return addr_is_equal((const struct sockaddr *)&a->addr, (const struct sockaddr *)&b->addr,
	                     compare_ports) &&
	       a->socktype == b->socktype;
}

int addr_record_to_string(const addr_record_t *record, char *buffer, size_t size) {
	return addr_to_string((const struct sockaddr *)&record->addr, buffer, size);
}

unsigned long addr_record_hash(const addr_record_t *record, bool with_port) {
	return addr_hash((const struct sockaddr *)&record->addr, with_port) +
	       (record->socktype == SOCK_DGRAM ? 0 : 1);
}

#include "conn.h"
#include "agent.h"
#include "addr.h"
#include "udp.h"
#include "timestamp.h"
#include "thread.h"

#include "netcode.h"
#include "netcode_socket.h"
#include "ConnNetcode.h"

#include <stdlib.h>
#include <string.h>



typedef XLINK_SOCKADDR_IN __sockaddr_in;
typedef XLINK_SOCKADDR_IN6 __sockaddr_in6;

#define CONN_NETCODE_BUFFER_SIZE 4096
#define CONN_NETCODE_SOCKET_BUFFER (1024 * 1024)
#define CONN_NETCODE_MAX_LOCAL_ADDRS 4
#define CONN_NETCODE_RECV_BUDGET 1000
#define CONN_NETCODE_POLL_INTERVAL_SECONDS 0.001

typedef enum conn_netcode_state {
	CONN_NETCODE_NEW = 0,
	CONN_NETCODE_READY,
	CONN_NETCODE_FINISHED
} conn_netcode_state_t;

typedef struct conn_netcode_impl {
	conn_registry_t *registry;
	conn_netcode_state_t state;
	struct netcode_socket_t udp_sock;
	timestamp_t next_timestamp;
} conn_netcode_impl_t;

// Per-registry worker-thread state: the I/O thread handle and the flag that asks it to stop.
typedef struct conn_netcode_registry_impl {
	thread_t thread;
	atomic(int) stop;
} conn_netcode_registry_impl_t;

// Converts a libjuice sockaddr-based address into a netcode address for the socket layer, returning 0 for an address family we do not handle.
// called from main thread AND libjuice worker thread
static int addr_record_to_netcode(const addr_record_t *rec, struct netcode_address_t *out) {
	memset(out, 0, sizeof(*out));
    
    //union { uint8_t ipv4[4]; uint16_t ipv6[8]; } data;
    //uint16_t port;
    //uint8_t type;
    
	const struct sockaddr *sa = (const struct sockaddr *)&rec->addr;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)&rec->addr;
		out->type = NETCODE_ADDRESS_IPV4;
		memcpy(out->data.ipv4, &s->sin_addr, 4);
		out->port = ntohs(s->sin_port);
		return 1;
	}
	if (sa->sa_family == AF_INET6) {
		const __sockaddr_in6 *s = (const __sockaddr_in6 *)&rec->addr;
		const uint16_t *words = (const uint16_t *)&s->sin6_addr;
		out->type = NETCODE_ADDRESS_IPV6;
		for (int i = 0; i < 8; ++i)
			out->data.ipv6[i] = ntohs(words[i]);
		out->port = ntohs(s->sin6_port);
		return 1;
	}
	return 0;
}

// Converts a netcode address from the socket layer back into the libjuice sockaddr record the agent consumes, returning 0 for an unknown type.
// called from main thread AND libjuice worker thread
static int netcode_to_addr_record(const struct netcode_address_t *in, addr_record_t *rec) {
	memset(rec, 0, sizeof(*rec));
	rec->socktype = SOCK_DGRAM;
	if (in->type == NETCODE_ADDRESS_IPV4) {
		__sockaddr_in *s = (__sockaddr_in *)&rec->addr;
		s->sin_family = AF_INET;
		memcpy(&s->sin_addr, in->data.ipv4, 4);
		s->sin_port = htons(in->port);
		rec->len = sizeof(__sockaddr_in);
		return 1;
	}
	if (in->type == NETCODE_ADDRESS_IPV6) {
		__sockaddr_in6 *s = (__sockaddr_in6 *)&rec->addr;
		uint16_t *words = (uint16_t *)&s->sin6_addr;
		s->sin6_family = AF_INET6;
		for (int i = 0; i < 8; ++i)
			words[i] = htons(in->data.ipv6[i]);
		s->sin6_port = htons(in->port);
		rec->len = sizeof(__sockaddr_in6);
		return 1;
	}
	return 0;
}

// Services one agent (caller must hold registry->mutex): drains its socket up to a fairness budget feeding each datagram to the agent, then advances the agent timer when fresh input arrived or its deadline is due.
// called from libjuice worker thread
static void conn_netcode_service_agent(juice_agent_t *agent, conn_netcode_impl_t *impl) {
	char buffer[CONN_NETCODE_BUFFER_SIZE];
	struct netcode_address_t netcode_src;
	int received_any = 0;
	int budget = CONN_NETCODE_RECV_BUDGET;
	while (budget-- > 0) {
		int received = netcode_socket_receive_packet(&impl->udp_sock, &netcode_src, buffer,
		                                              CONN_NETCODE_BUFFER_SIZE);
		if (received <= 0)
			break;

		received_any = 1;

		addr_record_t juice_src;
		if (!netcode_to_addr_record(&netcode_src, &juice_src))
			continue;

		if (agent_conn_recv(agent, buffer, (size_t)received, &juice_src) != 0) {
			impl->state = CONN_NETCODE_FINISHED;
			return;
		}
	}

	if (impl->state == CONN_NETCODE_FINISHED)
		return;

	if (received_any || impl->next_timestamp <= current_timestamp()) {
		if (agent_conn_update(agent, &impl->next_timestamp) != 0)
			impl->state = CONN_NETCODE_FINISHED;
	}
}
// Runs until conn_netcode_registry_cleanup sets stop; each pass services every agent under registry->mutex, then yields for one poll interval.
// runs as the libjuice worker thread
static thread_return_t THREAD_CALL conn_netcode_thread_entry(void *arg) {
	thread_set_name_self("juice netcode");
	conn_registry_t *registry = (conn_registry_t *)arg;
	conn_netcode_registry_impl_t *rimpl = (conn_netcode_registry_impl_t *)registry->impl;

	while (!atomic_load(&rimpl->stop)) {
		mutex_lock(&registry->mutex);
		for (int i = 0; i < registry->agents_size; ++i) {
			juice_agent_t *agent = registry->agents[i];
			if (!agent)
				continue;

			conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
			if (!impl)
				continue;
			if (impl->state != CONN_NETCODE_NEW && impl->state != CONN_NETCODE_READY)
				continue;
			if (impl->state == CONN_NETCODE_NEW)
				impl->state = CONN_NETCODE_READY;

			conn_netcode_service_agent(agent, impl);
		}
		mutex_unlock(&registry->mutex);

		netcode_sleep(CONN_NETCODE_POLL_INTERVAL_SECONDS);
	}

	return (thread_return_t)0;
}

// Allocates the worker-thread state and starts the single I/O thread that drives every agent in this registry.
// called from main thread
int conn_netcode_registry_init(conn_registry_t *registry, udp_socket_config_t *config) {
	(void)config;
	conn_netcode_registry_impl_t *impl =
	    (conn_netcode_registry_impl_t *)calloc(1, sizeof(conn_netcode_registry_impl_t));
	if (!impl)
		return -1;
    
    // we ddon't have a proper interrupt socket for the worker thread, just an atomic
	atomic_store(&impl->stop, 0);
	registry->impl = impl;

	if (thread_init(&impl->thread, conn_netcode_thread_entry, registry)) {
		registry->impl = NULL;
		free(impl);
		return -1;
	}
	return 0;
}

// Signals the worker thread to stop and joins it before freeing its state, which is deadlock-free because release_registry has already dropped registry->mutex by the time this runs.
// called from main thread
void conn_netcode_registry_cleanup(conn_registry_t *registry) {
	conn_netcode_registry_impl_t *impl = (conn_netcode_registry_impl_t *)registry->impl;
	if (!impl)
		return;

	atomic_store(&impl->stop, 1);
	thread_join(impl->thread, NULL);
	free(impl);
	registry->impl = NULL;
}

static bool g_netcodeAllowRegistryRelease = false;

bool conn_netcode_can_release_registry(conn_registry_t *registry) {
	(void)registry;
	return g_netcodeAllowRegistryRelease;
}

void conn_netcode_release_registry(void) {
	g_netcodeAllowRegistryRelease = true;
	conn_release_registry(JUICE_CONCURRENCY_MODE_NETCODE);
	g_netcodeAllowRegistryRelease = false;
}

// Per-agent setup that allocates the connection state and opens its UDP socket through the netcode socket layer.
// Returns nonzero on failure so libjuice aborts creating the agent, and otherwise hands ownership of the state to agent->conn_impl.
// called from main thread
int conn_netcode_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)calloc(1, sizeof(conn_netcode_impl_t));
	if (!impl)
		return -1;

	struct netcode_address_t bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.type = NETCODE_ADDRESS_IPV4;
	bind_addr.port = config ? config->port_begin : 0;

	if (netcode_socket_create(&impl->udp_sock, &bind_addr, CONN_NETCODE_SOCKET_BUFFER,
	                          CONN_NETCODE_SOCKET_BUFFER) != NETCODE_SOCKET_ERROR_NONE) {
		free(impl);
		return -1;
	}

	impl->registry = registry;
	impl->state = CONN_NETCODE_NEW;
	impl->next_timestamp = current_timestamp();
	agent->conn_impl = impl;
	return 0;
}

// Per-agent teardown that closes the netcode socket and frees the connection state, mirroring conn_netcode_init.
// called from main thread
void conn_netcode_cleanup(juice_agent_t *agent) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (!impl)
		return;
    // no sendmutex needed -- we don't do differentiated services or TCP
	netcode_socket_destroy(&impl->udp_sock);
	free(impl);
	agent->conn_impl = NULL;
}

// Serializes main-thread juice API calls against the worker thread by taking the same registry->mutex the worker holds while servicing agents.
// called from main thread
void conn_netcode_lock(juice_agent_t *agent) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (impl && impl->registry)
		mutex_lock(&impl->registry->mutex);
}

// Releases the registry->mutex taken by conn_netcode_lock.
// called from main thread
void conn_netcode_unlock(juice_agent_t *agent) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (impl && impl->registry)
		mutex_unlock(&impl->registry->mutex);
}

// Pulls the agent's next service deadline forward to now, under the registry mutex, so the worker thread picks it up on its next poll iteration.
// called from main thread
int conn_netcode_interrupt(juice_agent_t *agent) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (!impl)
		return -1;
	if (impl->registry)
		mutex_lock(&impl->registry->mutex);
	impl->next_timestamp = current_timestamp();
	if (impl->registry)
		mutex_unlock(&impl->registry->mutex);
	return 0;
}

// Transmits exactly one datagram to dst by converting the address and handing the bytes to the netcode socket layer.
// Returns the byte count on success and -1 when dst is an address family the IPv4 socket cannot reach, which the agent treats as a tolerated dropped send.
// per udp_set_diffserv, DS has been broken on windows forever so we can't realistically use it anyway
// ... and according to my research, IP_TOS is usually broken on routers regardless 
// ... therefore, we just ignore the DS header 
// called from main thread AND libjuice worker thread
int conn_netcode_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                      int ds) {
	(void)ds;
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (!impl || size == 0)
		return (int)size;

	struct netcode_address_t to;
	if (!addr_record_to_netcode(dst, &to))
		return -1;

	netcode_socket_send_packet(&impl->udp_sock, &to, (void *)data, (int)size);
	return (int)size;
}

// Reports local host candidates so two peers on the same LAN (or the same machine behind one public IP) can connect directly instead of falling back to STUN hairpinning or a TURN relay.
// Desktop Windows defers to libjuice's udp_get_addrs against the netcode socket handle, which is a real winsock SOCKET that getsockname and WSAIoctl accept.
// Consoles ask netcode for the device's primary IP and stamp on this agent's bound port, because udp.c and its interface-enumeration syscalls are dropped from console builds
// called from main thread
int conn_netcode_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_netcode_impl_t *impl = (conn_netcode_impl_t *)agent->conn_impl;
	if (!impl)
		return -1;

#if XLINK_NETCODE_USE_UDP_GET_ADDRS
	return udp_get_addrs((socket_t)impl->udp_sock.handle, records, size);
#else
	struct netcode_address_t locals[CONN_NETCODE_MAX_LOCAL_ADDRS];
	int found = netcode_get_local_addresses(locals, CONN_NETCODE_MAX_LOCAL_ADDRS);
	int written = 0;
	for (int i = 0; i < found && (size_t)written < size; ++i) {
		locals[i].port = impl->udp_sock.address.port;
		if (netcode_to_addr_record(&locals[i], &records[written]))
			++written;
	}
	return written;
#endif
}

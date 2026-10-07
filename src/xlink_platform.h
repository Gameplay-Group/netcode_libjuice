#ifndef JUICE_XLINK_PLATFORM_H
#define JUICE_XLINK_PLATFORM_H

#if defined(__has_include)
#if __has_include("xlink_platform_netcode.h")
#include "xlink_platform_netcode.h"
#endif
#endif

#ifndef XLINK_PLATFORM_PS
#define XLINK_PLATFORM_PS 0
#endif

#ifndef XLINK_PLATFORM_SWITCH
#define XLINK_PLATFORM_SWITCH 0
#endif

#ifndef XLINK_SOCKADDR_IN
#define XLINK_SOCKADDR_IN struct sockaddr_in
#endif

#ifndef XLINK_SOCKADDR_IN6
#define XLINK_SOCKADDR_IN6 struct sockaddr_in6
#endif

#ifndef XLINK_THREAD_SET_NAME
#define XLINK_THREAD_SET_NAME(name) pthread_set_name_np(pthread_self(), name)
#endif

#ifndef XLINK_NETCODE_USE_UDP_GET_ADDRS
#if defined(_WIN32)
#define XLINK_NETCODE_USE_UDP_GET_ADDRS 1
#else
#define XLINK_NETCODE_USE_UDP_GET_ADDRS 0
#endif
#endif

#endif // JUICE_XLINK_PLATFORM_H

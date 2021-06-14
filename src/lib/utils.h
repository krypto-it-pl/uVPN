/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

int ipstr_to_sockaddr(const char * ip_str, unsigned short port, \
    struct sockaddr * addr, socklen_t * addrlen);

#endif

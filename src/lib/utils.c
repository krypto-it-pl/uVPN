/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "utils.h"
#include <sys/shm.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

int ipstr_to_sockaddr(const char * ip_str, unsigned short port, \
    struct sockaddr * addr, socklen_t * addrlen)
{
  struct in_addr ip_addr;

  if (inet_pton(AF_INET, ip_str, &ip_addr) == 1) {
    struct sockaddr_in * ip_sockaddr = (struct sockaddr_in *)addr;
    ip_sockaddr->sin_family = AF_INET;
    ip_sockaddr->sin_port = htons(port);
    memcpy(&ip_sockaddr->sin_addr, &ip_addr, sizeof(struct in_addr));
    
    *addrlen = sizeof(struct sockaddr_in);
    return 4;
  }

  struct in6_addr ip6_addr;
  if (inet_pton(AF_INET6, ip_str, &ip6_addr) == 1) {
    struct sockaddr_in6 * ip6_sockaddr = (struct sockaddr_in6 *)addr;
    memset(ip6_sockaddr, 0, sizeof(struct sockaddr_in6));

    ip6_sockaddr->sin6_family = AF_INET6;
    ip6_sockaddr->sin6_port = htons(port);
    memcpy(&ip6_sockaddr->sin6_addr, &ip6_addr, sizeof(struct in6_addr));

    *addrlen = sizeof(struct sockaddr_in6);
    return 6;
  }

  return 0;
}

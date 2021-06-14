/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "dns.h"
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int dns_iterate_by_hostname(const char * hostname, unsigned short port, \
    dns_iterator iterator, void * data)
{
  struct hostent *hostent_ptr = NULL;
  char ip_addr[64] = "";

  hostent_ptr = gethostbyname(hostname);
  if (!hostent_ptr)
    return -1;

  if (hostent_ptr->h_addr_list) {
    for (size_t i = 0; hostent_ptr->h_addr_list[i]; i++) {
      inet_ntop(hostent_ptr->h_addrtype, hostent_ptr->h_addr_list[i], ip_addr, \
          sizeof(ip_addr));
      if (iterator(ip_addr, port, data))
        return 1;
    }
  }

  return 0;
}

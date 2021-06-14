/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __TCP_H__
#define __TCP_H__

#include "global.h"
#include <queue.h>
#include <tcpc.h>

void tcp_init(struct tcp_conn_info * info, tcp_conn_t conn, conn_id_t conn_id, \
    const unsigned short keepalive[2], const char * name, unsigned int auth,
    const char * ipstr, unsigned short port, int cipher);
void tcp_done(struct tcp_conn_info * info);
void tcp_ping(struct tcp_conn_info * data, int flag);
void tcp_worker(struct tcp_conn_info * info, void * data, size_t data_size);

#endif

/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stddef.h>
#include <time.h>

#include "rsa.h"

struct static_servers_config_t
{
  char * name;
  char * connect_addr;
  unsigned short connect_port;
  char * public_key;
  unsigned short keepalive[2];
  unsigned char auto_connect;
  unsigned char allow_new_connect;
  unsigned short try_reconnect_sec;
  char * cipher;

  // non configurable part
  time_t last_reconnect_try;
};

struct config_t
{
  char * name;
  char * listen_addr;
  unsigned short listen_port;
  unsigned char crypto_workers;
  unsigned char checksum_workers;
  char * tap_name;
  char * private_key;
  char * servers_config;
  char * log_file;
  char * pid_file;
  unsigned short log_level;
  unsigned char forground;

  char * onTapCreate;
  char * onTcpListen;
  char * onClientConnect;
  char * onConnect;
  char * onClientConnectFail;
  char * onConnectFail;
  char * onConnectionEnd;

  // non configurable part
  size_t static_servers_count;
  struct static_servers_config_t * static_servers;
};

extern struct config_t * config;

int config_load(int argc, char * argv[]);
void config_done();

int parse_servers_file(const char * path, \
    struct static_servers_config_t ** config, size_t * sections);

struct RSA * load_rsakey(const char * path);

#endif

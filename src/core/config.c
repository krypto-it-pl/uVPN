/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iniparser.h>

struct config_t * config = NULL;

#define MAX_PARSE_STRING_BYTES 255

#define MAX_CONFIG_FILE_SIZE (1024 * 1024)

#define CONFIG_KEYWORD "config"

static int parser_string(const char * str, size_t length, unsigned int count, \
    void * result);
static int parser_ushort(const char * str, size_t length, unsigned int count, \
    void * result);
static int parser_uchar(const char * str, size_t length, unsigned int count, \
    void * result);
static int parser_uchar_bool(const char * str, size_t length, \
    unsigned int count, void * result);

struct config_args
{
  char * keyword;
  unsigned int params;
  int (*parser)(const char * str, size_t length, unsigned int count, \
      void * result);
  size_t result;
};

struct ini_pair
{
  size_t count;
  struct static_servers_config_t * sections;
};

struct config_args config_const[] =
{
  { "name", 1, parser_string, offsetof(struct config_t, name) },
  { "listen_addr", 1, parser_string, offsetof(struct config_t, listen_addr) },
  { "listen_port", 1, parser_ushort, offsetof(struct config_t, listen_port) },
  { "crypto_workers", 1, parser_uchar, \
      offsetof(struct config_t, crypto_workers) },
  { "checksum_workers", 1, parser_uchar, \
      offsetof(struct config_t, checksum_workers) },
  { "tap_name", 1, parser_string, offsetof(struct config_t, tap_name) },
  { "private_key", 1, parser_string, offsetof(struct config_t, private_key) },
  { "servers_config", 1, parser_string, \
      offsetof(struct config_t, servers_config) },
  { "log_file", 1, parser_string, offsetof(struct config_t, log_file) },
  { "pid_file", 1, parser_string, offsetof(struct config_t, pid_file) },
  { "log_level", 1, parser_ushort, offsetof(struct config_t, log_level) },
  { "forground", 1, parser_uchar_bool, offsetof(struct config_t, forground) },
  { "onTapCreate", 1, parser_string, offsetof(struct config_t, onTapCreate) },
  { "onTcpListen", 1, parser_string, offsetof(struct config_t, onTcpListen) },
  { "onClientConnect", 1, parser_string, offsetof(struct config_t,
      onClientConnect) },
  { "onConnect", 1, parser_string, offsetof(struct config_t, onConnect) },
  { "onClientConnectFail", 1, parser_string, offsetof(struct config_t,
      onClientConnectFail) },
  { "onConnectFail", 1, parser_string, offsetof(struct config_t,
      onConnectFail) },
  { "onConnectionEnd", 1, parser_string, offsetof(struct config_t,
      onConnectionEnd) },
};

struct config_args servers_ini[] = {
  { "connect_addr", 1, parser_string, \
      offsetof(struct static_servers_config_t, connect_addr) },
  { "connect_port", 1, parser_ushort, \
      offsetof(struct static_servers_config_t, connect_port) },
  { "public_key", 1, parser_string, \
      offsetof(struct static_servers_config_t, public_key) },
  { "keepalive", 2, parser_ushort, \
      offsetof(struct static_servers_config_t, keepalive) },
  { "auto_connect", 1, parser_uchar_bool, \
      offsetof(struct static_servers_config_t, auto_connect) },
  { "allow_new_connect", 1, parser_uchar_bool, \
      offsetof(struct static_servers_config_t, allow_new_connect) }, \
  { "try_reconnect_sec", 1, parser_ushort, \
      offsetof(struct static_servers_config_t, try_reconnect_sec) },
  { "cipher", 1, parser_string, \
      offsetof(struct static_servers_config_t, cipher) },
};

static int parse_args(int argc, char * argv[]);

static int parse_config_file(char * str, size_t str_len)
{
  char * ptr = str;
  char quote = 0;
  char * new_str = malloc(str_len + 1);
  char * new_ptr = new_str;
  size_t argc = 0;
  int next = 0;

  while (ptr < str + str_len) {
    if ((*ptr <= ' ') && (!quote) && (!next)) {
      ptr++;
      continue;
    }

    if (*ptr == '"') {
      if (!quote)
        quote = '"';
      else if (quote == '"')
        quote = 0;
    } else if (*ptr == '\'') {
      if (!quote)
        quote = '\'';
      else if (*ptr == '\'')
        quote = 0;
    } else if ((*ptr <= ' ') && (!quote)) {
      *new_ptr++ = 0;
      argc++;
      next = 0;
    } else if (*ptr >= ' ') {
      *new_ptr++ = *ptr++;
      next = 1;
    } else
      ptr++;
  }

  char ** argv = malloc(sizeof(char *) * argc);
  new_ptr = new_str;

  for (int i = 0; i < argc; i++) {
    argv[i] = new_ptr;
    new_ptr += strlen(new_ptr) + 1;
  }

  int r = parse_args(argc, argv);
  
  free(argv);
  free(new_str);

  return r;
}

static int config_from_file(char * path)
{
  char * file = malloc(MAX_CONFIG_FILE_SIZE);
  FILE * f = fopen(path, "r");
  if (!f)
    return 1;
  size_t size = fread(file, 1, MAX_CONFIG_FILE_SIZE - 1, f);
  fclose(f);
  file[size] = ' ';

  int r = parse_config_file(file, size + 1);

  free(file);
  return r;
}

static int parse_args(int argc, char * argv[])
{
  const int config_const_size = sizeof(config_const) / sizeof(config_const[0]);

  for (int i = 0; i < argc; i++) {
    int j;
    for (j = 0; j < config_const_size; j++)
      if (strcmp(argv[i], config_const[j].keyword) == 0)
        break;
    if (j == config_const_size) {
      if (strcmp(argv[i], CONFIG_KEYWORD) == 0) {
        if (i + 1 == argc) {
          fprintf(stderr, "Configuration error. " CONFIG_KEYWORD \
              " keyword needs parameter!\n");
          return 1;
        }
        i++;
        int r = config_from_file(argv[i]);
        if (r)
          return r;
      } else {
        fprintf(stderr, "Configuration error. Unknown keyword \"%s\"!\n", \
            argv[i]);
        return 1;
      }
    } else {
      if (i + config_const[j].params >= argc)
        return 1;
      for (int k = 0; k < config_const[j].params; k++) {
        char * ptr = (char *)config + config_const[j].result;
        int r = config_const[j].parser(argv[i + 1 + k], \
            strlen(argv[i + 1 + k]), 1, ptr);
        if (r)
          return r;
        i++;
      }
    }
  }

  return 0;
}

static void * resize(void * ptr, size_t size)
{
  if (!ptr)
    return malloc(size);
  return realloc(ptr, size);
}

static int next_section(const char * section_name, void * void_data)
{
  struct ini_pair * pair = (struct ini_pair *)void_data;
  pair->count++;
  pair->sections = resize(pair->sections, \
      sizeof(*pair->sections) * pair->count);
  memset(&pair->sections[pair->count - 1], 0, sizeof(*pair->sections));

  pair->sections[pair->count - 1].name = strdup(section_name);

  return 0;
}

static int next_value(const char * name, const char * value, void * void_data)
{
  struct ini_pair * pair = (struct ini_pair *)void_data;
  struct static_servers_config_t * section = &pair->sections[pair->count - 1];
  const size_t servers_ini_size = sizeof(servers_ini) / sizeof(servers_ini[0]);

  for (size_t i = 0; i < servers_ini_size; i++) {
    if (strcmp(name, servers_ini[i].keyword) == 0) {
      char * ptr = (char *)section + servers_ini[i].result;
      return servers_ini[i].parser(value, strlen(value), servers_ini[i].params,
          ptr);
    }
  }

  fprintf(stderr, "Unknown key \"%s\" in section \"%s\"\n", name, \
      section->name);
  return 1;
}

int parse_servers_file(const char * path, \
    struct static_servers_config_t ** config, size_t * sections)
{
  struct ini_pair pair = { 0, NULL };

  int r = iniparser(path, next_section, next_value, &pair);

  if (r) {
    for (size_t i = 0; i < *sections; i++) {
      free((*config)[i].name);
      free((*config)[i].connect_addr);
      free((*config)[i].public_key);
      free((*config)[i].cipher);
    }
    free(pair.sections);
    return r;
  }

  *config = pair.sections;
  *sections = pair.count;

  return 0;
}

int config_load(int argc, char * argv[])
{
  if (config)
    config_done();
  config = malloc(sizeof(struct config_t));
  memset(config, 0, sizeof(struct config_t));

  return parse_args(argc, argv);
}

void config_done()
{
  free(config->name);
  free(config->listen_addr);
  free(config->tap_name);
  free(config->private_key);
  free(config->servers_config);
  free(config->log_file);

  for (size_t i = 0; i < config->static_servers_count; i++) {
    free(config->static_servers[i].name);
    free(config->static_servers[i].connect_addr);
    free(config->static_servers[i].public_key);
  }

  free(config->static_servers);
  free(config);
}

static int parser_string(const char * str, size_t length, unsigned int count, \
    void * result)
{
  if (!length)
    return 1;

  char ** out = (char **)result;
  *out = malloc(length + 1);
  memcpy(*out, str, length);
  (*out)[length] = 0;

  return 0;
}

static int parser_ushort(const char * str, size_t length, unsigned int count, \
    void * result)
{
  const char * end = str;
  unsigned short * out = (unsigned short *)result;

  for (int i = 0; i < count; i++) {
    unsigned long x = strtoul(end, (char **)&end, 10);
    if (x > 0xFFFF)
      return 1;

    if (i + 1 < count) {
      while ((end < str + length) && (*end <= ' '))
        end++;

      if ((end == str + length) || (*end == 0))
        return 1;
    }

    out[i] = x;
  }
  
  if (end < str + length) {
    fprintf(stderr, "Configuration error. Too many values in:\n%s\n", str);
    return 1;
  }

  return 0;
}

static int parser_uchar(const char * str, size_t length, unsigned int count, \
    void * result)
{
  const char * end = str;
  unsigned char * out = (unsigned char *)result;

  for (int i = 0; i < count; i++) {
    unsigned long x = strtoul(end, (char **)&end, 10);
    if (x > 0xFF)
      return 1;

    if (i + 1 < count) {
      while ((end < str + length) && (*end <= ' '))
        end++;

      if ((end == str + length) || (*end == 0))
        return 1;
    }

    out[i] = x;
  }
  
  if (end < str + length)
    return 1;

  return 0;
}

static int parser_uchar_bool(const char * str, size_t length, \
    unsigned int count, void * result)
{
  unsigned char * out = (unsigned char *)result;
  if (strncmp(str, "yes", 3) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(str, "no", 2) == 0) {
    *out = 0;
    return 0;
  }
  if (strncmp(str, "on", 2) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(str, "off", 3) == 0) {
    *out = 0;
    return 0;
  }
  if (strncmp(str, "1", 1) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(str, "0", 1) == 0) {
    *out = 0;
    return 0;
  }

  return 1;
}

static struct RSA * parse_rsa_file(char * file)
{
  char * n_ptr = strstr(file, "n=[");
  if (!n_ptr)
    return NULL;
  n_ptr += 3;
  char * n_ptr2 = strchr(n_ptr, ']');
  if (!n_ptr2)
    return NULL;

  char * e_ptr = strstr(file, "e=[");
  if (!e_ptr)
    return NULL;
  e_ptr += 3;
  char * e_ptr2 = strchr(e_ptr, ']');
  if (!e_ptr2)
    return NULL;

  char * d_ptr = strstr(file, "d=["), * d_ptr2 = NULL;
  if (d_ptr) {
    d_ptr += 3;
    d_ptr2 = strchr(d_ptr, ']');
    if (!d_ptr2)
      return NULL;

    if ((n_ptr < d_ptr2) && (n_ptr > d_ptr))
    return NULL;

    if ((d_ptr < n_ptr2) && (d_ptr > n_ptr))
      return NULL;

    if ((e_ptr < d_ptr2) && (e_ptr > d_ptr))
    return NULL;

    if ((d_ptr < e_ptr2) && (d_ptr > e_ptr))
      return NULL;
  }

  if ((n_ptr < e_ptr2) && (n_ptr > e_ptr))
    return NULL;

  if ((e_ptr < n_ptr2) && (e_ptr > n_ptr))
    return NULL;

  *n_ptr2 = 0;
  *e_ptr2 = 0;

  if (d_ptr) {
    *d_ptr2 = 0;
    return rsa_private(n_ptr, d_ptr, e_ptr);
  }

  return rsa_public(n_ptr, e_ptr);
}

struct RSA * load_rsakey(const char * path)
{
  char * file = malloc(MAX_CONFIG_FILE_SIZE);
  FILE * f = fopen(path, "r");
  if (!f)
    return NULL;

  size_t size = fread(file, 1, MAX_CONFIG_FILE_SIZE - 1, f);
  fclose(f);

  file[size] = 0;
  struct RSA * r = parse_rsa_file(file);

  free(file);
  return r;
}

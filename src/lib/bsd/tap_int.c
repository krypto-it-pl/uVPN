/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap_int.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

int tap_create(char * dev)
{
  if (strncmp(dev, "tap", 3) != 0)
    return -1;

  char tundev[16];
  snprintf(tundev, sizeof(tundev), "/dev/%s", dev);

  return open(tundev, O_RDWR);
}

int tap_destroy(int tap)
{
  return close(tap);
}

int tap_read(int tap, void * buffer, unsigned int * buffer_size)
{
  ssize_t r = read(tap, buffer + 4, *buffer_size);
  if (r >= 0) {
    memset(buffer, 0, 4);
    *buffer_size = r + 4;
  }

  return r;
}

int tap_write(int tap, void * buffer, unsigned int buffer_size)
{
  int size = buffer_size - 4;
  return write(tap, buffer + 4, (size > 58) ? size : 58);
}

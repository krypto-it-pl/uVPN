/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap_int.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>

int tap_create(char * dev)
{
  struct ifreq ifr;
  int fd, err;
  const char * tundev = "/dev/net/tun";

  if ((fd = open(tundev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP;

  if (strlen(dev) >= sizeof(ifr.ifr_name)) {
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
  } else {
    strcpy(ifr.ifr_name, dev);
  }
  
  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    close(fd);
    return err;
  }

  return fd;
}

int tap_destroy(int tap)
{
  return ioctl(tap, TUNSETPERSIST, 0);
}

int tap_read(int tap, void * buffer, unsigned int * buffer_size)
{
  ssize_t r = read(tap, buffer, *buffer_size);
  if (r >= 0)
    *buffer_size = r;

  return r;
}

int tap_write(int tap, void * buffer, unsigned int buffer_size)
{
  return write(tap, buffer, buffer_size);
}

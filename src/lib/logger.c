/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "logger.h"

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define STRTIME_SIZE 32

static FILE * logfile = NULL;
static char * logfile_path = NULL;
static unsigned int logfile_level = 0;

int logger_init(const char * path, unsigned int log_level)
{
  logfile = fopen(path, "a");
  if (!logfile)
    return 1;

  logfile_path = strdup(path);
  logfile_level = log_level;

  return 0;
}

int logger_reopen(void)
{
  if (logfile_path)
    return 1;

  if (logfile)
    fclose(logfile);

  logfile = fopen(logfile_path, "a");

  if (logfile)
    return 0;
  return 1;
}

void logger_close(void)
{
  fclose(logfile);
  free(logfile_path);
  logfile_path = NULL;
  logfile = NULL;
}

void logger_printf(unsigned int log_level, const char * format, ...)
{
  if (log_level > logfile_level)
    return;

  char * log;
  char timestr[STRTIME_SIZE];
  va_list list;

  va_start(list, format);
  (void)vasprintf(&log, format, list);
  va_end(list);

  time_t now = time(NULL);
  struct tm now_tm;
  localtime_r(&now, &now_tm);
  strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", &now_tm);

  fprintf(logfile, "%s  %s\n", timestr, log);
  fflush(logfile);
  free(log);
}

#include "exec.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

void exec_with_env(const char * path, ...)
{
  if (!path)
    return;

  pid_t p = fork();
  if (p != 0)
    return;

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);

  va_list ap;
  va_start(ap, path);

  char * next = va_arg(ap, char *);
  char * env = NULL;
  size_t len = 0;
  size_t count = 1;

  while (next) {
    count++;
    if (!env) {
      env = strdup(next);
      len = strlen(next) + 1;
    } else {
      size_t oldlen = len;
      size_t nextlen = strlen(next) + 1;
      len += nextlen;
      env = realloc(env, len);
      memcpy(env + oldlen, next, nextlen);
    }

    next = va_arg(ap, char *);
  }

  char ** env_arg = malloc(sizeof(char *) * count);
  size_t pos = 0;

  for (size_t i = 0; i + 1 < count; i++) {
    env_arg[i] = &env[pos];
    pos += strlen(&env[pos]) + 1;
  }
  env_arg[count - 1] = NULL;

  char * null[1] = { NULL };

  execve(path, null, env_arg);

  free(env_arg);
  free(env);

  va_end(ap);

  exit(0);
}

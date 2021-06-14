/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "thpool.h"
#include <stdlib.h>
#include <stdatomic.h>
#include <semaphore.h>
#include "threads.h"

struct thpool_t
{
  sem_t wait_sem;
  atomic_uintptr_t ptr;
  volatile int end_now;
  thpool_func func;
  size_t threads_count;
  void * threads[];
};

static void thpool_thread(void * void_data)
{
  struct thpool_t * data = (struct thpool_t *)void_data;

  while (!data->end_now) {
    sem_wait(&data->wait_sem);

    void * next_data = (void *)atomic_exchange(&data->ptr, 0);

    if (!next_data)
      continue;

    data->func(next_data);
  }

  sem_post(&data->wait_sem);
}

struct thpool_t * thpool_create(size_t threads_count, thpool_func func)
{
  struct thpool_t * thpool = malloc(sizeof(*thpool) \
    + threads_count * sizeof(void *));

  sem_init(&thpool->wait_sem, 0, 0);

  atomic_store(&thpool->ptr, 0);

  thpool->ptr = 0;
  thpool->end_now = 0;
  thpool->func = func;
  thpool->threads_count = threads_count;
  for (size_t i = 0; i < threads_count; i++)
    thpool->threads[i] = thread_new(thpool_thread, thpool);

  return thpool;
}

void thpool_dispose(struct thpool_t * thpool)
{
  thpool->end_now = 1;
  sem_post(&thpool->wait_sem);

  for (size_t i = 0; i < thpool->threads_count; i++)
    thread_join(thpool->threads[i]);

  sem_destroy(&thpool->wait_sem);

  free(thpool);
}

void thpool_push(struct thpool_t * thpool, void * data)
{
  while (!thpool->end_now) {
    size_t except = 0;
    if (atomic_compare_exchange_strong(&thpool->ptr, &except, (size_t)data))
      break;
  }

  sem_post(&thpool->wait_sem);
}

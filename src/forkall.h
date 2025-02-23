#ifndef FORKALL_H
#define FORKALL_H

#include <pthread.h>
#include <sys/types.h>

void setup_register(void);
void parent(void);
void cleanup(void);
void cleanup_unregister(void);

#endif /* FORKALL_H */

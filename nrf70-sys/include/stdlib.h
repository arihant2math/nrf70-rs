#ifndef NRF70_MINIMAL_STDLIB_H
#define NRF70_MINIMAL_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void *calloc(size_t, size_t);
void free(void *);
#endif

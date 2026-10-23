#pragma once
#include <stdint.h>
#include <stddef.h>

/* Returns a bounded view into the FDT, never copies or changes its contents. */
const uint8_t *polaris_dt_prop(const void *blob, size_t available,
                             const char *path, const char *name, uint32_t *len);
int polaris_dt_matches(const void *blob, size_t available);

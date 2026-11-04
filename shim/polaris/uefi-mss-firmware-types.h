/* Structural identity only. Generated firmware bytes/bindings stay private. */
#ifndef POLARIS_UEFI_MSS_FIRMWARE_TYPES_H
#define POLARIS_UEFI_MSS_FIRMWARE_TYPES_H
#include <stdint.h>
struct pmsf_asset {uint32_t offset,bytes;uint8_t sha256[32];};
struct pmsf_segment {uint32_t index,target_offset,filesz,memsz,flags,alignment,asset;};
#endif

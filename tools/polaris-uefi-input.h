/* Bounded single-contact test channel between resident EFI and XNU.
 * Separate128-byte producer/consumer lines prevent cache-maintenance races.
 * No address, keycode, shell command or arbitrary memory access is accepted. */
#ifndef POLARIS_UEFI_INPUT_H
#define POLARIS_UEFI_INPUT_H
#include <stdint.h>
#define POLARIS_INPUT_READY UINT64_C(0x504f4c4152495349)
struct polaris_uefi_input_slot {
    volatile uint64_t request,x,y,down;
    uint8_t producer_padding[96];
    volatile uint64_t acknowledged,ready,error,events;
    uint8_t consumer_padding[96];
} __attribute__((aligned(128)));
struct polaris_uefi_input_status {uint32_t ready,request,acknowledged,error;};
static inline int polaris_uefi_input_valid(uint64_t down,uint64_t x,uint64_t y)
{return down<=1 && x<1080 && y<2160;}
_Static_assert(sizeof(struct polaris_uefi_input_slot)==256,"input mailbox ABI");
_Static_assert(__builtin_offsetof(struct polaris_uefi_input_slot,acknowledged)==128,"separate consumer cache lines");
#endif

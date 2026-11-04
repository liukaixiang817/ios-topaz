/* EDK2/virt probe for the same virtual BSS representation used by MSS.
 * No Qualcomm hardware, firmware services beyond console, or storage writes. */
#include "uefi.h"
#pragma clang section bss=".mssbss"
static volatile uint8_t storage[20u*1024u*1024u];
static volatile uint8_t*volatile relocated=storage;
efi_status EfiMain(efi_handle image,struct efi_system*system)
{
    (void)image;unsigned ok=relocated==storage;
    for(unsigned n=0;n<sizeof(storage);n++)if(storage[n])ok=0;
    for(unsigned n=0;n<sizeof(storage);n+=4096){storage[n]=(uint8_t)(n/4096+1);if(storage[n]!=(uint8_t)(n/4096+1))ok=0;}
    storage[sizeof(storage)-1]=0xa5;if(storage[sizeof(storage)-1]!=0xa5)ok=0;
    system->out->string(system->out,(const uint16_t*)(ok?L"MSS_VIRTUAL_BSS_PASS\r\n":L"MSS_VIRTUAL_BSS_FAIL\r\n"));
    return ok?0:EFI_ERROR;
}

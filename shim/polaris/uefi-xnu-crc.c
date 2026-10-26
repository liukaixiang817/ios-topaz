#include "uefi-xnu.h"
uint32_t polaris_efi_crc32(const uint8_t *data,uint64_t bytes)
{
    uint32_t crc=~0u;
    for(uint64_t i=0;i<bytes;i++){
        crc^=data[i];
        for(unsigned bit=0;bit<8;bit++)crc=(crc>>1)^(0xedb88320u&-(crc&1));
    }return ~crc;
}

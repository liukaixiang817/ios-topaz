/* Pure selector for the current MSS parent's eight own CmdDb resources.
 * Input must be a complete current128KiB capture. This is format/value
 * validation, not permission to read the database or submit an RPMh vote. */
#ifndef POLARIS_MSS_CMDDB_RESOURCES_H
#define POLARIS_MSS_CMDDB_RESOURCES_H
#include "polaris-wifi-firmware-identity.h"
#define PMDC_BYTES 0x20000u
#define PMDC_RESOURCES 8u
struct pmdc_resource {
    uint32_t entry,aux_offset,address,priority[2],length,version,minimum;
    uint8_t raw[24],aux[32];
};
static inline int pmdc_select(const uint8_t*b,struct pmdc_resource*out)
{
    static const char names[PMDC_RESOURCES][8]={"cx.lvl","mx.lvl","mss.lvl","ldoa5","ldoa7","ldoa17","ldoa25","xo.lvl"};
    static const uint32_t address[PMDC_RESOURCES]={0x30000,0x30010,0x30060,0x40f00,0x41300,0x40c00,0x42000,0x30080};
    unsigned found[PMDC_RESOURCES]={0};
    if(!b||!out||pwfi_le(b,4)!=1||pwfi_le(b+4,4)!=0x0c0330db)return 0;
    for(unsigned group=0;group<8;group++){
        const uint8_t*h=b+8+16*group;
        unsigned id=(unsigned)pwfi_le(h,2),off=(unsigned)pwfi_le(h+2,2),aux=(unsigned)pwfi_le(h+4,2),count=(unsigned)pwfi_le(h+6,2);
        if(!count)continue;
        if(id<3||id>5||count>512||off>PMDC_BYTES-144||count>(PMDC_BYTES-144-off)/24)return 0;
        for(unsigned n=0;n<count;n++){
            unsigned at=144+off+24*n;const uint8_t*e=b+at;
            for(unsigned k=0;k<PMDC_RESOURCES;k++)if(pgcd_equal(e,names[k],8)){
                struct pmdc_resource*r=&out[k];unsigned arc=k<3||k==7;
                if(++found[k]!=1||id!=(arc?3u:4u)||pwfi_le(e+16,4)!=address[k])return 0;
                r->entry=at;r->aux_offset=144+aux+(unsigned)pwfi_le(e+22,2);r->address=address[k];
                r->priority[0]=(uint32_t)pwfi_le(e+8,4);r->priority[1]=(uint32_t)pwfi_le(e+12,4);
                r->length=(uint32_t)pwfi_le(e+20,2);r->version=(uint32_t)pwfi_le(h+8,2);r->minimum=UINT32_MAX;
                pgcd_copy(r->raw,e,24);
                if(!arc){if(r->length||r->version||r->aux_offset>PMDC_BYTES)return 0;continue;}
                if(r->length!=32||r->aux_offset>PMDC_BYTES-32)return 0;pgcd_copy(r->aux,b+r->aux_offset,32);
                if(k==7){
                    static const unsigned levels[16]={0,32,80,128};
                    for(unsigned j=0;j<16;j++)if(pwfi_le(r->aux+2*j,2)!=levels[j])return 0;
                    r->minimum=3;
                }else{
                    unsigned ended=0,previous=0;
                    for(unsigned j=0;j<16;j++){
                        unsigned level=(unsigned)pwfi_le(r->aux+2*j,2);
                        if(j&&!level)ended=1;
                        if(ended){if(level)return 0;continue;}
                        if((!j&&level)||level<previous)return 0;previous=level;
                        if(level>=384&&r->minimum==UINT32_MAX)r->minimum=j;
                    }
                    if(!r->minimum||r->minimum>15)return 0;
                }
            }
        }
    }
    for(unsigned n=0;n<PMDC_RESOURCES;n++)if(found[n]!=1)return 0;return 1;
}
#endif

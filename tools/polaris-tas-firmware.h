/* Bounded, non-executing catalog of the original Polaris TAS2559 0x401 file.
 * Wire correspondence: own MiCode c7cb50c1 tas2559-core.c, blob e17bef78...
 * Independent implementation; no Linux driver code, allocation, I2C, MMIO,
 * DSP startup, register replay or calibration writes. Checksums are retained,
 * NOT authenticated or checked against a device. A parsed command span is NOT
 * permission to execute it. The caller must keep the input immutable/alive.
 */
#ifndef POLARIS_TAS_FIRMWARE_H
#define POLARIS_TAS_FIRMWARE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define PTF_FILE_LIMIT UINT32_C(0x400000)
#define PTF_ENTRY_LIMIT 256u
#define PTF_BLOCK_LIMIT 1024u
#define PTF_DESCRIPTION_LIMIT 4096u
enum { PTF_PLL=1, PTF_PROGRAM=2, PTF_CONFIG=3, PTF_CALIBRATION=4 };
struct polaris_tas_span { uint32_t offset,bytes; };
struct polaris_tas_block {
    uint32_t offset,type,commands;
    struct polaris_tas_span data;
    uint8_t p_present,p_checksum,y_present,y_checksum;
};
struct polaris_tas_entry {
    struct polaris_tas_span name,description,data_name,data_description;
    uint32_t kind,index,first_block,blocks,devices,program,pll,configuration,rate;
    uint32_t mode,boost,pll_source,pll_source_rate;
};
struct polaris_tas_catalog {
    uint32_t bytes,checksum,ppc_version,firmware_version,driver_version,timestamp;
    uint32_t plls,programs,configurations,calibrations,entry_count,block_count;
    struct polaris_tas_span name,description;
    struct polaris_tas_entry entries[PTF_ENTRY_LIMIT];
    struct polaris_tas_block blocks[PTF_BLOCK_LIMIT];
};
/* Caller-owned storage, never a native kernel stack object. Only the final
 * complete catalog is published to out; a refusal leaves out byte-identical. */
struct polaris_tas_workspace { struct polaris_tas_catalog candidate; };
struct ptf_cursor { const uint8_t *data;uint32_t size,at;bool failed; };
static inline const uint8_t *ptf_take(struct ptf_cursor *c,uint32_t n)
{
    if(c->failed||c->at>c->size||n>c->size-c->at){c->failed=true;return NULL;}
    const uint8_t *p=c->data+c->at;c->at+=n;return p;
}
static inline bool ptf_number(struct ptf_cursor *c,unsigned n,uint32_t *out)
{
    const uint8_t *p=ptf_take(c,n);if(!p)return false;
    uint32_t v=0;for(unsigned i=0;i<n;i++)v=(v<<8)|p[i];*out=v;return true;
}
static inline bool ptf_description(struct ptf_cursor *c,struct polaris_tas_span *out)
{
    uint32_t at=c->at;
    for(uint32_t i=0;i<=PTF_DESCRIPTION_LIMIT;i++) {
        const uint8_t *p=ptf_take(c,1);if(!p)return false;
        if(!*p){*out=(struct polaris_tas_span){at,i};return true;}
    }return false;
}
static inline bool ptf_named(struct ptf_cursor *c,struct polaris_tas_span *name,
    struct polaris_tas_span *description)
{
    *name=(struct polaris_tas_span){c->at,64};
    return ptf_take(c,64)&&ptf_description(c,description);
}
static inline bool ptf_block(struct ptf_cursor *c,struct polaris_tas_catalog *out)
{
    if(out->block_count==PTF_BLOCK_LIMIT)return false;
    struct polaris_tas_block *b=&out->blocks[out->block_count];b->offset=c->at;
    if(!ptf_number(c,4,&b->type))return false;
    const uint8_t *crc=ptf_take(c,4);if(!crc||crc[0]>1||crc[2]>1)return false;
    b->p_present=crc[0];b->p_checksum=crc[1];b->y_present=crc[2];b->y_checksum=crc[3];
    if(!ptf_number(c,4,&b->commands)||b->commands>(c->size-c->at)/4)return false;
    b->data=(struct polaris_tas_span){c->at,b->commands*4};
    if(!ptf_take(c,b->data.bytes))return false;
    out->block_count++;return true;
}
static inline bool ptf_data(struct ptf_cursor *c,struct polaris_tas_catalog *out,
    struct polaris_tas_entry *e)
{
    if(!ptf_named(c,&e->data_name,&e->data_description)||
       !ptf_number(c,2,&e->blocks)||e->blocks>PTF_BLOCK_LIMIT-out->block_count)return false;
    for(uint32_t i=0;i<e->blocks;i++)if(!ptf_block(c,out))return false;
    return true;
}
static inline bool ptf_entries(struct ptf_cursor *c,struct polaris_tas_catalog *out,
    unsigned kind,uint32_t *count)
{
    if(!ptf_number(c,2,count)||*count>PTF_ENTRY_LIMIT-out->entry_count)return false;
    for(uint32_t i=0;i<*count;i++) {
        struct polaris_tas_entry *e=&out->entries[out->entry_count++];
        e->kind=kind;e->index=i;e->first_block=out->block_count;
        if(!ptf_named(c,&e->name,&e->description))return false;
        if(kind==PTF_PLL) {
            e->blocks=1;if(!ptf_block(c,out))return false;
        } else {
            if(kind==PTF_PROGRAM) {
                if(!ptf_number(c,1,&e->mode)||!ptf_number(c,2,&e->boost))return false;
            } else if(kind==PTF_CONFIG) {
                if(!ptf_number(c,2,&e->devices)||!e->devices||e->devices>3||
                   !ptf_number(c,1,&e->program)||e->program>=out->programs||
                   !ptf_number(c,1,&e->pll)||e->pll>=out->plls||
                   !ptf_number(c,4,&e->rate)||!e->rate||
                   !ptf_number(c,1,&e->pll_source)||
                   !ptf_number(c,4,&e->pll_source_rate))return false;
            } else {
                if(!ptf_number(c,1,&e->program)||e->program>=out->programs||
                   !ptf_number(c,1,&e->configuration)||
                   e->configuration>=out->configurations)return false;
            }
            if(!ptf_data(c,out,e))return false;
        }
    }return true;
}
static inline bool ptf_overlap(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y||(x<y+bn&&y<x+an);
}
static inline bool polaris_tas_firmware_catalog(const void *data,size_t size,
    struct polaris_tas_catalog *out,struct polaris_tas_workspace *work)
{
    if(!data||!out||!work||size<104||size>PTF_FILE_LIMIT||
       ptf_overlap(data,size,out,sizeof(*out))||ptf_overlap(data,size,work,sizeof(*work))||
       ptf_overlap(out,sizeof(*out),work,sizeof(*work)))return false;
    struct polaris_tas_catalog *p=&work->candidate;
    uint8_t *zero=(uint8_t *)p;for(size_t i=0;i<sizeof(*p);i++)zero[i]=0;
    struct ptf_cursor c={(const uint8_t *)data,(uint32_t)size,0,false};
    const uint8_t *magic=ptf_take(&c,4);
    if(!magic||magic[0]!='5'||magic[1]!='5'||magic[2]!='5'||magic[3]!='2'||
       !ptf_number(&c,4,&p->bytes)||p->bytes!=size||
       !ptf_number(&c,4,&p->checksum)||!ptf_number(&c,4,&p->ppc_version)||
       !ptf_number(&c,4,&p->firmware_version)||!ptf_number(&c,4,&p->driver_version)||
       p->driver_version!=0x401||!ptf_number(&c,4,&p->timestamp)||
       !ptf_named(&c,&p->name,&p->description))return false;
    uint32_t family,device;
    if(!ptf_number(&c,4,&family)||family||!ptf_number(&c,4,&device)||device!=4||
       !ptf_entries(&c,p,PTF_PLL,&p->plls)||
       !ptf_entries(&c,p,PTF_PROGRAM,&p->programs)||
       !ptf_entries(&c,p,PTF_CONFIG,&p->configurations))return false;
    if(c.at!=c.size&&!ptf_entries(&c,p,PTF_CALIBRATION,&p->calibrations))return false;
    if(c.failed||c.at!=c.size)return false;
    *out=*p;return true;
}
#endif

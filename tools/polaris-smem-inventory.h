/* Read-only private/common SMEM metadata inventory, never an allocator.
 * Wire fields checked against MiCode c7cb50c1 msm_smem.c (1bbd7514...) and
 * smem_private.h. Independent implementation; no MMIO, pointers, writes,
 * lock acquisition, retry, DSP start or permission to use item contents.
 * Caller must first bind the original DT region and a safe read-only mapping.
 * Stable metadata is not evidence that a remote processor is running.
 */
#ifndef POLARIS_SMEM_INVENTORY_H
#define POLARIS_SMEM_INVENTORY_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define PSM_TABLE_BYTES 4096u
#define PSM_LEGACY_HEADER_BYTES 208u
#define PSM_LEGACY_BYTES (PSM_LEGACY_HEADER_BYTES + 512u * 16u)
#define PSM_HOST_COUNT 10u
#define PSM_MAX_PARTS ((PSM_TABLE_BYTES-32u)/48u)
struct polaris_smem_part {
    uint32_t index,offset,bytes,flags,cacheline,uncached_end,cached_begin;
    uint32_t exclusions[4];
    uint16_t host0,host1;
    /* APPS/common header was checked, not access or write authorization. */
    uint8_t accessible,reserved[3];
};
struct polaris_smem_inventory {
    uint32_t version,count,accessible_count,common_index;
    struct polaris_smem_part parts[PSM_MAX_PARTS];
};
/* Caller-owned workspace: do not put this on a native kernel stack. */
struct polaris_smem_workspace {
    uint8_t legacy[PSM_LEGACY_HEADER_BYTES],table[PSM_TABLE_BYTES],scratch[PSM_LEGACY_HEADER_BYTES];
    uint8_t part_headers[PSM_MAX_PARTS][32];
    struct polaris_smem_inventory candidate;
};
struct polaris_smem_reader {
    bool (*read)(void *,uint32_t,void *,size_t);
    void *context;
    uint32_t bytes;
};
static inline uint16_t psm_u16(const uint8_t *p)
{return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static inline uint32_t psm_u32(const uint8_t *p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline bool psm_equal(const uint8_t *a,const uint8_t *b,size_t n)
{for(size_t i=0;i<n;i++)if(a[i]!=b[i])return false;return true;}
static inline bool psm_read(const struct polaris_smem_reader *r,uint32_t offset,void *out,size_t n)
{
    return r&&r->read&&out&&n&&offset<=r->bytes&&n<=r->bytes-offset&&
        r->read(r->context,offset,out,n);
}
static inline bool polaris_smem_inventory(const struct polaris_smem_reader *r,
    struct polaris_smem_inventory *out,struct polaris_smem_workspace *work)
{
    if(!out||!r||!work||out==&work->candidate||r->bytes<16384||r->bytes>UINT32_C(0x10000000))return false;
    uint8_t *legacy=work->legacy,*table=work->table;
    if(!psm_read(r,0,legacy,PSM_LEGACY_HEADER_BYTES))return false;
    uint32_t version=psm_u32(legacy+64+7*4);
    if((version!=0xb0000&&version!=0xc0000)||psm_u32(legacy+192)!=1||psm_u32(legacy+204))return false;
    uint32_t toc=r->bytes-PSM_TABLE_BYTES;
    if(!psm_read(r,toc,table,PSM_TABLE_BYTES)||psm_u32(table)!=UINT32_C(0x434f5424)||psm_u32(table+4)!=1)return false;
    uint32_t count=psm_u32(table+8);
    if(!count||count>PSM_MAX_PARTS)return false;
    struct polaris_smem_inventory *inventory=&work->candidate;
    uint8_t *zero=(uint8_t *)inventory;
    for(size_t n=0;n<sizeof(*inventory);n++)zero[n]=0;
    inventory->version=version;inventory->count=count;inventory->common_index=UINT32_MAX;
    for(uint32_t i=0;i<count;i++) {
        const uint8_t *e=table+32+i*48;struct polaris_smem_part *p=&inventory->parts[i];
        p->index=i;p->offset=psm_u32(e);p->bytes=psm_u32(e+4);p->flags=psm_u32(e+8);
        p->host0=psm_u16(e+12);p->host1=psm_u16(e+14);p->cacheline=psm_u32(e+16);
        for(unsigned n=0;n<4;n++)p->exclusions[n]=psm_u32(e+32+n*4);
        if(!p->offset&&!p->bytes)continue; /* Empty TOC slot is not a partition. */
        if(p->offset<PSM_LEGACY_BYTES||!p->bytes||p->bytes<32||p->offset>toc||p->bytes>toc-p->offset)return false;
        for(uint32_t j=0;j<i;j++) {
            const struct polaris_smem_part *q=&inventory->parts[j];
            if(q->bytes&&p->offset<q->offset+q->bytes&&q->offset<p->offset+p->bytes)return false;
        }
        bool common=p->host0==0xfffe&&p->host1==0xfffe;
        if(!common&&p->host0&&p->host1)continue; /* Never inspect another host's header. */
        if(!p->cacheline||(p->cacheline&(p->cacheline-1))||p->cacheline<16||p->cacheline>4096)return false;
        if(common) {
            if(inventory->common_index!=UINT32_MAX)return false;
            inventory->common_index=i;
        } else {
            uint16_t remote=p->host0?p->host0:p->host1;
            if(!remote||remote>=PSM_HOST_COUNT)return false;
            for(uint32_t j=0;j<i;j++) {
                const struct polaris_smem_part *q=&inventory->parts[j];
                if(q->accessible&&((q->host0==p->host0&&q->host1==p->host1)||
                    (q->host0==p->host1&&q->host1==p->host0)))return false;
            }
        }
        uint8_t *header=work->part_headers[i];
        uint8_t header_after[32];
        if(!psm_read(r,p->offset,header,32)||psm_u32(header)!=UINT32_C(0x54525024)||
           psm_u16(header+4)!=p->host0||psm_u16(header+6)!=p->host1||psm_u32(header+8)!=p->bytes)return false;
        p->uncached_end=psm_u32(header+12);p->cached_begin=psm_u32(header+16);
        if(p->uncached_end<32||p->uncached_end>p->cached_begin||p->cached_begin>p->bytes)return false;
        if(!psm_read(r,p->offset,header_after,sizeof(header_after))||!psm_equal(header,header_after,32))return false;
        p->accessible=1;inventory->accessible_count++;
    }
    if(version==0xc0000&&inventory->common_index==UINT32_MAX)return false;
    /* Optimistic consistency only: this is not an atomic snapshot or a remote
     * lock. Reject changes observed across the entire inventory; callers may
     * not use these offsets to read item data or modify shared memory. */
    for(uint32_t at=0;at<PSM_TABLE_BYTES;) {
        uint32_t n=PSM_TABLE_BYTES-at;if(n>sizeof(work->scratch))n=sizeof(work->scratch);
        if(!psm_read(r,toc+at,work->scratch,n)||!psm_equal(table+at,work->scratch,n))return false;
        at+=n;
    }
    if(!psm_read(r,0,work->scratch,PSM_LEGACY_HEADER_BYTES)||!psm_equal(legacy,work->scratch,PSM_LEGACY_HEADER_BYTES))return false;
    for(uint32_t i=0;i<count;i++)if(inventory->parts[i].accessible) {
        if(!psm_read(r,inventory->parts[i].offset,work->scratch,32)||
           !psm_equal(work->part_headers[i],work->scratch,32))return false;
    }
    *out=*inventory;return true;
}
#endif

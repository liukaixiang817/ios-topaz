/* Read-only GLINK SMEM item inventory for Polaris. Independent implementation
 * checked against own MiCode c7cb50c1 msm_smem.c allocation/get-entry rules and
 * glink_smem_native_xprt.c items 478/479/480. The dipper-xnu transport was a
 * useful comparison, not authority for this phone's addresses or permissions.
 * Only fixed-size candidate allocation-header reads; no FIFO payload consumer,
 * allocator, FIFO index write, doorbell, lock, DSP or MMIO. Corrupt metadata can
 * mislabel bytes inside the bounded partition; this is not memory ownership.
 * Caller must bind a safely readable own-DT SMEM mapping first. Optimistic
 * metadata consistency is NOT a remote lock or permission to start transport.
 */
#ifndef POLARIS_GLINK_INVENTORY_H
#define POLARIS_GLINK_INVENTORY_H
#include "polaris-smem-inventory.h"
#define PGL_MAX_ITEMS 512u
#define PGL_MAX_HEADERS (2u * PGL_MAX_ITEMS)
struct polaris_glink_item { uint32_t offset,bytes,cached; };
struct polaris_glink_layout {
    uint32_t remote,partition,partition_bytes,headers;
    struct polaris_glink_item descriptor,tx,rx;
};
struct polaris_glink_witness { uint32_t offset;uint8_t bytes[16]; };
/* Caller-owned, not a native kernel stack allocation. */
struct polaris_glink_workspace {
    struct polaris_smem_workspace smem;
    struct polaris_smem_inventory inventory;
    struct polaris_glink_witness headers[PGL_MAX_HEADERS];
    uint8_t seen[2][PGL_MAX_ITEMS / 8];
    struct polaris_glink_item items[2][3];
    uint32_t count;
};
static inline bool pgl_headers(const struct polaris_smem_reader *r,
    const struct polaris_smem_part *p,struct polaris_glink_workspace *w,bool cached)
{
    uint32_t at=cached?p->bytes:32,end=cached?p->cached_begin:p->uncached_end;
    while(at!=end) {
        uint32_t header_bytes=cached?p->cacheline:16;
        if(w->count==PGL_MAX_HEADERS||
           (cached?(at<end||at-end<header_bytes):(at>end||end-at<16)))return false;
        uint32_t h=cached?at-header_bytes:at;
        struct polaris_glink_witness *record=&w->headers[w->count];
        record->offset=p->offset+h;
        if(!psm_read(r,record->offset,record->bytes,16))return false;
        const uint8_t *v=record->bytes;
        uint32_t id=psm_u16(v+2),size=psm_u32(v+4);
        uint32_t pad=psm_u16(v+8),header_pad=psm_u16(v+10);
        if(psm_u16(v)!=0xa5a5||id>=PGL_MAX_ITEMS||!size||
           (size&((cached?p->cacheline:8)-1))||pad>=size||
           pad>=(cached?p->cacheline:8)||header_pad!=header_bytes-16||
           (w->seen[cached][id/8]&(1u<<(id%8))))return false;
        uint32_t data,next;
        if(cached) {
            if(size>h||h-size<end)return false;
            data=h-size;next=data;
        } else {
            if(header_bytes>end-at||size>end-at-header_bytes)return false;
            data=at+header_bytes;next=data+size;
        }
        w->seen[cached][id/8]|=(uint8_t)(1u<<(id%8));w->count++;
        if(id>=478&&id<=480) {
            uint32_t n=(size-pad+7u)&~7u;
            if(!n||n>size)return false;
            w->items[cached][id-478]=(struct polaris_glink_item){p->offset+data,n,cached};
        }
        at=next;
    }
    return true;
}
static inline bool polaris_glink_inventory(const struct polaris_smem_reader *r,
    uint32_t remote,struct polaris_glink_layout *out,struct polaris_glink_workspace *w)
{
    if(!out||!w||!remote||remote>=PSM_HOST_COUNT||
       !polaris_smem_inventory(r,&w->inventory,&w->smem))return false;
    const struct polaris_smem_part *p=0;
    for(uint32_t i=0;i<w->inventory.count;i++) {
        const struct polaris_smem_part *q=&w->inventory.parts[i];
        if(q->accessible&&((!q->host0&&q->host1==remote)||(!q->host1&&q->host0==remote))) {
            if(p)return false;
            p=q;
        }
    }
    if(!p||p->flags||p->exclusions[0]||p->exclusions[1]||
       p->exclusions[2]||p->exclusions[3])return false; /* No unsupported layout. */
    for(unsigned k=0;k<2;k++) {
        for(unsigned n=0;n<sizeof(w->seen[k]);n++)w->seen[k][n]=0;
        for(unsigned n=0;n<3;n++)w->items[k][n]=(struct polaris_glink_item){0};
    }
    w->count=0;
    if(!pgl_headers(r,p,w,false)||!pgl_headers(r,p,w,true))return false;
    /* Own probe allocates descriptor and TX uncached. Only get_rx_fifo tries
     * cached first and then uncached; do not substitute a cached TX allocation
     * merely because the reference port's generic lookup can find one. */
    struct polaris_glink_layout candidate={remote,p->offset,p->bytes,w->count,
        w->items[0][0],w->items[0][1],
        w->items[w->items[1][2].bytes?1:0][2]};
    if(candidate.descriptor.bytes!=32||w->items[1][0].bytes)return false;
    const struct polaris_glink_item *items[3]={&candidate.descriptor,&candidate.tx,&candidate.rx};
    for(unsigned i=0;i<3;i++) {
        const struct polaris_glink_item *v=items[i];
        if(!v->bytes||(v->offset&7)||v->offset<p->offset+32||v->offset>p->offset+p->bytes||
           v->bytes>p->offset+p->bytes-v->offset||
           (i&&(v->bytes<64||v->bytes>0x200000||(v->bytes&7))))return false;
        for(unsigned j=0;j<i;j++)if(v->offset<items[j]->offset+items[j]->bytes&&
            items[j]->offset<v->offset+v->bytes)return false;
    }
    /* Exact re-read of every inspected allocation header, the chosen partition
     * header, legacy header and whole TOC. Never read item contents or publish
     * partial results when the remote changes allocation metadata. */
    uint8_t bytes[PSM_LEGACY_HEADER_BYTES];
    for(uint32_t n=0;n<w->count;n++)if(!psm_read(r,w->headers[n].offset,bytes,16)||
        !psm_equal(bytes,w->headers[n].bytes,16))return false;
    if(!psm_read(r,p->offset,bytes,32)||!psm_equal(bytes,w->smem.part_headers[p->index],32)||
       !psm_read(r,0,bytes,PSM_LEGACY_HEADER_BYTES)||
       !psm_equal(bytes,w->smem.legacy,PSM_LEGACY_HEADER_BYTES))return false;
    for(uint32_t at=0;at<PSM_TABLE_BYTES;) {
        uint32_t n=PSM_TABLE_BYTES-at;if(n>sizeof(bytes))n=sizeof(bytes);
        if(!psm_read(r,r->bytes-PSM_TABLE_BYTES+at,bytes,n)||
           !psm_equal(bytes,w->smem.table+at,n))return false;
        at+=n;
    }
    *out=candidate;return true;
}
#endif

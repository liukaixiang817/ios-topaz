/* Read-only own-NV input collection BEFORE the continuous native interval.
 * UEFI2.10 13.9 BlockIO/ReadBlocks and 10.3.5 HardDrive device-path ABI:
 * https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html
 * No write/reset/flush interface is callable here. Private generated plans
 * bind this phone's two GPTs; historical NV content is never an input. */
#ifndef POLARIS_UEFI_WIFI_NV_INPUTS_H
#define POLARIS_UEFI_WIFI_NV_INPUTS_H
#include "uefi.h"
#include "uefi-memory.h"
#include "../../tools/polaris-wifi-firmware-identity.h"
#define PNV_PARTS 4u
#define PNV_DISKS 2u
#define PNV_INPUT_BYTES 0x1840000u
#define PNV_SHADOW_BYTES 0x1c00000u
#define PNV_SCRATCH (PNV_INPUT_BYTES+PNV_SHADOW_BYTES)
#define PNV_BYTES (PNV_SCRATCH+65536u)
struct pnv_media {
    uint32_t id;uint8_t removable,present,logical,readonly,write_cached,pad[3];
    uint32_t block,align;uint64_t last;
};
struct pnv_block {
    uint64_t revision;struct pnv_media*media;void*reset;
    efi_status(*read)(struct pnv_block*,uint32_t,uint64_t,uint64_t,void*);
};
_Static_assert(offsetof(struct pnv_media,last)==24,"BlockIO Media.LastBlock");
_Static_assert(offsetof(struct pnv_block,read)==24,"BlockIO.ReadBlocks");
struct pnv_disk_plan {
    uint64_t blocks,table_lba[2];uint32_t table_bytes,reserved;
    uint8_t header_hash[2][32],table_hash[32];
};
struct pnv_part_plan {uint64_t start,blocks;uint32_t disk,number;uint8_t guid[16];};
struct pnv_plan {struct pnv_disk_plan disk[PNV_DISKS];struct pnv_part_plan part[PNV_PARTS];};
struct pnv_device {
    efi_handle handle;struct pnv_block*io;struct pnv_block protocol;struct pnv_media media;
    uint32_t matches,path_bytes;uint8_t path[4096];
};
struct pnv_result {
    struct pnv_plan plan;struct pnv_device part[PNV_PARTS],disk[PNV_DISKS];
    uint64_t boot,allocation,enumeration_status,release_status;
    uint64_t handles,handle_count,read_status,last_lba,last_bytes;
    uint32_t attempted,unknown,error,reads,returned,passes,complete,reserved;
    uint32_t selection_stage,selection_index;uint64_t selection_status;
    uint8_t hash[PNV_PARTS][32],digest[32];
};
static inline int pnv_equal(const void*a,const void*b,size_t n)
{for(size_t i=0;i<n;i++)if(((const uint8_t*)a)[i]!=((const uint8_t*)b)[i])return 0;return 1;}
static inline void pnv_copy(void*a,const void*b,size_t n)
{for(size_t i=0;i<n;i++)((uint8_t*)a)[i]=((const uint8_t*)b)[i];}
static inline void pnv_hash(const void*data,size_t n,uint8_t hash[32])
{struct pwfi_sha256 h;pwfi_init(&h);for(size_t i=0;i<n;i++)pwfi_byte(&h,((const uint8_t*)data)[i]);pwfi_final(&h,hash);}
static inline int pnv_zero(const void*p,size_t n)
{for(size_t i=0;i<n;i++)if(((const uint8_t*)p)[i])return 0;return 1;}
static inline int pnv_fail(struct pnv_result*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline uint32_t pnv_part_bytes(unsigned part){return part==3?0x40000:0x800000;}
static inline uint32_t pnv_part_offset(unsigned part){return part*0x800000;}
static inline int pnv_plan_valid(const struct pnv_plan*p)
{
    if(!p)return 0;
    for(unsigned n=0;n<PNV_DISKS;n++){
        const struct pnv_disk_plan*d=&p->disk[n];
        if(d->blocks<8||d->blocks>UINT64_MAX/4096||!d->table_bytes||d->table_bytes>65536||(d->table_bytes&4095)||d->reserved)return 0;
        for(unsigned j=0;j<2;j++)if(d->table_lba[j]<2||d->table_lba[j]>=d->blocks-1||d->table_bytes/4096>d->blocks-1-d->table_lba[j])return 0;
    }
    for(unsigned n=0;n<PNV_PARTS;n++){
        const struct pnv_part_plan*q=&p->part[n];if(q->disk>=PNV_DISKS||!q->number||q->number>512||!q->start||q->blocks!=pnv_part_bytes(n)/4096||pnv_zero(q->guid,16))return 0;
        const struct pnv_disk_plan*d=&p->disk[q->disk];if(q->start>=d->blocks-1||q->blocks>d->blocks-1-q->start)return 0;
        for(unsigned j=0;j<n;j++)if(pnv_equal(q->guid,p->part[j].guid,16)||(q->disk==p->part[j].disk&&q->start<p->part[j].start+p->part[j].blocks&&p->part[j].start<q->start+q->blocks))return 0;
    }return 1;
}
static inline int pnv_media_valid(const struct pnv_block*b,uint64_t blocks,unsigned logical)
{
    if(!b||!b->media||!b->read||(b->revision!=0x10000&&b->revision!=0x20001&&b->revision!=0x2001f))return 0;
    const struct pnv_media*m=b->media;return !m->removable&&m->present==1&&m->logical==logical&&m->block==4096&&
        m->last==blocks-1&&(m->align<=1||(m->align<=4096&&!(m->align&(m->align-1))));
}
static inline unsigned pnv_path(const uint8_t*path,const struct pnv_part_plan*p)
{
    unsigned at=0,found=0;
    while(at<=4092){
        unsigned bytes=path[at+2]|(unsigned)path[at+3]<<8;if(bytes<4||bytes>4096-at)return 0;
        if(path[at]==0x7f)return path[at+1]==0xff&&bytes==4&&found==1?at+4:0;
        if(path[at]==4&&path[at+1]==1){
            if(bytes!=42||++found!=1||path[at+40]!=2||path[at+41]!=2||pwfi_le(path+at+4,4)!=p->number||
               pwfi_le(path+at+8,8)!=p->start||pwfi_le(path+at+16,8)!=p->blocks||!pnv_equal(path+at+24,p->guid,16))return 0;
        }at+=bytes;
    }return 0;
}
/* Return the prefix ending just before the single terminal GPT HD node. */
static inline unsigned pnv_parent_bytes(const uint8_t*p,unsigned bytes)
{
    unsigned at=0;while(at+4<=bytes){unsigned n=p[at+2]|(unsigned)p[at+3]<<8;if(n<4||n>bytes-at)return 0;
        if(p[at]==4&&p[at+1]==1)return n==42&&at+n+4==bytes?at:0;at+=n;
    }return 0;
}
static inline int pnv_read(struct pnv_result*r,struct pnv_device*d,uint64_t lba,unsigned bytes,void*out)
{
    uint64_t address=(uintptr_t)out;
    if(address<r->allocation||address-r->allocation>PNV_BYTES||bytes>PNV_BYTES-(address-r->allocation)||
       (address<r->allocation+PNV_SCRATCH&&address+bytes>r->allocation+PNV_INPUT_BYTES))return pnv_fail(r,5);
    if(r->unknown||r->error||!d->io||!pnv_equal(d->io,&d->protocol,sizeof(d->protocol))||!bytes||(bytes&4095)||bytes>65536||((uintptr_t)out&4095)||
       lba>d->media.last||bytes/4096-1>d->media.last-lba||!pnv_equal(d->io->media,&d->media,sizeof(d->media)))return pnv_fail(r,5);
    if(r->reads==4096)return pnv_fail(r,5);r->last_lba=lba;r->last_bytes=bytes;r->reads++;
    r->read_status=d->io->read(d->io,d->media.id,lba,bytes,out);
    if(r->read_status||!pnv_equal(d->io,&d->protocol,sizeof(d->protocol))||!pnv_equal(d->io->media,&d->media,sizeof(d->media)))return pnv_fail(r,5);r->returned++;return 1;
}
/* Whole current GPT copies must match the independently verified private
 * plan. This checks current data, not cached firmware partition metadata. */
static inline int pnv_gpt(struct pnv_result*r)
{
    uint8_t*scratch=(void*)(uintptr_t)(r->allocation+PNV_SCRATCH);uint8_t hash[32];
    for(unsigned n=0;n<PNV_DISKS;n++){
        const struct pnv_disk_plan*p=&r->plan.disk[n];struct pnv_device*d=&r->disk[n];
        for(unsigned side=0;side<2;side++){
            if(!pnv_read(r,d,side?p->blocks-1:1,4096,scratch))return 0;pnv_hash(scratch,4096,hash);
            if(!pnv_equal(hash,p->header_hash[side],32)||!pnv_read(r,d,p->table_lba[side],p->table_bytes,scratch))return pnv_fail(r,6);
            pnv_hash(scratch,p->table_bytes,hash);if(!pnv_equal(hash,p->table_hash,32))return pnv_fail(r,6);
        }
    }return 1;
}
/* Caller supplies its freshly allocated independent RAM claim. This collector
 * does not claim allocation ownership from a memory type or an integer PA.
 * The native parent must prove/retain all PNV_BYTES and keep its image, bank,
 * other allocations and result outside this range before calling. */
static inline int pnv_collect(struct efi_boot*bs,const struct pnv_plan*plan,uint64_t allocation,struct pnv_result*r)
{
    static const efi_guid bg={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
    static const efi_guid dg={0x9576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
    if(!bs||!bs->locate_buffer||!bs->handle_protocol||!bs->free_pool||!pnv_plan_valid(plan)||!r||!pnv_zero(r,sizeof(*r))||
       !allocation||(allocation&4095)||allocation>UINT64_MAX-PNV_BYTES)return 0;
    if((uintptr_t)r<allocation+PNV_BYTES&&allocation<(uintptr_t)r+sizeof(*r))return 0;
    r->plan=*plan;r->boot=(uintptr_t)bs;r->allocation=allocation;r->attempted=1;
    efi_handle*handles=0;r->enumeration_status=bs->locate_buffer(2,&bg,0,&r->handle_count,&handles);r->handles=(uintptr_t)handles;
    if(r->enumeration_status||!handles||!r->handle_count||r->handle_count>256){if(handles)r->release_status=bs->free_pool(handles);return pnv_fail(r,1);}
    for(unsigned i=0;i<r->handle_count;i++){
        const uint8_t*path=0;if(bs->handle_protocol(handles[i],&dg,(void**)&path)||!path)continue;
        for(unsigned n=0;n<PNV_PARTS;n++){
            const struct pnv_part_plan*p=&r->plan.part[n];unsigned bytes=pnv_path(path,p);if(!bytes)continue;
            struct pnv_device*d=&r->part[n];d->matches++;d->handle=handles[i];d->path_bytes=bytes;pnv_copy(d->path,path,bytes);
        }
    }
    /* Cached selection diagnostics: 1..5 partition match/protocol/media/prefix/parent,
     * 6..9 disk path/match/protocol/media, 10 distinct disks, 11 selected.
     * No new service calls or relaxed acceptance conditions. */
    for(unsigned n=0;n<PNV_PARTS;n++){
        struct pnv_device*d=&r->part[n];r->selection_index=n;r->selection_stage=1;
        if(d->matches!=1)goto fail;
        r->selection_stage=2;r->selection_status=bs->handle_protocol(d->handle,&bg,(void**)&d->io);
        if(r->selection_status)goto fail;
        r->selection_stage=3;
        if(d->io){d->protocol=*d->io;if(d->io->media)d->media=*d->io->media;}
        if(!pnv_media_valid(d->io,r->plan.part[n].blocks,1))goto fail;
        r->selection_stage=4;unsigned prefix=pnv_parent_bytes(d->path,d->path_bytes);
        if(!prefix||pwfi_le(d->path+prefix+4,4)!=r->plan.part[n].number)goto fail;
        struct pnv_device*parent=&r->disk[r->plan.part[n].disk];
        r->selection_stage=5;
        if(parent->path_bytes){if(parent->path_bytes!=prefix+4||!pnv_equal(parent->path,d->path,prefix))goto fail;continue;}
        parent->path_bytes=prefix+4;pnv_copy(parent->path,d->path,prefix);parent->path[prefix]=0x7f;parent->path[prefix+1]=0xff;parent->path[prefix+2]=4;
    }
    for(unsigned n=0;n<PNV_DISKS;n++){
        struct pnv_device*d=&r->disk[n];r->selection_index=n;r->selection_stage=6;if(!d->path_bytes)goto fail;
        for(unsigned i=0;i<r->handle_count;i++){
            const uint8_t*path=0;if(bs->handle_protocol(handles[i],&dg,(void**)&path)||!path)continue;
            /* Compare node-by-node so a short returned path is never read past
             * its end merely because the expected prefix is longer. */
            unsigned at=0,match=1;
            while(at<d->path_bytes){unsigned bytes=path[at+2]|(unsigned)path[at+3]<<8;
                if(bytes<4||bytes>d->path_bytes-at||!pnv_equal(path+at,d->path+at,bytes)){match=0;break;}at+=bytes;}
            if(match&&at==d->path_bytes){d->matches++;d->handle=handles[i];}
        }
        r->selection_stage=7;if(d->matches!=1)goto fail;
        r->selection_stage=8;r->selection_status=bs->handle_protocol(d->handle,&bg,(void**)&d->io);
        if(r->selection_status)goto fail;
        r->selection_stage=9;
        if(d->io){d->protocol=*d->io;if(d->io->media)d->media=*d->io->media;}
        if(!pnv_media_valid(d->io,r->plan.disk[n].blocks,0))goto fail;
    }
    r->selection_stage=10;r->selection_index=0;
    if(r->disk[0].handle==r->disk[1].handle)goto fail;
    r->selection_stage=11;
    r->release_status=bs->free_pool(handles);handles=0;if(r->release_status)return pnv_fail(r,3);
    if(!pnv_gpt(r))return 0;
    for(unsigned pass=0;pass<2;pass++){
        for(unsigned n=0;n<PNV_PARTS;n++){
            struct pwfi_sha256 h;pwfi_init(&h);uint8_t hash[32];
            for(unsigned at=0;at<pnv_part_bytes(n);at+=65536){
                unsigned bytes=pnv_part_bytes(n)-at;if(bytes>65536)bytes=65536;
                uint8_t*out=(void*)(uintptr_t)(allocation+(pass?PNV_SCRATCH:pnv_part_offset(n)+at));
                if(!pnv_read(r,&r->part[n],at/4096,bytes,out))return 0;
                for(unsigned j=0;j<bytes;j++)pwfi_byte(&h,out[j]);
            }
            pwfi_final(&h,hash);if(pass){if(!pnv_equal(hash,r->hash[n],32))return pnv_fail(r,7);}else pnv_copy(r->hash[n],hash,32);
        }
        r->passes++;if(!pnv_gpt(r))return 0;
    }
    if(!pnv_equal(plan,&r->plan,sizeof(*plan)))return pnv_fail(r,8);
    r->complete=1;pnv_hash(r,offsetof(struct pnv_result,digest),r->digest);return 1;
fail:
    r->release_status=bs->free_pool(handles);return pnv_fail(r,2);
}
#endif

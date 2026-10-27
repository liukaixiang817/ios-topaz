/* Bounded ext4 ownership admission for a NEW pinned runtime file.
 * This header performs reads only. It is not connected to the phone's UFS
 * write path. Integration additionally requires exclusive controller ownership
 * and kernel filesystem quiesce/flush/shutdown proof before reset.
 * Packet metadata must come from a fresh read-only export of the owned file.
 */
#ifndef POLARIS_RUNTIME_OWNER_H
#define POLARIS_RUNTIME_OWNER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define POLARIS_OWNER_NODES 64u
#define POLARIS_OWNER_MAPS 4096u
#define POLARIS_OWNER_HEADER 384u
#define POLARIS_OWNER_BLOCK 4096u
#define POLARIS_OWNER_FLAGS 0x80090u
#define POLARIS_OWNER_INCOMPAT (0x10042u|0x80u|0x200u|0x2000u)
#define POLARIS_OWNER_RO_REFUSED (0x200u|0x1000u|0x4000u|0x10000u)
struct polaris_owner_extent {uint64_t logical,physical,blocks;};
struct polaris_owner_work {
    /* Caller-owned heap/static storage, never a small kernel stack. */
    uint8_t buffers[7][4096];
    struct polaris_owner_extent map[POLARIS_OWNER_MAPS];
    uint64_t partition_start,partition_blocks,file_blocks,seen,error_lba;
    unsigned map_count,map_used,node_count,error;
    uint32_t checksum_seed,file_checksum_seed;
    bool metadata_checksum,metadata_verified,admitted;
};
typedef bool (*polaris_owner_read)(void *,uint64_t,uint8_t *);
static inline uint16_t po16(const uint8_t *p)
{return (uint16_t)p[0]|(uint16_t)p[1]<<8;}
static inline uint32_t po32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static inline uint64_t po64(const uint8_t *p)
{return (uint64_t)po32(p)|(uint64_t)po32(p+4)<<32;}
/* Independent bitwise implementations; ext4 checksum layouts checked against
 * e2fsprogs1.47.4 lib/ext2fs/csum.c. No table/source code copied from it. */
static inline uint32_t po_crc32c(uint32_t seed,const uint8_t *p,unsigned bytes)
{
    for(unsigned i=0;i<bytes;i++){
        seed^=p[i];for(unsigned bit=0;bit<8;bit++)seed=(seed>>1)^((seed&1)?0x82f63b78u:0);
    }return seed;
}
static inline uint16_t po_crc16(uint16_t seed,const uint8_t *p,unsigned bytes)
{
    for(unsigned i=0;i<bytes;i++){
        seed^=p[i];for(unsigned bit=0;bit<8;bit++)seed=(uint16_t)((seed>>1)^((seed&1)?0xa001u:0));
    }return seed;
}
static inline uint32_t po_number_crc(uint32_t seed,uint32_t number)
{uint8_t b[4];for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(number>>(i*8));return po_crc32c(seed,b,4);}
static inline uint16_t po_group_checksum(const uint8_t *desc,unsigned bytes,unsigned group,
    const uint8_t *uuid,bool metadata,uint32_t seed)
{
    uint8_t number[4];for(unsigned i=0;i<4;i++)number[i]=(uint8_t)(group>>(i*8));
    if(metadata){
        uint32_t crc=po_crc32c(seed,number,4);
        for(unsigned i=0;i<bytes;i++){uint8_t b=(i==30||i==31)?0:desc[i];crc=po_crc32c(crc,&b,1);}
        return (uint16_t)crc;
    }
    uint16_t crc=po_crc16(po_crc16(UINT16_MAX,uuid,16),number,4);
    crc=po_crc16(crc,desc,30);return po_crc16(crc,desc+32,bytes-32);
}
static inline bool po_equal(const uint8_t *a,const uint8_t *b,unsigned n)
{for(unsigned i=0;i<n;i++)if(a[i]!=b[i])return false;return true;}
static inline bool po_fail(struct polaris_owner_work *w,unsigned error,uint64_t lba)
{w->admitted=false;w->error=error;w->error_lba=lba;return false;}
static inline const uint8_t *po_node(const uint8_t *packet,unsigned index)
{return packet+POLARIS_OWNER_HEADER+(uint64_t)index*(4096+8);}
static inline const uint8_t *po_map(const uint8_t *packet,unsigned nodes,unsigned index)
{return po_node(packet,nodes)+(uint64_t)index*24;}
static inline bool po_read(struct polaris_owner_work *w,polaris_owner_read read,
    void *context,uint64_t relative,uint8_t *data)
{
    if(relative>=w->partition_blocks)return po_fail(w,2,relative);
    if(!read(context,w->partition_start+relative,data))return po_fail(w,3,relative);
    return true;
}
static inline bool po_metadata(const uint8_t *p,unsigned nodes,uint64_t block)
{
    if(!block||block==po64(p+48)||block==po64(p+56))return true;
    for(unsigned i=0;i<nodes;i++)if(block==po64(po_node(p,i)))return true;
    return false;
}
static inline bool po_tree(struct polaris_owner_work *w,const uint8_t *packet,
    const uint8_t *data,unsigned bytes,unsigned depth,unsigned level,
    uint64_t low,uint64_t high,polaris_owner_read read,void *context)
{
    unsigned count=po16(data+2),maximum=po16(data+4);
    if(po16(data)!=0xf30a||po16(data+6)!=depth||!count||count>maximum||
       maximum>(bytes-12)/12||level>5)return po_fail(w,8,low);
    for(unsigned i=0;i<count;i++){
        const uint8_t *entry=data+12+i*12;
        uint64_t logical=po32(entry),end=i+1<count?po32(entry+12):high;
        if(logical<low||logical>=high||(!i&&logical!=low)||end<=logical||end>high)
            return po_fail(w,9,logical);
        if(depth){
            uint64_t lba=(uint64_t)po32(entry+4)|(uint64_t)po16(entry+8)<<32;
            unsigned index=0;
            while(index<w->node_count&&po64(po_node(packet,index))!=lba)index++;
            if(po16(entry+10)||index==w->node_count||w->seen&(UINT64_C(1)<<index))
                return po_fail(w,10,lba);
            w->seen|=UINT64_C(1)<<index;
            uint8_t *raw=w->buffers[level+1];
            if(!po_read(w,read,context,lba,raw))return false;
            if(!po_equal(raw,po_node(packet,index)+8,4096))return po_fail(w,11,lba);
            if(w->metadata_checksum){
                unsigned tail=12+po16(raw+4)*12;
                if(tail>4092||po32(raw+tail)!=po_crc32c(w->file_checksum_seed,raw,tail))return po_fail(w,16,lba);
            }
            if(!po_tree(w,packet,raw,4096,depth-1,level+1,logical,end,read,context))return false;
        }else{
            uint64_t physical=(uint64_t)po16(entry+6)<<32|po32(entry+8);
            unsigned blocks=po16(entry+4);
            if(!blocks||blocks>32768||blocks!=end-logical||w->map_used>=w->map_count)
                return po_fail(w,12,logical);
            const uint8_t *expected=po_map(packet,w->node_count,w->map_used++);
            if(po64(expected)!=logical||po64(expected+8)!=physical||po64(expected+16)!=blocks)
                return po_fail(w,13,logical);
        }
    }
    return true;
}

/* Absolute device reads are bounded to this GPT-verified partition by caller.
 * Only the inode's256bytes are compared, so activity on neighboring inodes
 * does not falsely invalidate a pinned file. Dedicated extent blocks compare
 * in full; group descriptor counters and superblock mount times may change.
 */
static inline bool polaris_owner_verify(const uint8_t *p,size_t bytes,
    uint64_t expected_start,uint64_t expected_blocks,
    polaris_owner_read read,void *context,struct polaris_owner_work *w)
{
    if(!w)return false;
    w->metadata_verified=false;w->admitted=false;w->error=0;w->error_lba=0;w->seen=0;w->map_used=0;
    if(!p||!read||bytes<POLARIS_OWNER_HEADER||!po_equal(p,(const uint8_t*)"PROWN001",8)||
       po32(p+8)!=POLARIS_OWNER_HEADER)return po_fail(w,1,0);
    unsigned nodes=po32(p+72),maps=po32(p+76);
    if(nodes>POLARIS_OWNER_NODES||!maps||maps>POLARIS_OWNER_MAPS||
       bytes!=POLARIS_OWNER_HEADER+(uint64_t)nodes*4104+(uint64_t)maps*24||po32(p+12)!=bytes)
        return po_fail(w,1,0);
    w->partition_start=po64(p+16);w->partition_blocks=po64(p+24);w->file_blocks=po64(p+32);
    w->node_count=nodes;w->map_count=maps;
    if(w->partition_start!=expected_start||w->partition_blocks!=expected_blocks||
       w->partition_start<256||w->partition_start>UINT32_MAX||!w->partition_blocks||
       w->partition_blocks>UINT64_C(0x100000000)-w->partition_start||
       !w->file_blocks||w->file_blocks>(UINT64_C(64)<<18))return po_fail(w,1,0);
    uint64_t inode_lba=po64(p+48),descriptor_lba=po64(p+56),table=po64(p+80);
    unsigned descriptor_offset=po32(p+64),inode_offset=po32(p+68),desc_size=po32(p+116);
    bool uuid_present=false;for(unsigned i=88;i<104;i++)if(p[i])uuid_present=true;
    if(!inode_lba||inode_lba>=w->partition_blocks||!descriptor_lba||
       descriptor_lba>=w->partition_blocks||inode_lba==descriptor_lba||
       !table||table>=w->partition_blocks||(desc_size!=32&&desc_size!=64)||
       descriptor_offset>4096-desc_size||descriptor_offset%desc_size||
       inode_offset>3840||inode_offset%256||!uuid_present)return po_fail(w,1,0);
    for(unsigned i=0;i<nodes;i++){
        uint64_t block=po64(po_node(p,i));
        if(!block||block>=w->partition_blocks||block==inode_lba||block==descriptor_lba)
            return po_fail(w,1,block);
        for(unsigned j=0;j<i;j++)if(block==po64(po_node(p,j)))return po_fail(w,1,block);
    }
    uint64_t next=0;
    for(unsigned i=0;i<maps;i++){
        const uint8_t *e=po_map(p,nodes,i);
        uint64_t logical=po64(e),physical=po64(e+8),blocks=po64(e+16);
        if(logical!=next||next>=w->file_blocks||!blocks||blocks>w->file_blocks-next||
           !physical||physical>=w->partition_blocks||blocks>w->partition_blocks-physical)
            return po_fail(w,1,physical);
        for(unsigned j=0;j<i;j++){
            struct polaris_owner_extent *a=&w->map[j];
            uint64_t absolute=physical+w->partition_start;
            if(absolute<a->physical+a->blocks&&a->physical<absolute+blocks)
                return po_fail(w,1,physical);
        }
        for(uint64_t block=0;block<3+nodes;block++){
            uint64_t meta=block==0?0:block==1?inode_lba:block==2?descriptor_lba:po64(po_node(p,(unsigned)block-3));
            if(meta>=physical&&meta-physical<blocks)return po_fail(w,1,physical);
        }
        w->map[i]=(struct polaris_owner_extent){logical,w->partition_start+physical,blocks};
        next+=blocks;
    }
    if(next!=w->file_blocks)return po_fail(w,1,next);
    uint8_t *raw=w->buffers[0];
    if(!po_read(w,read,context,0,raw))return false;
    const uint8_t *sb=raw+1024;
    uint32_t incompat=po32(sb+96),ro=po32(sb+100);
    uint64_t total=po32(sb+4)|((incompat&0x80)?(uint64_t)po32(sb+336)<<32:0);
    if(po16(sb+56)!=0xef53||po32(sb+24)!=2||po32(sb+28)!=2||po32(sb+20)||po32(sb+76)!=1||total!=w->partition_blocks||
       po16(sb+58)!=1||po32(sb+232)||incompat&~POLARIS_OWNER_INCOMPAT||!(incompat&0x40)||
       ro&POLARIS_OWNER_RO_REFUSED||!(ro&(0x400|0x10))||po16(sb+88)!=256||po32(sb+72)||!po_equal(sb+104,p+88,16)||
       po32(sb)!=po32(p+104)||po32(sb+40)<16||po32(sb+40)>32768||po32(sb+40)!=po32(p+108)||
       po32(sb+32)<1024||po32(sb+32)>32768||(po32(sb+32)&(po32(sb+32)-1))||
       po32(sb+32)!=po32(p+112)||po32(sb+36)!=po32(sb+32)||
       ((incompat&0x80)?po16(sb+254):32)!=desc_size||
       incompat!=po32(p+120)||ro!=po32(p+124))return po_fail(w,4,0);
    w->metadata_checksum=(ro&0x400)!=0;
    w->checksum_seed=(incompat&0x2000)?po32(sb+624):po_crc32c(UINT32_MAX,sb+104,16);
    if(w->metadata_checksum&&(sb[373]!=1||po32(sb+1020)!=po_crc32c(UINT32_MAX,sb,1020)))return po_fail(w,16,0);
    unsigned inode=po32(p+40),ipg=po32(sb+40);
    if(!inode||inode>po32(sb))return po_fail(w,4,0);
    uint64_t group=(inode-1)/ipg,index=(inode-1)%ipg,desc_bytes=group*desc_size;
    if(descriptor_lba!=1+desc_bytes/4096||descriptor_offset!=desc_bytes%4096||
       inode_lba!=table+index*256/4096||inode_offset!=index*256%4096)
        return po_fail(w,5,descriptor_lba);
    if(!po_read(w,read,context,descriptor_lba,raw))return false;
    const uint8_t *desc=raw+descriptor_offset;
    if(((uint64_t)po32(desc+8)|(desc_size==64?(uint64_t)po32(desc+40)<<32:0))!=table||
       po16(desc+30)!=po_group_checksum(desc,desc_size,(unsigned)group,p+88,w->metadata_checksum,w->checksum_seed))
        return po_fail(w,5,descriptor_lba);
    if(!po_read(w,read,context,inode_lba,raw))return false;
    const uint8_t *ino=raw+inode_offset,*expected=p+128;
    if(!po_equal(ino,expected,256))return po_fail(w,6,inode_lba);
    uint64_t size=(uint64_t)po32(ino+4)|(uint64_t)po32(ino+108)<<32;
    uint64_t allocated=(uint64_t)po32(ino+28)|(uint64_t)po16(ino+116)<<32;
    if(po16(ino)!=0x8180||po16(ino+2)||po16(ino+24)||po16(ino+120)||po16(ino+122)||
       po16(ino+26)!=1||po32(ino+20)||po32(ino+32)!=POLARIS_OWNER_FLAGS||
       po32(ino+104)||po16(ino+118)||size!=w->file_blocks*4096||allocated<size/512||
       po32(ino+100)!=po32(p+44)||po16(ino+46)>5||po16(ino+128)>128||po16(ino+128)%4)return po_fail(w,7,inode_lba);
    w->file_checksum_seed=po_number_crc(po_number_crc(w->checksum_seed,inode),po32(ino+100));
    if(w->metadata_checksum){
        bool high=po16(ino+128)>=4;uint32_t provided=po16(ino+124),crc=w->file_checksum_seed;
        if(high)provided|=(uint32_t)po16(ino+130)<<16;
        for(unsigned i=0;i<256;i++){
            uint8_t b=(i==124||i==125||(high&&(i==130||i==131)))?0:ino[i];crc=po_crc32c(crc,&b,1);
        }
        if(provided!=(high?crc:crc&0xffff))return po_fail(w,16,inode_lba);
    }
    if(!po_tree(w,p,expected+40,60,po16(expected+46),0,0,w->file_blocks,read,context))return false;
    uint64_t all=nodes==64?UINT64_MAX:(UINT64_C(1)<<nodes)-1;
    if(w->seen!=all||w->map_used!=maps)return po_fail(w,14,0);
    w->metadata_verified=true;return true;
}

/* Require an independently bound preserved-base map. Metadata validation alone
 * never admits data writes, and the runtime may not reuse even one base block.
 * The integration must bind this protected map to the immutable-root baseline,
 * not accept a different map from an untrusted command or a mutable caller.
 */
static inline bool polaris_owner_exclude_base(struct polaris_owner_work *w,
    const struct polaris_owner_extent *base,unsigned count,uint64_t file_blocks)
{
    if(!w)return false;w->admitted=false;
    if(!w->metadata_verified||!base||!count||count>POLARIS_OWNER_MAPS||
       !file_blocks||file_blocks>(UINT64_C(64)<<18))return po_fail(w,15,0);
    uint64_t next=0;
    for(unsigned i=0;i<count;i++){
        const struct polaris_owner_extent *b=&base[i];
        if(b->logical!=next||!b->blocks||next>=file_blocks||
           b->blocks>file_blocks-next||b->physical<w->partition_start||
           b->physical-w->partition_start>=w->partition_blocks||
           b->blocks>w->partition_blocks-(b->physical-w->partition_start))return po_fail(w,15,b->physical);
        for(unsigned j=0;j<i;j++)if(b->physical<base[j].physical+base[j].blocks&&
            base[j].physical<b->physical+b->blocks)return po_fail(w,15,b->physical);
        for(unsigned j=0;j<w->map_count;j++)if(b->physical<w->map[j].physical+w->map[j].blocks&&
            w->map[j].physical<b->physical+b->blocks)return po_fail(w,15,b->physical);
        next+=b->blocks;
    }
    if(next!=file_blocks)return po_fail(w,15,next);
    w->admitted=true;return true;
}

/* This is an OFFLINE policy predicate until explicitly integrated/tested with
 * the native driver. It does not construct a descriptor or ring a doorbell.
 * Generic partition access must remain refused independently of this predicate.
 */
static inline bool polaris_owned_data_cdb(const struct polaris_owner_work *w,
    const uint8_t *cdb,unsigned size,uint32_t bytes,bool write,unsigned lun)
{
    if(!w||!w->admitted||!cdb||lun||size!=10||
       cdb[0]!=(write?0x2a:0x28)||cdb[1]||cdb[6]||cdb[9])return false;
    uint64_t lba=(uint32_t)cdb[2]<<24|(uint32_t)cdb[3]<<16|(uint32_t)cdb[4]<<8|cdb[5];
    unsigned blocks=(unsigned)cdb[7]<<8|cdb[8];
    if(!blocks||blocks>256||bytes!=blocks*4096||blocks-1>UINT32_MAX-lba)return false;
    for(unsigned i=0;i<w->map_count;i++){
        const struct polaris_owner_extent *e=&w->map[i];
        if(lba>=e->physical&&lba-e->physical<e->blocks&&blocks<=e->blocks-(lba-e->physical))return true;
    }
    return false;
}
static inline bool polaris_owned_sync_cdb(const struct polaris_owner_work *w,
    const uint8_t *cdb,unsigned size,uint32_t bytes,bool write,unsigned lun)
{
    if(!w||!w->admitted||!cdb||size!=10||cdb[0]!=0x35||bytes||write||lun)return false;
    for(unsigned i=1;i<10;i++)if(cdb[i])return false;
    return true;
}
#endif

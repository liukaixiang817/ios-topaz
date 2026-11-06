/* Real own GPT identity metadata, entirely synthetic NV data and UEFI services.
 * Never accesses a phone, block device or NV source. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include "uefi-wifi-nv-inputs.h"
#include "own-nv-plan.h"
static unsigned nv_checks,scenario,mode,reads,freed,part_reads[4];
#ifdef CHECK
#undef CHECK
#endif
#define CHECK(x) do{assert(x);nv_checks++;}while(0)
struct device {struct pnv_block io;struct pnv_media media;uint8_t path[128];unsigned index;};
static struct device device[6];static efi_handle handles[7];static struct efi_boot boot;
static struct pnv_result*result;static uint8_t*memory;static uint8_t headers[2][2][4096],tables[2][65536];
static void le(void*p,uint64_t value,unsigned n){for(unsigned k=0;k<n;k++)((uint8_t*)p)[k]=(uint8_t)(value>>(k*8));}
static uint8_t nv_byte(unsigned part,uint64_t off){return (uint8_t)((part*37+off*17)^(off>>12));}
static efi_status read_blocks(struct pnv_block*io,uint32_t id,uint64_t lba,uint64_t bytes,void*out)
{
    struct device*d=(void*)io;CHECK(id==d->media.id&&bytes&&bytes<=65536&&!(bytes&4095)&&!((uintptr_t)out&4095));
    CHECK(lba+bytes/4096<=d->media.last+1);reads++;
    if(d->index<2){
        unsigned n=d->index;const struct pnv_disk_plan*p=&polaris_nv_plan.disk[n];
        if(lba==1||lba==p->blocks-1){CHECK(bytes==4096);memcpy(out,headers[n][lba!=1],4096);}
        else{CHECK((lba==p->table_lba[0]||lba==p->table_lba[1])&&bytes==p->table_bytes);memcpy(out,tables[n],bytes);}
        if(mode==3&&reads==1)((uint8_t*)out)[10]^=1;
    }else{
        unsigned part=d->index-2;part_reads[part]++;
        for(unsigned n=0;n<bytes;n++)((uint8_t*)out)[n]=nv_byte(part,lba*4096+n);
        if(mode==4&&part_reads[part]>pnv_part_bytes(part)/65536)((uint8_t*)out)[0]^=1;
        if(mode==5){d->media.id++;return 0;}
        if(mode==6)return EFI_ERROR|7;
        if(mode==7)d->io.revision^=1;
    }return 0;
}
static efi_status locate(uint32_t how,const efi_guid*guid,void*key,uint64_t*count,efi_handle**out)
{CHECK(how==2&&guid->a==0x964e5b21&&!key);*count=mode==1?7:6;*out=handles;return 0;}
static efi_status handle(efi_handle h,const efi_guid*guid,void**out)
{struct device*d=h;CHECK(d>=device&&d<device+6);if(guid->a==0x9576e91)*out=d->path;else{
    CHECK(guid->a==0x964e5b21);
    if((mode==13&&d==&device[2])||(mode==14&&d==&device[0]))return EFI_ERROR|7;
    *out=&d->io;
}return 0;}
static efi_status release(void*p){CHECK(p==handles&&!freed);freed++;return mode==8?EFI_ERROR|7:0;}
static void nv_setup(unsigned fault)
{
    scenario++;mode=fault;reads=freed=0;memset(part_reads,0,sizeof(part_reads));memset(result,0,sizeof(*result));
    memset(memory,0xa5,PNV_BYTES);memset(device,0,sizeof(device));boot=(struct efi_boot){.locate_buffer=locate,.handle_protocol=handle,.free_pool=release};
    for(unsigned n=0;n<6;n++){
        struct device*d=&device[n];d->index=n;handles[n]=d;d->io=(struct pnv_block){.revision=0x20031,.media=&d->media,.read=read_blocks};
        unsigned disk=n<2?n:polaris_nv_plan.part[n-2].disk;
        d->media=(struct pnv_media){.id=100+n,.present=1,.logical=n>=2,.block=4096,.align=4096,
            .last=(n<2?polaris_nv_plan.disk[n].blocks:polaris_nv_plan.part[n-2].blocks)-1};
        d->path[0]=1;d->path[1]=4;d->path[2]=20;d->path[4]=(uint8_t)(disk+1);
        unsigned end=20;
        if(n>=2){const struct pnv_part_plan*p=&polaris_nv_plan.part[n-2];uint8_t*h=d->path+20;
            h[0]=4;h[1]=1;h[2]=42;le(h+4,p->number,4);le(h+8,p->start,8);le(h+16,p->blocks,8);memcpy(h+24,p->guid,16);h[40]=h[41]=2;end+=42;
        }
        d->path[end]=0x7f;d->path[end+1]=0xff;d->path[end+2]=4;
    }
    handles[6]=handles[2];if(mode==2)device[2].path[44]^=1;
    if(mode==9)device[2].media.logical=0;
    if(mode==10)device[3].path[4]^=0x40;
    if(mode==11)device[0].path[4]^=0x40;
    if(mode==12){uint8_t*p=device[2].path;p[62]=1;p[63]=4;p[64]=4;p[66]=0x7f;p[67]=0xff;p[68]=4;}
    if(mode==15)device[0].media.block=512;
    if(mode==16)device[2].io.media=0;
    if(mode==17)device[2].io.read=0;
}
/* Spec revisions and the independently observed old EDK2 value share only
 * the prefix this reader consumes. Unknown revisions and bad media still fail. */
static void revision_cases(void)
{
    const uint64_t accepted[]={0x10000,0x20001,0x2001f,0x20031};
    const uint64_t refused[]={0,0x10001,0x20000,0x20002,0x20030,0x20032,0x30000,UINT64_MAX};
    struct pnv_media m={.present=1,.logical=1,.block=4096,.last=0x7ff};
    struct pnv_block b={.media=&m,.read=read_blocks};
    for(unsigned i=0;i<sizeof(accepted)/sizeof(*accepted);i++){
        b.revision=accepted[i];CHECK(pnv_media_valid(&b,0x800,1));
        m.block=512;CHECK(!pnv_media_valid(&b,0x800,1));m.block=4096;
        m.last=0x800;CHECK(!pnv_media_valid(&b,0x800,1));m.last=0x7ff;
        m.logical=0;CHECK(!pnv_media_valid(&b,0x800,1));m.logical=1;
        m.present=0;CHECK(!pnv_media_valid(&b,0x800,1));m.present=1;
        m.removable=1;CHECK(!pnv_media_valid(&b,0x800,1));m.removable=0;
        m.align=3;CHECK(!pnv_media_valid(&b,0x800,1));m.align=8192;CHECK(!pnv_media_valid(&b,0x800,1));m.align=0;
        b.media=0;CHECK(!pnv_media_valid(&b,0x800,1));b.media=&m;
        b.read=0;CHECK(!pnv_media_valid(&b,0x800,1));b.read=read_blocks;
    }
    for(unsigned i=0;i<sizeof(refused)/sizeof(*refused);i++){b.revision=refused[i];CHECK(!pnv_media_valid(&b,0x800,1));}
}
static void load(const char*dir,const char*name,void*out,unsigned bytes)
{char path[4096];CHECK(snprintf(path,sizeof(path),"%s/%s",dir,name)>0);FILE*f=fopen(path,"rb");CHECK(f&&fread(out,1,bytes,f)==bytes&&fgetc(f)==EOF&&!fclose(f));}
#ifndef PNV_TEST_ENTRY
#define PNV_TEST_ENTRY main
#endif
int PNV_TEST_ENTRY(int argc,char**argv)
{
    revision_cases();CHECK(argc==2);result=calloc(1,sizeof(*result));memory=aligned_alloc(4096,PNV_BYTES);CHECK(result&&memory);
    load(argv[1],"gpt0-primary.bin",headers[0][0],4096);load(argv[1],"gpt0-backup.bin",headers[0][1],4096);load(argv[1],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[1],"gpt1-primary.bin",headers[1][0],4096);load(argv[1],"gpt1-backup.bin",headers[1][1],4096);load(argv[1],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    nv_setup(0);CHECK(pnv_collect(&boot,&polaris_nv_plan,(uintptr_t)memory,result)&&result->complete&&result->passes==2&&freed==1&&result->reads==reads&&result->reads==result->returned);
    for(unsigned part=0;part<4;part++){
        uint8_t*input=memory+pnv_part_offset(part),digest[32];
        for(unsigned n=0;n<pnv_part_bytes(part);n++)CHECK(input[n]==nv_byte(part,n));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CC_SHA256(input,pnv_part_bytes(part),digest);
#pragma clang diagnostic pop
        CHECK(!memcmp(digest,result->hash[part],32));
    }
    for(unsigned n=PNV_INPUT_BYTES;n<PNV_SCRATCH;n++)CHECK(memory[n]==0xa5);
    CHECK(!pnv_collect(&boot,&polaris_nv_plan,(uintptr_t)memory,result));
    for(unsigned fault=1;fault<=8;fault++){nv_setup(fault);CHECK(!pnv_collect(&boot,&polaris_nv_plan,(uintptr_t)memory,result)&&result->unknown&&!result->complete&&freed==1);}
    const unsigned steps[]={3,5,7,4,2,8,9,3,3};
    for(unsigned fault=9;fault<=17;fault++){
        nv_setup(fault);CHECK(!pnv_collect(&boot,&polaris_nv_plan,(uintptr_t)memory,result));
        CHECK(result->error==2&&result->unknown&&!result->complete&&freed==1&&!reads);
        CHECK(result->selection_stage==steps[fault-9]&&result->selection_index==(fault==10?1u:0u));
        CHECK(result->selection_status==((fault==13||fault==14)?EFI_ERROR|7:0));
        if(fault==9)CHECK(result->part[0].media.logical==0&&result->part[0].media.block==4096);
        if(fault==15)CHECK(result->disk[0].media.block==512);
    }
    free(memory);free(result);printf("PASS %u NV input checks, %u scenarios; own GPT fixtures/synthetic NV/UEFI, no device\n",nv_checks,scenario);return 0;
}

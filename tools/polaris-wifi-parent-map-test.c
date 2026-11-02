/* Actual incoming parent-map wrapper with explicit SOFTWARE API/FP/clock
 * leaves. Original Core is inert DATA; no original instruction or USB runs. */
#define main parent_original_GCD_fixture_not_executed
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-remote-memory.h"
static struct pwmc_parent_map*parent;
static struct pwmc_parent_input input;
static struct pgcd_io parent_io;
static unsigned point,kind,offset,fired,leaf_fault,stride_bytes;
static unsigned map_calls,arch_calls,fp_saves,fp_restores;
static void mutate(unsigned where)
{
    if(fired||where!=point||!kind)return;fired=1;
    if(kind==1){((uint8_t*)parent)[offset]^=1;return;}
    switch(kind){
    case 2:input.system=(void*)8;break;case 3:input.image=(void*)8;break;
    case 4:input.native_flag=(void*)8;break;case 5:input.output=(void*)8;break;
    case 6:input.bank+=4096;break;case 7:parent_io.arch=0;break;
    case 8:s->boot=(void*)8;break;case 9:self->bytes--;break;
    case 10:put(core+0x1b838,(uintptr_t)core+0xd3f0,8);break;
    case 11:parent->before.cpu.tcr^=4096;break;case 12:parent->fp.q8_q15[2]^=1;break;
    case 13:parent->map.key^=1;break;case 14:parent->data[0]^=1;break;
    case 15:parent->complete=1;break;case 16:parent->issued=2;break;
    case 17:parent->native_values[0]=1;break;case 18:parent->fp_save_issued=0;break;
    case 19:put(arena+0x81000,1,4);break;default:assert(0);
    }
}
static int parent_arch(void*opaque,struct pgcd_arch*a)
{
    arch_calls++;int ok=arch(opaque,a);
    if(leaf_fault==1&&arch_calls==1)return 0;
    if(leaf_fault==2&&arch_calls==2)return 0;
    if(leaf_fault==3&&arch_calls==2)a->cpu.ticks+=PGCD_FRESH_TICKS+1;
    if(leaf_fault==4)a->cpu.daif=0x80;
    mutate(arch_calls==1?0:4);return ok;
}
static int parent_save(void*opaque,struct pgcd_fp_guard*g)
{fp_saves++;int ok=fp_save(opaque,g);mutate(1);return leaf_fault==5?0:ok;}
static int parent_restore(void*opaque,struct pgcd_fp_guard*g)
{fp_restores++;int ok=fp_restore(opaque,g);mutate(5);return leaf_fault==6?0:ok;}
static void parent_order(void*opaque){(void)opaque;mutate(2);}
static int parent_map(void*opaque,struct efi_system*sys,struct pgcd_map*m,void*out)
{
    (void)opaque;assert(sys==s&&m==&parent->map&&out==parent->data&&m->issued&&parent->issued&&parent->unknown);
    map_calls++;struct efi_memory descriptors[2]={{3,0,(uintptr_t)arena,0,256,8},
        {input.phase==1?7:2,0,input.bank,0,input.bank_bytes/4096,8}};
    for(unsigned i=0;i<2;i++){memcpy((uint8_t*)out+stride_bytes*i,&descriptors[i],40);memset((uint8_t*)out+stride_bytes*i+40,0x5a,stride_bytes-40);}
    m->bytes=2*stride_bytes;m->status=0;m->key=0x1234+input.phase;m->stride=stride_bytes;m->version=1;
    parent->data[PWMC_PARENT_MAP_CAP-1]=0xa5; /* Preserve the unreturned raw tail. */
    switch(leaf_fault){
    case 7:return 0;case 8:m->status=EFI_ERROR|5;break;case 9:m->bytes=PWMC_PARENT_MAP_CAP+1;break;
    case 10:m->key=0;break;case 11:m->stride=0;break;case 12:m->version=2;break;
    case 13:((struct efi_memory*)((uint8_t*)out+stride_bytes))->type=4;break;
    case 14:((struct efi_memory*)((uint8_t*)out+stride_bytes))->pages--;break;
    case 15:((struct efi_memory*)((uint8_t*)out+stride_bytes))->physical=(uintptr_t)arena;break;
    case 16:m->valid=1;break;
    }
    mutate(3);return 1;
}
static void setup_parent(unsigned phase)
{
    reset(0);self->bytes=0x100000;parent=(void*)(arena+0x50000);memset(parent,0,sizeof(*parent));
    assert((uint8_t*)parent+sizeof(*parent)<arena+0x70000);
    memset(arena+0x70000,0xcc,PWMC_PARENT_MAP_CAP);point=kind=offset=fired=leaf_fault=0;
    map_calls=arch_calls=fp_saves=fp_restores=0;stride_bytes=48;
    input=(struct pwmc_parent_input){.system=s,.image=self,.native_flag=(void*)(arena+0x81000),.output=arena+0x70000,
        .capacity=PWMC_PARENT_MAP_CAP,.image_handle=0x123,.phase=phase,.bank=0xc0000000,.bank_bytes=0x200000};
    parent_io=(struct pgcd_io){.system=s,.arch=parent_arch,.map=parent_map,.fp_save=parent_save,.fp_restore=parent_restore,.order=parent_order};
}
static void stopped(void)
{
    unsigned count=map_calls+arch_calls+fp_saves+fp_restores;
    assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&count==map_calls+arch_calls+fp_saves+fp_restores);
}
int main(int argc,char**argv)
{
    assert((argc==2||argc==3)&&!posix_memalign((void**)&arena,4096,0x101000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    for(unsigned phase=1;phase<=2;phase++)for(unsigned stride=40;stride<=64;stride+=8){
        setup_parent(phase);stride_bytes=stride;int ok=pwmc_parent_map_read(parent,&input,&parent_io);
        if(!ok)fprintf(stderr,"phase%u stride%u error%u call%u/%u arch%u/%u native%x/%x fp%u/%u/%u/%u mapvalid%u status%llx bytes%llu key%llu\n",phase,stride,parent->error,parent->issued,parent->returned,parent->arch_issued,parent->arch_returned,parent->native_issued,parent->native_returned,parent->fp_save_issued,parent->fp_save_returned,parent->fp_restore_issued,parent->fp_restore_returned,parent->map.valid,(unsigned long long)parent->map.status,(unsigned long long)parent->map.bytes,(unsigned long long)parent->map.key);
        assert(ok);
        assert(parent->complete&&parent->map.valid&&!parent->unknown&&!parent->error&&map_calls==1&&arch_calls==2&&fp_saves==1&&fp_restores==1);
        assert(parent->native_issued==31&&parent->native_returned==31&&parent->map.key==0x1234+phase&&parent->map.bytes==2*stride);
        assert(parent->data[PWMC_PARENT_MAP_CAP-1]==0xa5&&arena[0x70000+2*stride]==0xcc);
        assert(!memcmp(input.output,parent->data,parent->map.bytes)&&!memcmp(parent->BS_before,parent->BS_after,PWMC_BS_BYTES));
        assert(!memcmp(&parent->image_before,&parent->image_after,sizeof(*self)));stopped();checks++;
    }
    for(unsigned field=2;field<=10;field++)for(unsigned stage=0;stage<6;stage++){
        setup_parent(1);kind=field;point=stage;assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&fired&&parent->unknown&&!parent->complete);
        assert(map_calls==(stage>=3));if(stage==3||stage==4)assert(!fp_restores);stopped();checks++;
    }
    for(unsigned stage=0;stage<=4;stage+=4)for(unsigned byte=0;byte<offsetof(struct pwmc_parent_map,map);byte++){
        setup_parent(1);kind=1;point=stage;offset=byte;assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&fired&&parent->unknown&&!parent->complete);
        assert(map_calls==(stage==4)&&!fp_restores);stopped();checks++;
    }
    for(unsigned field=11;field<=18;field++)for(unsigned stage=2;stage<6;stage++){
        if((field==13||field==14)&&stage<4)continue;
        setup_parent(1);kind=field;point=stage;assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&fired&&parent->unknown);
        assert(map_calls==(stage>=3));if(stage==3||stage==4)assert(!fp_restores);stopped();checks++;
    }
    for(unsigned stage=0;stage<6;stage++){
        setup_parent(1);kind=19;point=stage;assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&fired&&parent->unknown);
        assert(map_calls==(stage>=3));if(stage==3||stage==4)assert(!fp_restores);stopped();checks++;
    }
    for(unsigned bad=1;bad<=16;bad++){
        setup_parent(1);leaf_fault=bad;assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&parent->unknown&&!parent->complete);
        if(bad<=6)assert(map_calls==(bad==2||bad==3||bad==6));
        if(bad==7||bad==8)assert(arch_calls==1&&fp_restores==0&&parent->native_issued==3);
        if(bad>=9)assert(arch_calls==1&&fp_restores==0);
        if(bad==2||bad==3)assert(!fp_restores);stopped();checks++;
    }
    for(unsigned bad=0;bad<12;bad++){
        setup_parent(1);
        switch(bad){case 0:input.phase=0;break;case 1:input.phase=3;break;case 2:input.capacity--;break;
        case 3:input.native_flag=(void*)8;break;case 4:input.output=parent;break;
        case 5:input.payload=0x123;input.payload_bytes=4096;break;case 6:input.log_snapshot=0x456;input.log_snapshot_bytes=4096;break;
        case 7:input.bank_bytes=0;break;case 8:input.bank_bytes--;break;case 9:input.bank=(uintptr_t)arena;break;
        case 10:put(core+0x1b838,(uintptr_t)core+0xd3f0,8);break;case 11:put(arena+0x81000,1,4);break;}
        assert(!pwmc_parent_map_read(parent,&input,&parent_io)&&parent->unknown&&!map_calls&&!arch_calls&&!fp_saves);stopped();checks++;
    }
    setup_parent(2);assert(pwmc_parent_map_read(parent,&input,&parent_io));
    if(argc==3){FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(parent,1,sizeof(*parent),out)==sizeof(*parent)&&!fclose(out));}
    printf("{\"passed\":true,\"checks\":%u,\"parent_record_bytes\":%zu,\"input_bytes\":%zu,\"map_offset\":%zu,\"data_offset\":%zu,\"SOFTWARE_only\":true,\"firmware_executed\":false,\"MSS_admission\":false}\n",checks,sizeof(*parent),sizeof(input),offsetof(struct pwmc_parent_map,map),offsetof(struct pwmc_parent_map,data));
    free(original);free(arena);return 0;
}

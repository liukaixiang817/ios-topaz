/* Executable complete preparation/retirement peer. Original EFI is data only;
 * these callbacks MODEL its RAM effects, not physical provider/API execution. */
#define POLARIS_RPMH_FIXTURE_ONLY 1
#include "polaris-wifi-rpmh-test.c"
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE 1
#include "uefi-wifi-rpmh-client.h"
static struct pwrcl_result *cr;
static struct pgcd_context *early;
static uint8_t *pool,*active_header,*free_header,*foreign_client,*own_client;
static const char *own_name;
static unsigned cf,create_calls,delete_calls,private_maps,changed;
static uint64_t map_key;
static int client_core_arch(void *ctx,struct pgcd_arch *a)
{
    int ok=arch(ctx,a);
    if(cf==21&&create_calls)a->cpu.ticks+=3840001;
    if(cf==22&&create_calls)a->cpacr=0;
    return ok;
}
static int client_arch(void *ctx,struct paic_arch *a)
{
    struct pgcd_arch g;int ok=client_core_arch(ctx,&g);
    *a=(struct paic_arch){g.cpu.el,g.cpu.mpidr,g.cpu.ttbr0,g.cpu.ttbr1,g.cpu.tcr,g.cpu.sctlr,g.cpu.mair,
        g.cpu.daif,g.cpu.sre,g.cpu.group1,g.cpu.frequency,g.cpu.ticks};
    if(cf==23&&!changed&&cr->pools[0][0].complete&&!cr->pools[0][1].complete){foreign_client[8]^=1;changed=1;}
    return ok;
}
static int client_core_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    (void)ctx;assert(sys==s&&m->issued);maps++;
    struct efi_memory *d=out;*d=(struct efi_memory){3,0,(uintptr_t)arena,0,0x240000/4096,8};
    m->bytes=sizeof(*d);m->key=map_key;m->stride=sizeof(*d);m->version=1;m->status=0;return 1;
}
static int client_map(void *ctx,struct efi_system *sys,uint8_t *buffer,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);rcalls++;if(create_calls)private_maps++;
    struct efi_memory d[3]={{3,0,(uintptr_t)arena,0,0x1b0000/4096,8},
        {cf==3?3:4,0,(uintptr_t)links,0,0x10000/4096,8},
        {3,0,(uintptr_t)arena+0x1c0000,0,0x80000/4096,8}};
    memset(buffer,0,4096);memcpy(buffer,d,sizeof(d));m->bytes=sizeof(d);m->key=map_key;
    m->stride=sizeof(d[0]);m->version=1;m->status=0;
    if((cf==11&&private_maps==1)||(cf==19&&private_maps==2))m->status=0x8000000000000005ULL;
    if((cf==10&&private_maps==1)||(cf==18&&private_maps==2))return 0;
    return 1;
}
static void header(uint8_t *h,unsigned count,uint8_t *head,uint8_t *tail)
{memset(h,0,24);put(h,80,4);put(h+4,count,4);put(h+8,(uintptr_t)head,8);put(h+16,(uintptr_t)tail,8);}
static void own_state(int live)
{
    memset(own_client,0,88);put(own_client,2,4);
    put(own_client+8,live?(uintptr_t)own_name:(uintptr_t)rimage+0xaf50,8);
    put(own_client+0x30,live?UINT64_C(0xffffffff00000000):UINT64_MAX,8);
    for(unsigned k=0;k<4;k++){
        uint8_t *q=links+0x9000+32*k;put(own_client+0x10+8*k,(uintptr_t)q,8);
        memset(q,0,24);put(q,k<2?16:24,4);
    }
}
static int client_create(void *ctx,uint64_t fn,uint32_t drv,const char *name,void **out,uint64_t *status)
{
    (void)ctx;assert(fn==(uintptr_t)rimage+0x1ab0&&drv==2&&name==own_name);
    assert(cr->outstanding==1&&cr->provider_issued==1&&early->record->outstanding);
    create_calls++;*status=0;
    if(cf==7){*status=0x8000000000000002ULL;return 1;}
    if(cf==8)return 1;
    unsigned free_count=(unsigned)pwfi_le(free_header+4,4);
    uint64_t next=free_count?pwfi_le(own_client+80,8):0;
    if(free_count)header(free_header,free_count-1,(void*)(uintptr_t)next,free_count>1?(void*)(uintptr_t)pwfi_le(free_header+16,8):0);
    own_state(1);
    uint32_t count=(uint32_t)pwfi_le(active_header+4,4);uint8_t *tail=(void*)(uintptr_t)pwfi_le(active_header+16,8);
    if(tail)put(tail+80,(uintptr_t)own_client,8);else put(active_header+8,(uintptr_t)own_client,8);
    put(active_header+16,(uintptr_t)own_client,8);put(active_header+4,count+1,4);
    if(cf!=38)map_key++;
    *out=cf==12?(void*)foreign_client:(void*)own_client;
    if(cf==13)put(own_client+0x40,0x1234,8);
    if(cf==14)rimage[0x1000]^=1;
    if(cf==27)ticket->spent=1;
    return cf!=9;
}
static int client_drop(void *ctx,uint64_t fn,void *handle,uint64_t *status)
{
    (void)ctx;assert(fn==(uintptr_t)rimage+0x1b24&&handle==own_client&&create_calls==1);
    assert(cr->outstanding==3&&cr->provider_issued==2&&early->record->outstanding);
    delete_calls++;*status=0;
    if(cf==16){*status=0x8000000000000002ULL;return 1;}
    if(cf!=17){
        unsigned count=(unsigned)pwfi_le(active_header+4,4);assert(count>=1);
        uint8_t *head=(void*)(uintptr_t)pwfi_le(active_header+8,8),*previous=0,*at=head;
        for(unsigned k=0;k<count&&at!=own_client;k++){previous=at;at=(void*)(uintptr_t)pwfi_le(at+80,8);}
        assert(at==own_client);if(previous)put(previous+80,0,8);
        header(active_header,count-1,previous?head:0,previous);
        put(own_client+8,(uintptr_t)rimage+0xaf50,8);put(own_client+0x30,UINT64_MAX,8);put(own_client+0x38,0,4);
        unsigned free_count=(unsigned)pwfi_le(free_header+4,4);uint8_t *tail=(void*)(uintptr_t)pwfi_le(free_header+16,8);
        if(tail)put(tail+80,(uintptr_t)own_client,8);
        header(free_header,free_count+1,free_count?(void*)(uintptr_t)pwfi_le(free_header+8,8):own_client,own_client);
        if(cf!=38)map_key++;
    }
    if(cf==20)foreign_client[8]^=1;
    return cf!=15;
}
static void client_reset(unsigned f)
{
    rp_reset(0);cf=f;map_key=1;create_calls=delete_calls=private_maps=changed=0;
    self->bytes=r->self_owner.bytes=r->self_bytes=0x186000;
    cr=(void*)(arena+0x120000);early=(void*)(arena+0x180000);memset(cr,0,sizeof(*cr));memset(early,0,sizeof(*early));
    assert((uintptr_t)cr+sizeof(*cr)<(uintptr_t)early);
    own_name=(void*)(arena+0x182000);memcpy((void*)own_name,pwrcl_name,sizeof(pwrcl_name));
    pool=links+0x1000;active_header=links+0x1100;free_header=links+0x1140;
    foreign_client=links+0x2000;own_client=links+0x8000;
    put(rimage+0xd300,(uintptr_t)pool,8);put(pool,(uintptr_t)active_header,8);put(pool+8,(uintptr_t)free_header,8);
    put(foreign_client,2,4);header(active_header,1,foreign_client,foreign_client);own_state(0);header(free_header,1,own_client,own_client);
    c->io.arch=client_core_arch;c->io.map=client_core_map;
    if(f==1)put(active_header+4,PWRCL_NODES+1,4);
    if(f==2)put(foreign_client+80,(uintptr_t)foreign_client,8);
    if(f==4)put(own_client+0x40,1,8);
    if(f==5)put(own_client+0x48,1,8);
    if(f==6)put(links+0x9004,1,4);
    if(f==24)put(active_header+8,(uintptr_t)rimage+0xd1a0,8);
    if(f==25)put(foreign_client+0x10,(uintptr_t)links+0x9000,8);
    if(f==26)c->opened=1;
    if(f==28)header(free_header,0,0,0);
    if(f==29){
        for(unsigned k=0;k<PWRCL_NODES;k++){uint8_t *v=foreign_client+96*k;memset(v,0,88);put(v,2,4);put(v+80,k+1==PWRCL_NODES?0:(uintptr_t)v+96,8);}
        header(active_header,PWRCL_NODES,foreign_client,foreign_client+96*(PWRCL_NODES-1));
    }
    if(f==30)put(active_header+16,0,8);
    if(f==31)header(free_header,1,foreign_client,foreign_client);
    if(f==32){
        uint8_t *b=own_client+0x100,*d=own_client+0x200;put(b,2,4);put(d,2,4);
        put(own_client+80,(uintptr_t)b,8);put(b+80,(uintptr_t)d,8);header(free_header,3,own_client,d);
    }
    if(f==33){uint8_t *b=foreign_client+0x100;put(b,2,4);put(foreign_client+80,(uintptr_t)b,8);header(active_header,2,foreign_client,b);}
    if(f==34)header(active_header,0,0,0);
    if(f==35)r->phase=1;
    if(f==36)r->pre_mask=1;
    if(f==37)r->prestart_count=1;
    if(f==39){early->record=&cr->core;early->opened=1;}
    if(f==40)cr->core_ticket.spent=1;
    if(f==41)cr->reader_ticket.used=1;
}
int main(int argc,char **argv)
{
    assert(argc==4);assert(!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);assert(original&&npa_original&&rp_original);
    const size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};uint8_t *dst[]={original,npa_original,rp_original};
    for(unsigned k=0;k<3;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    struct pwrcl_io ops={{{NULL,NULL,client_arch,identity,order},rp_locate,client_map},client_create,client_drop,NULL};unsigned checks=0;
    client_reset(0);ops.reader.memory.system=s;ops.name=own_name;
    int ok=pwrcl_run(&ops,enumeration,2,c,early,cr,rw);
    if(!ok)fprintf(stderr,"baseline error%u unknown%u core%u reader%u provider%u/%u pools%u%u%u\n",cr->error,cr->unknown,cr->core.error,cr->reader.error,cr->provider_issued,cr->provider_returned,cr->pools_complete[0],cr->pools_complete[1],cr->pools_complete[2]);
    assert(ok&&cr->retired&&cr->client_returned&&!pwrcl_result_unsafe(cr)&&create_calls==1&&delete_calls==1&&cr->provider_issued==2);
    assert(cr->core.map[0].key==1&&cr->maps[0].key==2&&cr->maps[1].key==3&&cr->final_context_untouched&&!ticket->spent&&!pwrph_ticket.used);checks++;
    assert(!pwrcl_run(&ops,enumeration,2,c,early,cr,rw)&&create_calls==1&&delete_calls==1);checks++;
    assert(all()&&r->map[0].key==3&&r->map[1].key==3&&queries==8);checks++;
    /* Full real ordering: independent private phase -> NPA -> late RPMh ->
     * final GCD. Distinct record/tickets, no final-map rebasing or reset. */
    client_reset(0);ops.reader.memory.system=s;ops.name=own_name;
    npa=arena+0x200000;memcpy(npa,npa_original,PWNPI_IMAGE_BYTES);
    for(unsigned j=0;j<PWNPI_RELOC_COUNT;j++)put(npa+pwnpi_relocs[j],pwfi_le(npa+pwnpi_relocs[j],8)+(uintptr_t)npa,8);
    uint8_t *nlinks=arena+0x1e0000;put(npa+0x108b0,(uintptr_t)nlinks,8);
    put(nlinks+16,(uintptr_t)nlinks+0x100,8);strcpy((char*)nlinks+0x100,"post-private namespace");
    struct efi_loaded *nowner=(void*)(arena+0x188100);
    *nowner=(struct efi_loaded){.revision=0x1000,.system=s,.base=npa,.bytes=PWNPI_IMAGE_BYTES,.code_type=3,.data_type=4};
    enumeration->handle_count=2;enumeration->loaded_address[1]=(uintptr_t)nowner;
    assert(pwrcl_run(&ops,enumeration,2,c,early,cr,rw)&&!ticket->spent&&!pwrph_ticket.used);
    nr=(void*)(arena+0x50000);memset(nr,0,sizeof(*nr));
    struct pwnpa_io np={{s,NULL,client_arch,identity,order},locate_npa,client_map};
    assert(pwnpa_collect(&np,2,enumeration,c,nr,nw)&&nr->stable&&nr->issued==4);
    struct pwrph_io rp={{s,NULL,client_arch,identity,order},rp_locate,client_map};
    rr=(void*)(arena+0x110000);memset(rr,0,sizeof(*rr));
    assert(pwrph_collect(&rp,2,enumeration,c,rr,rw)&&rr->stable&&rr->issued==4);
    assert(cr->retired&&cr->client_returned&&!pwrcl_result_unsafe(cr)&&all());
    assert(r->map[0].key==3&&r->map[1].key==3&&queries==8&&cr->core.map[0].key==1);checks++;
    for(unsigned k=1;k<=41;k++){
        client_reset(k);ops.reader.memory.system=s;ops.name=own_name;ok=pwrcl_run(&ops,enumeration,2,c,early,cr,rw);
        if(k==28||k==32||k==33||k==34||k==38){
            assert(ok&&cr->client_returned&&!pwrcl_result_unsafe(cr));
            if(k==28)assert(cr->pools[0][1].list[1].count==0&&cr->pools[2][1].list[1].count==1);
            if(k==32)assert(cr->pools[2][1].list[1].count==3&&cr->pools[2][1].list[1].node[2].address==(uintptr_t)own_client);
            if(k==33)assert(cr->pools[2][1].list[0].count==2);
            if(k==34)assert(cr->pools[2][1].list[0].count==0);
            if(k==38)assert(cr->core.map[0].key==cr->maps[0].key&&cr->maps[1].key==1);
        }
        else{
            if(ok||!cr->error)fprintf(stderr,"fault%u ok%d err%u unknown%u calls%u/%u\n",k,ok,cr->error,cr->unknown,create_calls,delete_calls);
            assert(!ok&&cr->error);
            int pre=k<=6||k==23||k==24||k==25||k==26||k==29||k==30||k==31||k==35||k==36||k==37;
            int lifetime=k==26||k==35||k==36||k==37||k>=39;
            if(lifetime)assert(!create_calls&&!delete_calls&&cr->unknown&&!cr->retired&&pwrcl_result_unsafe(cr));
            else if(pre)assert(!create_calls&&!delete_calls&&cr->retired&&cr->refused_before_API&&!pwrcl_result_unsafe(cr));
            else{assert(pwrcl_result_unsafe(cr)&&create_calls==1);if(k<=14||k==21||k==22)assert(delete_calls==0);else assert(delete_calls==1);}
            if(k==9)assert(cr->handle_output==own_client&&cr->outstanding==1&&cr->guard[0].unknown);
            if(k==10)assert(cr->outstanding==2&&cr->guard[1].unknown);
            if(k==15)assert(cr->outstanding==3&&cr->guard[2].unknown);
            if(k==18)assert(cr->outstanding==4&&cr->guard[3].unknown);
            if(k==27)assert(ticket->spent==1); /* never reset a corrupted final ticket */
        }checks++;
    }
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"pool_bytes\":%zu,\"node_bytes\":%zu,\"SOFTWARE_peer_only\":true,\"physical_original_API_executed\":false,\"votes\":0,\"MMIO\":0,\"MSS\":false}\n",checks,sizeof(*cr),sizeof(struct pwrcl_pool),sizeof(struct pwrcl_node));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}

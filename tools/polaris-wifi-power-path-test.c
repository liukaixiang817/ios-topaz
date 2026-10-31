/* ONE original-ABI private-client/CmdDb/CPU/RSC/retirement execution chain.
 * Real original images are DATA. UEFI, PSCI, translations, registers and NV
 * namespace are explicit SOFTWARE peers; no phone or firmware code executes. */
#define POLARIS_PRIVATE_CLIENT_FIXTURE_ONLY 1
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1
#define POLARIS_CMDDB_SOFTWARE_TEST 1
#include "polaris-wifi-rpmh-client-test.c"
#include "uefi-wifi-power-path.h"
static struct pwrpt_result *path;
static uint8_t *cmd_original,*cmd_image,cmd_database[PWCD_DB_BYTES];
static unsigned jf,api_queries,psci_calls,mask_calls,unmask_calls,modeled_stores,requests,acks;
static uint64_t DAIF,Group1;
static volatile uint32_t *native_on;
static uint32_t hardware[0x3000/4],initial[0x3000/4],votes[3];
static uint8_t pwcd_test_load(uint64_t at)
{assert(at>=0x85fe0000&&at<0x86000000);return cmd_database[at-0x85fe0000];}
static int path_arch(void *ctx,struct pgcd_arch *a)
{int ok=arch(ctx,a);a->cpu.daif=DAIF;a->cpu.group1=Group1;return ok;}
static int path_memory_arch(void *ctx,struct paic_arch *a)
{
    struct pgcd_arch g;if(!path_arch(ctx,&g))return 0;
    *a=(struct paic_arch){g.cpu.el,g.cpu.mpidr,g.cpu.ttbr0,g.cpu.ttbr1,g.cpu.tcr,g.cpu.sctlr,g.cpu.mair,
        g.cpu.daif,g.cpu.sre,g.cpu.group1,g.cpu.frequency,g.cpu.ticks};return 1;
}
static int path_identity(void *ctx,uint64_t at,uint64_t bytes,uint64_t *where,uint64_t *par)
{
    (void)ctx;(void)bytes;*where=at;*par=at&~UINT64_C(4095);
    if(at>=0x85fe0000&&at<0x86000000){*par|=UINT64_C(0xff00000000000b80);if(jf==6&&DAIF)*par^=0x200;}
    return 1;
}
static int path_core_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    (void)ctx;assert(sys==s&&m->issued);maps++;
    struct efi_memory d[2]={{3,0,(uintptr_t)arena,0,0x800000/4096,8},{0,0,0x85fe0000,0,32,8}};
    memcpy(out,d,sizeof(d));m->bytes=sizeof(d);m->key=map_key;m->stride=sizeof(d[0]);m->version=1;m->status=0;return 1;
}
static int path_map(void *ctx,struct efi_system *sys,uint8_t *out,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);
    struct efi_memory d[4]={{3,0,(uintptr_t)arena,0,0x600000/4096,8},
        {4,0,(uintptr_t)links,0,0x10000/4096,8},{3,0,(uintptr_t)arena+0x610000,0,(0x800000-0x610000)/4096,8},
        {0,0,0x85fe0000,0,32,8}};
    memset(out,0,4096);memcpy(out,d,sizeof(d));m->bytes=sizeof(d);m->key=map_key;m->stride=sizeof(d[0]);m->version=1;m->status=0;return 1;
}
static int path_locate(void *ctx,struct efi_system *sys,const efi_guid *guid,void **out,uint64_t *status)
{
    (void)ctx;assert(sys==s);*status=0;
    if(guid->a==0xe1d0b573)*out=rimage+0xd0d8;
    else{assert(guid->a==0x1c34f691);*out=cmd_image+0x5088;}return 1;
}
static int path_descriptor(void *ctx,uint64_t function,uint64_t page,struct pgcd_descriptor *d,uint64_t *status)
{
    (void)ctx;assert(function==(uintptr_t)core+0x2c68&&early->record->outstanding);*status=0;
    if(page>=0x85fe0000&&page<0x86000000)*d=(struct pgcd_descriptor){0x85fe0000,0x20000,8,8,2,0,0,0};
    else{
        assert(page>=0x179e0000&&page<=0x179e2000);*d=(struct pgcd_descriptor){page,4096,1,0,3,0,0x123,0};
        if(jf==3&&path->CPU.local_restored)d->length=8192;
    }return 1;
}
static uint64_t query_abi(void *This,void *query,void *response,void *aux,uint32_t *status)
{
    assert(This==cmd_image+0x5088&&path->cmd.outstanding&&early->record->outstanding&&!DAIF&&Group1==1);
    uint8_t *q=query,*out=response;unsigned k;for(k=0;k<3&&memcmp(q,pwcd_names[k],9);k++){}assert(k<3);api_queries++;
    memcpy(out,q,9);memcpy(out+12,cmd_database+144+24*k+16,4);memcpy(out+16,cmd_database+144+24*k+8,8);
    put(out+24,32,4);put(out+28,0x100,2);memcpy(aux,cmd_database+144+0x1000+32*k,32);*status=0;return 0;
}
static int path_query(void *ctx,uint64_t fn,uint64_t This,uint8_t *q,uint8_t *out,uint8_t *aux,uint32_t *status,uint64_t *EFI_status)
{assert(fn==(uintptr_t)cmd_image+0x1878);return pwcd_actual_query(ctx,(uintptr_t)query_abi,This,q,out,aux,status,EFI_status);}
static int path_affinity(void *ctx,uint64_t target,int64_t *raw)
{
    (void)ctx;assert(target==0x100+0x100*(psci_calls%7));
    if(psci_calls<7)assert(!DAIF&&Group1==1&&early->record->outstanding);
    else assert(DAIF==0xc0&&!Group1&&!early->record->outstanding&&path->CPU.outstanding);
    psci_calls++;*raw=(jf==4&&psci_calls==8)||(jf==13&&psci_calls==1)?0:1;return 1;
}
static int path_mask(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;assert(!DAIF&&Group1==1&&psci_calls==7);mask_calls++;
    t->daif_before=DAIF;t->group_before=Group1;DAIF=0xc0;Group1=0;
    t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int path_restore(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;assert(DAIF==0xc0&&!Group1&&pwrsc_retired(&path->transaction)&&path->access.retired);unmask_calls++;
    t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
    t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int path_AT(void *ctx,struct pwrmd_translation *t)
{
    (void)ctx;t->saved=t->restored=0x12345678;t->read_par=t->write_par=t->page|0x280;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(jf==7&&path->access.events&&path->access.history[path->access.events-1].operation==2)t->write_par|=1;
    return 1;
}
static int path_read(void *ctx,uint64_t at,uint32_t *value)
{
    (void)ctx;
    if(at==0x179e000c)*value=(16u<<27)|(8u<<12);
    else{assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(hardware));*value=hardware[(at-PWRSC_BASE)/4];}
    return 1;
}
static int path_write(void *ctx,uint64_t at,uint32_t value)
{
    struct pwra_context *access=ctx;
    assert(access==&path->access_context&&path->access.outstanding&&path->access.local_held&&path->CPU.local_quiescent&&DAIF==0xc0&&!Group1);
    assert(cr->client_held&&!early->record->outstanding&&pwrsc_writable(&path->transaction,at,value));
    unsigned off=(unsigned)(at-PWRSC_BASE);assert(off&&off<sizeof(hardware));modeled_stores++;
    if(jf==11){assert(!pwra_write(access,at,value));return 1;}
    if(off==8){hardware[1]&=~value;acks++;return 1;}
    hardware[off/4]=value;
    if(jf==8)return 0;
    if(off%PWRSC_STRIDE==0x14&&(value&PWRSC_TRIGGER)){
        unsigned t=off-0x14;requests++;
        for(unsigned k=0;k<3;k++){
            uint32_t addr=hardware[(t+0x34+20*k)/4];unsigned resource=addr==0x30000?0:addr==0x30010?1:2;
            assert(addr==pwcd_addresses[resource]);votes[resource]=hardware[(t+0x38+20*k)/4];
            hardware[(t+0x3c+20*k)/4]=PWRSC_DONE;
            if(jf==12&&k==0)hardware[(t+0x3c)/4]|=0x20000;
        }
        if(jf!=1){hardware[1]|=1u<<(t/PWRSC_STRIDE);hardware[off/4]&=~PWRSC_TRIGGER;}
        if(jf==2&&requests==1)cmd_database[PWCD_DB_BYTES-1]^=1;
        if(jf==9&&requests==2)ticket->spent=1;
    }return 1;
}
static void configure(unsigned scenario)
{
    client_reset(0);jf=scenario;api_queries=psci_calls=mask_calls=unmask_calls=modeled_stores=requests=acks=0;DAIF=0;Group1=1;
    uint8_t *old=rimage;rimage=arena+0x400000;memcpy(rimage,old,PWRPI_IMAGE_BYTES);
    for(unsigned k=0;k<PWRPI_RELOC_COUNT;k++){
        uint8_t *p=rimage+pwrpi_relocs[k];uint64_t v=pwfi_le(p,8);
        if(v>=(uintptr_t)old&&v<(uintptr_t)old+PWRPI_IMAGE_BYTES)put(p,v+(uintptr_t)rimage-(uintptr_t)old,8);
    }
    ((struct efi_loaded*)(arena+0x188000))->base=rimage;
    /* Keep the modeled foreign pool OUTSIDE our expanded resident image.
     * Original allocations are4B-aligned, including pointer-bearing nodes. */
    uint8_t *old_links=links;links=arena+0x600000;memcpy(links,old_links,0x10000);
    for(unsigned k=0;k+8<=0x10000;k+=4){uint64_t value=pwfi_le(links+k,8);
        if(value>=(uintptr_t)old_links&&value<(uintptr_t)old_links+0x10000)put(links+k,value+(uintptr_t)links-(uintptr_t)old_links,8);}
    for(unsigned k=0xd2e8;k+8<=0xd3f8;k+=4){uint64_t value=pwfi_le(rimage+k,8);
        if(value>=(uintptr_t)old_links&&value<(uintptr_t)old_links+0x10000)put(rimage+k,value+(uintptr_t)links-(uintptr_t)old_links,8);}
    pool=links+(pool-old_links);active_header=links+(active_header-old_links);free_header=links+(free_header-old_links);
    foreign_client=links+(foreign_client-old_links);own_client=links+(own_client-old_links);
    self->bytes=r->self_owner.bytes=r->self_bytes=0x3c0000;
    struct pgcd_config original_config=*cfg;cfg=(void*)(arena+0x780000);*cfg=original_config;s->tables=cfg;
    path=(void*)(arena+0x240000);memset(path,0,sizeof(*path));assert(sizeof(*path)<0x180000);
    native_on=(void*)(arena+0x183000);*native_on=0;
    put(own_client+8,(uintptr_t)rimage+0xaf50,8);header(free_header,0,0,0);
    put(foreign_client+0x34,UINT32_MAX,4);
    for(unsigned k=0;k<4;k++){
        uint8_t *q=links+0xb004+32*k;put(foreign_client+0x10+8*k,(uintptr_t)q,8);memset(q,0,24);put(q,k<2?16:24,4);
    }
    for(unsigned k=0;k<5;k++){uint8_t *q=links+0x200+64*k;memset(q,0,40);put(q,40,4);}
    for(unsigned k=0;k<8;k++){put(links+0x400+24*k,k,4);put(links+0x404+24*k,k<4?0:3,4);}
    memset(rimage+0xd538,0,392);rimage[0xd538]=1;put(rimage+0xd53c,pwfi_le(rimage+0xd228,4),4);
    put(rimage+0xd538+48+0xc,0x179c0000,4);put(rimage+0xd538+48+0x10,2,4);rimage[0xd538+48+0x14]=1;
    put(rimage+0xd538+48+0x18,8,4);put(rimage+0xd538+48+0x1c,16,4);
    put(rimage+0xd2ec,3,4);put(rimage+0xd2f0,(uintptr_t)links+0x3004,8);
    static const uint32_t saved[3]={8,2,1};
    for(unsigned k=0;k<3;k++){
        uint8_t *row=links+0x3004+24*k,*state=links+0x4004+128*k;
        put(row,jf==5&&k==2?0x30070:pwcd_addresses[k],4);put(row+8,(uintptr_t)state,8);
        put(state,2,4);put(state+0xc,saved[k],4);state[0x10]=1;put(state+0x18,saved[k],4);state[0x1c]=1;votes[k]=saved[k];
    }
    cmd_image=arena+0x500000;memcpy(cmd_image,cmd_original,PWCDI_IMAGE_BYTES);
    for(unsigned k=0;k<PWCDI_RELOC_COUNT;k++)put(cmd_image+pwcdi_relocs[k],pwfi_le(cmd_image+pwcdi_relocs[k],8)+(uintptr_t)cmd_image,8);
    put(cmd_image+0x5158,0x85fe0000,8);put(cmd_image+0x5198,0x85fe0000,8);
    if(jf==14||jf==15){uint64_t bad=jf==14?0x861e0000:0x85fe1000;
        put(cmd_image+0x5158,bad,8);put(cmd_image+0x5198,bad,8);}
    struct efi_loaded *owner=(void*)(arena+0x188100);*owner=(struct efi_loaded){.revision=0x1000,.system=s,.base=cmd_image,.bytes=PWCDI_IMAGE_BYTES,.code_type=3,.data_type=4};
    enumeration->handle_count=2;enumeration->loaded_address[1]=(uintptr_t)owner;
    memset(cmd_database,0,sizeof(cmd_database));put(cmd_database,1,4);put(cmd_database+4,0x0c0330db,4);
    put(cmd_database+8,3,2);put(cmd_database+12,0x1000,2);put(cmd_database+14,3,2);put(cmd_database+16,0x100,2);
    const uint16_t levels[3][16]={{0,16,48,64,128,192,256,384,416},{0,16,16,256,384},{0,16,48,64,128,192,256,384}};
    for(unsigned k=0;k<3;k++){
        uint8_t *entry=cmd_database+144+24*k;memcpy(entry,pwcd_names[k],8);put(entry+8,k==1?0:4,4);put(entry+12,1,4);
        put(entry+16,pwcd_addresses[k],4);put(entry+20,32,2);put(entry+22,32*k,2);
        for(unsigned j=0;j<16;j++)put(cmd_database+144+0x1000+32*k+2*j,levels[k][j],2);
    }
    memset(hardware,0,sizeof(hardware));hardware[0]=4;for(unsigned k=0;k<8;k++)hardware[(PWRSC_STRIDE*k+0x18)/4]=1;
    memcpy(initial,hardware,sizeof(initial));
    c->io.arch=path_arch;c->io.map=path_core_map;c->io.query=path_descriptor;c->io.identity=path_identity;
    if(jf==10)cf=15;
}
static int execute(unsigned scenario)
{
    configure(scenario);
    const struct paic_io memory={s,0,path_memory_arch,path_identity,order};
    struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,path_map},client_create,client_drop,own_name};
    struct pwrpt_io io={{{memory,path_locate,path_map},path_query},{&memory,0,path_AT,path_read},
        {0,path_affinity,path_mask,path_restore},{&memory,&path->access_context,path_AT,path_read,path_write},enumeration,(uintptr_t)native_on,path};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,pwrpt_body,&io);
}
static char *parent_report;static size_t parent_report_bytes,parent_report_capacity;
static void parent_append(const char *s)
{size_t n=strlen(s);assert(n<=parent_report_capacity-parent_report_bytes);memcpy(parent_report+parent_report_bytes,s,n);parent_report_bytes+=n;}
static int cached_parent(void)
{memcpy(&pwrpt_record,path,sizeof(*path));memcpy(&pwrcl_record,cr,sizeof(*cr));return pwrpt_parent_unsafe();}
static void check_raw_segment(const char *begin,const char *end,const void *raw,size_t bytes)
{
    char *s=strstr(parent_report,begin);assert(s);s+=strlen(begin);assert(!strncmp(s+bytes*2,end,strlen(end)));
    const uint8_t *p=raw;for(size_t k=0;k<bytes;k++)assert(s[k*2]=="0123456789abcdef"[p[k]>>4]&&s[k*2+1]=="0123456789abcdef"[p[k]&15]);
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;int ok=execute(0);
    if(!ok||path->error||pwrpt_unsafe(path))fprintf(stderr,"path err%u phase%u unknown%u clienterr%u reader%u CPU%u access%u tx%u dev%u/%u cmd%u calls%u/%u stores%u earlycore%u stage%u opened%u attempted%u RAM%u rows%u/%u\n",path->error,path->phase,path->unknown,cr->error,cr->reader.error,path->CPU.error,path->access.error,path->transaction.error,path->device[0].error,path->device[1].error,path->cmd.error,api_queries,psci_calls,modeled_stores,cr->core.error,early->stage,early->opened,cr->core.attempted,path->RAM[0].error,path->RAM[0].rows,path->RAM[0].clients);
    assert(ok&&path->retired&&!path->error&&!pwrpt_unsafe(path)&&cr->client_returned&&cr->retired&&!pwrcl_result_unsafe(cr));
    assert(api_queries==6&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&requests==2&&acks==2&&delete_calls==1&&!ticket->spent);
    assert(path->transaction.tcs==2&&path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete);
    assert(votes[0]==8&&votes[1]==2&&votes[2]==1&&!memcmp(hardware,initial,0x30));checks++;
    assert(!cached_parent());
    parent_report_capacity=2*(sizeof(pwrpt_record)+sizeof(pwrcl_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_CLIENT_RAW_V1_END",&pwrcl_record,sizeof(pwrcl_record));
    check_raw_segment("WIFI_POWER_PATH_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_PATH_RAW_V1_END",&pwrpt_record,sizeof(pwrpt_record));
    assert(!strstr(parent_report,"ZERO_VOTE")&&strstr(parent_report,"NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION"));checks++;
    free(parent_report);
    for(unsigned k=1;k<=15;k++){
        ok=execute(k);
        if(k==5||k==14||k==15){assert(ok&&path->known_refusal&&path->retired&&path->refusal.retired&&!path->unknown&&!modeled_stores&&!mask_calls&&delete_calls==1);}
        else{
            if(ok||!pwrcl_result_unsafe(cr))fprintf(stderr,"unexpected fault%u ok%d err%u phase%u client%u unknown%u del%u\n",k,ok,path->error,path->phase,cr->error,path->unknown,delete_calls);
            assert(!ok&&pwrcl_result_unsafe(cr)&&cr->client_held&&cr->unknown);
            if(k!=10)assert(!delete_calls);
            if(k==1)assert(!acks&&!unmask_calls&&DAIF==0xc0);
            if(k==2)assert(path->transaction.restored&&!unmask_calls&&DAIF==0xc0&&path->access.CmdDb[1].bytes==PWCD_DB_BYTES);
            if(k==3)assert(path->CPU.local_restored&&unmask_calls==1&&!DAIF);
            if(k==4||k==6||k==7)assert(!modeled_stores&&!unmask_calls&&DAIF==0xc0);
            if(k==8||k==11)assert(modeled_stores==1&&!requests&&!acks&&!unmask_calls&&DAIF==0xc0);
            if(k==9)assert(path->retired&&ticket->spent&&!delete_calls);
            if(k==10)assert(path->retired&&delete_calls==1&&cr->outstanding&&!cr->client_returned);
            if(k==12)assert(path->access.error==PWRA_UNKNOWN_STATUS&&(path->access.command_status_OR[0]&0x20000)&&!acks&&!unmask_calls);
            if(k==13)assert(!mask_calls&&!modeled_stores&&!path->refusal.attempted&&path->unknown);
        }assert(cached_parent()==(k!=5&&k!=14&&k!=15));checks++;
    }
    printf("{\"checks\":%u,\"path_raw_bytes\":%zu,\"access_raw_bytes\":%zu,\"CPU_raw_bytes\":%zu,\"ONE_SOFTWARE_original_API_to_RSC_retirement_path\":true,\"queries\":6,\"PSCI_calls\":14,\"real_firmware_or_MMIO_execution\":false,\"physical_lease_proven\":false,\"parent_cached_gate_checked\":true,\"whole_raw_report_bytes\":%zu,\"parent_registered\":false}\n",checks,sizeof(*path),sizeof(path->access),sizeof(path->CPU),parent_report_bytes);
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}

/* SOFTWARE full staged preparation using original images as data. No real
 * firmware, AT, CPU_ON, clients, PSCI, MMIO or radio operation executes. */
#define EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE 1
#define POLARIS_CMDDB_BOUNDED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-bounded-test.c"
static struct pwsp_result *prep;
static unsigned sf,locates,part_maps,part_translates,injected;
static int staged_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    struct pwsp_phase *p=&prep->phase[prep->active];ns=&p->namespace;ng=&p->context;
    if(m==&p->core.map[0]){
        part_maps=part_translates=0;
        if(sf==2&&prep->active==1)*native_on=1;
        if(sf==6&&prep->active==1){put(cmd_image+0x5158,0x85fe1000,8);put(cmd_image+0x5198,0x85fe1000,8);}
        if(sf==13&&prep->active==1)put(nodes+80+48,9,8);
        if(sf==16&&prep->active==2)cmd_database[PWCD_DB_BYTES-1]^=1;
    }
    struct paic_map_sample sample={0};assert(ns_map(ctx,sys,out,&sample));maps++;part_maps++;
    m->status=sample.status;m->bytes=sample.bytes;m->key=sample.key;m->stride=sample.stride;m->version=sample.version;
    if(m==&p->core.map[1]){
        if(sf==5)cmd_image[0x1000]^=1;
        if(sf==7)((struct efi_loaded*)(arena+0x188000))->bytes--;
        if(sf==8)m->key++;
        if(sf==9)return 0;
        if(sf==10)m->version=2;
        if(sf==21)put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+88,8);
        if(sf==22&&!injected){cmd_database[0x1000]^=1;injected=1;}
    }
    return 1;
}
static int staged_locate(void *ctx,struct efi_system *sys,const efi_guid *guid,void **out,uint64_t *status)
{locates++;if(sf==23){*status=0;return 0;}int ok=path_locate(ctx,sys,guid,out,status);if(sf==12)cmd_image[0x5088+8]^=1;return ok;}
static int staged_arch(void *ctx,struct pgcd_arch *a)
{
    int ok=path_arch(ctx,a);struct pwsp_phase *p=&prep->phase[prep->active];
    if(sf==14&&p->bytes>=8192)a->cpu.ticks=p->core.before.cpu.ticks+3840001;
    if(sf==15&&p->bytes>=4096)a->cpu.ticks=p->core.before.cpu.ticks-1;
    if(sf==18&&p->bytes>=4096)a->cpacr=0;
    return ok;
}
static int staged_restore(void *ctx,struct pgcd_fp_guard *g)
{int ok=fp_restore(ctx,g);if(sf==17&&part_maps==2){g->restored=0;return 0;}return ok;}
static int staged_AT(void *ctx,struct pgns_translation *t)
{
    struct pwsp_phase *p=&prep->phase[prep->active];part_translates++;
    if(sf==3&&prep->active==2)ticket->spent=1;
    if(sf==4&&p->bytes>=4096&&!injected){core[0x1000]^=1;injected=1;}
    if(sf==11&&p->bytes>=4096){t->issued=1;return 0;}
    if(sf==19&&p->preflight_pages==PWSP_PAGES&&p->bytes==0){t->issued=t->returned=1;t->saved=1;t->restored=2;return 1;}
    if(sf==20&&p->preflight_pages==PWSP_PAGES&&p->bytes==0)*native_on=1;
    return ns_AT(ctx,t);
}
static void staged_reset(unsigned scenario,unsigned nodefault,unsigned count)
{
    configure(0);sf=scenario;nf=nodefault;ntrans=flipped=original_queries=locates=part_maps=part_translates=injected=0;
    prep=(void*)(arena+0x240000);memset(prep,0,sizeof(*prep));assert((uint8_t*)prep+sizeof(*prep)<arena+0x480000);
    c->io.arch=staged_arch;c->io.map=staged_map;c->io.identity=path_identity;c->io.query=no_original_GCD;c->io.fp_restore=staged_restore;
    ns=&prep->phase[0].namespace;ng=&prep->phase[0].context;fill_namespace(count);
    if(sf==1)*native_on=1;
    if(sf==24){put(cmd_image+0x5158,0x861e0000,8);put(cmd_image+0x5198,0x861e0000,8);}
    if(sf==25)cmd_database[4]^=1;
}
static int staged_execute(void)
{
    const struct paic_io memory={s,0,path_memory_arch,path_identity,order};
    const struct pwsp_io io={&memory,0,staged_locate,staged_AT};
    return pwsp_run(&io,enumeration,2,c,native_on,prep);
}
static void no_hardware(void)
{assert(!create_calls&&!delete_calls&&!cr->attempted&&!pwrcl_record.attempted&&!original_queries&&!api_queries&&!psci_calls&&!mask_calls&&!unmask_calls&&!modeled_stores&&!requests&&!acks);}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(unsigned count=3;count<=512;count+=509){
        staged_reset(0,0,count);struct pgcd_result before=*r;struct pgcd_lifetime initial=*ticket;
        int ok=staged_execute();if(!ok)fprintf(stderr,"staged%u global%u phase%u err%u core%u ns%u reader%u bytes%u\n",count,prep->error,prep->active,prep->phase[prep->active].error,prep->phase[prep->active].core.error,prep->phase[prep->active].namespace.error,prep->phase[prep->active].reader.error,prep->phase[prep->active].bytes);
        assert(ok&&prep->complete&&prep->retired&&!pwsp_unsafe(prep)&&prep->parts==4&&maps==8&&locates==4);
        assert(!memcmp(&before,r,sizeof(before))&&!memcmp(&initial,ticket,sizeof(initial))&&pwrcl_final_unopened(c));
        assert(!memcmp(prep->database[0],cmd_database,PWCD_DB_BYTES)&&!memcmp(prep->database[1],cmd_database,PWCD_DB_BYTES));
        for(unsigned k=0;k<4;k++){
            const struct pwsp_phase *p=&prep->phase[k];assert(p->retired&&p->complete&&!p->unknown&&p->bytes==65536&&p->offset==(k&1)*65536);
            assert(p->core.phase==3&&p->context.finished&&p->ticket.spent==1&&p->ticket.result==(uintptr_t)&p->core);
            assert(p->core.map[0].key==p->core.map[1].key&&p->namespace.stable&&p->namespace.pass[1].count==count);
            assert(p->native_before_valid&&p->native_after_valid&&!p->native_before&&!p->native_after&&p->native_reads);
            assert(p->reader.complete&&p->reader.closed&&p->reader.image_count==enumeration->handle_count);
            for(unsigned j=0;j<17;j++)assert(p->target[j].complete&&p->target[j].hash_count==5&&!p->target[j].hash_failed);
            if(k)assert(p->core.before.cpu.ticks>prep->phase[k-1].core.after.cpu.ticks);
        }
        assert(prep->parsed[0]&&prep->parsed[1]&&prep->resources[0][0].index==7&&prep->resources[0][1].index==4&&prep->resources[0][2].index==7);no_hardware();checks++;
    }
    for(unsigned scenario=1;scenario<=25;scenario++){
        staged_reset(scenario,0,3);int ok=staged_execute();no_hardware();
        if(scenario==24||scenario==25){assert(ok&&prep->known_refusal&&prep->retired&&!prep->complete&&!pwsp_unsafe(prep));}
        else{if(ok)fprintf(stderr,"unexpected staged success%u\n",scenario);assert(!ok&&prep->unknown&&pwsp_unsafe(prep));}
        if(scenario==11)assert(prep->phase[0].bytes==4096&&prep->phase[0].namespace.outstanding);
        if(scenario==16)assert(prep->parts==4&&prep->error==PWSP_CHANGED&&!memcmp(prep->database[0],prep->database[1],PWCD_DB_BYTES-1));
        if(scenario==24)assert(!prep->phase[0].namespace.attempted&&!prep->phase[0].bytes&&prep->parts==0);
        checks++;
    }
    const unsigned nodefaults[]={3,4,7,8,9,10,11,12,13,14,15,18,19,20,25,27};
    for(unsigned k=0;k<sizeof(nodefaults)/sizeof(nodefaults[0]);k++){
        unsigned f=nodefaults[k];staged_reset(0,f,f==18?513:3);assert(!staged_execute()&&pwsp_unsafe(prep));no_hardware();checks++;
    }
    for(unsigned f=23;f<=24;f++){
        staged_reset(0,f,3);assert(staged_execute()&&prep->known_refusal&&prep->retired&&!pwsp_unsafe(prep)&&!prep->phase[0].bytes);no_hardware();checks++;
    }
    staged_reset(0,0,3);assert(staged_execute());unsigned oldmaps=maps;assert(!staged_execute()&&prep->unknown&&maps==oldmaps);checks++;
    staged_reset(0,0,3);ticket->spent=1;assert(!staged_execute()&&prep->unknown&&!maps&&!locates);checks++;
    staged_reset(0,0,3);prep->phase[2].ticket.spent=1;assert(!staged_execute()&&prep->unknown&&prep->parts==2&&locates==2&&maps==4);checks++;
    staged_reset(0,0,3);assert(staged_execute());pwsp_record=*prep;
    parent_report_capacity=2*sizeof(pwsp_record)+2048;parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_CMDDB_STAGED_RO_RAW_V1_BEGIN\r\n","\r\nWIFI_CMDDB_STAGED_RO_RAW_V1_END",&pwsp_record,sizeof(pwsp_record));
    assert(!strstr(parent_report,"WIFI_POWER_CLIENT_RAW")&&!strstr(parent_report,"WIFI_POWER_PATH_RAW")&&!strstr(parent_report,"ZERO_VOTE"));checks++;
    assert(!pwrpt_parent_unsafe());pwsp_record.phase[2].target[0].complete=0;assert(pwrpt_parent_unsafe());checks++;
    printf("{\"passed\":true,\"checks\":%u,\"staged_raw_bytes\":%zu,\"phase_bytes\":%zu,\"RO_owner_bytes\":%zu,\"source_bytes\":%zu,\"actual_two_DB_assembled_in_SOFTWARE\":true,\"same_final_ticket_unchanged\":true,\"private_Create_Delete_Query_PSCI_RSC\":0,\"physical_firmware_executed\":false}\n",checks,sizeof(*prep),sizeof(struct pwsp_phase),sizeof(struct pgns_ro_owner),sizeof(struct pwsp_source));
    free(parent_report);free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}

/* Actual later-parent relay with explicit SOFTWARE BS/AT/FP/clock leaves.
 * Original Core PE is inert DATA. No device or original code executes. */
#define main current_map_original_GCD_fixture_not_executed
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-current-map.h"
static struct pcmp_result*cur;static struct pcmp_payload*binding;static struct ppli_result*images;
static struct pcmp_input current_input;static struct pgcd_io original_io;
static uint32_t*cpu_flag,*load_flag;static uint8_t**payload_slot,**log_slot;
static uint64_t*got,*count;static struct polaris_plan*boot_plan;static uint8_t*payload_data,*log_data;
static struct pcmp_result*integration_records[2];static unsigned integration_mode;
static unsigned stage,mutation,mutbyte,triggered,which_fault,leaf_maps,leaf_arches,leaf_saves,leaf_restores,leaf_pages;
static uint8_t enum_map[65536] __attribute__((aligned(8)));
static uint64_t fixture_image_bytes=0x300000;
static int inventory_page(struct ppli_at*a)
{a->saved=a->restored=0x123400;a->par=UINT64_C(0xff00000000000b80)|a->page;a->issued=a->returned=1;return 1;}
static void change(unsigned where)
{
    if(triggered||where!=stage||!mutation)return;triggered=1;
    switch(mutation){case 1:((uint8_t*)cur)[mutbyte]^=1;break;case 2:c->record=(void*)8;break;case 3:c->ticket=(void*)8;break;
    case 4:*payload_slot=(void*)8;break;case 5:*log_slot=(void*)8;break;case 6:*got=0;break;case 7:*count=0;break;
    case 8:*load_flag=3;break;case 9:*cpu_flag=1;break;case 10:boot_plan->top++;break;case 11:binding->header[0]^=1;break;
    case 12:images->entry[0].image[0].bytes--;break;case 13:s->boot=(void*)8;break;case 14:self->bytes--;break;
    case 15:cur->call.boot_address=8;s->boot=(void*)8;break;case 16:cur->header[0]^=1;break;
    case 17:current_input.context=(void*)8;break;case 18:original_io.arch=0;break;
    case 19:r->map_guard[cur->slot].fp.saved=0;break;case 20:cur->source_before.self_owner_address=8;break;
    case 21:c->io.map=original_io.map;break;case 22:cur->call.input.system=(void*)8;break;
    case 23:cur->header_bytes=PCMP_HEADER_CAP+1;break;case 24:cur->images_before.count=UINT64_MAX;break;default:assert(0);}
}
static int current_arch(void*o,struct pgcd_arch*a)
{leaf_arches++;int ok=arch(o,a);if((which_fault==7&&leaf_arches==3)||(which_fault==9&&leaf_arches==1))a->cpu.ticks+=PGCD_FRESH_TICKS;change(leaf_arches==1?0:leaf_arches==2?4:7);return ok;}
static int current_save(void*o,struct pgcd_fp_guard*g)
{leaf_saves++;int ok=fp_save(o,g);change(1);return ok;}
static int current_restore(void*o,struct pgcd_fp_guard*g)
{leaf_restores++;int ok=fp_restore(o,g);change(5);return ok;}
static void current_order(void*o){(void)o;change(2);}
static int current_map(void*o,struct efi_system*sys,struct pgcd_map*m,void*out)
{
    (void)o;assert(sys==s);leaf_maps++;
    struct efi_memory rows[5]={{3,0,(uintptr_t)arena,0,fixture_image_bytes/4096,8},{2,0,0xc0000000,0,512,8},
        {2,0,(uintptr_t)payload_data,0,1,8},{2,0,(uintptr_t)log_data,0,1,8},
        {6,0,(uintptr_t)cfg,0,1,UINT64_C(0x800000000000000f)}};
    for(unsigned n=0;n<5;n++){memcpy((uint8_t*)out+48*n,&rows[n],40);memset((uint8_t*)out+48*n+40,0x5a,8);}
    m->status=0;m->bytes=240;m->key=1234;m->stride=48;m->version=1;
    if(which_fault==1)return 0;if(which_fault==2)m->status=EFI_ERROR|5;if(which_fault==3)m->bytes=PGCD_MAP_CAP+8;
    if(which_fault==4)((struct efi_memory*)((uint8_t*)out+96))->type=7;
    if(which_fault==5)((struct efi_memory*)((uint8_t*)out+144))->type=7;
    if(which_fault==8)payload_data[0]^=1;
    change(3);return 1;
}
static int current_page(struct ppli_at*a)
{leaf_pages++;int ok=inventory_page(a);if(which_fault==6)a->returned=0;change(6);return ok;}
static int(*current_fixture_page)(struct ppli_at*)=current_page;
static int fixture_relay(void*o,struct efi_system*sys,struct pgcd_map*m,void*data)
{assert(!o&&sys==s);if(integration_mode){unsigned slot=m==&r->map[0]?0:1;cur=integration_records[slot];}return pcmp_read(cur,&current_input,&original_io,m,data,current_fixture_page);}
static int current_identity(void*o,uint64_t at,uint64_t bytes,uint64_t*where,uint64_t*par)
{(void)o;(void)bytes;*where=at;*par=UINT64_C(0xff00000000000b80)|(at&~UINT64_C(4095));return 1;}
static void setup_current(unsigned slot)
{
    reset(0);memset(arena+0x100000,0,0x200000);self->bytes=fixture_image_bytes;memset(r,0,sizeof(*r));assert(pgcd_bind(r,self));
    struct pgcd_config old_config=cfg[0];cfg=(void*)(arena+fixture_image_bytes);cfg[0]=old_config;s->tables=cfg;
    cur=(void*)(arena+0x100000);binding=(void*)(arena+0x160000);images=(void*)(arena+0x170000);
    assert((uint8_t*)cur+sizeof(*cur)<(uint8_t*)binding);
    cpu_flag=(void*)(arena+0x1c0000);load_flag=cpu_flag+1;payload_slot=(void*)(cpu_flag+2);log_slot=payload_slot+1;
    got=(void*)(log_slot+1);count=got+1;boot_plan=(void*)(count+1);
    *load_flag=2;*payload_slot=payload_data;*log_slot=log_data;*got=*count=4096;
    *boot_plan=(struct polaris_plan){0xc0010000,0xc0014000,0xc0018000,0xc0008000};
    memset(payload_data,0,4096);struct polaris_payload*p=(void*)payload_data;
    memcpy(p->magic,"SWEETXNU",8);p->version=1;p->nsegs=1;p->phys_base=0xc0000000;p->mem_size=0x200000;
    strcpy(p->cmdline,"ufsrw=0 polarisramcow=1 polarisrammb=512");assert(pcmp_payload_bind(binding,payload_data,4096,boot_plan));
    memset(enum_map,0,sizeof(enum_map));*(struct efi_memory*)enum_map=(struct efi_memory){3,0,(uintptr_t)arena,0,fixture_image_bytes/4096,8};
    uint64_t*handle=(void*)(arena+0x1d0000);*handle=0x123;
    assert(ppli_bind(images,cpu_flag,0x123)&&ppli_start(images,(uintptr_t)s,(uintptr_t)handle,1,enum_map,40,40,12,100,inventory_page));
    assert(ppli_capture(images,0,0,*handle,(uintptr_t)self,inventory_page)&&ppli_second(images,enum_map,40,40,12,inventory_page));
    assert(ppli_capture(images,1,0,*handle,(uintptr_t)self,inventory_page)&&ppli_finish(images,200));
    original_io=(struct pgcd_io){.system=s,.arch=current_arch,.map=current_map,.identity=current_identity,.query=query,
        .fp_save=current_save,.fp_restore=current_restore,.order=current_order};c->io=original_io;c->io.map=fixture_relay;
    stage=mutation=which_fault=triggered=integration_mode=0;
    if(slot){r->map[0]=(struct pgcd_map){.bytes=PGCD_MAP_CAP,.issued=1};assert(current_map(0,s,&r->map[0],r->maps[0]));r->map[0].returned=r->map[0].valid=1;}
    c->opened=c->finished=slot;ticket->spent=1;ticket->result=(uintptr_t)r;r->attempted=1;r->phase=slot;
    r->outstanding=0x20000+slot;r->pre_mask=r->post_mask=slot?15:0;
    r->before=(struct pgcd_arch){.cpu={.el=4,.mpidr=0x81000000,.ttbr0=0x180000001,.tcr=0x80803520,.sctlr=0x30d00801,.mair=0xffbb4400,
        .sre=1,.group1=1,.frequency=19200000,.ticks=1000},.cpacr=0x300000};r->after=r->before;
    r->map[slot]=(struct pgcd_map){.bytes=PGCD_MAP_CAP,.issued=1};r->map_guard[slot].entered=r->map_guard[slot].unknown=1;r->map_guard[slot].fp.saved=1;
    current_input=(struct pcmp_input){.context=c,.image=self,.images=images,.payload_binding=binding,.native_flag=cpu_flag,.load_state=load_flag,
        .payload_slot=payload_slot,.log_slot=log_slot,.received=got,.payload_count=count,.plan=boot_plan,
        .image_handle=0x123,.bank=0xc0000000,.bank_bytes=0x200000,.log_bytes=4096};
    stage=mutation=mutbyte=triggered=which_fault=leaf_maps=leaf_arches=leaf_saves=leaf_restores=leaf_pages=0;
    arches=saves=restores=0;
}
static int run_current(unsigned slot)
{return fixture_relay(0,s,&r->map[slot],r->maps[slot]);}
#ifndef POLARIS_CURRENT_MAP_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert((argc==2||argc==3)&&!posix_memalign((void**)&arena,4096,0x401000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;
    /* Exercise the real generic pgcd_open/query/finish call chain as well as
     * the individual callback faults below. Only its IO leaves are simulated. */
    setup_current(0);integration_records[0]=cur;integration_records[1]=(void*)(arena+0x200000);
    memset(r,0,sizeof(*r));assert(pgcd_bind(r,self));memset(ticket,0,sizeof(*ticket));
    *c=(struct pgcd_context){.io=original_io,.record=r,.ticket=ticket,.stage=2};c->io.map=fixture_relay;integration_mode=1;
    for(unsigned k=0;k<4;k++){
        const struct pgcd_observation*observation=0;int ok=pgcd_query_page(c,pgcd_pages[k],&observation);
        if(!ok)fprintf(stderr,"integration index%u GCDerror%u phase%u uncertain%u opened%u currenterror%u complete%u maps%u arches%u\n",k,r->error,r->phase,r->uncertain,c->opened,cur->error,cur->complete,leaf_maps,leaf_arches);
        assert(ok);
    }
    assert(pgcd_finish(c)&&r->phase==2&&c->finished&&ticket->spent==1&&leaf_maps==2);
    assert(integration_records[0]->complete&&integration_records[1]->complete&&!integration_records[0]->unknown&&!integration_records[1]->unknown);checks++;
    for(unsigned slot=0;slot<2;slot++){
        setup_current(slot);assert(run_current(slot));assert(cur->complete&&!cur->unknown&&!cur->error&&leaf_maps==1&&leaf_pages==1&&leaf_arches==3&&leaf_saves==1&&leaf_restores==1);
        assert(cur->map_issued==1&&cur->map_returned==1&&r->map[slot].key==1234&&r->map[slot].valid&&cur->slot==slot);checks++;
        for(unsigned faultno=1;faultno<=9;faultno++){
            setup_current(slot);which_fault=faultno;assert(!run_current(slot)&&cur->unknown&&!cur->complete);
            if(faultno<=5)assert(!leaf_pages&&!leaf_restores);if(faultno<=2)assert(leaf_arches==1);
            if(faultno==6)assert(cur->header_AT.issued==1&&!cur->header_AT.returned&&leaf_arches==2);checks++;
            if(faultno==9)assert(!leaf_maps&&!leaf_saves&&!leaf_pages);
        }
        for(unsigned when=0;when<8;when++)for(unsigned bad=2;bad<=24;bad++){
            setup_current(slot);stage=when;mutation=bad;assert(!run_current(slot)&&triggered&&cur->unknown&&!cur->complete);
            assert(leaf_maps==(when>=3));if(when<=4)assert(!leaf_restores);if(when<=6)assert(leaf_arches<3);checks++;
        }
        for(unsigned when=0;when<8;when++)for(unsigned off=0;off<sizeof(struct pcmp_input);off++){
            setup_current(slot);stage=when;mutation=1;mutbyte=off;assert(!run_current(slot)&&triggered&&cur->unknown&&!cur->complete);
            assert(leaf_maps==(when>=3));if(when<=4)assert(!leaf_restores);if(when<=6)assert(leaf_arches<3);checks++;
        }
        for(unsigned bad=0;bad<16;bad++){
            setup_current(slot);
            switch(bad){case 0:c->stage=1;break;case 1:c->io.opaque=(void*)8;break;case 2:c->io.map=original_io.map;break;
            case 3:ticket->spent=2;break;case 4:ticket->result=0;break;case 5:r->self_owner_address++;break;
            case 6:r->outstanding++;break;case 7:r->phase++;break;case 8:r->self_bound=0;break;case 9:*count=1024;break;
            case 10:*load_flag=1;break;case 11:*cpu_flag=1;break;case 12:images->entry[0].image[1].bytes--;break;
            case 13:binding->header[0]^=1;break;case 14:if(slot)r->map[0].valid=0;else c->opened=1;break;case 15:r->before.cpu.ticks=0;break;}
            assert(!run_current(slot)&&cur->unknown&&!cur->complete&&!leaf_maps&&!leaf_arches&&!leaf_saves&&!leaf_pages);checks++;
        }
    }
    setup_current(1);assert(run_current(1));
    if(argc==3){FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(cur,1,sizeof(*cur),out)==sizeof(*cur)&&!fclose(out));}
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"payload_binding_bytes\":%zu,\"input_bytes\":%zu,\"call_offset\":%zu,\"digest_offset\":%zu,\"SOFTWARE_only\":true,\"firmware_executed\":false}\n",checks,sizeof(*cur),sizeof(*binding),sizeof(current_input),offsetof(struct pcmp_result,call),offsetof(struct pcmp_result,digest));
    free(original);free(arena);free(payload_data);free(log_data);return 0;
}
#endif

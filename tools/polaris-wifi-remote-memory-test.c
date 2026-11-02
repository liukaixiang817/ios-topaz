/* Actual allocation adapter/control flow with SOFTWARE BS/AT leaves only.
 * The pinned original PE is inert DATA for full immutable-source checks.
 * No firmware instruction, physical allocator, page-table write or USB runs.
 */
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#define POLARIS_WIFI_MEMORY_SOFTWARE_PEER 1
#define main pwmc_original_GCD_fixture_not_executed
#include "polaris-uefi-gcd-test.c"
#undef main
#include "uefi-wifi-remote-memory.h"
static struct pwmc_result*mr;
static unsigned mf,mt,claims,drops,translations,physical_owned,active_stride=48;
static unsigned event_ATs;static uint8_t*event_base;
static unsigned allocator_ATs;static uint8_t*allocator_base;
static uint64_t allocated_base,allocated_bytes;
static uint64_t live_base[2],live_bytes[2];static unsigned live[2];
static int memory_identity(void*p,uint64_t at,uint64_t bytes,uint64_t*where,uint64_t*par)
{
    unsigned op=mr&&mr->source[1].attempted?1:0;
    if(mr&&mr->events[op].attempted&&!mr->events[op].complete&&mr->events[op].count<PWMC_EVENT_MAX&&
       mr->events[op].node[mr->events[op].count].issued){event_ATs++;if(mf==32&&event_ATs==mt)return 0;}
    if(mr&&mr->allocator[op].attempted&&!mr->allocator[op].complete){
        for(unsigned list=0;list<2;list++)if(mr->allocator[op].count[list]<PWMC_MAP_NODE_MAX&&
           mr->allocator[op].node[list][mr->allocator[op].count[list]].issued){allocator_ATs++;if(mf==33&&allocator_ATs==mt)return 0;}
    }
    int ok=identity(p,at,bytes,where,par);if(ok)*par|=UINT64_C(0xff00000000000b80);return ok;
}
static void corrupt_pending(void)
{
    struct pwmc_call*q=&mr->call[0];
    switch(mt){
    case 1:q->guard.entered=0;break;case 2:q->guard.unknown=0;break;
    case 3:q->guard.left=1;break;case 4:q->guard.foreign_returned=1;break;
    case 5:q->guard.fp.saved=0;break;case 6:q->guard.fp.restored=1;break;
    case 7:q->guard.TPL_before=8;break;case 8:q->guard.boot_before+=8;break;
    case 9:q->guard.tables_before+=8;break;case 10:q->guard.count_before++;break;
    case 11:mr->source[0].outstanding=0x10001;break;case 12:mr->source[0].uncertain=1;break;
    case 13:q->requested+=4096;break;case 14:q->returned_address+=4096;break;
    case 15:q->pages++;break;case 16:q->entry+=4;break;case 17:q->native_address+=4;break;
    case 18:q->issued=2;break;case 19:q->returned=1;break;default:assert(0);
    }
}
static int memory_arch(void*p,struct pgcd_arch*a)
{
    int ok=arch(p,a);
    if(mf==14&&claims)a->cpu.daif=0x80;
    if(mf==22&&!claims&&mr->call[0].guard.entered)mr->kind^=1;
    if(mf==27&&!claims&&mr->call[0].guard.entered&&mr->call[0].entry)corrupt_pending();
    if(mf==29&&claims&&mr->call[0].returned&&!mr->call[0].guard.left)put(core+0x1b838,(uintptr_t)core+0xd3f0,8);
    if(mf==30&&!claims&&mr->events[0].complete)put(core+0x1dbc0,1,8);
    if(mf==34&&!claims&&mr->allocator[0].complete)put(core+0x1cc08,1,8);
    return ok;
}
static void memory_order(void*p)
{
    order(p);
    if(mf==13&&mr->call[0].issued&&!claims)mr->call[0].pages++;
    if(mf==28&&mr->call[0].issued&&!claims)corrupt_pending();
    if(mf==31&&mr->call[0].issued&&!claims)put(core+0x1dbc0,1,8);
    if(mf==35&&mr->call[0].issued&&!claims)put(core+0x1dc10,1,8);
}
static void descriptor(uint8_t*out,unsigned index,uint32_t type,uint64_t base,uint64_t pages,uint64_t attrs)
{
    struct efi_memory*d=(void*)(out+active_stride*index);*d=(struct efi_memory){type,0,base,0,pages,attrs};
    for(unsigned k=40;k<active_stride;k++)out[active_stride*index+k]=0x5a;
}
static int memory_map(void*p,struct efi_system*sys,struct pgcd_map*m,void*out)
{
    (void)p;assert(sys==s);maps++;assert(m->issued);
    memset(out,0,PGCD_MAP_CAP);descriptor(out,0,3,(uintptr_t)arena,0x100000/4096,8);
    descriptor(out,1,4,(uintptr_t)arena+0x100000,0x100000/4096,8);
    unsigned n=2;uint64_t cursor=0xc0000000,hi=0xc2000000;
    for(unsigned step=0;step<2;step++){
        unsigned which=2;for(unsigned k=0;k<2;k++)if(live[k]&&live_base[k]>=cursor&&(which==2||live_base[k]<live_base[which]))which=k;
        if(which==2)break;
        if(live_base[which]>cursor)descriptor(out,n++,7,cursor,(live_base[which]-cursor)/4096,mf==7?9:8);
        descriptor(out,n++,mf==8?7:2,live_base[which],live_bytes[which]/4096,8);cursor=live_base[which]+live_bytes[which];
    }
    if(cursor<hi)descriptor(out,n++,7,cursor,(hi-cursor)/4096,8);
    if(mf==20){uint8_t copy[PGCD_MAP_CAP];memcpy(copy,out,n*active_stride);for(unsigned k=0;k<n;k++)memcpy((uint8_t*)out+k*active_stride,copy+(n-1-k)*active_stride,active_stride);}
    m->bytes=n*active_stride;m->stride=active_stride;m->version=1;m->key=1+claims+drops;m->status=0;return 1;
}
static void allocator_chain(unsigned list,const uint32_t*types,const uint64_t*bases,const uint64_t*pages,unsigned count)
{
    uint64_t head=(uintptr_t)core+(list?0x1bcc0:0x1b358),previous=head;uint8_t*base=allocator_base+list*0x20000;
    assert(count<=PWMC_MAP_NODE_MAX+1);
    for(unsigned k=0;k<count;k++){
        uint8_t*n=base+128*k;memset(n,0,64);put(n,0x70616d6d,8);
        put(n+8,k+1<count?(uintptr_t)n+128+8:head,8);put(n+16,previous,8);n[24]=1;
        if(!list){put(n+28,types[k],4);put(n+32,bases[k],8);put(n+40,bases[k]+4096*pages[k]-1,8);put(n+56,8,8);}
        previous=(uintptr_t)n+8;
    }
    put((void*)(uintptr_t)head,count?(uintptr_t)base+8:head,8);put((void*)(uintptr_t)(head+8),previous,8);
}
static void allocator_model(void)
{
    uint32_t types[8]={3,4};uint64_t bases[8]={(uintptr_t)arena,(uintptr_t)arena+0x100000},pages[8]={256,256};
    unsigned n=2;uint64_t cursor=0xc0000000;
    for(unsigned step=0;step<2;step++){
        unsigned which=2;for(unsigned k=0;k<2;k++)if(live[k]&&live_base[k]>=cursor&&(which==2||live_base[k]<live_base[which]))which=k;
        if(which==2)break;
        if(cursor<live_base[which]){types[n]=7;bases[n]=cursor;pages[n++]=(live_base[which]-cursor)/4096;}
        types[n]=2;bases[n]=live_base[which];pages[n++]=live_bytes[which]/4096;cursor=live_base[which]+live_bytes[which];
    }
    if(cursor<0xc2000000){types[n]=7;bases[n]=cursor;pages[n++]=(0xc2000000-cursor)/4096;}
    allocator_chain(0,types,bases,pages,n);allocator_chain(1,0,0,0,8-2*physical_owned);
    put(core+0x1cdb0,1+claims+drops,8);put(core+0x1cc08,0,8);put(core+0x1dc10,0,8);
}
/* The public GetMap peer coalesces adjacent conventional entries. Split its
 * same physical span into many independent internal metadata nodes, keeping
 * one sufficient final entry for the actual request. */
static void allocator_many(unsigned count,unsigned pool)
{
    uint32_t types[PWMC_MAP_NODE_MAX+1]={3,4};
    uint64_t bases[PWMC_MAP_NODE_MAX+1]={(uintptr_t)arena,(uintptr_t)arena+0x100000};
    uint64_t pages[PWMC_MAP_NODE_MAX+1]={256,256};
    assert(count>=3&&count<=PWMC_MAP_NODE_MAX+1);
    for(unsigned k=2;k<count;k++){types[k]=7;bases[k]=UINT64_C(0xc0000000)+4096*(k-2);pages[k]=k+1==count?(UINT64_C(0xc2000000)-bases[k])/4096:1;}
    allocator_chain(0,types,bases,pages,count);allocator_chain(1,0,0,0,pool);
}
static int pwmc_test_call(struct pwmc_result*r,unsigned op)
{
    struct pwmc_call*q=&r->call[op];assert(r==mr&&q->issued&&q->unknown&&q->guard.entered&&!q->guard.left&&r->held);
    assert(!r->unknown&&!r->external_issued&&q->requested==r->backing&&q->pages==r->pages);
    if(op){
        drops++;unsigned which=2;for(unsigned k=0;k<2;k++)if(live[k]&&live_base[k]==q->requested&&live_bytes[k]==q->pages*4096)which=k;
        assert(physical_owned&&which<2);
        if(mf==15)return 0;if(mf==16){q->status=EFI_ERROR|14;return 1;}
        physical_owned--;live[which]=0;q->status=0;
    }else{
        claims++;assert(physical_owned<2&&pwmc_parameters(r));allocated_base=q->requested;allocated_bytes=q->pages*4096;
        if(mf==5){q->status=EFI_ERROR|14;return 1;}
        unsigned which=live[0]?1:0;assert(!live[which]);for(unsigned k=0;k<2;k++)if(live[k])assert(allocated_base+allocated_bytes<=live_base[k]||live_base[k]+live_bytes[k]<=allocated_base);
        physical_owned++;live[which]=1;live_base[which]=allocated_base;live_bytes[which]=allocated_bytes;
        q->status=0;if(mf==4)return 0;if(mf==6)q->returned_address+=4096;
    }allocator_model();return 1;
}
static int memory_AT(struct pwmc_translation*t)
{
    translations++;t->saved=0x123456;t->read_issued=t->read_returned=t->write_issued=t->write_returned=1;
    t->read_par=t->write_par=UINT64_C(0xff00000000000b80)|t->page;t->restored=t->saved;
    unsigned release=mr->source[1].attempted;
    if(translations==mt){
        if(mf==9)t->read_par^=1;
        if(mf==10)t->write_returned=0;
        if(mf==11){t->page+=4096;t->read_par=t->write_par=UINT64_C(0xff00000000000b80)|t->page;}
        if(mf==12)mr->backing+=4096;
        if(mf==23)mr->kind^=1;
        if(mf==24)arches+=50000;
    }
    if(mf==17&&release)t->restored++;
    if(mf==25&&translations==mr->pages)core[0x1000]^=1;
    return !(mf==26&&translations==mt);
}
static void setup(unsigned kind,unsigned f)
{
    mr=0;reset(0);mf=f;claims=drops=translations=physical_owned=event_ATs=allocator_ATs=0;allocated_base=allocated_bytes=0;
    event_base=arena+0x110000;memset(arena+0x100000,0,0x100000);
    allocator_base=arena+0x130000;
    memset(live,0,sizeof(live));memset(live_base,0,sizeof(live_base));memset(live_bytes,0,sizeof(live_bytes));
    self->bytes=0xf8000;mr=(void*)(arena+0x50000);assert((uint8_t*)mr+sizeof(*mr)<arena+0xf4000);
    /* Keep the genuine firmware ConfigurationTable outside the enlarged
     * modeled loader image, as required by the original Core bootstrap. */
    struct pgcd_config previous=*cfg;cfg=(void*)(arena+0xf9000);*cfg=previous;s->tables=cfg;
    put(core+0x1c368,(uintptr_t)core+0x1c368,8);put(core+0x1c370,(uintptr_t)core+0x1c368,8);
    allocator_model();
    struct pgcd_io io={0,s,memory_arch,memory_map,memory_identity,query,fp_save,fp_restore,memory_order};
    assert(pwmc_bind(mr,self,s,(void*)(arena+0xf4000),kind,&io));
    if(f==1)put(core+0x1b828,(uintptr_t)core+PWMC_ALLOC_RVA+4,8);
    if(f==2)put(core+0x1cb78,(uintptr_t)core+0x1000,8);
    if(f==3)put(arena+0xf4000,1,4);
}
/* Original notification metadata is SOFTWARE RAM, outside the modeled
 * loader image. No notification function is called by this peer. */
static void event_list(unsigned count,unsigned matching)
{
    uint64_t head=(uintptr_t)core+0x1c368,previous=head;
    assert(count<=PWMC_EVENT_MAX+1);
    for(unsigned k=0;k<count;k++){
        uint8_t*n=event_base+128*k;memset(n,0,88);
        put(n,0x746e7665,8);put(n+8,0x200,4);put(n+16,k+1<count?(uintptr_t)n+128+16:head,8);
        put(n+24,previous,8);put(n+32,8,8);put(n+40,0x12345678,8);n[56]=1;
        if(k==matching)memcpy(n+56,&pwmc_map_change_group,16);
        previous=(uintptr_t)n+16;
    }
    put(core+0x1c368,count?(uintptr_t)event_base+16:head,8);put(core+0x1c370,previous,8);
}
static unsigned delta_oracle_cases(void)
{
    struct pgcd_result*p=calloc(1,sizeof(*p));assert(p);unsigned count=0;
    for(unsigned stride=40;stride<=48;stride+=8)for(unsigned off=1;off<30;off++)for(unsigned wrong=0;wrong<9;wrong++){
        memset(p,0,sizeof(*p));active_stride=stride;
        p->map[0]=(struct pgcd_map){.valid=1,.version=1,.key=1,.stride=stride,.bytes=stride};
        p->map[1]=(struct pgcd_map){.valid=1,.version=1,.key=2,.stride=stride,.bytes=3*stride};
        uint64_t base=UINT64_C(0xc0000000)+4096*off;
        descriptor(p->maps[0],0,7,0xc0000000,32,8);
        descriptor(p->maps[1],0,7,0xc0000000,off,8);
        descriptor(p->maps[1],1,2,base,2,8);
        descriptor(p->maps[1],2,7,base+8192,30-off,8);
        if(wrong==1)((struct efi_memory*)p->maps[1])->attributes=9;
        if(wrong==2)((struct efi_memory*)(p->maps[1]+stride))->type=4;
        if(wrong==3)((struct efi_memory*)(p->maps[1]+stride))->attributes=9;
        if(wrong==4)((struct efi_memory*)(p->maps[1]+2*stride))->physical+=4096;
        if(wrong==5)p->map[1].key=1;
        if(wrong==6)p->maps[1][stride==48?40:4]^=1;
        if(wrong==7)((struct efi_memory*)(p->maps[1]+2*stride))->physical=base;
        if(wrong==8)p->map[1].stride=stride==48?40:48;
        /* Independent page oracle over the entire32-page physical span. */
        unsigned oracle=wrong!=5&&wrong!=6&&wrong!=8;
        for(unsigned page=0;page<32;page++){
            uint64_t address=UINT64_C(0xc0000000)+4096*page;unsigned found=0;uint32_t type=0;uint64_t attr=0;
            for(unsigned n=0;n<3;n++){const struct efi_memory*d=(const void*)(p->maps[1]+n*stride);
                if(d->physical<=address&&address<d->physical+d->pages*4096){found++;type=d->type;attr=d->attributes;}}
            if(found!=1||type!=(page>=off&&page<off+2?2u:7u)||attr!=8)oracle=0;
        }
        assert(pwmc_map_delta(p,base,8192,0)==(int)oracle);count++;
    }
    active_stride=48;
    for(unsigned kind=0;kind<2;kind++)for(unsigned x=0;x<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);x++){
        memset(p,0,sizeof(*p));p->map[0]=(struct pgcd_map){.valid=1,.version=1,.key=1,.stride=48,.bytes=48};
        uint64_t lo=(pwmc_exclusions[x].base-0x400000)&~UINT64_C(4095),hi=pwmc_exclusions[x].base+pwmc_exclusions[x].bytes+4096;
        descriptor(p->maps[0],0,7,lo,(hi-lo)/4096,8);uint64_t got=0,best=0,bytes=pwmc_bytes(kind),alignment=kind?4096:0x200000;
        for(uint64_t at=(lo+alignment-1)&~(alignment-1);at<=hi-bytes;at+=alignment){
            unsigned allowed=at>=0x80000000&&at+bytes<=UINT64_C(0x100000000);
            for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++)if(at<pwmc_exclusions[k].base+pwmc_exclusions[k].bytes&&pwmc_exclusions[k].base<at+bytes)allowed=0;
            if(allowed)best=at;
        }
        assert(pwmc_select(p,kind,&got)==(best!=0)&&(!best||got==best));count++;
    }
    free(p);active_stride=48;return count;
}
int main(int argc,char**argv)
{
    assert((argc==2||argc==3)&&!posix_memalign((void**)&arena,4096,0x201000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned cases=delta_oracle_cases();
    for(unsigned kind=0;kind<2;kind++){
        setup(kind,0);int ok=pwmc_claim(mr,memory_AT);
        if(!ok)fprintf(stderr,"claim kind%u error%u unknown%u source%u/%u maps%u calls%u pages%u translated%u\n",kind,mr->error,mr->unknown,mr->source[0].error,mr->source[0].uncertain,maps,claims,mr->pages,mr->translated);
        if(!ok){uint64_t selected=0;int sel=pwmc_select(&mr->source[0],mr->kind,&selected);fprintf(stderr,"layout%d params%d select%d expected%llx actual%llx native%u kind%u/%u hook%llx alloc%llx expected%llx BS%zu\n",pwmc_layout(mr),pwmc_parameters(mr),sel,(unsigned long long)selected,(unsigned long long)mr->backing,*(uint32_t*)(arena+0xf4000),mr->kind,mr->bound_kind,(unsigned long long)pwfi_le(core+0x1cb78,8),(unsigned long long)(uintptr_t)s->boot->allocate_pages,(unsigned long long)((uintptr_t)core+PWMC_ALLOC_RVA),sizeof(struct efi_boot));}
        assert(ok&&claims==1&&!drops&&mr->held&&mr->allocated&&!mr->unknown);
        assert(mr->pages==(kind?514:512)&&mr->exposed==mr->backing+(kind?4096:0)&&mr->exposed_bytes==(kind?0x200000:0x100000));
        assert(!queries&&mr->source[0].hash_count[0]==5&&mr->source[0].hash_count[1]==5&&mr->final_hash_count[0]==5);
        assert(pwmc_release_local(mr,memory_AT)&&drops==1&&!mr->held&&mr->released&&!mr->unknown&&!physical_owned);
        assert(mr->ticket[0].spent&&mr->ticket[1].spent&&mr->ticket[0].result!=mr->ticket[1].result);
        assert(!pwmc_claim(mr,memory_AT)&&!pwmc_release_local(mr,memory_AT)&&claims==1&&drops==1);cases++;
        setup(kind,20);assert(pwmc_claim(mr,memory_AT)&&pwmc_release_local(mr,memory_AT));cases++;
    }
    setup(0,0);assert(pwmc_claim(mr,memory_AT));struct pwmc_result*first=mr;mr=(void*)(arena+0xa0000);
    struct pgcd_io pair_io={0,s,memory_arch,memory_map,memory_identity,query,fp_save,fp_restore,memory_order};
    assert(pwmc_bind(mr,self,s,(void*)(arena+0xf4000),PWMC_RMTFS,&pair_io)&&pwmc_claim(mr,memory_AT));
    struct pwmc_result*second=mr;assert(physical_owned==2&&first->backing!=second->backing&&first->backing_bytes!=second->backing_bytes);
    mr=first;assert(pwmc_release_local(mr,memory_AT)&&physical_owned==1);mr=second;
    assert(pwmc_release_local(mr,memory_AT)&&!physical_owned&&claims==2&&drops==2);cases++;
    for(unsigned f=1;f<=26;f++){
        if(f==18||f==19||f==20||f==21)continue;setup(0,f);mt=256;
        int ok=pwmc_claim(mr,memory_AT);
        if(f==15||f==16||f==17){assert(ok&&!pwmc_release_local(mr,memory_AT)&&mr->held&&mr->unknown&&!mr->released);}
        else{if(ok)fprintf(stderr,"unexpected claim success fault%u\n",f);assert(!ok&&!drops&&!mr->allocated);}
        if(f<=3)assert(!claims);
        if(f==4)assert(mr->call[0].issued&&!mr->call[0].returned&&mr->call[0].unknown&&mr->call[0].guard.left==0&&maps==1&&mr->unknown&&mr->held);
        if(f==13||f==22)assert(!claims);
        if(mr->unknown){unsigned calls=claims+drops;assert(!pwmc_release_local(mr,memory_AT)&&!pwmc_claim(mr,memory_AT)&&calls==claims+drops);}
        cases++;
    }
    for(unsigned at=1;at<=514;at++){
        setup(1,26);mt=at;assert(!pwmc_claim(mr,memory_AT)&&mr->translated==at-1&&mr->translation_pending==at&&mr->unknown&&mr->held&&!drops);cases++;
    }
    for(unsigned at=1;at<=514;at++){
        setup(1,0);assert(pwmc_claim(mr,memory_AT));mf=26;mt=translations+at;
        assert(!pwmc_release_local(mr,memory_AT)&&mr->release_translated==at-1&&mr->release_pending==at&&mr->unknown&&mr->held&&!drops);cases++;
    }
    for(unsigned phase=27;phase<=28;phase++)for(unsigned field=1;field<=19;field++){
        setup(0,phase);mt=field;assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&mr->unknown);cases++;
    }
    setup(0,29);assert(!pwmc_claim(mr,memory_AT)&&claims==1&&maps==1&&!drops&&mr->unknown&&mr->held);cases++;
    for(unsigned field=1;field<=24;field++)for(unsigned expose=0;expose<2;expose++){
        setup(0,0);assert(pwmc_claim(mr,memory_AT));
        switch(field){
        case 1:mr->held=0;break;case 2:mr->allocated=0;break;case 3:mr->bound_kind^=1;break;
        case 4:mr->backing+=4096;break;case 5:mr->translated--;break;case 6:mr->translation_pending=1;break;
        case 7:mr->call[0].issued=0;break;case 8:mr->call[0].returned=0;break;case 9:mr->call[0].unknown=1;break;
        case 10:mr->call[0].status=1;break;case 11:mr->call[0].map_checked=0;break;
        case 12:mr->call[0].guard.left=0;break;case 13:mr->call[0].guard.fp.restored=0;break;
        case 14:mr->call[0].guard.TPL_after=8;break;case 15:mr->call[0].native_after=1;break;
        case 16:mr->context[0].finished=0;break;case 17:mr->ticket[0].spent=0;break;
        case 18:mr->source[0].hash_count[1]--;break;case 19:mr->final_hashes[0][0][0]^=1;break;
        case 20:mr->AT[0].write_returned=0;break;case 21:mr->call[0].BS_after[0]^=1;break;
        case 22:mr->native_last[0]=1;break;case 23:mr->source[0].map[1].key=mr->source[0].map[0].key;break;
        case 24:mr->AT[PWMC_PAGES-1].page=1;break;
        }
        assert(!(expose?pwmc_exposure_intent(mr):pwmc_release_local(mr,memory_AT))&&mr->unknown&&!drops);
        assert(!pwmc_release_local(mr,memory_AT)&&!drops);cases++;
    }
    setup(0,0);assert(pwmc_claim(mr,memory_AT)&&pwmc_exposure_intent(mr));assert(!pwmc_release_local(mr,memory_AT)&&!drops&&!mr->source[1].attempted);cases++;
    mr->external_issued=0;assert(!pwmc_release_local(mr,memory_AT)&&mr->unknown&&!drops&&mr->held);cases++;
    setup(0,0);assert(pwmc_claim(mr,memory_AT));mr->AT[PWMC_PAGES-1].page=1;assert(!pwmc_release_local(mr,memory_AT)&&!drops&&mr->unknown&&mr->held);cases++;
    setup(0,0);mr->AT[PWMC_PAGES-1].page=1;assert(!pwmc_claim(mr,memory_AT)&&!claims);cases++;
    /* Every chain length and every subscriber position, plus bounded bad
     * links, private prefix mutation and final callback/order races. */
    for(unsigned count=0;count<=PWMC_EVENT_MAX;count++){
        setup(0,0);event_list(count,UINT32_MAX);
        assert(pwmc_claim(mr,memory_AT)&&mr->events[0].count==count&&pwmc_events_replay(mr,0));
        assert(pwmc_release_local(mr,memory_AT)&&mr->events[1].count==count&&claims==1&&drops==1);cases++;
    }
    for(unsigned slot=0;slot<PWMC_EVENT_MAX;slot++){
        setup(0,0);event_list(PWMC_EVENT_MAX,slot);
        assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&!mr->held&&!mr->unknown&&mr->events[0].count==slot+1);cases++;
    }
    for(unsigned wrong=0;wrong<12;wrong++){
        setup(0,0);event_list(2,UINT32_MAX);uint8_t*n=event_base;
        switch(wrong){
        case 0:event_list(PWMC_EVENT_MAX+1,UINT32_MAX);break;
        case 1:put(core+0x1c368,8,8);break;case 2:put(core+0x1c368,(uintptr_t)n+17,8);break;
        case 3:put(n+24,0,8);break;case 4:put(n+16,(uintptr_t)n+16,8);break;
        case 5:put(n,0,8);break;case 6:put(core+0x1dbc0,1,8);break;
        case 7:put(core+0x1c360,2,4);break;case 8:put(core+0x1c350,16,8);break;
        case 9:put(core+0x1c368,(uintptr_t)arena+0xf5010,8);break;
        case 10:put(core+0x1c368,UINT64_C(0xc0010010),8);break;
        case 11:put(core+0x1c370,(uintptr_t)n+16,8);break;
        }
        assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops);cases++;
    }
    for(unsigned phase=30;phase<=31;phase++){
        setup(0,phase);event_list(2,UINT32_MAX);
        assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&mr->unknown);
        assert(pwfi_le(core+0x1dbc0,8)==1&&!pwmc_claim(mr,memory_AT));cases++;
    }
    for(unsigned field=0;field<88;field++){
        setup(0,0);event_list(2,UINT32_MAX);assert(pwmc_claim(mr,memory_AT));mr->events[0].node[1].raw[field]^=1;
        assert(!pwmc_release_local(mr,memory_AT)&&mr->unknown&&mr->held&&!drops);cases++;
    }
    setup(0,0);event_list(2,UINT32_MAX);assert(pwmc_claim(mr,memory_AT));event_list(2,1);
    assert(!pwmc_release_local(mr,memory_AT)&&mr->unknown&&mr->held&&!drops);cases++;
    setup(0,0);event_base+=0xfd8;event_list(2,UINT32_MAX);assert(pwmc_claim(mr,memory_AT));
    assert(mr->events[0].node[0].AT_count==2&&pwmc_release_local(mr,memory_AT)&&mr->events[1].node[0].AT_count==2);cases++;
    for(unsigned op=0;op<2;op++)for(unsigned at=1;at<=PWMC_EVENT_MAX;at++){
        setup(0,0);event_list(PWMC_EVENT_MAX,UINT32_MAX);if(op)assert(pwmc_claim(mr,memory_AT));
        mf=32;mt=at;event_ATs=0;
        assert(!(op?pwmc_release_local(mr,memory_AT):pwmc_claim(mr,memory_AT))&&mr->unknown&&!drops&&claims==op);
        assert(mr->events[op].count==at-1&&mr->events[op].node[at-1].issued&&!mr->events[op].node[at-1].returned&&event_ATs==at);cases++;
    }
    const unsigned boundary[]={2,3,4,63,64,255,256};
    for(unsigned k=0;k<sizeof(boundary)/sizeof(boundary[0]);k++){
        setup(0,0);allocator_many(boundary[k]<3?3:boundary[k],boundary[k]);
        assert(pwmc_claim(mr,memory_AT)&&pwmc_release_local(mr,memory_AT));cases++;
    }
    for(unsigned pool=0;pool<2;pool++){
        setup(0,0);allocator_many(3,pool);assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&!mr->unknown&&!mr->held);cases++;
    }
    for(unsigned wrong=0;wrong<19;wrong++){
        setup(0,0);uint8_t*n=allocator_base;
        switch(wrong){
        case 0:allocator_many(PWMC_MAP_NODE_MAX+1,2);break;
        case 1:allocator_many(3,PWMC_MAP_NODE_MAX+1);break;
        case 2:put(core+0x1b358,0,8);break;case 3:put(core+0x1bcc0,0,8);break;
        case 4:put(n+8,(uintptr_t)n+8,8);break;case 5:put(n+16,0,8);break;
        case 6:put(n,0,8);break;case 7:put(core+0x1cdb0,2,8);break;
        case 8:put(core+0x1cc08,1,8);break;case 9:put(core+0x1dc10,1,8);break;
        case 10:put(core+0x1b350,2,4);break;case 11:put(core+0x1b340,31,8);break;
        case 12:put(n+256+28,2,4);break;case 13:put(n+256+56,9,8);break;
        case 14:put(n+256+48,4096,8);break;case 15:put(n+256+40,UINT64_MAX,8);break;
        case 16:put(core+0x1bcc0,(uintptr_t)n+8,8);break;
        case 17:put(core+0x1b358,(uintptr_t)mr+8,8);break;
        case 18:put(n+128+32,(uintptr_t)arena,8);break;
        }
        assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&!mr->held);cases++;
    }
    for(unsigned phase=34;phase<=35;phase++){
        setup(0,phase);assert(!pwmc_claim(mr,memory_AT)&&!claims&&!drops&&mr->unknown);cases++;
    }
    for(unsigned field=0;field<64;field++){
        setup(0,0);assert(pwmc_claim(mr,memory_AT));mr->allocator[0].node[0][2].raw[field]^=1;
        assert(!pwmc_release_local(mr,memory_AT)&&mr->unknown&&mr->held&&!drops);cases++;
    }
    /* All returned metadata-AT failure prefixes in both original lists.
     * Existing claims remain held on a release refusal; no retry follows. */
    for(unsigned op=0;op<2;op++)for(unsigned list=0;list<2;list++)for(unsigned at=1;at<=PWMC_MAP_NODE_MAX;at++){
        setup(0,0);if(op)assert(pwmc_claim(mr,memory_AT));
        if(!op)allocator_many(list?3:PWMC_MAP_NODE_MAX,list?PWMC_MAP_NODE_MAX:2);
        else if(list)allocator_chain(1,0,0,0,PWMC_MAP_NODE_MAX);
        else{
            /* Retain actual claimed type2 as the last internal entry; split
             * the preceding conventional region into the remaining nodes. */
            uint32_t types[PWMC_MAP_NODE_MAX]={3,4};uint64_t bases[PWMC_MAP_NODE_MAX]={(uintptr_t)arena,(uintptr_t)arena+0x100000},pages[PWMC_MAP_NODE_MAX]={256,256};
            for(unsigned k=2;k<PWMC_MAP_NODE_MAX-1;k++){types[k]=7;bases[k]=UINT64_C(0xc0000000)+4096*(k-2);pages[k]=k+2==PWMC_MAP_NODE_MAX?(mr->backing-bases[k])/4096:1;}
            types[PWMC_MAP_NODE_MAX-1]=2;bases[PWMC_MAP_NODE_MAX-1]=mr->backing;pages[PWMC_MAP_NODE_MAX-1]=mr->pages;
            allocator_chain(0,types,bases,pages,PWMC_MAP_NODE_MAX);allocator_chain(1,0,0,0,2);
        }
        mf=33;mt=(list?(op?4:3):0)+at;allocator_ATs=0;
        assert(!(op?pwmc_release_local(mr,memory_AT):pwmc_claim(mr,memory_AT))&&mr->unknown&&!drops&&claims==op);
        assert(mr->allocator[op].count[list]==at-1&&mr->allocator[op].node[list][at-1].issued&&!mr->allocator[op].node[list][at-1].returned&&allocator_ATs==mt);cases++;
    }
    setup(0,0);allocator_base+=0xfe0;allocator_model();assert(pwmc_claim(mr,memory_AT)&&mr->allocator[0].node[0][0].AT_count==2&&pwmc_release_local(mr,memory_AT));cases++;
    setup(0,0);event_base+=0xfd8;event_list(3,UINT32_MAX);assert(pwmc_claim(mr,memory_AT));
    if(argc==3){FILE*out=fopen(argv[2],"wb");assert(out&&
        fwrite(&mr->events[0],1,sizeof(mr->events[0]),out)==sizeof(mr->events[0])&&
        fwrite(&mr->allocator[0],1,sizeof(mr->allocator[0]),out)==sizeof(mr->allocator[0])&&!fclose(out));}
    assert(pwmc_release_local(mr,memory_AT));cases++;
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"original_PE_executed\":false,\"SOFTWARE_BS_AT_only\":true,\"physical_allocator_or_VMID_grant\":false}\n",cases,sizeof(*mr));
    free(original);free(arena);return 0;
}

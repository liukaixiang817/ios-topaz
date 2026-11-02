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
static uint64_t allocated_base,allocated_bytes;
static uint64_t live_base[2],live_bytes[2];static unsigned live[2];
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
    return ok;
}
static void memory_order(void*p)
{
    order(p);
    if(mf==13&&mr->call[0].issued&&!claims)mr->call[0].pages++;
    if(mf==28&&mr->call[0].issued&&!claims)corrupt_pending();
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
    unsigned n=1;uint64_t cursor=0xc0000000,hi=0xc2000000;
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
    }return 1;
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
    reset(0);mf=f;claims=drops=translations=physical_owned=0;allocated_base=allocated_bytes=0;
    memset(live,0,sizeof(live));memset(live_base,0,sizeof(live_base));memset(live_bytes,0,sizeof(live_bytes));
    self->bytes=0xf8000;mr=(void*)(arena+0x50000);assert((uint8_t*)mr+sizeof(*mr)<arena+0xf4000);
    /* Keep the genuine firmware ConfigurationTable outside the enlarged
     * modeled loader image, as required by the original Core bootstrap. */
    struct pgcd_config previous=*cfg;cfg=(void*)(arena+0xf9000);*cfg=previous;s->tables=cfg;
    struct pgcd_io io={0,s,memory_arch,memory_map,identity,query,fp_save,fp_restore,memory_order};
    assert(pwmc_bind(mr,self,s,(void*)(arena+0xf4000),kind,&io));
    if(f==1)put(core+0x1b828,(uintptr_t)core+PWMC_ALLOC_RVA+4,8);
    if(f==2)put(core+0x1cb78,(uintptr_t)core+0x1000,8);
    if(f==3)put(arena+0xf4000,1,4);
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
    assert(argc==2&&!posix_memalign((void**)&arena,4096,0x101000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
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
    setup(0,0);assert(pwmc_claim(mr,memory_AT));struct pwmc_result*first=mr;mr=(void*)(arena+0x80000);
    struct pgcd_io pair_io={0,s,memory_arch,memory_map,identity,query,fp_save,fp_restore,memory_order};
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
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"original_PE_executed\":false,\"SOFTWARE_BS_AT_only\":true,\"physical_allocator_or_VMID_grant\":false}\n",cases,sizeof(*mr));
    free(original);free(arena);return 0;
}

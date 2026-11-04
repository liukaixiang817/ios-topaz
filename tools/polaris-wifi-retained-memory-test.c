/* Actual retained-claim caller with inert original Core bytes and software
 * leaves. No firmware instructions, hardware, remote or partition access. */
#define PWEA_TEST_ENTRY original_early_test
#include "polaris-wifi-early-native-test.c"
#include "../shim/polaris/uefi-wifi-retained-memory.h"
static struct pweh_result*held;static struct pweh_input hi;static unsigned h_fault,h_maps;
_Static_assert(sizeof(struct pweh_result)<0x1e000,"resident fixture bounds");
static efi_status pweh_test_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&m==&held->map);h_maps++;
    emit_descriptor(m->data,3,(uintptr_t)arena,0x100000);
    emit_descriptor(m->data+40,2,UINT64_C(0x180000000),0x10000000);
    emit_descriptor(m->data+80,2,early->memory.claim[0].requested,early->memory.claim[0].bytes);
    emit_descriptor(m->data+120,2,early->memory.claim[1].requested,early->memory.claim[1].bytes);
    emit_descriptor(m->data+160,2,held->payload,held->payload_bytes);
    emit_descriptor(m->data+200,2,held->log,hi.log_bytes);
    m->map.bytes=240;m->map.stride=40;m->map.key=100;m->map.version=1;
    switch(h_fault){
    case 1:held->input.log_bytes++;break;
    case 2:held->early_digest[0]^=1;break;
    case 3:early->memory.claim[0].exposed++;break;
    case 4:*(uint32_t*)(uintptr_t)hi.state=1;break;
    case 5:*(uint64_t*)(uintptr_t)hi.received=1;break;
    case 6:*(uint64_t*)(uintptr_t)hi.count=1;break;
    case 7:*(uint8_t**)(uintptr_t)hi.payload_slot=(void*)0xd0001000;break;
    case 8:*(uint8_t**)(uintptr_t)hi.log_slot=(void*)0xd1001000;break;
    case 9:held->fp.q8_q15[0]^=1;break;
    case 10:s->boot=(void*)8;break;
    case 11:held->map.map.key=0;break;
    case 12:held->map.map.bytes=8193;break;
    case 13:((struct efi_memory*)(m->data+80))->type=7;break;
    case 14:((struct efi_memory*)(m->data+120))->pages--;break;
    case 15:((struct efi_memory*)(m->data+160))->type=7;break;
    case 16:((struct efi_memory*)(m->data+200))->pages--;break;
    case 17:put(core+0x1b098,8,8);break;
    case 18:put(core+0x1cb78,8,8);break;
    case 19:core[0x1010]^=1;break;
    case 20:early->AT[0][0].read_par^=1;break;
    default:break;
    }
    return h_fault==21?EFI_ERROR|9:0;
}
static void prepare(unsigned f)
{
    setup(0,0);CHECK(run());held=(void*)(arena+0x60000);
    uint8_t*digest=arena+0x7f040;pweh_digest(early,sizeof(*early),digest);
    hi=(struct pweh_input){.early=early,.digest=digest,.payload_slot=(void*)(arena+0x7f008),.log_slot=(void*)(arena+0x7f010),
        .state=(void*)(arena+0x7f018),.received=(void*)(arena+0x7f020),.count=(void*)(arena+0x7f028),.logical_bytes=5000,.log_bytes=16384};
    *(uint8_t**)(uintptr_t)hi.payload_slot=(void*)UINT64_C(0xd0000000);
    *(uint8_t**)(uintptr_t)hi.log_slot=(void*)UINT64_C(0xd1000000);
    *(uint32_t*)(uintptr_t)hi.state=2;*(uint64_t*)(uintptr_t)hi.received=*(uint64_t*)(uintptr_t)hi.count=hi.logical_bytes;
    at_calls=core_at_calls=0;h_fault=f;h_maps=0;
}
#ifndef PWEH_TEST_ENTRY
#define PWEH_TEST_ENTRY main
#endif
int PWEH_TEST_ENTRY(int argc,char**argv)
{
    assert(argc==2||argc==3);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    prepare(0);CHECK(pweh_run(held,&hi)&&held->complete&&!held->unknown&&h_maps==1&&at_calls==1026&&core_at_calls==114);
    CHECK(held->payload_bytes==8192&&held->translated[0]==512&&held->translated[1]==514);
    CHECK(!pweh_run(held,&hi)&&h_maps==1);
    if(argc==3){
        FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(held,1,sizeof(*held),out)==sizeof(*held)&&!fclose(out));
        char name[4096];assert(snprintf(name,sizeof(name),"%s.early",argv[2])<(int)sizeof(name));
        out=fopen(name,"wb");assert(out&&fwrite(early,1,sizeof(*early),out)==sizeof(*early)&&!fclose(out));
    }
    for(unsigned n=1;n<=21;n++){prepare(n);CHECK(!pweh_run(held,&hi)&&held->unknown&&!held->complete&&h_maps==1);}
    for(unsigned n=0;n<12;n++){
        prepare(0);
        switch(n){
        case 0:*(uint8_t*)(uintptr_t)hi.digest^=1;break;
        case 1:early->memory.claim[1].bytes++;break;
        case 2:hi.logical_bytes=UINT64_MAX;break;
        case 3:hi.payload_slot=(void*)held;break;
        case 4:hi.log_bytes=0;break;
        case 5:*(uint32_t*)(uintptr_t)hi.state=0;break;
        case 6:*native_flag=1;break;
        case 7:*(uint8_t**)(uintptr_t)hi.payload_slot=(void*)(uintptr_t)early->memory.claim[0].requested;break;
        case 8:*(uint8_t**)(uintptr_t)hi.log_slot=*hi.payload_slot;break;
        case 9:*(uint8_t**)(uintptr_t)hi.payload_slot=(void*)(uintptr_t)early->memory.input.bank;break;
        case 10:*(uint8_t**)(uintptr_t)hi.log_slot=(void*)held;break;
        case 11:*(uint8_t**)(uintptr_t)hi.payload_slot=(void*)UINT64_C(0xd0000001);break;
        }
        CHECK(!pweh_run(held,&hi)&&held->unknown&&!held->complete&&!h_maps);
    }
    for(unsigned n=0;n<3;n++){
        prepare(0);efault=37;trigger=(unsigned[]){1,513,1026}[n];
        CHECK(!pweh_run(held,&hi)&&held->unknown&&h_maps==1&&at_calls==trigger);
    }
    free(original);free(arena);printf("PASS %u retained caller software checks\n",checks);return 0;
}

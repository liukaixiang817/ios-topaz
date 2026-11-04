/* Actual full native producer chain and handshake; independent remote SMEM
 * peer publishes version last and changes readiness asynchronously. */
#include <stdint.h>
struct pmni_command;
static void smp_peer_ring(const struct pmni_command*);
static void smp_peer_word(uint64_t);
#define PMSX_TEST_RING_HOOK smp_peer_ring
#define PMSX_TEST_WORD_HOOK smp_peer_word
#define PMSX_TEST_ENTRY unused_channel_suite
#define EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE 1
#include "polaris-mss-channel-native-test.c"
static struct pmsy_state*negotiation;
static unsigned remote_at,remote_samples,remote_mode,remote_flags,remote_rings,smp_scenarios;
static void smp_peer_ring(const struct pmni_command*c)
{
    if(!negotiation||c->value!=0x4000)return;remote_rings++;
    const uint8_t*out=sm_shadow+channel->item[0].data;
    CHECK(pms_u32(out)==0x504d5324&&pms_u32(out+4)==0x101&&pms_u32(out+8)==0x10000);
    if(remote_rings==1){
        CHECK(pms_u32(out+12)==16);unsigned header=0xb9000+pms_u32(sm_shadow+0xb900c);
        put(sm_shadow+header,0xa5a5|(435u<<16),4);put(sm_shadow+header+4,344,4);put(sm_shadow+header+8,4,4);put(sm_shadow+header+12,0,4);
        remote_at=header+16;memset(sm_shadow+remote_at,0,344);
        put(sm_shadow+remote_at,0x504d5324,4);put(sm_shadow+remote_at+8,1,4);
        put(sm_shadow+remote_at+12,16,4);put(sm_shadow+remote_at+16,remote_flags,4);
        put(sm_shadow+0xb900c,header+16+344-0xb9000,4);
    }else{
        CHECK(remote_rings==2&&pms_u32(out+12)==0x10010&&!memcmp(out+20,"master-kernel",13)&&!pms_u32(out+36));
        CHECK(pms_u32(out+16)==((remote_flags&1)?2u:0u));
    }
}
static void smp_peer_word(uint64_t address)
{
    if(!negotiation||!remote_at||address!=PMSQ_BASE+remote_at)return;
    remote_samples++;
    if(remote_samples==3){
        memcpy(sm_shadow+remote_at+20,remote_mode==2?"wrong-entry":"slave-kernel",remote_mode==2?11:12);
        put(sm_shadow+remote_at+12,0x10010,4);put(sm_shadow+remote_at+36,0,4); /* ERROR_READY deliberately absent. */
        put(sm_shadow+remote_at+4,remote_mode==1?0x201:0x101,4); /* Publish version last. */
    }
}
static void smp_setup(unsigned mode,unsigned flags)
{
    negotiation=0;channel_setup();remote_at=remote_samples=remote_rings=0;remote_mode=mode;remote_flags=flags;smp_scenarios++;
    negotiation=(void*)(arena+0x77a0000);CHECK(sizeof(*negotiation)<0x20000);memset(negotiation,0,sizeof(*negotiation));
    CHECK(pmsy_begin(negotiation,channel));
}
static int smp_drive(void)
{
    for(unsigned n=0;n<20;n++){
        int result=pmsy_step(negotiation);if(result!=1)return result;
        advance_to(negotiation->next_poll);
    }return 1;
}
int main(int argc,char**argv)
{
    CHECK(argc==7);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);CHECK(sm_original&&sm_shadow);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    for(unsigned flags=0;flags<=1;flags++){
        smp_setup(0,flags);int result=smp_drive();
        if(result!=2)fprintf(stderr,"SMP2P refusal result=%d phase=%u error=%u polls=%u in=%u samples=%u channel=%u source=%u\n",
            result,negotiation->phase,negotiation->error,negotiation->polls,negotiation->in_offset,remote_samples,channel->error,sm->error);
        CHECK(result==2&&channel->negotiated&&remote_rings==2&&negotiation->polls>=2&&pmsy_current(negotiation,channel));
        CHECK(!pms_u32(sm_shadow+remote_at+36)); /* No circular wait on ERROR_READY. */
        CHECK(pmsx_write(channel,2,0,0x12345678)&&pmsx_write(channel,1,4,8)&&pmsx_ring(channel,1));
        CHECK(!pmsx_write(channel,1,0,8)&&!pmsx_write(channel,1,12,8));
        put(sm_shadow+remote_at+36,2,4);CHECK(pmsy_current(negotiation,channel));
        if(flags)put(sm_shadow+remote_at+16,0,4);else put(sm_shadow+remote_at+36,1,4);
        CHECK(!pmsx_write(channel,2,4,0)&&channel->unknown&&negotiation->unknown);
    }
    fprintf(stderr,"native SMP2P delayed version/name/SSR-ACK + actual GLINK write/ring gate PASS; checking failures\n");
    for(unsigned mode=1;mode<=2;mode++){
        smp_setup(mode,0);CHECK(smp_drive()==0&&negotiation->unknown&&channel->unknown&&!channel->negotiated);
    }
    smp_setup(0,2);CHECK(smp_drive()==1&&!channel->negotiated);
    advance_to(negotiation->started+PMSY_TOTAL+1);CHECK(!pmsy_step(negotiation)&&negotiation->unknown);
    smp_setup(0,0);put(sm_shadow+channel->item[0].data+339,1,1);CHECK(!pmsy_step(negotiation)&&negotiation->unknown&&!channel_stores);
    auth_test_close();free(sm_original);free(sm_shadow);
    printf("PASS %u native SMP2P checks, %u scenarios; software privileged leaves only\n",checks,smp_scenarios);return 0;
}

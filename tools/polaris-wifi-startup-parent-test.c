/* The actual orchestrator with software stage outcomes. This tests ordering,
 * WAIT/failure retention and closed reentry, not hardware/whole-radio success.
 * Individual native producers retain their separate composed-leaf suites. */
#define EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE 1
#define PMWN_TEST_ENTRY unused_network_main
#include "polaris-wifi-network-native-test.c"
#undef CHECK
static unsigned parent_checks;
#define CHECK(x) do{parent_checks++;assert(x);}while(0)
static int parent_probe(const char*);
static unsigned parent_live=1,parent_mode,parent_calls;
#define pmsc_live(a) ((void)(a),(int)parent_live)
#define pmwi_live(a) ((void)(a),(int)(parent_mode!=1))
#define pmhd_live(a) ((void)(a),(int)(parent_mode!=1))
#define pmnp_live(a) ((void)(a),(int)(parent_mode!=1))
#define pmli_capture(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmli_capture"))
#define pmrg_capture(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmrg_capture"))
#define pmrd_capture(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmrd_capture"))
#define pmdc_capture(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmdc_capture"))
#define pmrs_capture(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmrs_capture"))
#define pmpn_begin(a0,a1,a2,a3,a4,a5) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),(void)(a4),(void)(a5),parent_probe("pmpn_begin"))
#define pmcn_begin(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmcn_begin"))
#define pman_begin(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pman_begin"))
#define pman_step(a0) ((void)(a0),parent_probe("pman_step"))
#define pmsp_begin(a0,a1,a2,a3,a4) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),(void)(a4),parent_probe("pmsp_begin"))
#define pmsp_next(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmsp_next"))
#define pmpn_supply(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmpn_supply"))
#define pmpn_proxy_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmpn_proxy_begin"))
#define pmpx_next(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmpx_next"))
#define pmpn_proxy(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmpn_proxy"))
#define pmcn_proxy(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmcn_proxy"))
#define pmcn_clock_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmcn_clock_begin"))
#define pmck_next(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmck_next"))
#define pmcn_clock(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmcn_clock"))
#define pmbn_begin(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmbn_begin"))
#define pmbn_step(a0) ((void)(a0),parent_probe("pmbn_step"))
#define pmsn_begin(a0,a1,a2,a3,a4) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),(void)(a4),parent_probe("pmsn_begin"))
#define pmsn_step(a0) ((void)(a0),parent_probe("pmsn_step"))
#define pmtf_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmtf_begin"))
#define pmtf_step(a0) ((void)(a0),parent_probe("pmtf_step"))
#define pmsq_capture(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmsq_capture"))
#define pmsl_acquire(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmsl_acquire"))
#define pmsa_prepare(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmsa_prepare"))
#define pmsa_publish(a0) ((void)(a0),parent_probe("pmsa_publish"))
#define pmsl_release(a0) ((void)(a0),parent_probe("pmsl_release"))
#define pmsx_begin(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmsx_begin"))
#define pmsy_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmsy_begin"))
#define pmsy_step(a0) ((void)(a0),parent_probe("pmsy_step"))
#define pmsg_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmsg_begin"))
#define pmsg_step(a0) ((void)(a0),parent_probe("pmsg_step"))
#define pmsg_peer_step(a0) ((void)(a0),parent_probe("pmsg_peer_step"))
#define pmrf_begin(a0,a1,a2,a3) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),parent_probe("pmrf_begin"))
#define pmwa_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmwa_begin"))
#define pmwa_step(a0) ((void)(a0),parent_probe("pmwa_step"))
#define pmce_begin(a0,a1,a2,a3,a4) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),(void)(a4),parent_probe("pmce_begin"))
#define pmce_step(a0) ((void)(a0),parent_probe("pmce_step"))
#define pmct_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmct_begin"))
#define pmhc_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmhc_begin"))
#define pmwi_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmwi_begin"))
#define pmwi_step(a0) ((void)(a0),parent_probe("pmwi_step"))
#define pmht_begin(a0,a1,a2) ((void)(a0),(void)(a1),(void)(a2),parent_probe("pmht_begin"))
#define pmht_step(a0) ((void)(a0),parent_probe("pmht_step"))
#define pmhd_begin(a0,a1) ((void)(a0),(void)(a1),parent_probe("pmhd_begin"))
#define pmnp_begin(a0,a1,a2,a3) ((void)(a0),(void)(a1),(void)(a2),(void)(a3),parent_probe("pmnp_begin"))
#define EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE 1
#include "uefi-wifi-startup-parent.h"
static int parent_probe(const char*name)
{
    parent_calls++;
    int waiting=strstr(name,"_step")!=0||!strcmp(name,"pmsp_next")||!strcmp(name,"pmpx_next")||!strcmp(name,"pmck_next");
    if(parent_mode==1)return waiting||!strcmp(name,"pmsp_begin")?-1:0;
    if(!strcmp(name,"pmsp_begin"))return PMSP_WAIT;
    if(!strcmp(name,"pmsp_next"))return parent_mode==2?PMSP_WAIT:PMSP_HELD;
    if(!strcmp(name,"pmpx_next"))return parent_mode==2?PMPX_WAIT:PMPX_HELD;
    if(!strcmp(name,"pmck_next"))return parent_mode==2?PMCK_WAIT:PMCK_HELD;
    if(!strcmp(name,"pman_step"))return parent_mode==2?PMAQ_WAIT:PMAQ_CONSUMED;
    if(!strcmp(name,"pmbn_step"))return parent_mode==2?PMBA_WAIT:PMBA_READY;
    if(!strcmp(name,"pmwi_step")||!strcmp(name,"pmht_step"))return parent_mode==2?1:3;
    if(waiting)return parent_mode==2?1:2;
    return 1;
}
int main(void)
{
    struct pwns_parent*s=calloc(1,sizeof(*s));CHECK(s);s->attempted=1;s->owner.held=1;
    for(unsigned phase=PWNS_IMAGES;phase<PWNS_READY;phase++){
        s->phase=phase;parent_mode=0;parent_calls=0;
        CHECK(pwns_step(s)==(phase+1==PWNS_READY?2:1)&&s->phase==phase+1&&parent_calls==1);
        s->phase=phase;parent_mode=1;parent_calls=0;
        CHECK(pwns_step(s)==-1&&s->phase==phase&&s->unknown&&s->error&&s->owner.held&&parent_calls==1);
        CHECK(pwns_step(s)==-1&&parent_calls==1);s->unknown=s->error=0;
    }
    const unsigned waiting[]={PWNS_AOP,PWNS_SUPPLY,PWNS_PROXY,PWNS_CLOCK,PWNS_BOOT,PWNS_AUTH,
        PWNS_RMTFS,PWNS_SMP,PWNS_GLINK,PWNS_QRTR,PWNS_WLAN,PWNS_CE,PWNS_WMI,PWNS_HTT};
    parent_mode=2;
    for(unsigned n=0;n<sizeof(waiting)/sizeof(waiting[0]);n++){
        s->phase=waiting[n];parent_calls=0;CHECK(pwns_step(s)==1&&s->phase==waiting[n]&&!s->unknown&&parent_calls==1);
    }
    parent_mode=0;s->phase=PWNS_READY;parent_calls=0;CHECK(pwns_step(s)==2&&s->phase==PWNS_READY&&!parent_calls);
    parent_live=0;CHECK(pwns_step(s)==-1&&s->unknown&&!parent_calls&&s->owner.held);
    parent_live=1;s->unknown=s->error=0;s->turns=UINT64_MAX;CHECK(pwns_step(s)==-1&&s->unknown&&!parent_calls);
    free(s);printf("PASS %u actual startup orchestrator checks with SOFTWARE stage outcomes; no hardware success claim\n",parent_checks);return 0;
}

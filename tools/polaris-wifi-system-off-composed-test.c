/* Actual startup/runtime/worker drain and native terminal continuation.
 * SOFTWARE kernel-drain, PSCI/cache/radio leaves; no physical shutdown. */
#include <stdint.h>
static void off_prepare(void),off_drive(void);
static int off_cache(uint64_t,uint64_t,unsigned);
#define PWRUNTIME_AFTER_PREPARE off_prepare
#define PWRUNTIME_AFTER_TRAFFIC off_drive
#define PWRUNTIME_OTHER_CACHE off_cache
#define EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_SYSTEM_OFF_SOFTWARE_PEER 1
#include "polaris-wifi-runtime-composed-test.c"
#include "uefi-wifi-system-off-native.h"
static struct polaris_shutdown_slot *off_slot,off_kernel;
static struct pwno_state *off_state;
static unsigned off_calls,off_requests,off_reads,off_fault;
static void off_prepare(void)
{
    off_slot=(void*)(kernel_memory+0x2000);memset(&off_kernel,0,sizeof(off_kernel));
    off_kernel.kernel.cookie=UINT64_C(0x1020304050607080);
    off_kernel.kernel.phase=POLARIS_Q_RUNNING;off_kernel.kernel.capabilities=POLARIS_Q_RAM_CONFIG;
    const char*p=getenv("POLARIS_OFF_TEST_FAULT");off_fault=p?(unsigned)strtoul(p,0,10):0;CHECK(off_fault<=4);
}
static int off_cache(uint64_t address,uint64_t bytes,unsigned clean)
{
    uint64_t first=(uintptr_t)off_slot;
    if(address<first||address-first>=256)return 0;
    CHECK(bytes==128&&(address==first||address==first+128));
    unsigned at=(unsigned)(address-first);
    if(clean){
        CHECK(!at&&++off_requests==1);memcpy(&off_kernel,off_slot,128);
        CHECK(off_kernel.firmware.cookie==off_kernel.kernel.cookie&&off_kernel.firmware.sequence==1&&
            off_kernel.firmware.mode==2&&pwmb_zero(off_kernel.firmware.reserved,112));
        off_kernel.kernel.sequence=1;off_kernel.kernel.mode=2;off_kernel.kernel.phase=POLARIS_Q_REQUESTED;
    }else{
        if(at&&off_requests&&++off_reads==2){
            off_kernel.kernel.phase=POLARIS_Q_SEALED;off_kernel.kernel.capabilities=POLARIS_Q_RAM_DRAINED;
            if(off_fault==2)off_kernel.kernel.error=5;
        }
        memcpy((uint8_t*)off_slot+at,(uint8_t*)&off_kernel+at,128);
    }return 1;
}
static int64_t pwno_smc(uint64_t function,uint64_t argument)
{
    CHECK(off_state&&off_state->pending&&off_state->command.function==function&&off_state->command.argument==argument);
    CHECK(owner->held==1&&pmsc_persistent(owner)&&worker->closing==2&&worker->retirement==(uintptr_t)off_state);
    off_calls++;
    if(function==0x84000000){CHECK(!argument&&off_calls==1);return 0x10000;}
    if(function==0x8400000a){CHECK(argument==0x84000008&&off_calls==2);
        if(off_fault==4)off_state->slot+=128;return off_fault==1?-1:0;}
    CHECK(off_requests==1&&off_kernel.kernel.phase==POLARIS_Q_SEALED&&!off_kernel.kernel.error);
    if(function==0xc4000004){CHECK(argument>=0x100&&argument<=0x700&&!(argument&255));
        if(off_fault==3&&argument==0x600)return 0;return argument==0x700?0:1;}
    CHECK(function==0x84000008&&!argument&&off_calls==10&&off_state->off_issued==1);
    return 0; /* A returned zero must be retained failure, never completion. */
}
static void off_drive(void)
{
    unsigned posted=0;
    for(unsigned n=0;n<12;n++)posted+=parent->transport.rings.source[n].posted;
    CHECK(posted>0); /* Last control command still needs its real RRI reap. */
    CHECK(pwwn_quiesce_begin(worker));int status=1;
    for(unsigned n=0;n<100&&status==1;n++){advance_to(owner->last+19200);status=pwwn_step(worker);}
    if(status!=2)fprintf(stderr,"quiesce status=%d phase=%u closing=%u worker_error=%u owner_error=%u network_closed=%u network_error=%u submitted=%u tx_wait=%u ethernet_tx=%u wpa_pending=%u group=%u/%u station=%u/%u htc=%u/%u data=%u/%u busy=%u/%u/%u\n",
        status,worker->phase,worker->closing,worker->error,owner->error,network->closed,network->error,
        network->submitted,network->tx_wait,network->ethernet.tx_bytes,network->wpa.pending,network->wpa.group_ready,network->wpa.group_issued,
        station->submitted,station->mgmt_wait,parent->htc.client.pending,parent->htc.frame_kind,
        parent->data.submitted,parent->data.frame_ready,parent->data.rings.busy,parent->transport.busy,parent->transport.rings.busy);
    CHECK(status==2&&worker->closing==2&&worker->network.closed&&worker->phase==PWWN_CLOSED);
    for(unsigned n=0;n<12;n++)CHECK(!parent->transport.rings.source[n].posted);
    off_state=(void*)(arena+0x7200000);memset(off_state,0,sizeof(*off_state));
    CHECK(pwno_begin(off_state,worker,runtime_payload->virt_base+0x2000)==1);
    status=1;
    for(unsigned n=0;n<100&&status==1;n++){advance_to(owner->last+19200);status=pwno_step(off_state);}
    CHECK(status==-1&&off_state->unknown&&off_state->error&&owner->held&&worker->retirement==(uintptr_t)off_state);
    if(!off_fault)CHECK(off_state->off_issued==1&&off_state->off_returned==1&&off_state->policy.error==9&&off_calls==10);
    else CHECK(!off_state->off_issued&&!off_state->off_returned);
    unsigned calls=off_calls;CHECK(pwno_step(off_state)==-1&&off_calls==calls);
    printf("actual terminal continuation fault=%u calls=%u retained PASS; SOFTWARE kernel/PSCI, no physical power-off\n",off_fault,off_calls);
}

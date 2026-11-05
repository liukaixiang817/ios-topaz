/* Complete existing native transport graph with software UEFI/MMIO/DMA.
 * The handoff record is injected; actual CPU_ON is separately tested. */
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 1
#define PMHT_TEST_CASES 1
static void runtime_transport(void);
#define PMHT_TEST_READY_HOOK runtime_transport
#include "polaris-wifi-htt-native-test.c"
static void runtime_transport(void)
{
    CHECK(pmsc_live(owner)&&pmsc_bound(owner)&&pmht_live(htt));
    struct pmsc_runtime*r=&owner->runtime;
    r->attempted=r->issued=r->returned=r->observed=r->complete=1;
    r->parent=1;r->copy=2;r->entry=3;r->context=4;r->started=owner->last;
    *native_flag=1;*(uint32_t*)(uintptr_t)held_input.state=4;owner->phase=4;
    CHECK(pmsc_bound(owner)&&pmht_live(htt));advance_to(owner->opening+PMSC_TOTAL+19200000);
    sm->reads=65536;channel->writes=channel->rings=65536;
    transport->operations=65536;htt->operations=16384;
    CHECK(pmct_poll(transport)==1&&sm->reads>65536);
    uint32_t value=(uint32_t)pwfi_le(sm_shadow+channel->item[1].data+4,4);
    CHECK(pmsx_write(channel,1,4,value)&&channel->writes==65537);
    CHECK(pmsx_ring(channel,1)&&channel->rings==65537);
    transport->busy=1;
    CHECK(pmct_cache(transport,transport->base+transport->rings.layout.rri,64,PWMK_INVALIDATE)==1);
    CHECK(pmct_mmio(transport,0,PMNI_FULL_ORDER,0,0)==1);transport->busy=0;
    uint8_t bytes[64];htt->busy=1;
    CHECK(pmht_memory(htt,htt->base+htt->layout.index,bytes,64,0)==1);htt->busy=0;
    CHECK(htt->operations==16385&&transport->operations>65536&&pmht_live(htt)&&pmsc_bound(owner));
    CHECK(!pmsc_close_unused(owner)&&owner->held&&!owner->restore_issued);
    htt->operations=UINT64_MAX;htt->busy=1;
    unsigned calls=htt_copies;CHECK(!pmht_io_begin(htt,2)&&htt_copies==calls);htt->busy=0;
    fprintf(stderr,"runtime transport: actual SMEM/GLINK/CE/HTT graph past startup time/count limits PASS; simulated handoff\n");
}

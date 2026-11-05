#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-ce-ring.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static struct pwcr_state state;
static struct pwce_init initialized;
static uint8_t descriptors[12][512][16],device_owned[12][512];
static void setup(void)
{
    memset(&state,0,sizeof(state));memset(&initialized,0,sizeof(initialized));
    memset(descriptors,0,sizeof(descriptors));memset(device_owned,0,sizeof(device_owned));
    CHECK(pwdm_plan(&initialized.layout,UINT64_C(0x701000000)));
    initialized.epoch=9;initialized.complete=1;CHECK(pwcr_begin(&state,&initialized,64)==1);
}
static unsigned refill(unsigned pipe)
{
    unsigned count=0;struct pwcr_transfer t;int result;
    while((result=pwcr_post_rx(&state,pipe,&t))==1){
        CHECK(t.receive==1&&!(t.descriptor&63)&&!(t.index&3));
        for(unsigned n=0;n<4;n++){
            unsigned slot=t.index+n;
            /* Every byte in the cache line must be CPU-owned when cleaned. */
            CHECK(!device_owned[pipe][slot]);memcpy(descriptors[pipe][slot],t.wire+16*n,16);
            CHECK(pwcr_get(t.wire+16*n,8)==t.buffer+(uint64_t)n*state.layout.pipe[pipe].buffer_bytes);
        }
        CHECK(pwcr_publish(&state,&t,1)==1);
        for(unsigned n=0;n<4;n++)device_owned[pipe][t.index+n]=1;count+=4;
    }
    CHECK(!result);return count;
}
static void receive(unsigned pipe,unsigned count)
{
    for(unsigned n=0;n<count;n++){
        struct pwcr_transfer t;struct pwcr_ring*r=&state.destination[pipe];unsigned slot=r->read;
        CHECK(r->posted&&device_owned[pipe][slot]);uint8_t*wire=descriptors[pipe][slot];
        CHECK(pwcr_receive(&state,pipe,wire,&t)==0); /* zero-length: device not done */
        pwcr_put(wire+8,31+n%113,2);pwcr_put(wire+12,0xabcdef,4);
        CHECK(pwcr_receive(&state,pipe,wire,&t)==1&&t.index==slot&&t.bytes==31+n%113);
        unsigned before=r->posted;CHECK(pwcr_consume_rx(&state,&t,1)==1&&r->posted==before-1);
        device_owned[pipe][slot]=0;
        /* CPU completion must not clear or clean the device-written record. */
        CHECK(pwcr_get(wire+8,2)==31+n%113);
    }
}
int main(void)
{
    setup();for(unsigned pipe=0;pipe<12;pipe++){
        unsigned entries=state.destination[pipe].entries;
        if(entries<8){CHECK(!refill(pipe));continue;}
        CHECK(refill(pipe)==entries-4);
        for(unsigned n=0;n<600;n++){
            receive(pipe,1);unsigned posted=refill(pipe);CHECK(posted==(n%4==3?4u:0u));
            CHECK(state.destination[pipe].posted<=entries-4);
        }
        CHECK(state.destination[pipe].completed==600&&state.destination[pipe].published==entries-4+600);
    }
    setup();for(unsigned pipe=0;pipe<12;pipe++){
        struct pwcr_ring*r=&state.source[pipe];if(!r->entries)continue;
        for(unsigned round=0;round<3;round++){
            unsigned slots=r->entries-1;struct pwcr_transfer t;
            for(unsigned n=0;n<slots;n++){
                CHECK(pwcr_send(&state,pipe,31,0xabc,&t)==1&&pwcr_get(t.wire,8)==t.buffer&&pwcr_get(t.wire+8,2)==31&&pwcr_get(t.wire+10,2)==0xabc0);
                CHECK(pwcr_publish(&state,&t,1)==1);
            }
            CHECK(pwcr_send(&state,pipe,31,0,&t)==0);
            CHECK(pwcr_complete_tx(&state,pipe,r->write)==(int)slots&&!r->posted&&r->read==r->write);
        }
    }
    setup();struct pwcr_transfer t;CHECK(pwcr_send(&state,0,2049,0,&t)==-1&&!state.unknown);
    CHECK(pwcr_send(&state,0,31,0,&t)==1);CHECK(pwcr_publish(&state,&t,0)==-1&&state.unknown&&state.busy);
    CHECK(pwcr_publish(&state,&t,1)==-1&&!state.source[0].posted);
    setup();CHECK(pwcr_complete_tx(&state,0,1)==-1&&state.unknown); /* unposted completion */
    setup();CHECK(refill(2)==60);uint8_t*wire=descriptors[2][0];pwcr_put(wire+8,2049,2);
    CHECK(pwcr_receive(&state,2,wire,&t)==-1&&state.unknown);
    setup();CHECK(refill(2)==60);wire=descriptors[2][0];pwcr_put(wire+8,31,2);wire[0]^=16;
    CHECK(pwcr_receive(&state,2,wire,&t)==-1&&state.unknown);
    setup();CHECK(refill(2)==60);wire=descriptors[2][0];pwcr_put(wire+8,31,2);
    CHECK(pwcr_receive(&state,2,wire,&t)==1);CHECK(pwcr_publish(&state,&t,1)==-1&&state.unknown); /* cannot post a receive-completion */
    memset(&state,0,sizeof(state));initialized.pipe[2].dest_read=initialized.pipe[2].dest_write=1;
    CHECK(pwcr_begin(&state,&initialized,64)==-1&&!state.started);
    initialized.pipe[2].dest_read=initialized.pipe[2].dest_write=0;CHECK(pwcr_begin(&state,&initialized,128)==-1&&!state.started);
    printf("PASS %u CE ring checks: RX wrap/recycle cache-line exclusivity, TX completion, partial publication, malformed descriptor\n",checks);return 0;
}

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-mailbox-transport.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
struct peer {unsigned role,calls,fault,dead,torn;uint8_t cpu[PWMB_BYTES];};
static struct peer producer,consumer;
static struct pwmb_link tx,rx;
static struct pwmb_message message;
static uint8_t memory[PWMB_BYTES],packet[1514];
static int live(void*p){return !((struct peer*)p)->dead;}
static int step(struct peer*p){p->calls++;return p->calls!=p->fault;}
static void span(struct peer*p,unsigned off,unsigned n,unsigned write)
{
    CHECK(off>=PWMB_TX*PWMB_SLOT&&off+n<=(PWMB_TX+1)*PWMB_SLOT);
    unsigned at=off-PWMB_TX*PWMB_SLOT,acknowledgement=at>=PWMB_ACK_OFFSET;
    CHECK(at+n<=(acknowledgement?PWMB_ACK_OFFSET+PWMB_LINE:PWMB_RECORD));
    if(write)CHECK((p->role==PWMB_PRODUCER)!=acknowledgement);
}
static int copy(void*ctx,unsigned off,void*private,unsigned n,unsigned write)
{
    struct peer*p=ctx;span(p,off,n,write);unsigned count=n;int ok=step(p);if(!ok)count=n>3?3:n;
    if(write)memcpy(p->cpu+off,private,count);else memcpy(private,p->cpu+off,count);return ok;
}
static int cache(void*ctx,unsigned off,unsigned n,unsigned write)
{
    struct peer*p=ctx;span(p,off,n,write);CHECK(!(off%128)&&!(n%128));int ok=step(p);
    unsigned count=ok?n:64;
    if(write)memcpy(memory+off,p->cpu+off,count);else memcpy(p->cpu+off,memory+off,count);
    return ok;
}
static int sequence(void*ctx,unsigned off,uint64_t*value,unsigned write)
{
    struct peer*p=ctx;span(p,off,8,write);CHECK(!(off%8));if(!step(p))return 0;
    if(write)pwmb_put64(p->cpu+off,*value);else *value=pwmb_u64(p->cpu+off);
    /* A different publication was observed during this copied snapshot. */
    if(!write&&p->torn&&p->calls==6){(*value)++;p->torn=0;}return 1;
}
static const struct pwmb_bus send_bus={&producer,live,copy,cache,sequence};
static const struct pwmb_bus receive_bus={&consumer,live,copy,cache,sequence};
static void setup(void)
{
    memset(&producer,0,sizeof(producer));memset(&consumer,0,sizeof(consumer));memset(memory,0,sizeof(memory));
    memset(&tx,0,sizeof(tx));memset(&rx,0,sizeof(rx));producer.role=PWMB_PRODUCER;consumer.role=PWMB_CONSUMER;
    CHECK(pwmb_link_open(&tx,PWMB_TX,PWMB_PRODUCER,33)&&pwmb_link_open(&rx,PWMB_TX,PWMB_CONSUMER,33));
}
static void send_packet(void){CHECK(pwmb_send(&tx,&send_bus,PWMB_ETHERNET_TX,packet,sizeof(packet))==1);}
static void receive_packet(void)
{
    CHECK(pwmb_receive_poll(&rx,&receive_bus,&message)==1&&message.bytes==sizeof(packet)&&!memcmp(message.data,packet,sizeof(packet)));
}
int main(void)
{
    for(unsigned n=0;n<sizeof(packet);n++)packet[n]=(uint8_t)n;
    setup();CHECK(!pwmb_receive_poll(&rx,&receive_bus,&message));
    for(unsigned n=0;n<100;n++){
        send_packet();CHECK(!pwmb_send(&tx,&send_bus,PWMB_ETHERNET_TX,packet,14));
        CHECK(!pwmb_send_ack_poll(&tx,&send_bus));receive_packet();
        CHECK(!pwmb_receive_poll(&rx,&receive_bus,&message));
        CHECK(pwmb_receive_complete(&rx,&receive_bus)==1&&pwmb_zero(rx.wire,sizeof(rx.wire)));
        CHECK(pwmb_send_ack_poll(&tx,&send_bus)==1&&pwmb_zero(tx.wire,sizeof(tx.wire)));
        CHECK(tx.state.next==n+2&&rx.state.next==n+2);
    }
    /* Every data publication/copy/cache/atomic leaf can fail, including after
     * partial stores. No ambiguous operation is retried or acknowledged. */
    for(unsigned fail=1;fail<=5;fail++){
        setup();producer.fault=fail;
        CHECK(pwmb_send(&tx,&send_bus,PWMB_ETHERNET_TX,packet,64)==-1&&tx.state.unknown&&tx.busy&&tx.state.next==1);
        unsigned calls=producer.calls;CHECK(!pwmb_send(&tx,&send_bus,PWMB_ETHERNET_TX,packet,64)&&producer.calls==calls);
        CHECK(tx.effects==fail&&tx.effect[fail-1].issued&&!tx.effect[fail-1].returned);
    }
    for(unsigned fail=1;fail<=6;fail++){
        setup();send_packet();consumer.fault=fail;
        CHECK(pwmb_receive_poll(&rx,&receive_bus,&message)==-1&&rx.state.unknown&&rx.state.next==1);
        unsigned calls=consumer.calls;CHECK(pwmb_receive_complete(&rx,&receive_bus)==-1&&consumer.calls==calls);
        CHECK(!pwmb_send_ack_poll(&tx,&send_bus)&&tx.state.next==1);
    }
    for(unsigned fail=1;fail<=5;fail++){
        setup();send_packet();receive_packet();consumer.fault=consumer.calls+fail;
        CHECK(pwmb_receive_complete(&rx,&receive_bus)==-1&&rx.state.unknown&&rx.state.next==1);
        unsigned calls=consumer.calls;CHECK(pwmb_receive_complete(&rx,&receive_bus)==-1&&consumer.calls==calls);
    }
    for(unsigned fail=1;fail<=5;fail++){
        setup();send_packet();receive_packet();CHECK(pwmb_receive_complete(&rx,&receive_bus)==1);producer.fault=producer.calls+fail;
        CHECK(pwmb_send_ack_poll(&tx,&send_bus)==-1&&tx.state.unknown&&tx.state.next==1);
        unsigned calls=producer.calls;CHECK(pwmb_send_ack_poll(&tx,&send_bus)==-1&&producer.calls==calls);
    }
    setup();send_packet();consumer.torn=1;
    CHECK(!pwmb_receive_poll(&rx,&receive_bus,&message)&&!rx.state.stage&&!rx.state.unknown);
    receive_packet();CHECK(pwmb_receive_complete(&rx,&receive_bus)==1&&pwmb_send_ack_poll(&tx,&send_bus)==1);
    setup();producer.dead=1;CHECK(pwmb_send(&tx,&send_bus,PWMB_ETHERNET_TX,packet,14)==-1&&!producer.calls&&tx.state.unknown);
    setup();send_packet();consumer.dead=1;CHECK(pwmb_receive_poll(&rx,&receive_bus,&message)==-1&&!consumer.calls&&rx.state.unknown);
    printf("PASS %u cached mailbox checks, independent CPU/peer memory views; SOFTWARE callbacks, no runtime authority\n",checks);return 0;
}

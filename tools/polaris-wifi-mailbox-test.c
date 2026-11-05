#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-mailbox.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static struct pwmb_state tx,rx;
static struct pwmb_message message;
static uint8_t record[PWMB_RECORD],saved[PWMB_RECORD],ack[PWMB_LINE],packet[1514],join[112],response[32];
static void open_lane(unsigned lane)
{
    memset(&tx,0,sizeof(tx));memset(&rx,0,sizeof(rx));
    CHECK(pwmb_open(&tx,lane,PWMB_PRODUCER,79)&&pwmb_open(&rx,lane,PWMB_CONSUMER,79));
    CHECK(!pwmb_open(&tx,lane,PWMB_PRODUCER,80));
}
static void exchange(unsigned op,const uint8_t*p,unsigned bytes)
{
    uint64_t seq=tx.next;CHECK(seq==rx.next&&pwmb_prepare(&tx,op,p,bytes,record));
    CHECK(!pwmb_prepare(&tx,op,p,bytes,record));
    CHECK(pwmb_tx_published(&tx,seq,1)==1);
    CHECK(!pwmb_receive(&rx,record,seq-1,seq-1,&message));
    CHECK(!pwmb_receive(&rx,record,seq-1,seq,&message));
    CHECK(pwmb_receive(&rx,record,seq,seq,&message)==1);
    CHECK(message.sequence==seq&&message.operation==op&&message.bytes==bytes&&(!bytes||!memcmp(message.data,p,bytes)));
    CHECK(!pwmb_receive(&rx,record,seq,seq,&message));
    CHECK(pwmb_ack_prepare(&rx,ack)&&pwmb_rx_ack_published(&rx,seq,1)==1);
    CHECK(!pwmb_ack(&tx,ack,seq-1,seq-1)&&!pwmb_ack(&tx,ack,seq-1,seq));
    CHECK(pwmb_ack(&tx,ack,seq,seq)==1&&tx.next==seq+1&&rx.next==seq+1&&!tx.stage&&!rx.stage);
    pwmb_clear(&message,sizeof(message));pwmb_clear(record,sizeof(record));
    CHECK(pwmb_zero(&message,sizeof(message))&&pwmb_zero(record,sizeof(record)));
}
int main(void)
{
    struct pwmb_identity identity={.epoch=79,.mac={2,1,2,3,4,5}},parsed={0};
    uint8_t bootstrap[PWMB_LINE];CHECK(pwmb_bootstrap_make(&identity,bootstrap)&&pwmb_bootstrap_parse(bootstrap,&parsed));
    CHECK(parsed.epoch==identity.epoch&&!memcmp(parsed.mac,identity.mac,6));
    for(unsigned n=0;n<PWMB_LINE;n++){
        if((n>=16&&n<24)||(n>=33&&n<38))continue;
        bootstrap[n]^=1;CHECK(!pwmb_bootstrap_parse(bootstrap,&parsed));bootstrap[n]^=1;
    }
    identity.epoch=0;CHECK(!pwmb_bootstrap_make(&identity,bootstrap));identity.epoch=79;
    memset(identity.mac,0,6);CHECK(!pwmb_bootstrap_make(&identity,bootstrap));
    for(unsigned k=0;k<sizeof(packet);k++)packet[k]=(uint8_t)k;
    open_lane(PWMB_TX);
    /* Exercise sequence progress beyond the startup transport's finite
     * operation budget. This grants no such lifetime to native hardware. */
    for(unsigned k=0;k<70000;k++)exchange(PWMB_ETHERNET_TX,packet,14+k%1501);
    CHECK(tx.next==70001);
    open_lane(PWMB_RX);exchange(PWMB_ETHERNET_RX,packet,1514);
    CHECK(!pwmb_prepare(&tx,PWMB_ETHERNET_RX,packet,1515,record)&&!tx.stage);
    CHECK(!pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,1514,record)&&!tx.stage);
    open_lane(PWMB_CONTROL);exchange(PWMB_STATE,0,0);exchange(PWMB_SCAN,0,0);exchange(PWMB_DISCONNECT,0,0);
    uint8_t index[4]={31};exchange(PWMB_SCAN_ENTRY,index,4);index[0]=32;CHECK(!pwmb_prepare(&tx,PWMB_SCAN_ENTRY,index,4,record));
    pwmb_put32(join,2);join[4]=4;join[5]=8;join[6]=1;memcpy(join+16,"test",4);memcpy(join+48,"password",8);
    exchange(PWMB_JOIN,join,112);
    join[6]=2;join[5]=32;for(unsigned k=0;k<32;k++)join[48+k]=(uint8_t)k;exchange(PWMB_JOIN,join,112);
    memcpy(saved,join,112);
    for(unsigned fault=0;fault<12;fault++){
        memcpy(join,saved,112);
        if(fault==0)join[0]=0;if(fault==1)join[4]=0;if(fault==2)join[4]=33;if(fault==3)join[5]=31;
        if(fault==4)join[6]=3;if(fault==5)join[7]=1;if(fault==6)join[8]=1;if(fault==7)join[14]=1;
        if(fault==8)join[20]=1;if(fault==9)join[111]=1;
        if(fault==10){join[6]=1;join[5]=7;}if(fault==11){join[6]=1;join[5]=32;}
        CHECK(!pwmb_prepare(&tx,PWMB_JOIN,join,112,record)&&!tx.stage);
    }
    pwmb_clear(join,sizeof(join));pwmb_clear(saved,sizeof(saved));
    open_lane(PWMB_REPLY);pwmb_put64(response,19);pwmb_put32(response+8,PWMB_SCAN_ENTRY);exchange(PWMB_RESPONSE,response,32);
    pwmb_put32(response+12,4096);CHECK(!pwmb_prepare(&tx,PWMB_RESPONSE,response,32,record));
    open_lane(PWMB_EVENT);memset(response,0,sizeof(response));pwmb_put32(response,3);exchange(PWMB_NOTIFY,response,16);
    pwmb_put32(response,6);CHECK(!pwmb_prepare(&tx,PWMB_NOTIFY,response,16,record));
    open_lane(PWMB_TX);CHECK(pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record));memcpy(saved,record,sizeof(saved));
    for(unsigned offset=0;offset<PWMB_RECORD;offset++){
        /* Variable payload/length are validated separately, not by a fake CRC. */
        if((offset>=32&&offset<36)||(offset>=128&&offset<192))continue;
        memset(&rx,0,sizeof(rx));CHECK(pwmb_open(&rx,PWMB_TX,PWMB_CONSUMER,79));
        memcpy(record,saved,sizeof(record));record[offset]^=1;
        CHECK(pwmb_receive(&rx,record,1,1,&message)==-1&&rx.unknown);
        CHECK(pwmb_receive(&rx,saved,1,1,&message)==-1);
    }
    open_lane(PWMB_TX);CHECK(pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record)&&pwmb_tx_published(&tx,1,1)==1);
    CHECK(pwmb_receive(&rx,record,1,1,&message)==1&&pwmb_ack_prepare(&rx,ack));
    uint8_t saved_ack[PWMB_LINE];memcpy(saved_ack,ack,sizeof(ack));
    for(unsigned offset=0;offset<PWMB_LINE;offset++){
        memset(&tx,0,sizeof(tx));CHECK(pwmb_open(&tx,PWMB_TX,PWMB_PRODUCER,79));
        CHECK(pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record)&&pwmb_tx_published(&tx,1,1)==1);
        memcpy(ack,saved_ack,sizeof(ack));ack[offset]^=1;
        CHECK(pwmb_ack(&tx,ack,1,1)==-1&&tx.unknown&&tx.next==1);
    }
    open_lane(PWMB_TX);CHECK(pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record));
    CHECK(pwmb_tx_published(&tx,1,0)==-1&&tx.unknown&&!pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record));
    CHECK(pwmb_receive(&rx,record,1,1,&message)==1&&pwmb_rx_ack_published(&rx,1,0)==-1&&rx.unknown);
    open_lane(PWMB_TX);CHECK(pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,64,record));
    CHECK(pwmb_receive(&rx,record,2,2,&message)==-1&&rx.unknown);
    open_lane(PWMB_TX);tx.next=rx.next=UINT64_MAX-1;exchange(PWMB_ETHERNET_TX,packet,14);
    CHECK(!pwmb_live(&tx,PWMB_PRODUCER)&&!pwmb_live(&rx,PWMB_CONSUMER));
    CHECK(!pwmb_prepare(&tx,PWMB_ETHERNET_TX,packet,14,record)&&!pwmb_open(&tx,PWMB_TX,PWMB_PRODUCER,80));
    printf("PASS %u fixed mailbox protocol checks; SOFTWARE only, no native mapping/runtime/CPU handoff\n",checks);return 0;
}

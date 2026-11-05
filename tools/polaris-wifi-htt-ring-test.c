#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-htt-ring.h"
static struct phtr_state rings;
static struct phtt_state setup;
static unsigned checks;
static uint8_t payload[2048],event[2040];
#define CHECK(x) do{assert(x);checks++;}while(0)
static void start(void)
{
    memset(&rings,0,sizeof(rings));memset(&setup,0,sizeof(setup));struct phtm_layout m={0};CHECK(phtm_plan(&m,0x130000000));
    CHECK(phtt_open(&setup,&m,7,100)&&phtt_next(&setup,101)==1&&phtt_sent(&setup,102,1)==1);
    uint8_t version[]={0,4,3,0};CHECK(phtt_receive(&setup,version,4,103)==1);
    for(unsigned n=0;n<3;n++)CHECK(phtt_next(&setup,104+2*n)==1&&phtt_sent(&setup,105+2*n,1)==1);
    CHECK(phtr_open(&rings,&setup));for(unsigned n=0;n<sizeof(payload);n++)payload[n]=(uint8_t)n;
}
static void completion(unsigned id,unsigned status)
{memset(event,0,sizeof(event));event[0]=7;event[1]=(uint8_t)status;event[2]=1;phtt_put16(event+4,id);}
static void indication(unsigned slot,unsigned bytes)
{
    memset(event,0,sizeof(event));event[0]=0x12;phtt_put16(event+2,7);phtt_put16(event+6,1);
    phtt_put64(event+8,rings.memory.allocation+rings.memory.receive+(uint64_t)2048*slot);phtt_put16(event+16,bytes);
}
int main(void)
{
    start();CHECK(rings.rx_posted==2047&&rings.rx_index==2047&&rings.rx_owner[2046]&&!rings.rx_owner[2047]);
    CHECK(phtr_tx(&rings,payload,100,1,0,0,1)==1&&rings.tx_id==0&&rings.tx_owner[0]==1&&rings.tx_bytes==72);
    CHECK(rings.command[0]==1&&rings.command[1]==0x25&&phtr_u16(rings.command+2)==0x800&&phtr_u16(rings.command+4)==100);
    CHECK(phtr_u64(rings.command+8)==rings.memory.allocation+rings.memory.fragments&&pwmi_get(rings.command+16)==65535&&!memcmp(rings.command+20,payload,52));
    CHECK(phtr_u64(rings.fragment+24)==((UINT64_C(100)<<48)|(rings.memory.allocation+rings.memory.transmit)));
    CHECK(phtr_tx_published(&rings,1)==1&&rings.tx_owner[0]==2);
    completion(0,2);CHECK(phtr_event(&rings,event,6)==1&&rings.tx_owner[0]==3&&rings.completed==1);unsigned status=99;
    CHECK(phtr_tx_ack(&rings,0,&status)&&status==2&&!rings.tx_owner[0]&&!phtr_tx_ack(&rings,0,&status));
    CHECK(phtr_tx(&rings,payload,25,3,0,17,1)==1&&rings.tx_bytes==48&&rings.command[1]==0x65&&phtr_u64(rings.command+8)==rings.memory.allocation+rings.memory.transmit+2048&&rings.command[45]==0&&rings.command[47]==0&&phtr_tx_published(&rings,1)==1);
    for(unsigned n=0;n<3000;n++){
        CHECK(phtr_tx(&rings,payload,64,2,0,0,0)==1);unsigned id=rings.tx_id;CHECK(phtr_tx_published(&rings,1)==1);
        completion(id,n%3);CHECK(phtr_event(&rings,event,6)==1&&phtr_tx_ack(&rings,id,&status)&&status==n%3);
        unsigned slot=n%2047;indication(slot,100);CHECK(phtr_event(&rings,event,20)==1&&rings.rx_owner[slot]==2&&rings.rx_posted==2046);
        CHECK(phtr_rx_copied(&rings,slot,1)==1&&!rings.rx_owner[slot]&&phtr_repost(&rings,slot)==1);
        CHECK(phtr_u64(rings.ring_entry)==rings.memory.allocation+rings.memory.receive+(uint64_t)2048*slot&&phtr_reposted(&rings,1)==1&&rings.rx_posted==2047);
    }
    CHECK(rings.received==3000&&rings.reposted==3000&&rings.rx_index==((2047+3000)&2047));
    start();memset(event,0,sizeof(event));event[0]=3;phtt_put16(event+2,99);event[4]=2;event[9]=7;
    CHECK(phtr_event(&rings,event,12)==1&&rings.peer[0].valid&&rings.peer[0].id==99&&rings.peer[0].mac[5]==7);
    event[0]=4;CHECK(phtr_event(&rings,event,4)==1&&!rings.peer[0].valid);
    for(unsigned fault=0;fault<8;fault++){
        start();CHECK(phtr_tx(&rings,payload,64,2,0,0,0)==1);
        if(!fault){CHECK(phtr_tx_published(&rings,0)==-1&&rings.tx_owner[0]==1&&rings.error);continue;}
        if(fault==1){completion(0,0);CHECK(phtr_event(&rings,event,6)==-1&&rings.tx_owner[0]==1);continue;}
        CHECK(phtr_tx_published(&rings,1)==1);completion(0,0);
        if(fault==2){event[2]=2;phtt_put16(event+6,0);CHECK(phtr_event(&rings,event,8)==-1&&rings.tx_owner[0]==2);continue;}
        if(fault==3){event[2]=2;phtt_put16(event+6,1056);CHECK(phtr_event(&rings,event,8)==-1&&rings.tx_owner[0]==2);continue;}
        if(fault==4){CHECK(phtr_event(&rings,event,5)==-1&&rings.tx_owner[0]==2);continue;}
        indication(fault==5?2047:0,fault==6?1689:100);
        if(fault<7){CHECK(phtr_event(&rings,event,20)==-1&&rings.rx_posted==2047);continue;}
        phtt_put16(event+6,2);memcpy(event+20,event+8,12);CHECK(phtr_event(&rings,event,32)==-1&&rings.rx_owner[0]==1&&rings.rx_posted==2047);
    }
    start();indication(4,100);CHECK(phtr_event(&rings,event,20)==1&&phtr_rx_copied(&rings,4,0)==-1&&rings.rx_owner[4]==2);
    start();indication(4,100);CHECK(phtr_event(&rings,event,20)==1&&phtr_rx_copied(&rings,4,1)==1&&phtr_repost(&rings,4)==1&&phtr_reposted(&rings,0)==-1&&rings.busy==2&&!rings.rx_owner[4]);
    printf("PASS %u HTT buffer ownership checks; SOFTWARE only\n",checks);return 0;
}

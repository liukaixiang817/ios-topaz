/* Own QMI CFG/MISSION/OFF on the real GLINK/QRTR client; software modem.
 * Exercises maximum array framing and failure ordering, not DMA or radio. */
#define PWFW_TEST_ENTRY unused_wlfw_startup_suite
#include "polaris-wifi-wlfw-test.c"
#include "polaris-wifi-wcn3990-config.h"
static struct pwfw_ce_config ce_plan(void)
{
    struct pwfw_ce_config q={.targets=12,.services=24,.shadows=24};
    for(unsigned n=0;n<12;n++)q.target[n]=(struct pwfw_ce_target){n,3,32,2048,0};
    for(unsigned n=0;n<24;n++){
        q.service[n]=(struct pwfw_ce_service){0x100+n/2,n%2+1,n/2};
        q.shadow[n]=(struct pwfw_ce_shadow){n/2,n%2?0x40:0x3c};
    }return q;
}
static void ce_answer(struct model*m,const uint8_t*p,uint32_t size)
{
    struct wf_fixture*f=m->data_context;const uint8_t*q=p+32;unsigned bytes=get32(p+20),msg=get16(q+3);
    assert(size>=39&&((bytes+3)&~3u)==size-32&&get32(p+24)==3&&get32(p+28)==77&&get16(q+1)==++f->requests);
    assert(q[0]==0&&get16(q+5)==bytes-7&&f->requests>=5&&f->requests<=7);
    assert(polaris_wifi_wlfw_enable(&f->client,&f->client.ce)==EBUSY&&polaris_wifi_wlfw_disable(&f->client)==EBUSY);
    if(f->requests==5&&f->fault==9){
        assert(msg==0x23&&bytes==559&&q[7]==0x11&&get16(q+8)==241&&q[10]==12);
        assert(get32(q+11+20*6)==6&&get32(q+15+20*6)==3&&get32(q+23+20*6)==16384);
        assert(get32(q+15+20*7)==4&&!get32(q+19+20*7)&&get32(q+27+20*7)==8);
        assert(q[251]==0x12&&get16(q+252)==253&&q[254]==21&&!get32(q+495)&&!get32(q+499)&&!get32(q+503));
        assert(q[507]==0x13&&get16(q+508)==49&&q[510]==12&&get16(q+511)==0&&get16(q+513)==0x3c&&get16(q+555)==11&&get16(q+557)==0x40);
    }else if(f->requests==5){
        assert(msg==0x23&&bytes==643&&q[7]==0x11&&get16(q+8)==241&&q[10]==12);
        for(unsigned n=0;n<12;n++)assert(get32(q+11+20*n)==n&&get32(q+15+20*n)==3&&get32(q+19+20*n)==32&&get32(q+23+20*n)==2048&&!get32(q+27+20*n));
        assert(q[251]==0x12&&get16(q+252)==289&&q[254]==24);
        for(unsigned n=0;n<24;n++)assert(get32(q+255+12*n)==0x100+n/2&&get32(q+259+12*n)==n%2+1&&get32(q+263+12*n)==n/2);
        assert(q[543]==0x13&&get16(q+544)==97&&q[546]==24);
        for(unsigned n=0;n<24;n++)assert(get16(q+547+4*n)==n/2&&get16(q+549+4*n)==(n%2?0x40:0x3c));
    }else assert(msg==0x22&&bytes==14&&q[7]==1&&get16(q+8)==4&&get32(q+10)==(f->requests==6?0u:4u));
    uint8_t response[14]={2,q[1],q[2],q[3],q[4],7,0,2,4,0,0,0,0,0};
    if((f->fault==1&&f->requests==5)||(f->fault==2&&f->requests==6)||(f->fault==3&&f->requests==7)){response[10]=1;response[12]=3;}
    if(f->fault==4&&f->requests==5)response[1]++;
    if(f->fault==5&&f->requests==5)return;
    remote_qrtr(m,Q_DATA,f->local_port,response,sizeof(response));
    if(f->fault==6&&f->requests==5)remote_qrtr(m,Q_DATA,f->local_port,response,sizeof(response));
}
int main(void)
{
    unsigned scenarios=0;
    for(unsigned fault=0;fault<=9;fault++){
        struct wf_fixture*f=wf_setup(0);assert(!wf_drive(f)&&f->client.ready);f->m->data_hook=ce_answer;f->fault=fault;
        struct pwfw_ce_config q=fault==9?polaris_wcn3990_config:ce_plan();assert(polaris_wifi_wlfw_disable(&f->client)==EALREADY);
        if(!fault)for(unsigned bad=0;bad<12;bad++){
            struct pwfw_ce_config b=q;
            switch(bad){
            case 0:b.targets=13;break;case 1:b.services=25;break;case 2:b.shadows=25;break;
            case 3:b.target[1].pipe=0;break;case 4:b.target[0].direction=5;break;
            case 5:b.target[0].entries=31;break;case 6:b.target[0].bytes=65536;break;
            case 7:b.target[0].flags=1;break;case 8:b.service[0].pipe=12;break;
            case 9:b.service[0].direction=3;break;case 10:b.shadow[0].offset=0x44;break;
            case 11:b.shadow[1]=b.shadow[0];break;
            }
            assert(polaris_wifi_wlfw_enable(&f->client,&b)==EINVAL&&!f->client.enable_requested&&f->requests==4);
        }
        if(fault==7)f->current=false;
        int e=polaris_wifi_wlfw_enable(&f->client,&q);
        if(fault!=7){assert(!e);assert(polaris_wifi_wlfw_enable(&f->client,&q)==EALREADY);
            if(fault==8)f->client.ce.targets=13;e=wf_drive(f);}
        if(!fault||fault==3||fault==9){
            assert(!e&&f->client.enabled&&!f->client.disabled&&f->requests==6&&f->client.phase==6);
            assert(!polaris_wifi_wlfw_disable(&f->client));assert(polaris_wifi_wlfw_disable(&f->client)==EALREADY);e=wf_drive(f);
            if(!fault||fault==9)assert(!e&&!f->client.enabled&&f->client.disabled&&f->client.phase==7&&f->requests==7);
        }
        if(fault&&fault!=9){
            assert(e&&e!=EAGAIN&&f->client.error&&!f->client.disabled);
            if(fault!=3)assert(!f->client.enabled);
            unsigned requests=f->requests;assert(polaris_wifi_wlfw_poll(&f->client,f->m->now)==e&&requests==f->requests);
        }
        scenarios++;discard_test_only(f->m);free(f);
    }
    printf("PASS %u WLFW CE CFG/MISSION/OFF scenarios; real transport, software modem, no DMA/radio\n",scenarios);return 0;
}

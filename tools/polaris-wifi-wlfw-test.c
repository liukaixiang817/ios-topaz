/* Real GLINK/QRTR packets, synthetic WLFW peer and assignment provider.
 * No device or secure call. Native consumer composition is a separate gate. */
#define main unused_transport_suite
#define POLARIS_TEST_CUSTOM_QMI 1
#include "polaris-wifi-transport-test.c"
#undef main
#include "polaris-wifi-wlfw.c"
struct wf_fixture {
    struct model*m;struct polaris_wifi_wlfw client;
    unsigned fault,requests,assigned,scope_calls,ready_requests;
    bool current;uint32_t local_port;
};
static bool wf_scope(void*ctx)
{struct wf_fixture*f=ctx;f->scope_calls++;return f->current;}
static bool wf_assign(void*ctx,const struct pwfw_region*r,unsigned n)
{
    struct wf_fixture*f=ctx;assert(++f->assigned==1&&n==2&&f->requests==2);
    assert(r[0].address==0xa0000000&&r[0].bytes==0x80000&&r[0].secure==1);
    assert(r[1].address==0xa0080000&&r[1].bytes==0x80000&&!r[1].secure);
    assert(polaris_wifi_wlfw_poll(&f->client,f->m->now)==EBUSY);
    if(f->fault==12)f->current=false;return f->fault!=11;
}
static void wf_ind(struct wf_fixture*f,unsigned msg)
{uint8_t q[7]={4,0,0,(uint8_t)msg,0,0,0};remote_qrtr(f->m,Q_DATA,f->local_port,q,7);}
static void wf_answer(struct model*m,const uint8_t*p,uint32_t size)
{
    struct wf_fixture*f=m->data_context;assert(size>=39&&((get32(p+20)+3)&~3u)==size-32&&get32(p+24)==3&&get32(p+28)==77);
    const uint8_t*q=p+32;unsigned bytes=get32(p+20),msg=get16(q+3);f->local_port=get32(p+12);f->requests++;
    const unsigned expected[]={0x20,0x2d,0x2e,0x24};assert(f->requests<=4&&msg==expected[f->requests-1]&&get16(q+1)==f->requests);
    assert(q[0]==0&&get16(q+5)==bytes-7);
    uint8_t response[210]={2,q[1],q[2],q[3],q[4],7,0,2,4,0,0,0,0,0};unsigned n=14;
    if(msg==0x20){
        static const uint8_t body[]={0x10,1,0,1,0x13,1,0,1,0x14,1,0,1,0x15,4,0,0x4c,0x45,0x4e,0x4b};
        assert(bytes==26&&!memcmp(q+7,body,sizeof(body)));
        response[n++]=0x10;response[n++]=8;response[n++]=0;response[n++]=f->fault==18?7:0;n+=7;
        if(f->fault==13)wf_ind(f,0x21); /* No early indication can stand in for this allocation. */
    }else if(msg==0x2d){
        static const uint8_t body[]={1,8,0,0,0,0,0xa0,0,0,0,0,2,4,0,0,0,0x10,0};
        assert(bytes==25&&!memcmp(q+7,body,sizeof(body)));
        response[n++]=3;response[n++]=27;response[n++]=0;response[n++]=2;
        for(unsigned j=0;j<2;j++){put32(response+n,0xa0000000+0x80000*j);n+=8;put32(response+n,0x80000);n+=4;response[n++]=(uint8_t)!j;}
        if(f->fault==1)put32(response+18,0x9ffff000);
        if(f->fault==2)put32(response+31,0xa0040000);
        if(f->fault==3)response[18]++;
        if(f->fault==4)response[30]=2;
        if(f->fault==5)response[17]=3;
        if(f->fault==6)put32(response+39,0x81000);
        if(f->fault==7){response[17]=0;response[15]=1;n=18;}
        if(f->fault==8){memmove(response+7,response+14,n-14);n-=7;}
        if(f->fault==9){response[n++]=3;response[n++]=1;response[n++]=0;response[n++]=0;}
        if(f->fault==10){response[10]=1;response[12]=3;}
    }else if(msg==0x2e){assert(bytes==7&&f->assigned==1);f->ready_requests++;if(f->fault!=16){wf_ind(f,0x2b);wf_ind(f,0x21);}}
    else{
        assert(bytes==7);static const uint8_t info[]={0x10,8,0,0x34,0x12,0,0,2,0,0,0,0x13,6,0,1,0,0,0,1,'T'};
        memcpy(response+n,info,sizeof(info));n+=sizeof(info);
    }
    response[5]=(uint8_t)(n-7);response[6]=(uint8_t)((n-7)>>8);
    if(f->fault==14&&msg==0x2d)response[1]++;
    if(f->fault==15&&msg==0x2d)return;
    remote_qrtr(m,Q_DATA,f->local_port,response,n);
    if(f->fault==17&&msg==0x2d)remote_qrtr(m,Q_DATA,f->local_port,response,n);
}
static struct wf_fixture*wf_setup(unsigned fault)
{
    struct wf_fixture*f=calloc(1,sizeof(*f));assert(f);f->m=make_model(true);f->fault=fault;f->current=true;
    assert(!polaris_wifi_glink_start(f->m->g));for(unsigned j=0;j<8;j++)assert(!polaris_wifi_glink_poll_once(f->m->g));
    f->m->data_hook=wf_answer;f->m->data_context=f;
    struct polaris_wifi_wlfw_cfg cfg={.transport=f->m->g,.msa=0xa0000000,.bytes=0x100000,.scope=wf_scope,.assign=wf_assign,.ctx=f};
    assert(!polaris_wifi_wlfw_open(&f->client,&cfg,f->m->now));assert(polaris_wifi_wlfw_open(&f->client,&cfg,f->m->now)==EALREADY);return f;
}
static int wf_drive(struct wf_fixture*f)
{
    for(unsigned j=0;j<100;j++){
        int e=polaris_wifi_wlfw_poll(&f->client,f->m->now);if(e!=EAGAIN)return e;
        f->m->now+=1000000;
    }assert(0);return 0;
}
int main(void)
{
    unsigned scenarios=0;
    for(unsigned fault=0;fault<=18;fault++){
        struct wf_fixture*f=wf_setup(fault);int e=wf_drive(f);scenarios++;
        if(!fault||fault==18){
            assert(!e&&f->client.ready&&f->client.fw_ready&&f->assigned==1&&f->requests==4&&f->ready_requests==1&&f->client.capability.chip_id==0x1234);
            assert(f->client.fw_indications==1&&f->client.msa_indications==1);
            assert(!polaris_wifi_wlfw_poll(&f->client,f->m->now)&&f->requests==4);
            /* Exact server loss invalidates even a completed activation. */
            uint8_t body[20]={0};put32(body,Q_DEL_SERVER);put32(body+4,69);put32(body+8,1);put32(body+12,3);put32(body+16,77);
            remote_qrtr(f->m,Q_DEL_SERVER,CTRL,body,20);assert(polaris_wifi_wlfw_poll(&f->client,f->m->now)==ENOTCONN);
        }else{
            assert(e&&e!=EAGAIN&&!f->client.ready&&f->client.error);
            if(fault<=10||fault==13||fault==14||fault==15||fault==17)assert(!f->assigned&&!f->ready_requests);
            if(fault==11||fault==12)assert(f->assigned==1&&!f->ready_requests);
            unsigned requests=f->requests,assigned=f->assigned;
            assert(polaris_wifi_wlfw_poll(&f->client,f->m->now)==e&&f->requests==requests&&f->assigned==assigned);
        }
        discard_test_only(f->m);free(f);
    }
    printf("PASS %u WLFW startup scenarios; real GLINK/QRTR C, software peer/assignment only\n",scenarios);return 0;
}

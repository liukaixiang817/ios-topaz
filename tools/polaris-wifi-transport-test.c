/* Deterministic transport integration peer. Software shared-memory model only;
 * never opens USB or maps physical addresses. */
#define POLARIS_WIFI_GLINK_HOST_TEST 1
#include "polaris-wifi-glink.c"
#include "polaris-wifi-cap.c"
#include <assert.h>
#include <stdio.h>

struct model {
    uint8_t mem[0x50000];
    struct polaris_wifi_glink *g;
    uint64_t now;
    unsigned reads, writes, rings, invalidates, barriers, ready;
    unsigned fail_read, fail_write, fail_ring, fail_cache, fail_barrier;
    unsigned forbidden, local_intent, remote_intent, data_sent, producer_writes;
    uint32_t remote_head;
    bool lease, freeze_clock, responding;
    void (*data_hook)(struct model *, const uint8_t *, uint32_t);
    void *data_context;
};
static uint32_t const DESC = 0x10020, TX = 0x10040, RX = 0x20000, FSIZE = 0x4000;
static void remote_frame(struct model *m, unsigned cmd, uint32_t cid, uint32_t arg,
    const uint8_t *body, uint32_t n)
{
    uint8_t h[8]; header(h, cmd, cid, arg);
    uint32_t bytes = (8 + n + 7) & ~7u;
    uint32_t tail = get32(m->mem + DESC + 8);
    uint32_t free_bytes = tail <= m->remote_head ? FSIZE - m->remote_head + tail : tail - m->remote_head;
    assert(bytes + 8 <= free_bytes);
    for (uint32_t i = 0; i < bytes; i++)
        m->mem[RX + (m->remote_head + i) % FSIZE] = i < 8 ? h[i] : i < 8+n ? body[i-8] : 0;
    m->remote_head = (m->remote_head + bytes) % FSIZE;
    put32(m->mem + DESC + 12, m->remote_head);
}
static void remote_qrtr(struct model *m, uint32_t type, uint32_t dst_port, const uint8_t *body, uint32_t n)
{
    assert(m->local_intent);
    uint8_t packet[512] = {0}, frame[520];
    uint32_t bytes = 32 + ((n + 3) & ~3u);
    put32(packet, 1); put32(packet+4, type); put32(packet+8, 3); put32(packet+12, type==Q_DATA?77:CTRL);
    put32(packet+20,n); put32(packet+24,1); put32(packet+28,dst_port); memcpy(packet+32,body,n);
    put32(frame,bytes); put32(frame+4,0); memcpy(frame+8,packet,bytes);
    remote_frame(m,DATA,7,m->local_intent,frame,8+bytes);
}
static void peer(struct model *m)
{
    if (!m->responding) return;
    uint32_t at = get32(m->mem+DESC), end = get32(m->mem+DESC+4);
    while(at != end) {
        uint8_t h[16], body[512];
        for(unsigned i=0;i<8;i++) h[i]=m->mem[TX+(at+i)%FSIZE];
        uint32_t cmd=get16(h), cid=get16(h+2), arg=get32(h+4), n=8;
        if(cmd==OPEN) n+=arg;
        if(cmd==INTENT) n+=arg*8;
        if(cmd==DATA||cmd==DATA_MORE) {
            for(unsigned i=8;i<16;i++) h[i]=m->mem[TX+(at+i)%FSIZE];
            n=16+get32(h+8);
        }
        assert(n<=sizeof(body));
        for(unsigned i=8;i<n;i++) body[i-8]=m->mem[TX+(at+i)%FSIZE];
        if(cmd==VERSION) {
            remote_frame(m,VERSION_ACK,1,1,NULL,0);
            remote_frame(m,OPEN,7,7,(const uint8_t*)"IPCRTR",7);
        } else if(cmd==OPEN) {
            assert(cid==1&&arg==7&&!memcmp(body,"IPCRTR",7));
            remote_frame(m,OPEN_ACK,1,0,NULL,0);
        } else if(cmd==INTENT) {
            if(!m->local_intent) m->local_intent=get32(body+4);
        } else if(cmd==DATA||cmd==DATA_MORE) {
            assert(arg==0); /* remote intent zero must remain legal. */
            assert(cmd==DATA&&get32(body+4)==0);
            remote_frame(m,DONE_REUSE,7,arg,NULL,0);
            const uint8_t *p=body+8;
            if(get32(p+4)==Q_DATA && m->data_hook) m->data_hook(m,p,get32(body));
            if(get32(p+4)==Q_NEW_LOOKUP) {
                assert(get32(p+32+4)==PW_SERVICE&&get32(p+32+8)==1);
                uint8_t service[20]={0};put32(service,Q_NEW_SERVER);put32(service+4,PW_SERVICE);
                put32(service+8,1);put32(service+12,3);put32(service+16,77);
                remote_qrtr(m,Q_DATA,get32(p+12),service,20);
            }
            if(get32(p+4)==Q_DATA&&get32(p+28)==77&&get32(p+20)==7) {
                const uint8_t *q=p+32;
                assert(q[0]==0&&pw_le16(q+3)==PW_CAP_MESSAGE);
                uint8_t reply[34]={2,q[1],q[2],PW_CAP_MESSAGE,0,27,0,
                    2,4,0,0,0,0,0,
                    0x10,8,0,0x34,0x12,0,0,2,0,0,0,
                    0x13,6,0,1,0,0,0,1,'T'};
                remote_qrtr(m,Q_DATA,get32(p+12),reply,sizeof(reply));
                m->data_sent++;
            }
        } else if(cmd==CLOSE) {
            remote_frame(m,CLOSE_ACK,1,0,NULL,0);
            remote_frame(m,CLOSE,7,0,NULL,0);
        }
        at=(at+((n+7)&~7u))%FSIZE;
        put32(m->mem+DESC,at); /* remote, not APPS, consumes TX. */
    }
    if(m->local_intent&&!m->ready) {
        uint8_t intent[8], hello[20]={0};
        put32(intent,65536); put32(intent+4,0);
        remote_frame(m,INTENT,7,1,intent,8); m->remote_intent++;
        put32(hello,Q_HELLO); remote_qrtr(m,Q_HELLO,CTRL,hello,20);
        m->ready=1;
    }
}
static bool lease(void *v,uint64_t epoch,const struct polaris_glink_layout *layout)
{ struct model*m=v;return m->lease&&epoch==9&&layout->remote==1; }
static bool read_mem(void*v,uint32_t at,void*dst,uint32_t n)
{
    struct model*m=v;m->reads++;if(m->fail_read==m->reads)return false;
    assert(at+n<=sizeof(m->mem));memcpy(dst,m->mem+at,n);return true;
}
static bool write_mem(void*v,uint32_t at,uint32_t value)
{
    struct model*m=v;m->writes++;
    if(!(at==DESC+4||at==DESC+8||inside(at,4,TX,FSIZE)))m->forbidden++;
    if(m->fail_write==m->writes)return false;
    put32(m->mem+at,value);if(at==DESC+4)m->producer_writes++;return true;
}
static bool barrier(void*v)
{struct model*m=v;m->barriers++;return m->fail_barrier!=m->barriers;}
static bool invalidate(void*v,uint32_t at,uint32_t n)
{struct model*m=v;m->invalidates++;assert(inside(at,n,RX,FSIZE));return m->fail_cache!=m->invalidates;}
static bool doorbell(void*v)
{struct model*m=v;m->rings++;if(m->fail_ring==m->rings)return false;peer(m);return true;}
static void sleep_model(void*v,uint32_t us)
{struct model*m=v;if(!m->freeze_clock)m->now+=us;peer(m);}
static uint64_t now_model(void*v){return ((struct model*)v)->now;}
static struct model *make_model(bool respond)
{
    struct model*m=calloc(1,sizeof(*m));assert(m);m->lease=true;m->responding=respond;
    m->remote_head=FSIZE-8; /* exercise wrapped RX control frame immediately. */
    put32(m->mem+DESC,8);put32(m->mem+DESC+4,8);
    put32(m->mem+DESC+8,m->remote_head);put32(m->mem+DESC+12,m->remote_head);
    struct polaris_wifi_glink_cfg cfg={.epoch=9,.smem_phys=0x86000000,.smem_bytes=0x200000,.local_node=1,
        .layout={1,0x10000,0x40000,3,{DESC,32,0},{TX,FSIZE,0},{RX,FSIZE,1}},
        .scope=lease,.smem_read=read_mem,.smem_write32=write_mem,.order=barrier,
        .invalidate=invalidate,.ring=doorbell,.sleep_us=sleep_model,.now_us=now_model,.ctx=m};
    m->g=polaris_wifi_glink_create(&cfg);assert(m->g);return m;
}
static void discard_test_only(struct model*m)
{
    /* Test harness teardown only: production destroy rejects faulted/unknown.
     * No peer/DMA exists in this software model; don't add such a production API. */
    struct polaris_wifi_glink*g=m->g;
    while(g->outgoing)finish(g,ECANCELED);
    while(g->commands){struct command*c=g->commands;g->commands=c->next;free(c);}
    clear_intents(g);instances[g->slot]=NULL;free(g);free(m);
}
static void integrated(void)
{
    struct model*m=make_model(true);struct polaris_wifi_glink_status s;
    assert(!polaris_wifi_glink_start(m->g));
    assert(get32(m->mem+DESC+8)==FSIZE-8); /* start did not reset RX consumer. */
    for(unsigned i=0;i<8;i++)assert(!polaris_wifi_glink_poll_once(m->g));
    assert(!polaris_wifi_glink_status(m->g,&s)&&s.opened&&s.peer_seen&&m->invalidates);
    struct polaris_wifi_cap_client client;
    assert(!polaris_wifi_cap_open(&client,m->g,m->now));
    assert(!client.discovered&&polaris_wifi_cap_request(&client,31,m->now)==EAGAIN);
    assert(polaris_wifi_cap_poll(&client,m->now)==EAGAIN);
    assert(client.discovered&&client.node==3&&client.service_port==77);
    assert(!polaris_wifi_cap_request(&client,31,m->now));
    for(unsigned i=0;i<8&&!client.done;i++)(void)polaris_wifi_cap_poll(&client,m->now);
    assert(client.done&&!client.error&&client.capability.chip_id==0x1234&&m->data_sent==1);
    assert(polaris_wifi_cap_request(&client,32,m->now)==EALREADY);
    assert(!polaris_wifi_cap_close(&client));
    int stop=EBUSY;
    for(unsigned i=0;i<12&&stop==EBUSY;i++) { (void)polaris_wifi_glink_poll_once(m->g);stop=polaris_wifi_glink_stop(m->g); }
    assert(!stop);assert(!polaris_wifi_glink_status(m->g,&s)&&s.quiescent&&!s.pending);
    assert(!m->forbidden&&m->remote_intent==1&&s.first_error==0);
    assert(!polaris_wifi_glink_destroy(m->g));free(m);
}
static void faults(void)
{
    for(unsigned kind=0;kind<7;kind++) {
        struct model*m=make_model(true);
        if(kind==0)m->lease=false;
        if(kind==1)m->fail_read=1;
        if(kind==2)m->fail_write=2;
        if(kind==3)m->fail_ring=1;
        if(kind==4)m->fail_barrier=1;
        if(kind==5)put32(m->mem+DESC+12,0); /* pending RX: don't reset/discard. */
        if(kind<6)assert(polaris_wifi_glink_start(m->g));
        else {assert(!polaris_wifi_glink_start(m->g));m->fail_cache=1;assert(polaris_wifi_glink_poll_once(m->g));}
        unsigned writes=m->writes,rings=m->rings;
        struct polaris_wifi_glink_status a,b;
        assert(!polaris_wifi_glink_status(m->g,&a)&&a.first_error);
        assert(polaris_wifi_glink_start(m->g));assert(polaris_wifi_glink_poll_once(m->g));
        assert(polaris_wifi_glink_stop(m->g));assert(polaris_wifi_glink_destroy(m->g));
        assert(!polaris_wifi_glink_status(m->g,&b)&&a.first_error==b.first_error);
        assert(m->writes==writes&&m->rings==rings&&!m->forbidden);
        if(kind==2||kind==3)assert(a.uncertain);
        if(kind==0||kind==1||kind==4||kind==5)assert(!m->writes);
        discard_test_only(m);
    }
}
static void bounded(void)
{
    struct model*m=make_model(true);assert(!polaris_wifi_glink_start(m->g));
    for(unsigned i=0;i<8;i++)assert(!polaris_wifi_glink_poll_once(m->g));
    struct polaris_wifi_qrtr_port*p=polaris_wifi_glink_qrtr_ops(m->g)->open(NULL,NULL,NULL);assert(p);
    m->responding=false;m->freeze_clock=true;
    memset(m->g->foreign,0,sizeof(m->g->foreign));
    uint8_t request[7];assert(polaris_wlfw_cap_request(1,request,7));
    assert(polaris_wifi_glink_qrtr_ops(m->g)->send(p,3,77,request,7)==EIO);
    assert(m->g->first_error==PWF_CLOCK);
    discard_test_only(m);
    m=make_model(true);assert(!polaris_wifi_glink_start(m->g));
    for(unsigned i=0;i<8;i++)assert(!polaris_wifi_glink_poll_once(m->g));
    p=polaris_wifi_glink_qrtr_ops(m->g)->open(NULL,NULL,NULL);assert(p);
    m->responding=false;
    assert(!polaris_wifi_glink_qrtr_ops(m->g)->send(p,3,77,request,7));
    assert(pending(m->g));
    remote_frame(m,CLOSE,7,0,NULL,0);
    assert(polaris_wifi_glink_poll_once(m->g)==EIO&&m->g->first_error==PWF_PROTOCOL&&m->g->uncertain);
    assert(pending(m->g)&&polaris_wifi_glink_destroy(m->g)==EBUSY);
    discard_test_only(m);
    m=make_model(true);assert(!polaris_wifi_glink_start(m->g));
    for(unsigned i=0;i<8;i++)assert(!polaris_wifi_glink_poll_once(m->g));
    m->now=100;
    p=polaris_wifi_glink_qrtr_ops(m->g)->open(NULL,NULL,NULL);assert(p);
    assert(!polaris_wifi_glink_qrtr_ops(m->g)->lookup(p,PW_SERVICE,1,0));
    m->now=99;
    assert(polaris_wifi_glink_qrtr_ops(m->g)->send(p,3,77,request,7)!=0&&m->g->first_error==PWF_CLOCK);
    discard_test_only(m);
    m=make_model(false);m->g->owner=(uintptr_t)pthread_self()+1;
    assert(polaris_wifi_glink_start(m->g)==EBUSY&&m->writes==0);
    m->g->owner=0;assert(!polaris_wifi_glink_destroy(m->g));free(m);
}
int main(void)
{integrated();faults();bounded();puts("PASS full GLINK/QRTR/WLFW software integration; 7 sticky fault classes; finite clock/gate; no hardware");return 0;}

/* Full software GLINK FIFO/QRTR/RMTFS integration. No physical memory or USB. */
#define main polaris_existing_transport_test_main
#include "polaris-wifi-transport-test.c"
#undef main
#include "polaris-wifi-rmtfs.c"

struct fixture {
    struct model *m;
    struct polaris_rmtfs *s;
    struct polaris_rmtfs_cfg cfg;
    uint8_t *inputs[4], shared[PWR_SHARED];
    bool current, owned, retired, lose_scope, fail_reply, reenter;
    unsigned read_count, write_count, order_count, fail_read, fail_write, fail_order;
    uint32_t service_port, response_bytes, response_port;
    uint8_t response[25];
    bool inject;
    uint8_t injected[128]; unsigned injected_n;
};
static bool input_current(void *ctx,const struct polaris_rmtfs_cfg *cfg)
{ struct fixture *f=ctx; return f->current && cfg->epoch==9; }
static bool ram_scope(void *ctx,uint64_t epoch,uint32_t node,uint64_t pa,uint32_t n)
{ struct fixture *f=ctx; return f->owned&&epoch==9&&node==3&&pa==0xa0000000&&n==PWR_SHARED; }
static bool shared_read(void *ctx,uint64_t epoch,uint32_t at,void *dst,uint32_t n)
{
    struct fixture *f=ctx; assert(epoch==9&&at<=PWR_SHARED&&n<=PWR_SHARED-at);
    f->read_count++;
    if(f->reenter) assert(polaris_rmtfs_poll(f->s)==EBUSY);
    if(f->fail_read==f->read_count) return false;
    memcpy(dst,f->shared+at,n);
    if(f->lose_scope) f->owned=false;
    if(f->fail_reply&&f->read_count==2) f->m->fail_write=f->m->writes+1;
    return true;
}
static bool shared_write(void *ctx,uint64_t epoch,uint32_t at,const void *src,uint32_t n)
{
    struct fixture *f=ctx; assert(epoch==9&&at<=PWR_SHARED&&n<=PWR_SHARED-at);
    f->write_count++;
    if(f->fail_write==f->write_count) { memcpy(f->shared+at,src,n/2); return false; }
    memcpy(f->shared+at,src,n); return true;
}
static bool ram_order(void *ctx)
{ struct fixture *f=ctx; return ++f->order_count!=f->fail_order; }
static bool ram_retired(void *ctx,uint64_t epoch)
{ return epoch==9&&((struct fixture*)ctx)->retired; }
static void inject_qmi(struct fixture *f,uint32_t node,uint32_t port,const uint8_t *body,unsigned n)
{
    uint8_t packet[512]={0}, frame[520]; assert(n<=400);
    unsigned bytes=32+((n+3)&~3u);
    put32(packet,1); put32(packet+4,Q_DATA); put32(packet+8,node); put32(packet+12,port);
    put32(packet+20,n); put32(packet+24,1); put32(packet+28,f->service_port); memcpy(packet+32,body,n);
    put32(frame,bytes); put32(frame+4,0); memcpy(frame+8,packet,bytes);
    remote_frame(f->m,DATA,7,f->m->local_intent,frame,bytes+8);
}
static void answer_hook(struct model *m,const uint8_t *p,uint32_t n)
{
    struct fixture *f=m->data_context;
    assert(n>=32&&get32(p+20)<=n-32);
    if(get32(p+28)>=CTRL) return;
    unsigned bytes=get32(p+20);
    assert(bytes>=14&&bytes<=25&&p[32]==2&&get32(p+24)==3);
    memcpy(f->response,p+32,bytes); f->response_bytes=bytes; f->response_port=get32(p+28);
    if(f->inject) { f->inject=false; inject_qmi(f,3,78,f->injected,f->injected_n); }
}
static struct fixture *setup(void)
{
    struct fixture *f=calloc(1,sizeof(*f)); assert(f);
    f->m=make_model(true); f->current=f->owned=true;
    f->cfg=(struct polaris_rmtfs_cfg){.transport=f->m->g,.epoch=9,.remote_node=3,
        .shared_phys=0xa0000000,.shared_bytes=PWR_SHARED,.inputs_current=input_current,.scope=ram_scope,
        .shared_read=shared_read,.shared_write=shared_write,.order=ram_order,.retired=ram_retired,.ctx=f};
    for(unsigned i=0;i<4;i++) {
        f->inputs[i]=malloc(pwr_sizes[i]); assert(f->inputs[i]);
        for(unsigned j=0;j<pwr_sizes[i];j++) f->inputs[i][j]=(uint8_t)(i*13+j*37);
        f->cfg.inputs[i].data=f->inputs[i]; f->cfg.inputs[i].bytes=pwr_sizes[i];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CC_SHA256(f->inputs[i],pwr_sizes[i],f->cfg.inputs[i].sha256);
#pragma clang diagnostic pop
    }
    assert(!polaris_wifi_glink_start(f->m->g));
    for(unsigned i=0;i<8;i++) assert(!polaris_wifi_glink_poll_once(f->m->g));
    f->s=polaris_rmtfs_create(&f->cfg); assert(f->s);
    f->m->data_hook=answer_hook; f->m->data_context=f;
    assert(!polaris_rmtfs_start(f->s)); f->service_port=f->s->port->id;
    assert(f->s->port->published&&f->s->port->service==14&&f->s->port->version==1&&f->s->port->instance==1);
    return f;
}
static void cleanup(struct fixture *f,bool fault)
{
    for(unsigned i=0;i<4;i++) {
        /* Physical source is immutable even when its private shadow changed. */
        assert(pwr_hash(f->inputs[i],pwr_sizes[i],f->cfg.inputs[i].sha256));
        free(f->inputs[i]);
    }
    if(fault) {
        assert(polaris_rmtfs_destroy(f->s));
        /* Software peer only, with no hardware/lifetime. NOT a production API. */
        pwr_free_unexposed(f->s); discard_test_only(f->m);
    } else {
        assert(!polaris_rmtfs_destroy(f->s));
        int stop=EBUSY;
        for(unsigned i=0;i<16&&stop==EBUSY;i++) {
            (void)polaris_wifi_glink_poll_once(f->m->g); stop=polaris_wifi_glink_stop(f->m->g);
        }
        assert(!stop&&!f->m->forbidden); assert(!polaris_wifi_glink_destroy(f->m->g)); free(f->m);
    }
    free(f);
}
static unsigned header_qmi(uint8_t *q,uint16_t txn,unsigned msg)
{ memset(q,0,128); pwr_put(q+1,txn,2); pwr_put(q+3,msg,2); return 7; }
static void field_qmi(uint8_t *q,unsigned *n,unsigned tag,uint64_t value,unsigned width)
{ q[*n]=(uint8_t)tag; pwr_put(q+*n+1,width,2); pwr_put(q+*n+3,value,width); *n+=3+width; }
static void finish_qmi(uint8_t *q,unsigned n) { pwr_put(q+5,n-7,2); }
static void request(struct fixture *f,uint32_t port,uint8_t *q,unsigned n)
{
    finish_qmi(q,n); f->response_bytes=0; inject_qmi(f,3,port,q,n);
    for(unsigned i=0;i<16&&!f->response_bytes;i++) assert(!polaris_rmtfs_poll(f->s));
    assert(f->response_bytes>=14&&f->response_port==port);
    assert(pwr_get(f->response+1,4)==pwr_get(q+1,4));
}
static unsigned qerror(struct fixture *f)
{ assert((pwr_get(f->response+10,2)==0)==(pwr_get(f->response+12,2)==0)); return (unsigned)pwr_get(f->response+12,2); }
static unsigned open_qmi(uint8_t *q,uint16_t txn,const char *path)
{
    unsigned n=header_qmi(q,txn,PWR_OPEN),len=(unsigned)strlen(path);
    q[n]=1; pwr_put(q+n+1,len,2); memcpy(q+n+3,path,len); return n+3+len;
}
static uint32_t open_part(struct fixture *f,uint16_t txn,unsigned part)
{
    uint8_t q[128]; unsigned n=open_qmi(q,txn,pwr_paths[part]); request(f,77,q,n);
    assert(!qerror(f)&&f->response_bytes==21); return (uint32_t)pwr_get(f->response+17,4);
}
static unsigned rw_qmi(uint8_t *q,uint16_t txn,uint32_t h,unsigned dir,unsigned count,bool bad_last)
{
    unsigned n=header_qmi(q,txn,PWR_RW); field_qmi(q,&n,1,h,4); field_qmi(q,&n,2,dir,1);
    q[n]=3; pwr_put(q+n+1,1+12*count,2); q[n+3]=(uint8_t)count;
    for(unsigned i=0;i<count;i++) {
        uint8_t *v=q+n+4+12*i; pwr_put(v,i,4); pwr_put(v+4,0xa0000000+i*512,4); pwr_put(v+8,1,4);
        if(bad_last&&i==count-1) pwr_put(v,0xffffffffu,4);
    }
    return n+4+12*count;
}
static void close_part(struct fixture *f,uint16_t txn,uint32_t h)
{
    uint8_t q[128]; unsigned n=header_qmi(q,txn,PWR_CLOSE); field_qmi(q,&n,1,h,4);
    request(f,78,q,n); assert(!qerror(f));
}
static void retire(struct fixture *f)
{
    /* Close notice and outstanding replies must be DONE first. */
    assert(polaris_rmtfs_stop(f->s)==EBUSY); assert(!f->s->stopped);
    for(unsigned i=0;i<8;i++) assert(!polaris_wifi_glink_poll_once(f->m->g));
    assert(polaris_rmtfs_stop(f->s)==EBUSY); f->retired=true;
    assert(!polaris_rmtfs_stop(f->s));
}
static void happy(void)
{
    struct fixture *f=setup(); uint32_t h=open_part(f,1,0); uint8_t q[128];
    assert(polaris_rmtfs_stop(f->s)==EBUSY&&!f->s->stopping);
    unsigned n=header_qmi(q,2,PWR_ALLOCATE); field_qmi(q,&n,1,1,4); field_qmi(q,&n,2,PWR_SHARED,4);
    request(f,77,q,n); assert(!qerror(f)&&pwr_get(f->response+17,8)==0xa0000000);
    n=rw_qmi(q,3,h,1,2,false); request(f,78,q,n); assert(!qerror(f));
    assert(!memcmp(f->shared,f->inputs[0],1024));
    memset(f->shared,0x76,1024); f->reenter=true;
    n=rw_qmi(q,4,h,0,2,false); request(f,78,q,n); assert(!qerror(f));
    assert(!memcmp(f->s->shadow[0],f->shared,1024)&&memcmp(f->inputs[0],f->shared,1024));
    /* Replay is byte-identical, with no repeated memory I/O even after input changes. */
    unsigned reads=f->read_count; memset(f->shared,0xa5,1024); request(f,78,q,n);
    assert(!qerror(f)&&f->read_count==reads&&f->s->shadow[0][0]==0x76);
    n=header_qmi(q,5,PWR_SYNC); field_qmi(q,&n,1,h,4); request(f,77,q,n); assert(!qerror(f));
    struct polaris_rmtfs_status s; assert(!polaris_rmtfs_status(f->s,&s));
    assert(s.dirty&&!s.durable_nv&&s.bytes_to_shadow==1024&&s.bytes_to_remote==1024&&s.replayed==1&&s.operations_completed==4);
    for(unsigned i=1;i<4;i++) { uint32_t k=open_part(f,(uint16_t)(10+i),i); close_part(f,(uint16_t)(20+i),k); }
    close_part(f,6,h); retire(f); cleanup(f,false);
}
static void malformed(void)
{
    struct fixture *f=setup(); uint8_t q[128]; uint32_t h=open_part(f,1,0);
    unsigned n=open_qmi(q,2,"/boot/modem_fsg_oem_1"); request(f,77,q,n); assert(qerror(f)==PWR_Q_INVAL);
    n=rw_qmi(q,3,h,0,2,true); request(f,77,q,n);
    assert(qerror(f)==PWR_Q_INVAL&&!f->read_count&&!f->s->dirty);
    n=header_qmi(q,4,PWR_ALLOCATE); field_qmi(q,&n,1,2,4); field_qmi(q,&n,2,512,4);
    request(f,77,q,n); assert(qerror(f)==PWR_Q_INVAL);
    n=header_qmi(q,5,PWR_CLOSE); field_qmi(q,&n,1,h,4); field_qmi(q,&n,1,h,4);
    request(f,77,q,n); assert(qerror(f)==PWR_Q_MALFORMED&&f->s->handles[0].live);
    n=header_qmi(q,6,PWR_CLOSE); field_qmi(q,&n,1,h,4); field_qmi(q,&n,8,0,4);
    request(f,77,q,n); assert(qerror(f)==PWR_Q_MALFORMED);
    n=header_qmi(q,7,PWR_SYNC); field_qmi(q,&n,1,0xffffffff,4);
    request(f,77,q,n); assert(qerror(f)==PWR_Q_BAD_HANDLE);
    n=header_qmi(q,8,99); request(f,77,q,n); assert(qerror(f)==PWR_Q_UNSUPPORTED);
    n=rw_qmi(q,9,h,1,1,false); finish_qmi(q,n); f->response_bytes=0;
    inject_qmi(f,4,77,q,n); assert(!polaris_rmtfs_poll(f->s)&&!f->response_bytes&&!f->write_count&&f->s->rejected_peer==1);
    close_part(f,10,h); retire(f); cleanup(f,false);
}
static void faults_rmtfs(void)
{
    for(unsigned kind=0;kind<8;kind++) {
        struct fixture *f=setup(); uint8_t q[128]; uint32_t h=open_part(f,1,0);
        unsigned n=rw_qmi(q,2,h,kind==1?1:0,2,false); finish_qmi(q,n);
        if(kind==0) f->fail_read=2;
        if(kind==1) f->fail_write=2;
        if(kind==2) f->fail_order=1;
        if(kind==3) f->lose_scope=true;
        if(kind==4) f->owned=false;
        if(kind==5) f->m->g->cfg.epoch=10;
        if(kind==6) f->fail_order=2;
        if(kind==7) f->fail_reply=true; /* failed reply after known RAM operation */
        f->response_bytes=0; inject_qmi(f,3,77,q,n);
        int e=polaris_rmtfs_poll(f->s);
        if(!e||f->response_bytes) fprintf(stderr,"fault kind=%u error=%d response=%u issued=%u completed=%u\n",kind,e,f->response_bytes,f->s->issued,f->s->completed);
        assert(e&&!f->response_bytes);
        if(kind==0) assert(!f->s->dirty&&!memcmp(f->s->shadow[0],f->inputs[0],1024));
        if(kind==1) assert(f->s->issued==2&&f->s->completed==1&&f->s->uncertain);
        if(kind==4||kind==5) assert(!f->read_count&&!f->write_count);
        unsigned reads=f->read_count,writes=f->write_count;
        assert(polaris_rmtfs_poll(f->s)&&polaris_rmtfs_stop(f->s)&&polaris_rmtfs_destroy(f->s));
        assert(reads==f->read_count&&writes==f->write_count);
        cleanup(f,true);
    }
}
static void identity_and_reentrancy(void)
{
    struct fixture *f=setup();
    f->current=false; assert(!polaris_rmtfs_create(&f->cfg)); f->current=true;
    f->cfg.inputs[1].sha256[0]^=1; assert(!polaris_rmtfs_create(&f->cfg)); f->cfg.inputs[1].sha256[0]^=1;
    f->cfg.shared_phys=0x8bf00001; assert(!polaris_rmtfs_create(&f->cfg)); f->cfg.shared_phys=0xa0000000;
    f->cfg.scope=NULL; assert(!polaris_rmtfs_create(&f->cfg)); f->cfg.scope=ram_scope;
    uint8_t q[128]; unsigned n=open_qmi(q,31,pwr_paths[0]);
    f->injected_n=open_qmi(f->injected,32,pwr_paths[1]); finish_qmi(f->injected,f->injected_n); f->inject=true;
    request(f,77,q,n); for(unsigned i=0;i<8;i++) assert(!polaris_rmtfs_poll(f->s));
    assert(f->s->next_handle==2&&!f->s->count&&f->s->replied==2);
    /* Same txn, different request cannot mutate again. */
    n=open_qmi(q,31,pwr_paths[2]); finish_qmi(q,n); inject_qmi(f,3,77,q,n);
    assert(polaris_rmtfs_poll(f->s)==EPROTO&&f->s->next_handle==2);
    cleanup(f,true);
}
static void pending_delivery(void)
{
    struct fixture *f=setup(); uint8_t q[128]; uint32_t h=open_part(f,1,0);
    unsigned n=header_qmi(q,2,PWR_CLOSE); field_qmi(q,&n,1,h,4); finish_qmi(q,n);
    f->m->responding=false; inject_qmi(f,3,77,q,n);
    assert(!polaris_rmtfs_poll(f->s)&&!f->s->handles[0].live);
    f->retired=true; /* A bare retirement boolean cannot bypass pending DONE. */
    assert(pending(f->m->g)&&polaris_rmtfs_stop(f->s)==EBUSY&&polaris_rmtfs_destroy(f->s)==EBUSY);
    f->m->responding=true; peer(f->m);
    for(unsigned i=0;i<8;i++) assert(!polaris_wifi_glink_poll_once(f->m->g));
    assert(!polaris_rmtfs_stop(f->s)); cleanup(f,false);
}
int main(void)
{
    happy(); malformed(); faults_rmtfs(); identity_and_reentrancy(); pending_delivery();
    puts("PASS software FIFO/QRTR RMTFS14/v1/1: four whole-hashed NV shadows, alloc/client1, read/write, replay, sync, close, retirement; 8 sticky faults; no hardware/radio/durable NV");
}

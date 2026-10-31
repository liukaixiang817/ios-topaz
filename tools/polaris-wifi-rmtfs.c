/*
MIT License

Copyright (c) 2026 yanei and dipper-xnu contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 * Adapted protocol behavior from dipper-xnu e930c26 bsd/dev/mi8_hostsvc.c.
 * Own differences: four whole-hashed CURRENT NV inputs only; no OEM blank EFS,
 * no disk-write API; epoch/node binding, checked shared access, staged batch
 * reads, retained replay responses and UNKNOWN until real remote retirement.
 */
#include "polaris-wifi-rmtfs.h"
#ifdef POLARIS_WIFI_GLINK_HOST_TEST
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <CommonCrypto/CommonDigest.h>
#define PWR_THREAD() ((uintptr_t)pthread_self())
#ifndef PWR_ALLOC
#define PWR_ALLOC(n) calloc(1, (n))
#define PWR_FREE(p, n) free(p)
#endif
#else
#include <sys/errno.h>
#include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#define PWR_THREAD() ((uintptr_t)current_thread())
#ifndef PWR_ALLOC
#define PWR_ALLOC(n) kalloc_data((n), Z_WAITOK | Z_ZERO)
#define PWR_FREE(p, n) kfree_data((p), (n))
#endif
#endif
#define PWR_REQUEST 8192u
#define PWR_QUEUE 32u
#define PWR_REPLAYS 16u
#define PWR_HANDLES 32u
#define PWR_SHARED 0x200000u
#define PWR_CTRL 0xfffffffeu
static const uint32_t pwr_sizes[PWR_PARTS] = {0x800000,0x800000,0x800000,0x40000};
static const char *const pwr_paths[PWR_PARTS] = {
    "/boot/modem_fs1", "/boot/modem_fs2", "/boot/modem_fsg", "/boot/modem_fsc"
};
/* These paths are Mi8's real wire protocol references, not proof our MSS has
 * requested them. An unexpected path fails; never manufacture a partition. */
enum { PWR_OPEN=1, PWR_CLOSE, PWR_RW, PWR_ALLOCATE, PWR_DEVERR, PWR_SYNC };
enum { PWR_Q_OK=0, PWR_Q_MALFORMED=1, PWR_Q_NOMEM=2,
    PWR_Q_BAD_HANDLE=9, PWR_Q_INVAL=48, PWR_Q_UNSUPPORTED=94 };
struct pwr_request { uint32_t node, port, n; uint8_t data[PWR_REQUEST]; };
struct pwr_replay {
    bool used;
    struct pwr_request request;
    uint32_t n;
    uint8_t response[25]; /* result TLV and at most one u64 field */
};
struct pwr_handle { uint32_t id; unsigned part; bool live; };
struct pwr_tlv { const uint8_t *p; unsigned n; };
struct polaris_rmtfs {
    struct polaris_rmtfs_cfg cfg;
    struct polaris_wifi_qrtr_port *port;
    const struct polaris_wifi_qrtr_ops *ops;
    uintptr_t owner;
    unsigned depth, head, count, next_replay;
    uint32_t next_handle, error;
    bool started, stopping, stopped, uncertain, dirty;
    uint32_t received, replied, replayed, rejected_peer, issued, completed;
    uint64_t to_shadow, to_remote;
    uint8_t *shadow[PWR_PARTS];
    struct pwr_handle handles[PWR_HANDLES];
    struct pwr_request queue[PWR_QUEUE];
    struct pwr_replay replay[PWR_REPLAYS];
};
static uint64_t pwr_get(const uint8_t *p, unsigned n)
{ uint64_t x=0; for(unsigned i=0;i<n;i++) x|=(uint64_t)p[i]<<(8*i); return x; }
static void pwr_put(uint8_t *p, uint64_t x, unsigned n)
{ for(unsigned i=0;i<n;i++) p[i]=(uint8_t)(x>>(8*i)); }
static int pwr_fail(struct polaris_rmtfs *s, int error, bool unknown)
{
    uint32_t expected=0;
    (void)__atomic_compare_exchange_n(&s->error,&expected,(uint32_t)error,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    if(unknown) __atomic_store_n(&s->uncertain,true,__ATOMIC_RELEASE);
    return (int)__atomic_load_n(&s->error,__ATOMIC_ACQUIRE);
}
static uint32_t pwr_error(struct polaris_rmtfs *s)
{ return __atomic_load_n(&s->error,__ATOMIC_ACQUIRE); }
static bool pwr_enter(struct polaris_rmtfs *s)
{
    if(!s) return false;
    uintptr_t me=PWR_THREAD(), expected=0;
    if(__atomic_compare_exchange_n(&s->owner,&expected,me,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        s->depth=1; return true;
    }
    if(expected==me && s->depth<4) { s->depth++; return true; }
    return false;
}
static void pwr_leave(struct polaris_rmtfs *s)
{ if(!--s->depth) __atomic_store_n(&s->owner,0,__ATOMIC_RELEASE); }
/* Only receive callbacks may nest under an API call. A provider must not
 * recursively dispatch or destroy a service while an operation owns it. */
static bool pwr_public_enter(struct polaris_rmtfs *s)
{
    if(!pwr_enter(s)) return false;
    if(s->depth==1) return true;
    pwr_leave(s); return false;
}
static bool pwr_scope(struct polaris_rmtfs *s)
{
    return !__atomic_load_n(&s->error,__ATOMIC_ACQUIRE) &&
        s->cfg.scope(s->cfg.ctx,s->cfg.epoch,s->cfg.remote_node,s->cfg.shared_phys,s->cfg.shared_bytes);
}
static int pwr_transport(struct polaris_rmtfs *s)
{
    struct polaris_wifi_glink_status g;
    int e=polaris_wifi_glink_status(s->cfg.transport,&g);
    if(e==EBUSY) return e;
    if(e || g.epoch!=s->cfg.epoch || g.first_error || g.uncertain || !g.up || g.stopping)
        return pwr_fail(s,EIO,true);
    if(!pwr_scope(s)) return pwr_fail(s,EACCES,false);
    return 0;
}
static bool pwr_hash(const void *p, uint32_t n, const uint8_t expected[32])
{
    uint8_t h[32];
#ifdef POLARIS_WIFI_GLINK_HOST_TEST
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256(p,n,h);
#pragma clang diagnostic pop
#else
    const struct ccdigest_info *di=&ccsha256_ltc_di;
    ccdigest_di_decl(di,context); ccdigest_init(di,context);
    ccdigest_update(di,context,n,p); ccdigest_final(di,context,h);
    ccdigest_di_clear(di,context);
#endif
    return !memcmp(h,expected,sizeof(h));
}
static void pwr_free_unexposed(struct polaris_rmtfs *s)
{
    for(unsigned i=0;i<PWR_PARTS;i++) if(s->shadow[i]) {
        /* Do not leave private NV copies in a general-purpose RAM allocation. */
        volatile uint8_t *p=s->shadow[i];
        for(uint32_t j=0;j<pwr_sizes[i];j++) p[j]=0;
        PWR_FREE(s->shadow[i],pwr_sizes[i]);
    }
    PWR_FREE(s,sizeof(*s));
}
struct polaris_rmtfs *polaris_rmtfs_create(const struct polaris_rmtfs_cfg *cfg)
{
    if(!cfg || !cfg->transport || !cfg->epoch || !cfg->remote_node || cfg->remote_node>=PWR_CTRL ||
        !cfg->shared_phys || (cfg->shared_phys&4095) || cfg->shared_bytes!=PWR_SHARED ||
        cfg->shared_phys>UINT32_MAX-PWR_SHARED+1ull || !cfg->inputs_current || !cfg->scope ||
        !cfg->shared_read || !cfg->shared_write || !cfg->order || !cfg->retired) return NULL;
    for(unsigned i=0;i<PWR_PARTS;i++) if(!cfg->inputs[i].data || cfg->inputs[i].bytes!=pwr_sizes[i]) return NULL;
    if(!cfg->inputs_current(cfg->ctx,cfg) || !cfg->scope(cfg->ctx,cfg->epoch,
        cfg->remote_node,cfg->shared_phys,cfg->shared_bytes)) return NULL;
    struct polaris_rmtfs *s=PWR_ALLOC(sizeof(*s));
    if(!s) return NULL;
    s->cfg=*cfg; s->ops=polaris_wifi_glink_qrtr_ops(cfg->transport);
    if(!s->ops) { pwr_free_unexposed(s); return NULL; }
    for(unsigned i=0;i<PWR_PARTS;i++) {
        s->shadow[i]=PWR_ALLOC(pwr_sizes[i]);
        if(!s->shadow[i]) { pwr_free_unexposed(s); return NULL; }
        memcpy(s->shadow[i],cfg->inputs[i].data,pwr_sizes[i]);
        if(!pwr_hash(s->shadow[i],pwr_sizes[i],cfg->inputs[i].sha256)) { pwr_free_unexposed(s); return NULL; }
    }
    if(!cfg->inputs_current(cfg->ctx,cfg) || !pwr_scope(s)) { pwr_free_unexposed(s); return NULL; }
    return s;
}
/* Callback does not execute operations or send. GLINK sends can synchronously
 * pump more receives; queued bytes remain private until this workloop returns. */
static void pwr_receive(void *ctx,uint32_t node,uint32_t port,const void *data,size_t n)
{
    struct polaris_rmtfs *s=ctx;
    if(!pwr_enter(s)) { (void)pwr_fail(s,EBUSY,true); return; }
    if(node!=s->cfg.remote_node || !port || port>=PWR_CTRL) { s->rejected_peer++; goto out; }
    if(pwr_error(s) || s->stopping) goto out;
    if(!data || n<7 || n>PWR_REQUEST || s->count==PWR_QUEUE) { (void)pwr_fail(s,EPROTO,false); goto out; }
    struct pwr_request *q=&s->queue[(s->head+s->count)%PWR_QUEUE];
    q->node=node; q->port=port; q->n=(uint32_t)n; memcpy(q->data,data,n);
    s->count++; s->received++;
out:
    pwr_leave(s);
}
int polaris_rmtfs_start(struct polaris_rmtfs *s)
{
    if(!pwr_public_enter(s)) return EBUSY;
    int e=0;
    if(s->started || s->stopping || s->stopped) { e=EALREADY; goto out; }
    if((e=pwr_transport(s))) goto out;
    if(!s->cfg.inputs_current(s->cfg.ctx,&s->cfg)) { e=pwr_fail(s,ESTALE,false); goto out; }
    s->port=s->ops->open(pwr_receive,NULL,s);
    if(!s->port) { e=EBUSY; goto out; }
    s->started=true; /* Even failed publish retains the port/lifetime. */
    e=polaris_wifi_glink_qrtr_publish(s->cfg.transport,s->port,14,1,1);
    if(e) e=pwr_fail(s,e,true);
out:
    pwr_leave(s); return e;
}
static bool pwr_parse(const struct pwr_request *q,struct pwr_tlv t[5],unsigned allowed)
{
    uint64_t seen[4]={0};
    memset(t,0,5*sizeof(*t));
    if(q->data[0] || pwr_get(q->data+5,2)!=q->n-7) return false;
    for(unsigned at=7;at<q->n;) {
        if(q->n-at<3) return false;
        unsigned tag=q->data[at],n=(unsigned)pwr_get(q->data+at+1,2);
        if(n>q->n-at-3 || (seen[tag/64]&(1ull<<(tag%64)))) return false;
        seen[tag/64]|=1ull<<(tag%64);
        if(tag<16) {
            if(tag>4 || !(allowed&(1u<<tag))) return false;
            t[tag].p=q->data+at+3; t[tag].n=n;
        }
        at+=3+n;
    }
    return true;
}
static bool pwr_has(const struct pwr_tlv *t,unsigned tag,unsigned n)
{ return t[tag].p && t[tag].n==n; }
static unsigned pwr_rw(struct polaris_rmtfs *s,unsigned part,const struct pwr_tlv t[5])
{
    if(!pwr_has(t,2,1) || !t[3].p || !t[3].n || (t[4].p&&!pwr_has(t,4,1))) return PWR_Q_MALFORMED;
    unsigned dir=t[2].p[0], count=t[3].p[0];
    if(dir>1 || !count || t[3].n!=1+12*count) return PWR_Q_INVAL;
    uint64_t total=0;
    for(unsigned i=0;i<count;i++) {
        const uint8_t *v=t[3].p+1+12*i;
        uint64_t off=pwr_get(v,4)*512,pa=pwr_get(v+4,4),n=pwr_get(v+8,4)*512;
        if(!n || off>pwr_sizes[part] || n>pwr_sizes[part]-off || pa<s->cfg.shared_phys ||
            pa-s->cfg.shared_phys>PWR_SHARED || n>PWR_SHARED-(pa-s->cfg.shared_phys) ||
            n>PWR_SHARED-total) return PWR_Q_INVAL;
        total+=n;
    }
    /* Incoming writes stage the ENTIRE batch before modifying any shadow. A
     * failed late read cannot corrupt earlier sectors. Shared writes can be
     * partial on failure and are explicitly UNKNOWN; never roll back/retry. */
    uint8_t *stage=dir?NULL:PWR_ALLOC((size_t)total);
    if(!dir&&!stage) return PWR_Q_NOMEM;
    if(!pwr_scope(s)) { (void)pwr_fail(s,EACCES,false); goto out; }
    if(!s->cfg.order(s->cfg.ctx)) { (void)pwr_fail(s,EIO,false); goto out; }
    uint32_t pos=0;
    for(unsigned i=0;i<count;i++) {
        const uint8_t *v=t[3].p+1+12*i;
        uint32_t off=(uint32_t)(pwr_get(v,4)*512),n=(uint32_t)(pwr_get(v+8,4)*512);
        uint32_t shared=(uint32_t)(pwr_get(v+4,4)-s->cfg.shared_phys);
        if(!pwr_scope(s)) { (void)pwr_fail(s,EACCES,s->issued!=s->completed); goto out; }
        s->issued++;
        bool ok=dir?s->cfg.shared_write(s->cfg.ctx,s->cfg.epoch,shared,s->shadow[part]+off,n):
            s->cfg.shared_read(s->cfg.ctx,s->cfg.epoch,shared,stage+pos,n);
        if(!ok || !pwr_scope(s)) { (void)pwr_fail(s,EIO,true); goto out; }
        s->completed++; pos+=n;
    }
    if(!s->cfg.order(s->cfg.ctx) || !pwr_scope(s)) { (void)pwr_fail(s,EIO,true); goto out; }
    if(!dir) {
        pos=0;
        for(unsigned i=0;i<count;i++) {
            const uint8_t *v=t[3].p+1+12*i;
            uint32_t off=(uint32_t)(pwr_get(v,4)*512),n=(uint32_t)(pwr_get(v+8,4)*512);
            memcpy(s->shadow[part]+off,stage+pos,n); pos+=n;
        }
        s->dirty=true; s->to_shadow+=total;
    } else s->to_remote+=total;
out:
    if(stage) { volatile uint8_t *p=stage; for(uint32_t i=0;i<total;i++) p[i]=0; PWR_FREE(stage,(size_t)total); }
    return PWR_Q_OK; /* On sticky error caller emits NO success response. */
}
static unsigned pwr_execute(struct polaris_rmtfs *s,const struct pwr_request *q,uint64_t *value,unsigned *width)
{
    struct pwr_tlv t[5];
    unsigned msg=(unsigned)pwr_get(q->data+3,2),allowed=1u<<1;
    if(msg==PWR_RW) allowed|=(1u<<2)|(1u<<3)|(1u<<4);
    if(msg==PWR_ALLOCATE) allowed|=1u<<2;
    if(!pwr_parse(q,t,allowed)) return PWR_Q_MALFORMED;
    if(msg<PWR_OPEN || msg>PWR_SYNC) return PWR_Q_UNSUPPORTED;
    if(msg==PWR_OPEN) {
        if(!t[1].p || !t[1].n || t[1].n>=256 || memchr(t[1].p,0,t[1].n)) return PWR_Q_MALFORMED;
        unsigned part;
        for(part=0;part<PWR_PARTS;part++) if(strlen(pwr_paths[part])==t[1].n && !memcmp(t[1].p,pwr_paths[part],t[1].n)) break;
        if(part==PWR_PARTS) return PWR_Q_INVAL;
        for(unsigned i=0;i<PWR_HANDLES;i++) if(!s->handles[i].live) {
            if(s->next_handle==UINT32_MAX) return PWR_Q_NOMEM;
            s->handles[i]=(struct pwr_handle){++s->next_handle,part,true};
            *value=s->next_handle; *width=4; return PWR_Q_OK;
        }
        return PWR_Q_NOMEM;
    }
    if(!pwr_has(t,1,4)) return PWR_Q_MALFORMED;
    uint32_t id=(uint32_t)pwr_get(t[1].p,4);
    if(msg==PWR_ALLOCATE) {
        if(!pwr_has(t,2,4)) return PWR_Q_MALFORMED;
        uint64_t n=pwr_get(t[2].p,4);
        if(id!=1 || !n || n>PWR_SHARED) return PWR_Q_INVAL;
        *value=s->cfg.shared_phys; *width=8; return PWR_Q_OK;
    }
    struct pwr_handle *handle=NULL;
    for(unsigned i=0;i<PWR_HANDLES;i++) if(s->handles[i].live&&s->handles[i].id==id) { handle=&s->handles[i]; break; }
    if(!handle) return PWR_Q_BAD_HANDLE;
    /* Node and epoch were bound before queueing. Different QRTR source ports
     * on that SAME MSS may use the handle, matching the real reference modem. */
    if(msg==PWR_RW) return pwr_rw(s,handle->part,t);
    if(msg==PWR_CLOSE) handle->live=false;
    if(msg==PWR_DEVERR) { *value=0; *width=4; }
    /* PWR_SYNC has no physical flush: only the admitted volatile NV shadow. */
    return PWR_Q_OK;
}
static int pwr_send(struct polaris_rmtfs *s,const struct pwr_request *q,const void *p,unsigned n)
{
    if(!pwr_scope(s)) return pwr_fail(s,EACCES,false);
    int e=s->ops->send(s->port,q->node,q->port,p,n);
    if(e) return pwr_fail(s,e,true); /* Response delivery unknown: never re-execute. */
    s->replied++; return 0;
}
static int pwr_dispatch(struct polaris_rmtfs *s,const struct pwr_request *q)
{
    if(q->data[0]) return pwr_fail(s,EPROTO,false);
    for(unsigned i=0;i<PWR_REPLAYS;i++) {
        struct pwr_replay *c=&s->replay[i];
        if(!c->used || c->request.node!=q->node || c->request.port!=q->port ||
            pwr_get(c->request.data+1,2)!=pwr_get(q->data+1,2)) continue;
        if(c->request.n!=q->n || memcmp(c->request.data,q->data,q->n))
            return pwr_fail(s,EPROTO,false); /* Recent txn collision, never mutate twice. */
        s->replayed++; return pwr_send(s,q,c->response,c->n);
    }
    /* Reserve full request/response storage BEFORE an effect. The latest16
     * transactions per service are retained; no exactly-once claim after QMI
     * transaction reuse/eviction. Send failure freezes all further processing. */
    struct pwr_replay *c=&s->replay[s->next_replay++%PWR_REPLAYS];
    c->used=false; c->request=*q;
    uint64_t value=0; unsigned width=0;
    unsigned err=pwr_execute(s,q,&value,&width);
    if(pwr_error(s)) return (int)pwr_error(s);
    memset(c->response,0,sizeof(c->response));
    c->response[0]=2; memcpy(c->response+1,q->data+1,4);
    c->response[7]=2; pwr_put(c->response+8,4,2);
    pwr_put(c->response+10,err?1:0,2); pwr_put(c->response+12,err,2);
    c->n=14;
    if(!err&&width) { c->response[14]=0x10; pwr_put(c->response+15,width,2); pwr_put(c->response+17,value,width); c->n+=3+width; }
    pwr_put(c->response+5,c->n-7,2); c->used=true;
    return pwr_send(s,q,c->response,c->n);
}
int polaris_rmtfs_poll(struct polaris_rmtfs *s)
{
    if(!pwr_public_enter(s)) return EBUSY;
    int e=0;
    if(!s->started || s->stopped) { e=ENOTCONN; goto out; }
    if(pwr_error(s)) { e=(int)pwr_error(s); goto out; }
    if((e=pwr_transport(s))) goto out;
    e=polaris_wifi_glink_poll_once(s->cfg.transport);
    if(e) { if(e!=EBUSY) e=pwr_fail(s,e,true); goto out; }
    for(unsigned budget=0;budget<8 && s->count && !pwr_error(s) && !s->stopping;budget++) {
        /* Keep slot occupied while send reenters: tail cannot overwrite q. */
        const struct pwr_request *q=&s->queue[s->head];
        if((e=pwr_transport(s)) || (e=pwr_dispatch(s,q))) break;
        s->head=(s->head+1)%PWR_QUEUE; s->count--;
    }
    if(!e&&pwr_error(s)) e=(int)pwr_error(s);
out:
    pwr_leave(s); return e;
}
int polaris_rmtfs_status(struct polaris_rmtfs *s,struct polaris_rmtfs_status *out)
{
    if(!out) return EINVAL;
    if(!pwr_public_enter(s)) return EBUSY;
    unsigned live=0; for(unsigned i=0;i<PWR_HANDLES;i++) live+=s->handles[i].live;
    *out=(struct polaris_rmtfs_status){.epoch=s->cfg.epoch,.bytes_to_shadow=s->to_shadow,.bytes_to_remote=s->to_remote,
        .first_error=pwr_error(s),.received=s->received,.replied=s->replied,.replayed=s->replayed,.rejected_peer=s->rejected_peer,
        .operations_issued=s->issued,.operations_completed=s->completed,.handles=live,.queued=s->count,
        .started=s->started,.stopping=s->stopping,.stopped=s->stopped,.uncertain=__atomic_load_n(&s->uncertain,__ATOMIC_ACQUIRE),.dirty=s->dirty,.durable_nv=false};
    pwr_leave(s); return 0;
}
int polaris_rmtfs_stop(struct polaris_rmtfs *s)
{
    if(!pwr_public_enter(s)) return EBUSY;
    int e=0; struct polaris_wifi_glink_status g;
    if(pwr_error(s)) { e=(int)pwr_error(s); goto out; }
    if(s->stopped) goto out;
    if(!s->started) { s->stopped=true; goto out; }
    for(unsigned i=0;i<PWR_HANDLES;i++) if(s->handles[i].live) { e=EBUSY; goto out; }
    if(s->count) { e=EBUSY; goto out; }
    s->stopping=true;
    if(s->port) {
        e=polaris_wifi_glink_close_port(s->port);
        if(e) goto out;
        s->port=NULL;
    }
    e=polaris_wifi_glink_status(s->cfg.transport,&g);
    if(e) goto out;
    if(g.epoch!=s->cfg.epoch || g.first_error || g.uncertain) { e=pwr_fail(s,EIO,true); goto out; }
    if(g.pending || !s->cfg.retired(s->cfg.ctx,s->cfg.epoch)) { e=EBUSY; goto out; }
    s->stopped=true;
out:
    pwr_leave(s); return e;
}
int polaris_rmtfs_destroy(struct polaris_rmtfs *s)
{
    if(!pwr_public_enter(s)) return EBUSY;
    int e=(int)pwr_error(s);
    if(!e && s->started && (!s->stopped || !s->cfg.retired(s->cfg.ctx,s->cfg.epoch))) e=EBUSY;
    if(e) { pwr_leave(s); return e; }
    /* Lifecycle owner must remove its last reference before calling destroy. */
    pwr_free_unexposed(s); return 0;
}

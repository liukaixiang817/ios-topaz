/* Own c7cb50c1 ICNSS ordering and wlan_firmware_service_v01 wire ABI.
 * Reuses the existing CAP decoder. No hardware access is inferred by parsing. */
#include "polaris-wifi-wlfw.h"
#if defined(POLARIS_WIFI_GLINK_FREESTANDING)
#include "polaris-wifi-glink-freestanding.h"
#elif defined(POLARIS_WIFI_GLINK_HOST_TEST)
#include <errno.h>
#include <string.h>
#else
#include <sys/errno.h>
#include <libkern/libkern.h>
#endif
#define PWFW_TIMEOUT UINT64_C(10000000)
#define PWFW_TOTAL UINT64_C(60000000)
static int pwfw_fail(struct polaris_wifi_wlfw*c,unsigned error)
{if(!c->error)c->error=error;return (int)c->error;}
static uint64_t pwfw_get(const uint8_t*p,unsigned n)
{uint64_t v=0;for(unsigned j=0;j<n;j++)v|=(uint64_t)p[j]<<(8*j);return v;}
static void pwfw_put(uint8_t*p,uint64_t v,unsigned n)
{for(unsigned j=0;j<n;j++)p[j]=(uint8_t)(v>>(8*j));}
static void pwfw_field(uint8_t*p,unsigned*at,unsigned tag,uint64_t v,unsigned bytes)
{p[*at]=(uint8_t)tag;pwfw_put(p+*at+1,bytes,2);pwfw_put(p+*at+3,v,bytes);*at+=3+bytes;}
static bool pwfw_packet(const uint8_t*p,size_t n,unsigned type,unsigned msg)
{return p&&n>=7&&p[0]==type&&pw_le16(p+3)==msg&&pw_le16(p+5)==n-7;}
static int pwfw_scope(struct polaris_wifi_wlfw*c)
{
    struct polaris_wifi_glink_status s;if(c->error)return (int)c->error;
    int error=polaris_wifi_glink_status(c->cfg.transport,&s);if(error)return pwfw_fail(c,(unsigned)error);
    if(s.epoch!=c->epoch||!s.up||s.stopping||s.first_error||s.uncertain||!c->cfg.scope(c->cfg.ctx))return pwfw_fail(c,EIO);
    return 0;
}
static void pwfw_server(void*ctx,bool arrived,uint32_t service,uint32_t version,uint32_t instance,uint32_t node,uint32_t port)
{
    struct polaris_wifi_wlfw*c=ctx;if(c->error||service!=PW_SERVICE||version!=PW_VERSION||instance!=PW_INSTANCE)return;
    if(node>=0xfffffffeu||!port||port>=0xfffffffeu){pwfw_fail(c,EPROTO);return;}
    if(!arrived){if(c->discovered&&c->node==node&&c->service_port==port)pwfw_fail(c,ENOTCONN);return;}
    if(c->discovered&&(c->node!=node||c->service_port!=port)){pwfw_fail(c,EADDRINUSE);return;}
    c->node=node;c->service_port=port;c->discovered=true;
}
static bool pwfw_pins(struct polaris_wifi_wlfw*c,const uint8_t*p,size_t n)
{
    unsigned seen=0;for(size_t at=7;at<n;){
        if(n-at<3)return false;unsigned tag=p[at],len=pw_le16(p+at+1);at+=3;
        if(tag<0x10||tag>0x12||len!=4||len>n-at||(seen&(1u<<(tag-0x10))))return false;
        seen|=1u<<(tag-0x10);c->pin[tag-0x10]=pw_le32(p+at);at+=len;
    }c->pin_valid=seen;return true;
}
static void pwfw_receive(void*ctx,uint32_t node,uint32_t port,const void*data,size_t n)
{
    struct polaris_wifi_wlfw*c=ctx;const uint8_t*p=data;
    if(!c->discovered||node!=c->node||port!=c->service_port){c->unrelated++;return;}if(c->error)return;
    if(!p||n<7||n>210||pw_le16(p+5)!=n-7){pwfw_fail(c,EPROTO);return;}
    unsigned msg=pw_le16(p+3);
    if(p[0]==4){
        if(!c->exchange[0].requested){pwfw_fail(c,EPROTO);return;}
        if(msg==0x21||msg==0x2b){
            if(n!=7||!c->exchange[2].requested||!c->assigned){pwfw_fail(c,EPROTO);return;}
            if(msg==0x21){c->fw_ready=true;c->fw_indications++;}else c->msa_indications++;
        }else if(msg==0x2c){if(!pwfw_pins(c,p,n))pwfw_fail(c,EPROTO);}
        else pwfw_fail(c,EPROTO); /* No rejuvenation/restart or dynamic-memory protocol is admitted. */
        return;
    }
    if(c->phase>=4){pwfw_fail(c,EPROTO);return;}struct pwfw_exchange*x=&c->exchange[c->phase];
    if(!x->requested||x->received||!pwfw_packet(p,n,2,x->message)||pw_le16(p+1)!=x->transaction){pwfw_fail(c,EPROTO);return;}
    memcpy(x->response,p,n);x->response_bytes=(uint32_t)n;x->received=true;
}
static bool pwfw_regions(struct polaris_wifi_wlfw*c,const uint8_t*p,unsigned bytes)
{
    if(!bytes||!p[0]||p[0]>2||bytes!=1+13u*p[0])return false;
    for(unsigned j=0;j<p[0];j++){
        const uint8_t*r=p+1+13*j;struct pwfw_region*v=&c->region[j];
        v->address=pwfw_get(r,8);v->bytes=pw_le32(r+8);v->secure=r[12];
        if(!v->bytes||(v->address&4095)||(v->bytes&4095)||v->secure>1||v->address<c->cfg.msa||
           v->address-c->cfg.msa>=c->cfg.bytes||v->bytes>c->cfg.bytes-(v->address-c->cfg.msa))return false;
        if(j&&v->address<c->region[0].address+c->region[0].bytes&&c->region[0].address<v->address+v->bytes)return false;
    }c->regions=p[0];return true;
}
static bool pwfw_accept(struct polaris_wifi_wlfw*c,struct pwfw_exchange*x)
{
    if(x->message==PW_CAP_MESSAGE)return polaris_wlfw_cap_response(PW_SERVICE,PW_VERSION,PW_INSTANCE,x->transaction,x->response,x->response_bytes,&c->capability)&&polaris_wlfw_cap_has_identity(&c->capability);
    const uint8_t*p=x->response;size_t n=x->response_bytes;uint8_t seen[32]={0};bool result=false,regions=false;
    for(size_t at=7;at<n;){
        if(n-at<3)return false;unsigned tag=p[at],len=pw_le16(p+at+1);at+=3;
        if(len>n-at||(seen[tag/8]&(1u<<(tag%8))))return false;seen[tag/8]|=(uint8_t)(1u<<(tag%8));
        if(tag==2){if(len!=4||pw_le16(p+at)||pw_le16(p+at+2))return false;result=true;}
        else if(tag==3&&x->message==0x2d){if(!pwfw_regions(c,p+at,len))return false;regions=true;}
        else if(tag==0x10&&x->message==0x20){if(len!=8)return false;c->fw_status=pwfw_get(p+at,8);}
        else if(tag<0x10)return false;
        at+=len;
    }return result&&(x->message!=0x2d||regions);
}
static int pwfw_send(struct polaris_wifi_wlfw*c,uint64_t now)
{
    static const uint16_t messages[4]={0x20,0x2d,0x2e,PW_CAP_MESSAGE};struct pwfw_exchange*x=&c->exchange[c->phase];
    x->message=messages[c->phase];x->transaction=(uint16_t)(c->phase+1);uint8_t*p=x->request;unsigned bytes=7;
    pwfw_put(p+1,x->transaction,2);pwfw_put(p+3,x->message,2);
    if(!c->phase){pwfw_field(p,&bytes,0x10,1,1);pwfw_field(p,&bytes,0x13,1,1);pwfw_field(p,&bytes,0x14,1,1);pwfw_field(p,&bytes,0x15,0x4b4e454c,4);}
    else if(c->phase==1){pwfw_field(p,&bytes,1,c->cfg.msa,8);pwfw_field(p,&bytes,2,c->cfg.bytes,4);}
    pwfw_put(p+5,bytes-7,2);x->request_bytes=bytes;x->issued=now;x->requested=true;
    int error=c->ops->send(c->port,c->node,c->service_port,p,bytes);if(error)return pwfw_fail(c,(unsigned)error);return (int)c->error;
}
int polaris_wifi_wlfw_open(struct polaris_wifi_wlfw*c,const struct polaris_wifi_wlfw_cfg*cfg,uint64_t now)
{
    if(!c||!cfg||!cfg->transport||!cfg->scope||!cfg->assign||!cfg->msa||(cfg->msa&0x1fffff)||cfg->msa>UINT32_MAX-0x100000+1ull||cfg->bytes!=0x100000||now>UINT64_MAX-PWFW_TOTAL)return EINVAL;
    for(size_t j=0;j<sizeof(*c);j++)if(((const uint8_t*)c)[j])return EALREADY;
    struct polaris_wifi_glink_status s;int error=polaris_wifi_glink_status(cfg->transport,&s);if(error)return error;
    if(!s.epoch||!s.up||s.first_error||s.stopping||s.uncertain||!cfg->scope(cfg->ctx))return ENOTCONN;
    c->cfg=*cfg;c->epoch=s.epoch;c->opening=c->last_us=now;c->busy=true;c->ops=polaris_wifi_glink_qrtr_ops(cfg->transport);
    if(!c->ops||!(c->port=c->ops->open(pwfw_receive,pwfw_server,c)))error=pwfw_fail(c,EBUSY);
    else if((error=c->ops->lookup(c->port,PW_SERVICE,PW_VERSION,PW_INSTANCE)))pwfw_fail(c,(unsigned)error);
    c->busy=false;return c->error?(int)c->error:error;
}
int polaris_wifi_wlfw_poll(struct polaris_wifi_wlfw*c,uint64_t now)
{
    if(!c||!c->port)return EINVAL;if(c->busy)return EBUSY;c->busy=true;int error;
    if((error=pwfw_scope(c)))goto out;
    if(now<c->last_us||(!c->ready&&now-c->opening>=PWFW_TOTAL)){error=pwfw_fail(c,ETIMEDOUT);goto out;}c->last_us=now;
    if((error=polaris_wifi_glink_poll_once(c->cfg.transport))){error=pwfw_fail(c,(unsigned)error);goto out;}
    if((error=pwfw_scope(c)))goto out;if(!c->discovered){error=EAGAIN;goto out;}
    if(c->phase<4){
        struct pwfw_exchange*x=&c->exchange[c->phase];
        if(!x->requested){error=pwfw_send(c,now);if(!error)error=EAGAIN;goto out;}
        if(!x->received){error=now-x->issued>=PWFW_TIMEOUT?pwfw_fail(c,ETIMEDOUT):EAGAIN;goto out;}
        if(!x->accepted){if(!pwfw_accept(c,x)){error=pwfw_fail(c,EPROTO);goto out;}x->accepted=true;}
        if(c->phase==1){
            if(c->assign_issued){error=pwfw_fail(c,EALREADY);goto out;}c->assign_issued=true;
            if(!c->cfg.assign(c->cfg.ctx,c->region,c->regions)){error=pwfw_fail(c,EIO);goto out;}c->assigned=true;
            if((error=pwfw_scope(c)))goto out;
        }
        c->phase++;error=EAGAIN;
    }else{c->ready=c->assigned&&c->fw_ready&&c->exchange[2].accepted&&c->exchange[3].accepted;error=c->ready?0:EAGAIN;}
 out:c->busy=false;return error;
}

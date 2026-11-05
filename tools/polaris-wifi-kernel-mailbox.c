/* Polaris kernel side of the fixed CPU0 mailbox. No radio MMIO, DMA address,
 * firmware service call, allocation or wait occurs here. The actual station/
 * ifnet frontend and firmware runtime owner are separate required components.
 * These source bytes are intended for the Polaris kernel profile, not Topaz. */
#include "polaris-wifi-kernel-mailbox.h"
#include "polaris-wifi-mailbox-transport.h"
#if defined(POLARIS_WIFI_KERNEL_MAILBOX_SOFTWARE)
#include <errno.h>
#include <stdbool.h>
static void pwk_preempt_disable(void),pwk_preempt_enable(void);
static uint64_t pwk_cpu(void);
static int pwk_platform(void),pwk_shutdown(void),pwk_cache_leaf(unsigned,unsigned,unsigned);
#else
#include <sys/errno.h>
#include <kern/cpu_data.h>
#include <pexpert/pexpert.h>
extern bool polaris_ram_overlay_allowed(void);
extern int polaris_uefi_shutdown_pending(void);
static void pwk_preempt_disable(void){disable_preemption();}
static void pwk_preempt_enable(void){enable_preemption();}
static uint64_t pwk_cpu(void){uint64_t n;__asm__ volatile("mrs %0,mpidr_el1":"=r"(n));return n&UINT64_C(0xffffff);}
static int pwk_platform(void)
{
    uint32_t wifi=0,mode=0,cpu=0,count=0;
    PE_parse_boot_argn("polariswifi",&wifi,sizeof(wifi));PE_parse_boot_argn("polarisuefi",&mode,sizeof(mode));
    PE_parse_boot_argn("polarisbootcpu",&cpu,sizeof(cpu));PE_parse_boot_argn("cpus",&count,sizeof(count));
    return wifi==1&&mode==1&&cpu==0x700&&count==4&&polaris_ram_overlay_allowed();
}
static int pwk_shutdown(void){return polaris_uefi_shutdown_pending();}
static int pwk_cache_leaf(unsigned offset,unsigned bytes,unsigned clean)
{
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    if((4u<<((ctr>>16)&15))!=64)return 0;
    for(unsigned n=0;n<bytes;n+=64){
        uintptr_t at=(uintptr_t)polaris_wifi_mailbox_page+offset+n;
        if(clean)__asm__ volatile("dc civac,%0"::"r"(at):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(at):"memory");
    }
    __asm__ volatile("dsb sy":::"memory");return 1;
}
#endif
/* Nonzero initialized DATA, not kernel startup zero-fill. Firmware must
 * validate the built symbol and prepare this complete reserved page before
 * CPU_ON. Initial source bytes deliberately do not form a valid bootstrap. */
__attribute__((used,aligned(16384))) uint8_t polaris_wifi_mailbox_page[PWMB_BYTES]={0x50,0x57};
static struct {
    struct pwmb_link lane[PWMB_LANES];struct pwmb_identity identity;
    uint8_t bootstrap[PWMB_LINE];uint64_t cpu,control_sequence;
    uint32_t gate,initialized,radio,link,fault,sealed,seal_requested,control_pending,control_operation;
} pwk;
static int pwk_enter(void)
{
    pwk_preempt_disable();
    if(__atomic_exchange_n(&pwk.gate,1,__ATOMIC_ACQUIRE)){pwk_preempt_enable();return EBUSY;}
    pwk.cpu=pwk_cpu();
    if(pwk.cpu<0x400||pwk.cpu>0x700||(pwk.cpu&255)){
        __atomic_store_n(&pwk.gate,0,__ATOMIC_RELEASE);pwk_preempt_enable();return ENXIO;
    }return 0;
}
static void pwk_exit(void)
{__atomic_store_n(&pwk.gate,0,__ATOMIC_RELEASE);pwk_preempt_enable();}
static int pwk_live(void*context)
{
    return context==&pwk&&pwk.gate==1&&pwk.initialized&&!pwk.fault&&!pwk.sealed&&
        !__atomic_load_n(&pwk.seal_requested,__ATOMIC_ACQUIRE)&&pwk_cpu()==pwk.cpu&&!pwk_shutdown();
}
static int pwk_copy(void*context,unsigned offset,void*private,unsigned bytes,unsigned write)
{
    if(context!=&pwk||!private||!bytes||offset>=PWMB_BYTES||bytes>PWMB_BYTES-offset||write>1)return 0;
    volatile uint8_t*p=polaris_wifi_mailbox_page+offset;uint8_t*q=private;
    for(unsigned n=0;n<bytes;n++){if(write)p[n]=q[n];else q[n]=p[n];}return 1;
}
static int pwk_cache(void*context,unsigned offset,unsigned bytes,unsigned clean)
{
    return context==&pwk&&bytes&&offset<PWMB_BYTES&&bytes<=PWMB_BYTES-offset&&
        !(offset%PWMB_LINE)&&!(bytes%PWMB_LINE)&&clean<=1&&pwk_cache_leaf(offset,bytes,clean);
}
static int pwk_sequence(void*context,unsigned offset,uint64_t*value,unsigned write)
{
    if(context!=&pwk||!value||(offset&7)||offset>PWMB_BYTES-8||write>1)return 0;
    uint64_t*p=(void*)(polaris_wifi_mailbox_page+offset);
    if(write)__atomic_store_n(p,*value,__ATOMIC_RELEASE);else *value=__atomic_load_n(p,__ATOMIC_ACQUIRE);return 1;
}
static const struct pwmb_bus pwk_bus={&pwk,pwk_live,pwk_copy,pwk_cache,pwk_sequence};
static int pwk_bootstrap(uint8_t*out)
{
    uint8_t second[PWMB_LINE];unsigned base=PWMB_BOOTSTRAP_OFFSET;
    if(!pwk_cache(&pwk,base,PWMB_LINE,0)||!pwk_copy(&pwk,base,out,PWMB_LINE,0)||
       !pwk_cache(&pwk,base,PWMB_LINE,0)||!pwk_copy(&pwk,base,second,PWMB_LINE,0))return 0;
    for(unsigned n=0;n<PWMB_LINE;n++)if(out[n]!=second[n])return 0;return 1;
}
static int pwk_fault(void){pwk.fault=1;pwk.radio=pwk.link=0;return EIO;}
static int pwk_current(void)
{
    uint8_t current[PWMB_LINE];
    if(!pwk_live(&pwk))return 0;
    if(!pwk_bootstrap(current)){pwk_fault();return 0;}
    for(unsigned n=0;n<PWMB_LINE;n++)if(current[n]!=pwk.bootstrap[n]){pwk_fault();return 0;}return 1;
}
int polaris_wifi_mailbox_attach(struct pwmb_identity*out)
{
    if(!out||!pwk_platform())return ENXIO;int error=pwk_enter();if(error)return error;
    if(pwk.fault||pwk.sealed||__atomic_load_n(&pwk.seal_requested,__ATOMIC_ACQUIRE)||pwk_shutdown()){pwk_exit();return ENXIO;}
    if(!pwk.initialized){
        if(!pwk_bootstrap(pwk.bootstrap)||!pwmb_bootstrap_parse(pwk.bootstrap,&pwk.identity)){pwk_exit();return EAGAIN;}
        for(unsigned n=0;n<PWMB_LANES;n++)if(!pwmb_link_open(&pwk.lane[n],n,n==PWMB_CONTROL||n==PWMB_TX?PWMB_PRODUCER:PWMB_CONSUMER,pwk.identity.epoch)){
            error=pwk_fault();pwk_exit();return error;
        }
        pwk.initialized=1;
    }else if(!pwk_current()){pwk_exit();return EIO;}
    *out=pwk.identity;pwk_exit();return 0;
}
static int pwk_send_locked(unsigned lane,unsigned operation,const uint8_t*p,unsigned bytes,uint64_t*sequence)
{
    if(!pwk_current())return ENXIO;struct pwmb_link*s=&pwk.lane[lane];
    if(s->state.stage==2){int done=pwmb_send_ack_poll(s,&pwk_bus);if(done<0)return pwk_fault();if(!done)return EWOULDBLOCK;}
    uint64_t number=s->state.next;int result=pwmb_send(s,&pwk_bus,operation,p,bytes);
    if(result<0)return pwk_fault();if(!result)return EINVAL;if(sequence)*sequence=number;return 0;
}
int polaris_wifi_mailbox_request(unsigned operation,const uint8_t*p,unsigned bytes,uint64_t*sequence)
{
    if(!sequence||!pwmb_payload(PWMB_CONTROL,operation,p,bytes))return EINVAL;
    int error=pwk_enter();if(error)return error;
    if(pwk.control_pending)error=EWOULDBLOCK;
    else error=!pwk.radio&&operation!=PWMB_STATE?EAGAIN:pwk_send_locked(PWMB_CONTROL,operation,p,bytes,sequence);
    if(!error){pwk.control_pending=1;pwk.control_sequence=*sequence;pwk.control_operation=operation;}
    pwk_exit();return error;
}
int polaris_wifi_mailbox_transmit(const uint8_t*p,unsigned bytes)
{
    if(!pwmb_payload(PWMB_TX,PWMB_ETHERNET_TX,p,bytes))return EINVAL;int error=pwk_enter();if(error)return error;
    error=pwk.link?pwk_send_locked(PWMB_TX,PWMB_ETHERNET_TX,p,bytes,0):ENETDOWN;pwk_exit();return error;
}
int polaris_wifi_mailbox_poll(unsigned lane,struct pwmb_message*out)
{
    if(!out||(lane!=PWMB_REPLY&&lane!=PWMB_RX&&lane!=PWMB_EVENT))return -EINVAL;
    int error=pwk_enter();if(error)return -error;
    if(!pwk_current()){pwk_exit();return -ENXIO;}
    /* Transport ACK is only buffer consumption, never association success
     * or an upper control response. Keep that request pending separately. */
    for(unsigned n=0;n<2;n++){
        struct pwmb_link*s=&pwk.lane[n?PWMB_TX:PWMB_CONTROL];
        if(s->state.stage==2&&pwmb_send_ack_poll(s,&pwk_bus)<0){error=pwk_fault();pwk_exit();return -error;}
    }
    int result=pwmb_receive_poll(&pwk.lane[lane],&pwk_bus,out);
    if(result<0){error=pwk_fault();pwk_exit();return -error;}
    if(result==1){
        if(lane==PWMB_REPLY&&(!pwk.control_pending||pwmb_u64(out->data)!=pwk.control_sequence||pwmb_u32(out->data+8)!=pwk.control_operation)){
            error=pwk_fault();pwmb_clear(out,sizeof(*out));pwk_exit();return -error;
        }
        if(lane==PWMB_EVENT&&pwmb_u32(out->data)==3&&(!pwk.radio||pwmb_u32(out->data+4)||pwmb_u64(out->data+8)!=1)){
            error=pwk_fault();pwmb_clear(out,sizeof(*out));pwk_exit();return -error;
        }
        if(pwmb_receive_complete(&pwk.lane[lane],&pwk_bus)!=1){error=pwk_fault();pwmb_clear(out,sizeof(*out));pwk_exit();return -error;}
        if(lane==PWMB_REPLY)pwk.control_pending=0;
        if(lane==PWMB_RX&&!pwk.link){pwmb_clear(out,sizeof(*out));result=0;}
        if(lane==PWMB_EVENT){
            unsigned event=pwmb_u32(out->data),status=pwmb_u32(out->data+4);
            if(event==1){if(status)pwk_fault();else pwk.radio=1;}
            if(event==3)pwk.link=1;
            if(event==4)pwk.link=0;
            if(event==5)pwk_fault();
        }
    }
    pwk_exit();return result;
}
unsigned polaris_wifi_mailbox_status(void)
{
    if(pwk_enter())return 16;
    unsigned result=pwk.radio|(pwk.link<<1)|(pwk.fault<<2)|((pwk.sealed||__atomic_load_n(&pwk.seal_requested,__ATOMIC_ACQUIRE))<<3);
    if(!pwk.initialized||pwk_shutdown())result|=16;pwk_exit();return result;
}
int polaris_wifi_mailbox_seal(void)
{
    __atomic_store_n(&pwk.seal_requested,1,__ATOMIC_RELEASE);
    int error=pwk_enter();if(error)return error;pwk.sealed=1;pwk.radio=pwk.link=0;
    for(unsigned n=0;n<PWMB_LANES;n++)pwmb_clear(pwk.lane[n].wire,sizeof(pwk.lane[n].wire));
    /* Shared producer bytes can still be owned by firmware until its ACK.
     * Seal private input only; never reclaim or zero a peer-owned message. */
    pwk_exit();return 0;
}

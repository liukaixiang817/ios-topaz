/* Polaris BSD Ethernet endpoint for the independently qualified CPU0 radio.
 * Follows XNU's own ether/ifnet KPI (also used by the pinned HackiOS reference),
 * with no Topaz hardware/provider code. All radio operations use the fixed
 * mailbox. READY creates an interface; only LINK permits packet traffic.
 * This private bring-up control interface does not impersonate Apple80211.
 */
#include "polaris-wifi-interface.h"
#include "polaris-wifi-kernel-mailbox.h"
#if defined(POLARIS_WIFI_INTERFACE_SOFTWARE)
#include "polaris-wifi-interface-test-kpi.h"
#else
#include <kern/clock.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <mach/thread_act.h>
#include <libkern/libkern.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_private.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/kpi_interface.h>
#include <pexpert/pexpert.h>
#include <sys/errno.h>
#include <sys/kern_event.h>
#include <sys/kpi_mbuf.h>
#include <sys/proc.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#endif
extern bool polaris_ram_overlay_allowed(void);
extern int polaris_uefi_shutdown_pending(void);
#define PWIF_QUEUE 16u
static LCK_GRP_DECLARE(pwif_group,"polaris-wifi");
static LCK_MTX_DECLARE(pwif_lock,&pwif_group);
static struct {
    ifnet_t interface;
    struct pwmb_identity identity;
    struct pwmb_message message;
    uint8_t frames[PWIF_QUEUE][1514],control[112],response[PWMB_DATA];
    unsigned length[PWIF_QUEUE],head,count,radio,link,fault,sealed;
    unsigned control_operation,control_bytes,pending,submitted,response_bytes,last_error;
    uint64_t request,completed,wire_sequence,sent,received,tx_drops,rx_drops;
    uint32_t started,worker_active;
} pwif;

static void pwif_link_event(ifnet_t interface,unsigned up)
{
    _Alignas(struct kern_event_msg) uint8_t raw[sizeof(struct kern_event_msg)+sizeof(struct net_event_data)]={0};
    struct kern_event_msg*m=(void*)raw;struct net_event_data*d=(void*)(m+1);
    m->total_size=sizeof(raw);m->vendor_code=KEV_VENDOR_APPLE;m->kev_class=KEV_NETWORK_CLASS;
    m->kev_subclass=KEV_DL_SUBCLASS;m->event_code=up?KEV_DL_LINK_ON:KEV_DL_LINK_OFF;
    d->if_family=ifnet_family(interface);d->if_unit=ifnet_unit(interface);strlcpy(d->if_name,ifnet_name(interface),IFNAMSIZ);
    ifnet_event(interface,m);
}
/* The lock protects input from arbitrary output/ioctl callers. Only the
 * worker consumes queues/calls the mailbox; no spin/wait with preemption off. */
static errno_t pwif_output(ifnet_t interface,mbuf_t packet)
{
    size_t length=mbuf_pkthdr_len(packet);int error=0;
    lck_mtx_lock(&pwif_lock);
    if(pwif.sealed||pwif.fault||!pwif.link||polaris_uefi_shutdown_pending())error=ENETDOWN;
    else if(length<14||length>1514)error=EMSGSIZE;
    else if(pwif.count==PWIF_QUEUE)error=ENOBUFS;
    else{
        unsigned index=(pwif.head+pwif.count)%PWIF_QUEUE;
        error=mbuf_copydata(packet,0,length,pwif.frames[index]);
        if(!error){pwif.length[index]=(unsigned)length;pwif.count++;}
    }
    if(error)pwif.tx_drops++;
    lck_mtx_unlock(&pwif_lock);
    if(error)ifnet_stat_increment_out(interface,0,0,1);
    else bpf_tap_out(interface,DLT_EN10MB,packet,NULL,0);
    mbuf_freem(packet);return error;
}
static int pwif_control(u_long command,void*data)
{
    if(command!=SIOCSDRVSPEC64&&command!=SIOCGDRVSPEC64)return EOPNOTSUPP;
    int error=proc_suser(current_proc());if(error)return error;
    struct ifdrv64*r=data;
    if(r->ifd_cmd!=PWIF_COMMAND||r->ifd_len!=PWIF_BYTES||!r->ifd_data)return EINVAL;
    uint8_t*record=kalloc_data(PWIF_BYTES,Z_WAITOK|Z_ZERO);if(!record)return ENOMEM;
    if(command==SIOCSDRVSPEC64){
        error=copyin(r->ifd_data,record,PWIF_BYTES);
        if(!error&&!pwif_request_valid(record))error=EINVAL;
        if(!error){
            lck_mtx_lock(&pwif_lock);
            if(pwif.sealed||pwif.fault||polaris_uefi_shutdown_pending())error=ENXIO;
            else if(pwif.pending)error=EBUSY;
            else if(pwif.request==UINT64_MAX)error=EOVERFLOW;
            else{
                pwif.control_operation=pwmb_u32(record+4);pwif.control_bytes=pwmb_u32(record+8);
                pwmb_clear(pwif.control,sizeof(pwif.control));
                memcpy(pwif.control,record+64,pwif.control_bytes);
                pwif.request++;pwif.pending=1;pwif.submitted=0;pwif.last_error=0;
                pwif.response_bytes=0;pwmb_clear(pwif.response,sizeof(pwif.response));
            }
            lck_mtx_unlock(&pwif_lock);
        }
    }else{
        lck_mtx_lock(&pwif_lock);
        pwmb_put32(record,PWIF_VERSION);pwmb_put32(record+4,pwif.radio|((pwif.link&&!pwif.sealed)<<1)|(pwif.fault<<2)|
            (pwif.sealed<<3)|(pwif.pending<<4)|((pwif.interface!=NULL)<<5));
        pwmb_put32(record+8,pwif.last_error);pwmb_put32(record+12,pwif.response_bytes);
        pwmb_put64(record+16,pwif.request);pwmb_put64(record+24,pwif.completed);
        pwmb_put64(record+32,pwif.sent);pwmb_put64(record+40,pwif.received);
        pwmb_put64(record+48,pwif.tx_drops);pwmb_put64(record+56,pwif.rx_drops);
        memcpy(record+64,pwif.response,pwif.response_bytes);lck_mtx_unlock(&pwif_lock);
        error=copyout(record,r->ifd_data,PWIF_BYTES);
    }
    pwmb_clear(record,PWIF_BYTES);kfree_data(record,PWIF_BYTES);return error;
}
static errno_t pwif_ioctl(ifnet_t interface,u_long command,void*data)
{
    struct ifreq*r=data;
    switch(command){
    case SIOCSIFADDR:return ifnet_set_flags(interface,IFF_UP,IFF_UP);
    case SIOCSIFFLAGS:return ifnet_set_flags(interface,(ifnet_flags(interface)&IFF_UP)?IFF_RUNNING:0,IFF_RUNNING);
    case SIOCSIFMTU:return r->ifr_mtu<IF_MINMTU||r->ifr_mtu>ETHERMTU?EINVAL:ifnet_set_mtu(interface,r->ifr_mtu);
    case SIOCGIFDEVMTU:
        r->ifr_devmtu.ifdm_current=ifnet_mtu(interface);r->ifr_devmtu.ifdm_min=IF_MINMTU;r->ifr_devmtu.ifdm_max=ETHERMTU;return 0;
    case SIOCGIFMEDIA32:case SIOCGIFMEDIA64:{
        struct ifmediareq*m=data;int media=IFM_IEEE80211|IFM_AUTO;
        user_addr_t list=command==SIOCGIFMEDIA64?((struct ifmediareq64*)data)->ifmu_ulist:
            CAST_USER_ADDR_T(((struct ifmediareq32*)data)->ifmu_ulist);
        lck_mtx_lock(&pwif_lock);unsigned up=pwif.link&&!pwif.sealed&&!pwif.fault;lck_mtx_unlock(&pwif_lock);
        int error=list&&m->ifm_count>0?copyout(&media,list,sizeof(media)):0;
        m->ifm_current=m->ifm_active=media;m->ifm_mask=0;m->ifm_status=IFM_AVALID|(up?IFM_ACTIVE:0);m->ifm_count=1;return error;
    }
    case SIOCADDMULTI:case SIOCDELMULTI:return 0;
    default:return pwif_control(command,data);
    }
}
static int pwif_attach(void)
{
    struct ifnet_init_eparams init={.ver=IFNET_INIT_CURRENT_VERSION,.len=sizeof(init),
        .flags=IFNET_INIT_LEGACY|IFNET_INIT_NX_NOAUTO,.uniqueid="polaris-wifi-en0",.uniqueid_len=sizeof("polaris-wifi-en0")-1,
        .name="en",.unit=0,.family=IFNET_FAMILY_ETHERNET,.subfamily=IFNET_SUBFAMILY_WIFI,.type=IFT_ETHER,
        .output=pwif_output,.demux=ether_demux,.add_proto=ether_add_proto,.del_proto=ether_del_proto,
        .check_multi=ether_check_multi,.framer_extended=ether_frameout_extended,.ioctl=pwif_ioctl,
        .broadcast_addr=etherbroadcastaddr,.broadcast_len=ETHER_ADDR_LEN};
    ifnet_t interface=NULL;int error=ifnet_allocate_extended(&init,&interface);if(error)return error;
    ifnet_set_capabilities_enabled(interface,0,-1);ifnet_set_addrlen(interface,ETHER_ADDR_LEN);
    ifnet_set_mtu(interface,ETHERMTU);ifnet_set_flags(interface,IFF_BROADCAST|IFF_MULTICAST|IFF_SIMPLEX,0xffff);
    ifnet_set_hdrlen(interface,ETHER_HDR_LEN);ifnet_set_offload(interface,0);
    error=ifnet_attach(interface,NULL);if(error){ifnet_release(interface);return error;}
    error=ifnet_set_lladdr(interface,pwif.identity.mac,ETHER_ADDR_LEN);
    if(error){ifnet_detach(interface);ifnet_release(interface);return error;}
    bpfattach(interface,DLT_EN10MB,ETHER_HDR_LEN);
    lck_mtx_lock(&pwif_lock);pwif.interface=interface;lck_mtx_unlock(&pwif_lock);
    printf("POLARIS WIFI: en0 attached after native READY; link down\n");return 0;
}
static void pwif_input(const struct pwmb_message*m)
{
    mbuf_t packet=NULL;unsigned chunks=1;int error=0;
    if(mbuf_allocpacket(MBUF_DONTWAIT,m->bytes,&chunks,&packet))error=ENOBUFS;
    else if(mbuf_copyback(packet,0,m->bytes,m->data,MBUF_DONTWAIT)){mbuf_freem(packet);error=ENOBUFS;}
    if(error){lck_mtx_lock(&pwif_lock);pwif.rx_drops++;lck_mtx_unlock(&pwif_lock);return;}
    void*header=mbuf_data(packet);mbuf_pkthdr_setrcvif(packet,pwif.interface);mbuf_pkthdr_setheader(packet,header);
    mbuf_adj(packet,ETHER_HDR_LEN);bpf_tap_in(pwif.interface,DLT_EN10MB,packet,header,ETHER_HDR_LEN);
    struct ifnet_stat_increment_param stats={.packets_in=1,.bytes_in=m->bytes};
    error=ifnet_input(pwif.interface,packet,&stats); /* KPI consumes the mbuf even on failure. */
    lck_mtx_lock(&pwif_lock);if(error)pwif.rx_drops++;else pwif.received++;lck_mtx_unlock(&pwif_lock);
}
/* Called before the existing VFS/CPU drain. Terminal only; no radio teardown
 * or DMA permission return is inferred. A busy mailbox is retried by caller. */
int polaris_wifi_interface_seal(void)
{
    if(!__atomic_load_n(&pwif.started,__ATOMIC_ACQUIRE))return 0;
    lck_mtx_lock(&pwif_lock);pwif.sealed=1;lck_mtx_unlock(&pwif_lock);
    int error=polaris_wifi_mailbox_seal();
    lck_mtx_lock(&pwif_lock);
    if(pwif.worker_active){lck_mtx_unlock(&pwif_lock);return EBUSY;}
    unsigned was_up=pwif.link;pwif.radio=pwif.link=0;
    pwif.tx_drops+=pwif.count;pwif.count=0;pwmb_clear(pwif.frames,sizeof(pwif.frames));
    pwmb_clear(pwif.control,sizeof(pwif.control));pwif.pending=pwif.submitted=0;
    pwmb_clear(pwif.response,sizeof(pwif.response));pwif.response_bytes=0;
    ifnet_t interface=pwif.interface;lck_mtx_unlock(&pwif_lock);
    if(was_up&&interface)pwif_link_event(interface,0);
    return error;
}
static int pwif_turn(void)
{
    struct pwmb_message*m=&pwif.message;
    int result=polaris_wifi_mailbox_poll(PWMB_EVENT,m);if(result<0)return -result;
    if(result==1){
        unsigned kind=pwmb_u32(m->data),error=pwmb_u32(m->data+4),was_up;
        lck_mtx_lock(&pwif_lock);
        if(pwif.sealed){lck_mtx_unlock(&pwif_lock);return ENXIO;}
        was_up=pwif.link;
        if(kind==1&&!error)pwif.radio=1;
        if(kind==3)pwif.link=1;
        if(kind==4||kind==5){pwif.link=0;pwif.tx_drops+=pwif.count;pwif.count=0;
            pwmb_clear(pwif.frames,sizeof(pwif.frames));}
        if(kind==5||error)pwif.last_error=error;
        unsigned now_up=pwif.link;lck_mtx_unlock(&pwif_lock);
        if(kind==5)return error?error:EIO;
        if(pwif.interface&&now_up!=was_up)pwif_link_event(pwif.interface,now_up);
    }
    if(!pwif.interface&&pwif.radio){int error=pwif_attach();if(error)return error;}
    if(!pwif.interface)return 0;
    result=polaris_wifi_mailbox_poll(PWMB_REPLY,m);if(result<0)return -result;
    if(result==1){
        lck_mtx_lock(&pwif_lock);
        int valid=pwif.pending&&pwif.submitted&&pwmb_u64(m->data)==pwif.wire_sequence&&pwmb_u32(m->data+8)==pwif.control_operation&&
            ((pwif.control_operation!=PWMB_JOIN&&pwif.control_operation!=PWMB_SCAN&&pwif.control_operation!=PWMB_DISCONNECT&&pwif.control_operation!=PWMB_POWER_OFF)||m->bytes==16);
        if(valid){pwif.last_error=pwmb_u32(m->data+12);pwif.response_bytes=m->bytes;memcpy(pwif.response,m->data,m->bytes);
            pwif.completed=pwif.request;pwif.pending=pwif.submitted=0;}
        lck_mtx_unlock(&pwif_lock);if(!valid)return EIO;
    }
    result=polaris_wifi_mailbox_poll(PWMB_RX,m);if(result<0)return -result;
    if(result==1)pwif_input(m);
    int error=0;
    lck_mtx_lock(&pwif_lock);
    if(!pwif.sealed&&pwif.pending&&!pwif.submitted){
        error=polaris_wifi_mailbox_request(pwif.control_operation,pwif.control,pwif.control_bytes,&pwif.wire_sequence);
        if(!error){pwif.submitted=1;pwmb_clear(pwif.control,sizeof(pwif.control));}
    }
    if(!error&&!pwif.sealed&&pwif.link&&pwif.count){
        unsigned at=pwif.head;
        error=polaris_wifi_mailbox_transmit(pwif.frames[at],pwif.length[at]);
        if(!error){ifnet_stat_increment_out(pwif.interface,1,pwif.length[at],0);pwif.sent++;
            pwmb_clear(pwif.frames[at],sizeof(pwif.frames[at]));pwif.head=(at+1)%PWIF_QUEUE;pwif.count--;}
    }
    lck_mtx_unlock(&pwif_lock);
    return error==EWOULDBLOCK||error==EBUSY||error==EAGAIN?0:error;
}
static void pwif_thread(__unused void*context,__unused wait_result_t result)
{
    int error=0;unsigned attached=0;
    for(;;){
        lck_mtx_lock(&pwif_lock);
        if(pwif.sealed||polaris_uefi_shutdown_pending()){lck_mtx_unlock(&pwif_lock);break;}
        pwif.worker_active=1;lck_mtx_unlock(&pwif_lock);
        error=attached?pwif_turn():polaris_wifi_mailbox_attach(&pwif.identity);
        if(!error)attached=1;
        lck_mtx_lock(&pwif_lock);pwif.worker_active=0;lck_mtx_unlock(&pwif_lock);
        if(error&&error!=EAGAIN&&error!=EBUSY)break;
        delay_for_interval(attached?2:100,NSEC_PER_MSEC);error=0;
    }
    if(error){lck_mtx_lock(&pwif_lock);pwif.fault=1;pwif.last_error=error;lck_mtx_unlock(&pwif_lock);
        printf("POLARIS WIFI: interface worker stopped, error=%d\n",error);}
    while(polaris_wifi_interface_seal()==EBUSY)delay_for_interval(2,NSEC_PER_MSEC);
    pwmb_clear(&pwif.message,sizeof(pwif.message));
    thread_terminate(current_thread());thread_block(THREAD_CONTINUE_NULL);
}
void polaris_wifi_interface_start(void)
{
    uint32_t wifi=0,mode=0,cpu=0,count=0;
    PE_parse_boot_argn("polariswifi",&wifi,sizeof(wifi));PE_parse_boot_argn("polarisuefi",&mode,sizeof(mode));
    PE_parse_boot_argn("polarisbootcpu",&cpu,sizeof(cpu));PE_parse_boot_argn("cpus",&count,sizeof(count));
    if(wifi!=1||mode!=1||cpu!=0x700||count!=4||!polaris_ram_overlay_allowed())return;
    if(__atomic_exchange_n(&pwif.started,1,__ATOMIC_ACQ_REL))return;
    thread_t thread;int error=kernel_thread_start(pwif_thread,NULL,&thread);
    if(!error)thread_deallocate(thread);else{pwif.fault=1;pwif.last_error=ENOMEM;}
}

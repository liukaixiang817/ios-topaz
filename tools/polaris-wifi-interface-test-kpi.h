/* Software KPI leaves for executing the actual interface source in tests.
 * Never included by a kernel build. No radio, CPU or device result is inferred. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
typedef int errno_t,wait_result_t,thread_t;
#if !defined(__APPLE__)
typedef uintptr_t user_addr_t;
#endif
struct test_mbuf {uint8_t data[2048];unsigned bytes,offset;void*header;};
typedef struct test_mbuf*mbuf_t;
struct test_ifnet {unsigned flags,mtu;uint8_t mac[6];};
typedef struct test_ifnet*ifnet_t;
struct ifreq {union{int ifr_mtu;struct{int ifdm_current,ifdm_min,ifdm_max;}ifr_devmtu;};};
struct ifdrv64 {char ifd_name[16];uint64_t ifd_cmd,ifd_len,ifd_data;};
struct ifmediareq {char name[16];int ifm_current,ifm_mask,ifm_status,ifm_active,ifm_count;};
struct ifmediareq64 {struct ifmediareq r;uint64_t ifmu_ulist;};
struct ifmediareq32 {struct ifmediareq r;uint32_t ifmu_ulist;};
struct kern_event_msg {unsigned total_size,vendor_code,kev_class,kev_subclass,event_code;};
struct net_event_data {unsigned if_family,if_unit;char if_name[16];};
struct ifnet_stat_increment_param {unsigned packets_in,bytes_in;};
struct ifnet_init_eparams {
    unsigned ver,len,flags,uniqueid_len,unit,family,subfamily,type,broadcast_len;
    const char*uniqueid,*name;const uint8_t*broadcast_addr;
    errno_t(*output)(ifnet_t,mbuf_t);errno_t(*ioctl)(ifnet_t,u_long,void*);
    int demux,add_proto,del_proto,check_multi,framer_extended;
};
enum{SIOCSDRVSPEC64=1,SIOCGDRVSPEC64,SIOCSIFADDR,SIOCSIFFLAGS,SIOCSIFMTU,SIOCGIFDEVMTU,SIOCGIFMEDIA32,SIOCGIFMEDIA64,SIOCADDMULTI,SIOCDELMULTI};
enum{IFF_UP=1,IFF_RUNNING=2,IFF_BROADCAST=4,IFF_MULTICAST=8,IFF_SIMPLEX=16};
enum{KEV_VENDOR_APPLE=1,KEV_NETWORK_CLASS,KEV_DL_SUBCLASS,KEV_DL_LINK_ON,KEV_DL_LINK_OFF};
enum{IFNET_INIT_CURRENT_VERSION=1,IFNET_INIT_LEGACY=2,IFNET_INIT_NX_NOAUTO=4,IFNET_FAMILY_ETHERNET=5,IFNET_SUBFAMILY_WIFI=6,IFT_ETHER=7};
enum{DLT_EN10MB=1,IFM_IEEE80211=2,IFM_AUTO=4,IFM_AVALID=8,IFM_ACTIVE=16,ETHERMTU=1500,IF_MINMTU=68,ETHER_HDR_LEN=14,ETHER_ADDR_LEN=6,IFNAMSIZ=16};
enum{Z_WAITOK=1,Z_ZERO=2,MBUF_DONTWAIT=1,NSEC_PER_MSEC=1000000,THREAD_CONTINUE_NULL=0};
#ifndef CAST_USER_ADDR_T
#define CAST_USER_ADDR_T(n) ((user_addr_t)(n))
#endif
#define LCK_GRP_DECLARE(n,s) int n __attribute__((unused))
#define LCK_MTX_DECLARE(n,g) int n
#define ether_demux 1
#define ether_add_proto 2
#define ether_del_proto 3
#define ether_check_multi 4
#define ether_frameout_extended 5
static const uint8_t etherbroadcastaddr[6]={255,255,255,255,255,255};
static unsigned mock_locked,mock_superuser,mock_shutdown,mock_alloc_failure,mock_copy_failure;
static unsigned mock_freed,mock_inputs,mock_events,mock_event_last,mock_attach,mock_threads,mock_kernel_error;
static unsigned mock_stat_sent,mock_stat_errors,mock_platform=1,mock_gate=1;
static uint8_t mock_input[2048];static unsigned mock_input_bytes;
static struct test_ifnet mock_interface;
static void lck_mtx_lock(int*p){(void)p;assert(!mock_locked);mock_locked=1;}
static int lck_mtx_try_lock(int*p){(void)p;if(mock_locked)return 0;mock_locked=1;return 1;}
static void lck_mtx_unlock(int*p){(void)p;assert(mock_locked);mock_locked=0;}
static void*kalloc_data(size_t n,unsigned flags){(void)flags;return mock_alloc_failure?NULL:calloc(1,n);}
static void kfree_data(void*p,size_t n){assert(pwmb_zero(p,(unsigned)n));free(p);}
static unsigned mbuf_pkthdr_len(mbuf_t m){return m->bytes;}
static int mbuf_copydata(mbuf_t m,unsigned off,size_t bytes,void*p)
{if(mock_copy_failure)return EFAULT;assert(off+bytes<=m->bytes);memcpy(p,m->data+m->offset+off,bytes);return 0;}
static void mbuf_freem(mbuf_t m){mock_freed++;free(m);}
static int mbuf_allocpacket(unsigned wait,unsigned bytes,unsigned*chunks,mbuf_t*out)
{(void)wait;assert(*chunks==1&&bytes<=2048);if(mock_alloc_failure)return ENOBUFS;*out=calloc(1,sizeof(**out));(*out)->bytes=bytes;return 0;}
static int mbuf_copyback(mbuf_t m,unsigned off,unsigned n,const void*p,unsigned wait)
{(void)wait;assert(off+n<=sizeof(m->data));if(mock_copy_failure)return EFAULT;memcpy(m->data+off,p,n);return 0;}
static void*mbuf_data(mbuf_t m){return m->data+m->offset;}
static void mbuf_pkthdr_setrcvif(mbuf_t m,ifnet_t i){(void)m;assert(i==&mock_interface);}
static void mbuf_pkthdr_setheader(mbuf_t m,void*p){m->header=p;}
static void mbuf_adj(mbuf_t m,unsigned n){assert(m->bytes>=n);m->bytes-=n;m->offset+=n;}
static int ifnet_input(ifnet_t i,mbuf_t m,const struct ifnet_stat_increment_param*s)
{assert(i==&mock_interface&&!mock_locked&&m->offset==14&&s->bytes_in==m->bytes+14&&m->header==m->data);
 mock_inputs++;mock_input_bytes=m->bytes;memcpy(mock_input,m->data+m->offset,m->bytes);mbuf_freem(m);return mock_kernel_error;}
static void ifnet_stat_increment_out(ifnet_t i,unsigned n,unsigned bytes,unsigned errors)
{(void)i;(void)bytes;mock_stat_sent+=n;mock_stat_errors+=errors;}
static void bpf_tap_out(ifnet_t i,unsigned kind,mbuf_t m,void*p,unsigned n){(void)i;(void)kind;(void)m;(void)p;(void)n;}
static void bpf_tap_in(ifnet_t i,unsigned kind,mbuf_t m,void*p,unsigned n){(void)i;(void)kind;(void)m;(void)p;assert(n==14&&!mock_locked);}
static void bpfattach(ifnet_t i,unsigned kind,unsigned n){(void)i;(void)kind;assert(n==14);}
static int proc_suser(int p){(void)p;return mock_superuser?0:EPERM;}
static int current_proc(void){return 1;}
static int copyin(user_addr_t p,void*q,size_t n){if(mock_copy_failure)return EFAULT;memcpy(q,(const void*)p,n);return 0;}
static int copyout(const void*p,user_addr_t q,size_t n){if(mock_copy_failure)return EFAULT;memcpy((void*)q,p,n);return 0;}
static unsigned ifnet_family(ifnet_t i){(void)i;return IFNET_FAMILY_ETHERNET;}
static unsigned ifnet_unit(ifnet_t i){(void)i;return 0;}
static const char*ifnet_name(ifnet_t i){(void)i;return "en";}
static void ifnet_event(ifnet_t i,const struct kern_event_msg*m)
{assert(i==&mock_interface&&!mock_locked);mock_events++;mock_event_last=m->event_code;}
static unsigned ifnet_flags(ifnet_t i){return i->flags;}
static int ifnet_set_flags(ifnet_t i,unsigned f,unsigned mask){i->flags=(i->flags&~mask)|(f&mask);return 0;}
static unsigned ifnet_mtu(ifnet_t i){return i->mtu;}
static int ifnet_set_mtu(ifnet_t i,unsigned n){i->mtu=n;return 0;}
static int ifnet_allocate_extended(const struct ifnet_init_eparams*p,ifnet_t*out)
{assert(!mock_locked&&p->unit==0&&p->subfamily==IFNET_SUBFAMILY_WIFI&&p->uniqueid_len==strlen(p->uniqueid));
 if(mock_alloc_failure)return ENOMEM;*out=&mock_interface;return 0;}
static void ifnet_set_capabilities_enabled(ifnet_t i,unsigned n,int mask){(void)i;(void)n;(void)mask;}
static void ifnet_set_addrlen(ifnet_t i,unsigned n){(void)i;assert(n==6);}
static void ifnet_set_hdrlen(ifnet_t i,unsigned n){(void)i;assert(n==14);}
static void ifnet_set_offload(ifnet_t i,unsigned n){(void)i;assert(!n);}
static int ifnet_attach(ifnet_t i,void*p){(void)p;assert(i==&mock_interface);mock_attach++;return mock_kernel_error;}
static void ifnet_release(ifnet_t i){assert(i==&mock_interface);}
static void ifnet_detach(ifnet_t i){assert(i==&mock_interface);}
static int ifnet_set_lladdr(ifnet_t i,const void*p,unsigned n){assert(n==6);memcpy(i->mac,p,n);return 0;}
static void delay_for_interval(unsigned n,unsigned scale){(void)n;(void)scale;assert(!mock_locked);}
static void thread_terminate(thread_t t){(void)t;}
static void thread_block(int n){(void)n;}
static thread_t current_thread(void){return 1;}
static int kernel_thread_start(void(*f)(void*,wait_result_t),void*p,thread_t*t)
{(void)f;(void)p;*t=1;mock_threads++;return mock_kernel_error;}
static void thread_deallocate(thread_t t){assert(t==1);}
static void PE_parse_boot_argn(const char*n,void*p,unsigned bytes)
{assert(bytes==4);*(uint32_t*)p=!mock_platform?0:!strcmp(n,"polarisbootcpu")?0x700:!strcmp(n,"cpus")?4:1;}

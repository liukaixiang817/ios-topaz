/* Actual DHCP/address helper with private OS-service peers. No host network
 * call escapes this translation unit; CoreFoundation serialization is real. */
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
#include "polaris-ipconfig.h"
static uid_t fake_uid(void);
static int fake_ioctl(int,unsigned long,...),fake_addresses(struct ifaddrs**);
static void fake_free(struct ifaddrs*);
static kern_return_t fake_lookup(mach_port_t,const char*,mach_port_t*);
static kern_return_t fake_deallocate(mach_port_t,mach_port_name_t);
#define geteuid fake_uid
#define ioctl fake_ioctl
#define getifaddrs fake_addresses
#define freeifaddrs fake_free
#define bootstrap_look_up fake_lookup
#define mach_port_deallocate fake_deallocate
#include "../userland/wifi/polaris-wifi-ip.c"
#undef mach_port_deallocate
#undef bootstrap_look_up
#undef freeifaddrs
#undef getifaddrs
#undef ioctl
#undef geteuid
static unsigned checks,mode,get_calls,sets,lookups,calls,releases;
#define CHECK(x) do{checks++;assert(x);}while(0)
static uid_t fake_uid(void){return mode==1?501:0;}
static int fake_ioctl(int fd,unsigned long command,...)
{
    CHECK(fd==42);va_list ap;va_start(ap,command);struct ifreq*r=va_arg(ap,struct ifreq*);va_end(ap);
    CHECK(!strcmp(r->ifr_name,"en0"));
    if(command==SIOCGIFFLAGS){get_calls++;r->ifr_flags=mode==2?IFF_UP:0;if(mode==3){errno=EIO;return -1;}return 0;}
    CHECK(command==SIOCSIFFLAGS&&r->ifr_flags==IFF_UP);sets++;
    if(mode==4){errno=EIO;return -1;}return 0;
}
static kern_return_t fake_lookup(mach_port_t port,const char*name,mach_port_t*out)
{CHECK(port==bootstrap_port&&!strcmp(name,"com.apple.network.IPConfiguration"));lookups++;*out=567;return mode==5?KERN_FAILURE:KERN_SUCCESS;}
static kern_return_t fake_deallocate(mach_port_t task,mach_port_name_t port)
{CHECK(task==mach_task_self()&&port==567);releases++;return KERN_SUCCESS;}
kern_return_t polaris_ipconfig_set_service(mach_port_t server,pwip_ifname name,pwip_data method,
    mach_msg_type_number_t length,pwip_service service,int*status)
{
    CHECK(server==567&&!strcmp(name,"en0")&&length>8&&!memcmp(method,"bplist00",8));calls++;
    CFDataRef data=CFDataCreate(NULL,method,length);CHECK(data);
    CFPropertyListRef value=CFPropertyListCreateWithData(NULL,data,kCFPropertyListImmutable,NULL,NULL);CHECK(value);
    CHECK(CFGetTypeID(value)==CFDictionaryGetTypeID()&&CFDictionaryGetCount(value)==1&&
        CFEqual(CFDictionaryGetValue(value,CFSTR("ConfigMethod")),CFSTR("DHCP")));
    CFRelease(value);CFRelease(data);
    *status=mode==7?1:0;memcpy(service,"fixture-service",16);
    if(mode==8)memset(service,'x',128);if(mode==9)service[0]=0;
    return mode==6?MACH_RCV_TIMED_OUT:KERN_SUCCESS;
}
static struct ifaddrs node;
static struct sockaddr_in address;
static unsigned address_mode;
static int fake_addresses(struct ifaddrs**out)
{
    memset(&node,0,sizeof(node));memset(&address,0,sizeof(address));
    node.ifa_name="en0";node.ifa_flags=IFF_UP;node.ifa_addr=(void*)&address;
    address.sin_family=AF_INET;
    const uint32_t addresses[]={0xc0a80164,0,0x7f000001,0xa9fe0102,0xe0000001,0xffffffff,0x00000102};
    address.sin_addr.s_addr=htonl(addresses[address_mode<7?address_mode:0]);
    if(address_mode==7)node.ifa_name="en1";if(address_mode==8)node.ifa_flags=0;
    if(address_mode==9)node.ifa_addr=NULL;if(address_mode==10)address.sin_family=AF_INET6;
    *out=&node;return 0;
}
static void fake_free(struct ifaddrs*list){CHECK(list==&node);}
static void reset(unsigned n){mode=n;get_calls=sets=lookups=calls=releases=0;}
int main(void)
{
    for(unsigned flags=0;flags<64;flags++){
        reset(0);int result=polaris_wifi_dhcp(42,flags);unsigned allowed=flags==35||flags==51;
        CHECK((result==0)==allowed);CHECK(calls==allowed&&releases==allowed&&get_calls==allowed&&sets==allowed);
    }
    for(unsigned n=1;n<=9;n++){
        reset(n);int result=polaris_wifi_dhcp(42,35);CHECK((result==0)==(n==2));
        if(n==1)CHECK(!get_calls&&!lookups&&!calls);
        if(n==2)CHECK(get_calls==1&&!sets&&calls==1&&releases==1);
        if(n==3||n==4)CHECK(!lookups&&!calls);
        if(n==5)CHECK(!calls&&!releases);
        if(n>=6)CHECK(calls==1&&releases==1);
        if(n==6)CHECK(errno==ETIMEDOUT);
    }
    for(address_mode=0;address_mode<=10;address_mode++)CHECK((polaris_wifi_addresses()==0)==!address_mode);
    printf("PASS %u actual DHCP/IP helper checks; private OS peers, no host network change\n",checks);return 0;
}

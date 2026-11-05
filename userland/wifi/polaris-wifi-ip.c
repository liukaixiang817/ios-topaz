/* Root bring-up control of configd's existing DHCP service. This does not
 * implement DHCP itself or write SystemConfiguration preferences. A successful
 * IPC reply means accepted, never an address, DNS or Internet success. */
#include "polaris-wifi-ip.h"
#include "polaris-ipconfig.h"
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
/* iOS exports this libSystem routine but the retained SDK omits servers/.
 * Signature matches Apple's bootstrap.h; the Mach types come from this SDK. */
extern kern_return_t bootstrap_look_up(mach_port_t,const char*,mach_port_t*);
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
_Static_assert(sizeof(__Request__polaris_ipconfig_set_service_t)==72,"ARM64 IPConfiguration request ABI");
_Static_assert(offsetof(__Request__polaris_ipconfig_set_service_t,name)==52,"IPConfiguration interface offset");
_Static_assert(sizeof(__Reply__polaris_ipconfig_set_service_t)==168,"ARM64 IPConfiguration reply ABI");

int polaris_wifi_dhcp(int fd,unsigned flags)
{
    if(geteuid()){errno=EPERM;return -1;}
    /* Native radio+authorized link+attached, neither failed nor sealed. */
    if((flags&47)!=35){errno=ENETDOWN;return -1;}
    struct ifreq request={0};memcpy(request.ifr_name,"en0",4);
    if(ioctl(fd,SIOCGIFFLAGS,&request))return -1;
    if(!(request.ifr_flags&IFF_UP)){
        request.ifr_flags|=IFF_UP;if(ioctl(fd,SIOCSIFFLAGS,&request))return -1;
    }
    const void *key=CFSTR("ConfigMethod"),*value=CFSTR("DHCP");
    CFDictionaryRef config=CFDictionaryCreate(NULL,&key,&value,1,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    if(!config){errno=ENOMEM;return -1;}
    CFDataRef data=CFPropertyListCreateData(NULL,config,kCFPropertyListBinaryFormat_v1_0,0,NULL);
    CFRelease(config);if(!data){errno=ENOMEM;return -1;}
    mach_port_t server=MACH_PORT_NULL;
    kern_return_t result=bootstrap_look_up(bootstrap_port,"com.apple.network.IPConfiguration",&server);
    pwip_ifname name="en0";pwip_service service={0};int status=-1;
    if(result==KERN_SUCCESS){
        CFIndex length=CFDataGetLength(data);
        if(length<=0||(uint64_t)length>UINT32_MAX)result=KERN_INVALID_ARGUMENT;
        else result=polaris_ipconfig_set_service(server,name,(pwip_data)CFDataGetBytePtr(data),
            (mach_msg_type_number_t)length,service,&status);
        mach_port_deallocate(mach_task_self(),server);
    }
    CFRelease(data);
    if(result!=KERN_SUCCESS){
        fprintf(stderr,"IPConfiguration IPC failed: 0x%x\n",result);
        errno=result==MACH_SEND_TIMED_OUT||result==MACH_RCV_TIMED_OUT?ETIMEDOUT:EIO;return -1;
    }
    if(status){fprintf(stderr,"IPConfiguration refused DHCP: status=%d\n",status);errno=EIO;return -1;}
    if(!memchr(service,0,sizeof(service))||!service[0]){errno=EPROTO;return -1;}
    /* Do not print a service-provided string as terminal control text. */
    puts("DHCP request accepted for en0; address acquisition is still pending.");return 0;
}

int polaris_wifi_addresses(void)
{
    struct ifaddrs *list=NULL;if(getifaddrs(&list))return -1;unsigned usable=0;
    for(const struct ifaddrs *p=list;p;p=p->ifa_next){
        if(!p->ifa_name||strcmp(p->ifa_name,"en0")||!p->ifa_addr||p->ifa_addr->sa_family!=AF_INET)continue;
        const struct sockaddr_in *address=(const void*)p->ifa_addr;
        uint32_t v=ntohl(address->sin_addr.s_addr);
        unsigned valid=(p->ifa_flags&IFF_UP)&&(v>>24)&&(v>>24)!=127&&(v>>16)!=0xa9fe&&(v>>28)<14;
        char text[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&address->sin_addr,text,sizeof(text)))continue;
        printf("en0 IPv4=%s usable=%u\n",text,valid);usable+=valid;
    }
    freeifaddrs(list);
    if(!usable){errno=EADDRNOTAVAIL;return -1;}
    puts("IPv4 address present; DNS and external traffic have not been verified.");return 0;
}

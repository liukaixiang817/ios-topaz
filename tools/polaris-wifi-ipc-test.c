/* Exercise the generated DHCP IPC client against a local Mach-port peer.
 * No bootstrap registration, configd request, interface or routing change. */
#include "polaris-ipconfig.h"
#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <mach/ndr.h>
#include <pthread.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef __Request__polaris_ipconfig_set_service_t request_t;
typedef __Reply__polaris_ipconfig_set_service_t reply_t;
_Static_assert(sizeof(request_t)==72,"Apple arm64 set_service request ABI");
_Static_assert(offsetof(request_t,name)==52,"interface field offset");
_Static_assert(sizeof(reply_t)==168,"Apple arm64 set_service reply ABI");
static const uint8_t input[]={1,4,9,16,25,36};
struct peer {mach_port_t port;unsigned mode;};
static void *server(void *context)
{
    struct peer *p=context;
    union {request_t request;uint8_t space[1024];} message={0};
    mach_msg_header_t *h=&message.request.Head;
    assert(mach_msg(h,MACH_RCV_MSG|MACH_RCV_TIMEOUT,0,sizeof(message),p->port,5000,MACH_PORT_NULL)==KERN_SUCCESS);
    assert(h->msgh_id==20011&&h->msgh_size==72&&(h->msgh_bits&MACH_MSGH_BITS_COMPLEX));
    assert(message.request.msgh_body.msgh_descriptor_count==1);
    assert(message.request.method.type==MACH_MSG_OOL_DESCRIPTOR&&message.request.method.size==sizeof(input));
    assert(message.request.methodCnt==sizeof(input)&&!memcmp(message.request.method.address,input,sizeof(input)));
    assert(!memcmp(message.request.name,"en0\0\0\0\0\0\0\0\0\0\0\0\0\0",16));
    reply_t reply={0};
    reply.Head.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE,0);
    reply.Head.msgh_size=sizeof(reply);reply.Head.msgh_remote_port=h->msgh_remote_port;
    reply.Head.msgh_id=p->mode==2?20112:20111;reply.NDR=NDR_record;
    reply.RetCode=KERN_SUCCESS;memcpy(reply.service,"fixture-service",16);
    reply.status=p->mode==1?1:0;
    if(p->mode==3)reply.Head.msgh_size=sizeof(mig_reply_error_t);
    h->msgh_remote_port=MACH_PORT_NULL;mach_msg_destroy(h);
    if(p->mode==4){
        struct timespec delay={5,300000000};nanosleep(&delay,NULL);
        mach_msg_destroy(&reply.Head);return NULL;
    }
    assert(mach_msg(&reply.Head,MACH_SEND_MSG|MACH_SEND_TIMEOUT,reply.Head.msgh_size,0,MACH_PORT_NULL,1000,MACH_PORT_NULL)==KERN_SUCCESS);
    return NULL;
}
int main(void)
{
    for(unsigned mode=0;mode<5;mode++){
        struct peer p={.mode=mode};
        assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&p.port)==KERN_SUCCESS);
        assert(mach_port_insert_right(mach_task_self(),p.port,p.port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
        pthread_t thread;assert(!pthread_create(&thread,NULL,server,&p));
        pwip_ifname name="en0";pwip_service service={0};int status=-1;
        kern_return_t result=polaris_ipconfig_set_service(p.port,name,(pwip_data)input,sizeof(input),service,&status);
        if(mode<2){assert(result==KERN_SUCCESS&&status==(int)mode&&!strcmp(service,"fixture-service"));}
        else{assert(result==(mode==2?MIG_REPLY_MISMATCH:mode==3?MIG_TYPE_ERROR:MACH_RCV_TIMED_OUT));assert(status==-1&&!service[0]);}
        assert(!pthread_join(thread,NULL));
        assert(mach_port_mod_refs(mach_task_self(),p.port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
        assert(mach_port_deallocate(mach_task_self(),p.port)==KERN_SUCCESS);
    }
    puts("PASS 5 actual local Mach IPC cases: accepted, denied, wrong ID, short reply, timeout; no network change");
    return 0;
}

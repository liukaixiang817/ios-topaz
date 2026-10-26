/* Original SDM845 firmware owns controller/PHY setup. This module uses only
 * its polled peripheral protocol; no direct MMIO, storage or variable writes.
 * Descriptor/API conventions checked against HackiOS d82c64a3 (MIT notice in
 * userland/gpu/LICENSE.hackios) and our own verified UsbDeviceDxe image. */
#include "uefi-usb.h"
#define CHUNK 65536u
#define SCREEN_LIMIT (16u*1024u*1024u)
static const efi_guid usb_guid={0xd9d9ce48,0x44b8,0x4f49,{0x8e,0x3e,0x2a,0x3b,0x92,0x7d,0xc6,0xc1}};
static const efi_guid init_guid={0x1c0cffce,0xfc8d,0x4e44,{0x8c,0x78,0x9c,0x9e,0x5b,0x53,0x0d,0x36}};
static const efi_guid gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static const uint8_t device[]={18,1,0x10,2,0,0,0,64,0xd1,0x18,0x0d,0xd0,0,1,1,2,3,1};
static const uint8_t ss_device[]={18,1,0,3,0,0,0,9,0xd1,0x18,0x0d,0xd0,0,1,1,2,3,1};
static const uint8_t config[]={9,2,32,0,1,1,0,0x80,0x50,9,4,0,0,2,0xff,0x42,3,0,
                             7,5,0x81,2,0,2,0,7,5,1,2,0,2,0};
static const uint8_t ss_config[]={9,2,44,0,1,1,0,0x80,0x10,9,4,0,0,2,0xff,0x42,3,0,
                                7,5,0x81,2,0,4,0,6,0x30,0,0,0,0,
                                7,5,1,2,0,4,0,6,0x30,0,0,0,0};
static const uint8_t qualifier[]={10,6,0,2,0,0,0,64,1,0};
static const uint8_t bos[]={5,15,22,0,2,7,16,2,6,0,0,0,10,16,3,0,0x0e,0,1,7,0x65,0};
static const uint8_t lang[]={4,3,9,4};
static const uint8_t maker[]={16,3,'P',0,'o',0,'l',0,'a',0,'r',0,'i',0,'s',0};
static const uint8_t product[]={26,3,'P',0,'o',0,'l',0,'a',0,'r',0,'i',0,'s',0,' ',0,'U',0,'E',0,'F',0,'I',0};
static const uint8_t serial[]={26,3,'p',0,'o',0,'l',0,'a',0,'r',0,'i',0,'s',0,'-',0,'u',0,'e',0,'f',0,'i',0};
struct service {
    struct efi_system *st;struct polaris_usb_protocol *usb;uint8_t *rx,*tx,*screen,*blt_pixels;
    uint64_t blt_capacity;
    int connected;uint64_t failures;efi_status last_status;
    const uint8_t *log,*map;const uint64_t *log_bytes;uint64_t map_bytes;
    struct polaris_gop *gop;void (*report)(const char *,uint64_t);
};
static void notify(void *event,void *context){(void)event;(void)context;}
static int poll(struct service *s,uint8_t endpoint,void *buffer,uint64_t limit,uint64_t *done)
{
    /* Waiting for the next host command is ordinary idle, with no deadline.
     * Only an in-flight IN transfer has a bounded wait for a vanished host. */
    for(uint64_t tries=0;endpoint==1 || tries<100000;tries++){
        union polaris_usb_event data={0};uint32_t event=0;uint64_t size=sizeof(data);
        efi_status status=s->usb->event(&event,&size,&data);
        if(status==(EFI_ERROR|6) && event==0){s->st->boot->stall(100);continue;}
        if((status&EFI_ERROR) || size>sizeof(data)){s->last_status=status?status:EFI_ERROR|4;return 0;}
        if(event==1){s->connected=data.state==0;if(!s->connected){s->last_status=EFI_ERROR|12;return 0;}}
        if(event==2 && data.transfer.endpoint==endpoint){
            if(data.transfer.status!=1 || data.transfer.buffer!=buffer || data.transfer.bytes>limit){
                s->last_status=EFI_ERROR|24;return 0;
            }
            *done=data.transfer.bytes;return 1;
        }
        if(event==0)s->st->boot->stall(100);
    }
    s->last_status=EFI_ERROR|18;s->usb->abort(endpoint);return 0;
}
static int transmit(void *context,const uint8_t *data,uint64_t bytes)
{
    struct service *s=context;if(!data || bytes>CHUNK)return 0;
    for(uint64_t i=0;i<bytes;i++)s->tx[i]=data[i];
    if(s->usb->send(0x81,bytes,s->tx)&EFI_ERROR)return 0;
    uint64_t done=0;return poll(s,0x81,s->tx,bytes,&done) && done==bytes;
}
static int stage(void *context,unsigned what,const uint8_t **data,uint64_t *bytes)
{
    struct service *s=context;
    if(what==1){*data=s->log;*bytes=*s->log_bytes;return *bytes<=32768;}
    if(what==2){*data=s->map;*bytes=s->map_bytes;return *bytes<=65568;}
    if(what!=3 || !s->gop || !s->gop->mode)return 0;
    if(!s->screen && (s->st->boot->allocate_pool(2,SCREEN_LIMIT,(void**)&s->screen)&EFI_ERROR))return 0;
    if(!polaris_usb_ppm(s->gop->mode,s->screen,SCREEN_LIMIT,bytes)){
        /* GOP is allowed to offer BLT-only video or bit masks instead of a
         * directly readable RGB framebuffer. Use the firmware's conversion. */
        struct polaris_gop_mode *mode=s->gop->mode;
        if(!s->gop->blt || !mode->info || mode->info_bytes<sizeof(*mode->info))return 0;
        struct polaris_gop_info info=*mode->info;
        if(!info.width || !info.height || info.width>4096 || info.height>4096)return 0;
        uint64_t pixels=(uint64_t)info.width*info.height;
        if(pixels>(SCREEN_LIMIT-32)/3)return 0;
        if(s->blt_capacity<pixels*4){
            if(s->blt_pixels)s->st->boot->free_pool(s->blt_pixels);
            s->blt_pixels=0;s->blt_capacity=0;
            if(s->st->boot->allocate_pool(2,pixels*4,(void**)&s->blt_pixels)&EFI_ERROR)return 0;
            if(!s->blt_pixels)return 0;s->blt_capacity=pixels*4;
        }
        efi_status status=s->gop->blt(s->gop,s->blt_pixels,1,0,0,0,0,info.width,info.height,info.width*4);
        if(status&EFI_ERROR)return 0;
        info.format=1;info.stride=info.width;
        struct polaris_gop_mode flat=*mode;flat.info=&info;flat.info_bytes=sizeof(info);
        flat.base=(uintptr_t)s->blt_pixels;flat.bytes=pixels*4;
        if(!polaris_usb_ppm(&flat,s->screen,SCREEN_LIMIT,bytes))return 0;
    }
    *data=s->screen;return 1;
}
efi_status polaris_efi_usb_serve(struct efi_system *st,const uint8_t *log,const uint64_t *log_bytes,
    const uint8_t *map,uint64_t map_bytes,void (*report)(const char *,uint64_t))
{
    if(!st || !st->boot || !st->boot->restore_tpl || !report || !log || !log_bytes)return EFI_ERROR|2;
    /* ReadyToBoot entered us at TPL_CALLBACK. This service never returns after
     * starting, so lower to APPLICATION to let firmware USB-init/timer events
     * run normally. The BDS OS-start path remains parked in our callback. */
    st->boot->restore_tpl(4);
    struct service s={0};s.st=st;s.report=report;s.log=log;s.log_bytes=log_bytes;
    s.map=map;s.map_bytes=map_bytes;void *event=0;report("USB_STEP=",1);
    efi_status status=st->boot->create_event_ex(0x200,8,notify,0,&init_guid,&event);
    if(!(status&EFI_ERROR)){st->boot->signal_event(event);st->boot->close_event(event);}
    report("USB_INIT_EVENT=",status);
    status=st->boot->locate_protocol(&usb_guid,0,(void**)&s.usb);
    if((status&EFI_ERROR)||!s.usb)return status?status:EFI_ERROR|14;
    report("USB_REVISION=",s.usb->revision);
    if(s.usb->revision!=UINT64_C(0x10000001) || !s.usb->start_ex || !s.usb->event ||
       !s.usb->send || !s.usb->allocate || !s.usb->free || !s.usb->stop || !s.usb->abort)return EFI_ERROR|3;
    st->boot->locate_protocol(&gop_guid,0,(void**)&s.gop);
    static const void *configs=config,*ss_configs=ss_config;
    static const void *strings[]={lang,maker,product,serial};
    struct polaris_usb_descriptors descriptors={device,&configs,ss_device,&ss_configs,
                                               qualifier,bos,4,strings};
    report("USB_STEP=",2);status=s.usb->start_ex(&descriptors);report("USB_START_EX=",status);
    if(status&EFI_ERROR)return status;
    status=s.usb->allocate(CHUNK,(void**)&s.rx);
    if(!(status&EFI_ERROR))status=s.usb->allocate(CHUNK,(void**)&s.tx);
    report("USB_BUFFERS=",status);
    if((status&EFI_ERROR)||!s.rx||!s.tx){
        if(s.rx)s.usb->free(s.rx);if(s.tx)s.usb->free(s.tx);
        s.usb->stop();return status?status:EFI_ERROR|9;
    }
    struct polaris_usb_diag d={&s,transmit,stage,0,0};report("USB_STEP=",3);
    for(;;){
        union polaris_usb_event data={0};uint32_t event_type=0;uint64_t size=sizeof(data);
        status=s.usb->event(&event_type,&size,&data);
        /* No event is not a disconnected device. An already connected host
         * needs the next OUT request queued even when EventHandler is idle. */
        if(status==(EFI_ERROR|6) && event_type==0)status=0;
        if(status&EFI_ERROR){s.connected=0;st->boot->stall(1000);continue;}
        if(event_type==1)s.connected=data.state==0;
        if(!s.connected){st->boot->stall(1000);continue;}
        status=s.usb->send(1,512,s.rx);
        uint64_t got=0;
        if((status&EFI_ERROR)||!poll(&s,1,s.rx,512,&got)){
            s.usb->abort(1);s.failures++;
            if(s.failures<=4 || !(s.failures&(s.failures-1)))report("USB_RX_ERROR=",status?status:s.last_status);
            st->boot->stall(1000);continue;
        }
        if(!polaris_usb_command(&d,s.rx,got)){
            s.usb->abort(0x81);s.failures++;
            if(s.failures<=4 || !(s.failures&(s.failures-1)))report("USB_TX_ERROR=",s.last_status);
        }
    }
}

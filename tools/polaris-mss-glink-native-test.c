/* Actual native producer chain + separate freestanding GLINK/QRTR TU.
 * The modem peer and privileged instructions are SOFTWARE only. */
struct pmni_command;
static void glink_peer_ring(const struct pmni_command*);
#define PMSY_TEST_GLINK_RING glink_peer_ring
#define PMSY_TEST_ENTRY unused_smp_suite
#define EFI_XNU_MSS_GLINK_NATIVE_AVAILABLE 1
#include "polaris-mss-smp2p-native-test.c"
#include "uefi-mss-glink-native.h"
static struct pmsg_state*glink;
static unsigned rx_offset,rx_head,local_intent,peer_ready,server_seen,glink_scenarios,cap_replies;
static void rx_frame(unsigned cmd,unsigned cid,unsigned arg,const uint8_t*body,unsigned bytes)
{
    uint8_t header[8];put(header,cmd,2);put(header+2,cid,2);put(header+4,arg,4);
    unsigned count=(8+bytes+7)&~7u,tail=pms_u32(sm_shadow+channel->item[1].data+8);
    unsigned space=tail<=rx_head?16384-rx_head+tail:tail-rx_head;CHECK(count+8<=space);
    for(unsigned n=0;n<count;n++)sm_shadow[rx_offset+(rx_head+n)%16384]=n<8?header[n]:n<8+bytes?body[n-8]:0;
    rx_head=(rx_head+count)%16384;put(sm_shadow+channel->item[1].data+12,rx_head,4);
}
static void rx_qrtr(unsigned type,unsigned dst,const uint8_t*body,unsigned n)
{
    CHECK(local_intent);uint8_t frame[128]={0};unsigned bytes=32+((n+3)&~3u);CHECK(bytes+8<=sizeof(frame));
    put(frame,bytes,4);put(frame+8,1,4);put(frame+12,type,4);put(frame+16,3,4);put(frame+20,type==1&&n!=20?77:0xfffffffe,4);
    put(frame+28,n,4);put(frame+32,1,4);put(frame+36,dst,4);memcpy(frame+40,body,n);
    rx_frame(9,7,local_intent,frame,bytes+8);
}
static void glink_peer_ring(const struct pmni_command*c)
{
    if(c->value!=0x1000||!glink||!rx_offset)return;
    unsigned desc=channel->item[1].data,tx=channel->item[2].data;
    unsigned at=pms_u32(sm_shadow+desc),end=pms_u32(sm_shadow+desc+4);
    while(at!=end){
        uint8_t packet[256];for(unsigned n=0;n<sizeof(packet);n++)packet[n]=sm_shadow[tx+(at+n)%16384];
        unsigned cmd=psm_u16(packet),cid=psm_u16(packet+2),arg=pms_u32(packet+4),bytes=8;
        if(cmd==2)bytes+=arg;if(cmd==5)bytes+=arg*8;if(cmd==9||cmd==12)bytes=16+pms_u32(packet+8);CHECK(bytes<=sizeof(packet));
        if(cmd==0){rx_frame(1,1,1,0,0);rx_frame(2,7,7,(const uint8_t*)"IPCRTR",7);}
        else if(cmd==2){CHECK(cid==1&&arg==7&&!memcmp(packet+8,"IPCRTR",7));rx_frame(4,1,0,0,0);}
        else if(cmd==5){if(!local_intent)local_intent=pms_u32(packet+12);}
        else if(cmd==9){
            CHECK(!arg&&!pms_u32(packet+12));rx_frame(14,7,0,0,0);const uint8_t*q=packet+16;
            if(pms_u32(q+4)==10){
                CHECK(pms_u32(q+36)==69&&pms_u32(q+40)==1);uint8_t service[20]={0};
                put(service,4,4);put(service+4,69,4);put(service+8,1,4);put(service+12,3,4);put(service+16,77,4);
                rx_qrtr(1,pms_u32(q+12),service,20);
            } else if(pms_u32(q+4)==1&&pms_u32(q+28)==77){
                CHECK(pms_u32(q+20)==7&&q[32]==0&&psm_u16(q+35)==0x24);
                uint8_t response[34]={2,q[33],q[34],0x24,0,27,0,2,4,0,0,0,0,0,
                    0x10,8,0,0x34,0x12,0,0,2,0,0,0,0x13,6,0,1,0,0,0,1,'T'};
                rx_qrtr(1,pms_u32(q+12),response,sizeof(response));cap_replies++;
            }
        }
        at=(at+((bytes+7)&~7u))%16384;put(sm_shadow+desc,at,4);
    }
    if(local_intent&&!peer_ready){uint8_t intent[8]={0},hello[20]={2};put(intent,65536,4);rx_frame(5,7,1,intent,8);rx_qrtr(2,0xfffffffe,hello,20);peer_ready=1;}
}
static void server(void*ctx,bool arrived,uint32_t service,uint32_t version,uint32_t instance,uint32_t node,uint32_t port)
{CHECK(ctx==glink&&arrived&&service==69&&version==1&&!instance&&node==3&&port==77);server_seen++;}
static void glink_setup(unsigned cached)
{
    glink=0;pmsg_runtime=0;smp_setup(0,0);CHECK(smp_drive()==2);rx_offset=rx_head=local_intent=peer_ready=server_seen=cap_replies=0;
    glink=(void*)(arena+0x7800000);CHECK(sizeof(*glink)<0x700000);memset(glink,0,sizeof(*glink));glink_scenarios++;
    unsigned header;
    if(cached){header=0xb9000+0x7c000-32;rx_offset=header-16384;put(sm_shadow+0xb9010,rx_offset-0xb9000,4);}
    else{header=0xb9000+pms_u32(sm_shadow+0xb900c);rx_offset=header+16;put(sm_shadow+0xb900c,rx_offset+16384-0xb9000,4);}
    put(sm_shadow+header,0xa5a5|(480u<<16),4);put(sm_shadow+header+4,16384,4);put(sm_shadow+header+8,cached?0x100000:0,4);put(sm_shadow+header+12,0,4);
    memset(sm_shadow+rx_offset,0,16384);CHECK(pmsg_begin(glink,channel));
}
int main(int argc,char**argv)
{
    CHECK(argc==7);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);CHECK(sm_original&&sm_shadow);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    for(unsigned cached=0;cached<2;cached++){
        glink_setup(cached);rx_frame(0,1,1,0,0); /* Remote-first startup must be consumed, never reset. */
        int result=pmsg_step(glink);if(result!=2)fprintf(stderr,"GLINK step=%d error=%u channel=%u source=%u reads=%u\n",result,glink->error,channel->error,sm->error,sm->reads);
        CHECK(result==2);const struct polaris_wifi_qrtr_ops*ops=polaris_wifi_glink_qrtr_ops(glink->transport);CHECK(ops);
        struct polaris_wifi_qrtr_port*port=ops->open(0,server,glink);CHECK(port);CHECK(!ops->lookup(port,69,1,0));
        for(unsigned n=0;n<20&&!server_seen;n++){int error=polaris_wifi_glink_poll_once(glink->transport);if(error)fprintf(stderr,"poll error=%d native=%u reads=%u\n",error,glink->error,sm->reads);CHECK(!error);}
        CHECK(server_seen==1&&peer_ready);struct polaris_wifi_glink_status status;CHECK(!polaris_wifi_glink_status(glink->transport,&status)&&status.opened&&status.peer_seen&&!status.first_error);
        CHECK(!polaris_wifi_cap_open(&glink->identity,glink->transport,pmsg_now(glink)));
        for(unsigned n=0;n<10&&!glink->identity.discovered;n++)(void)polaris_wifi_cap_poll(&glink->identity,pmsg_now(glink));
        CHECK(glink->identity.discovered&&!glink->identity.error);
        CHECK(!polaris_wifi_cap_request(&glink->identity,31,pmsg_now(glink)));
        for(unsigned n=0;n<10&&!glink->identity.done;n++)(void)polaris_wifi_cap_poll(&glink->identity,pmsg_now(glink));
        CHECK(glink->identity.done&&!glink->identity.error&&glink->identity.capability.chip_id==0x1234&&cap_replies==1);
        CHECK(polaris_wifi_cap_request(&glink->identity,32,pmsg_now(glink))!=0);
        uint8_t cross[211];for(unsigned n=0;n<sizeof(cross);n++)sm_shadow[rx_offset+4095+n]=(uint8_t)n;
        CHECK(pmsg_read(glink,rx_offset+4095,cross,sizeof(cross)));for(unsigned n=0;n<sizeof(cross);n++)CHECK(cross[n]==(uint8_t)n);
        uint8_t bytes[9];memcpy(sm_shadow+rx_offset+100,"unaligned",9);CHECK(pmsg_read(glink,rx_offset+101,bytes,7)&&!memcmp(bytes,"naligne",7));
        fprintf(stderr,"native GLINK cached=%u service69 discovered; reads=%u writes=%u allocations=%u\n",cached,sm->reads,channel->writes,glink->allocations);
        if(cached)sm_shadow[glink->selected[4].offset+4]^=8;else put(sm_shadow+remote_at+36,1,4);
        unsigned writes=channel_stores;CHECK(polaris_wifi_glink_poll_once(glink->transport)&&channel_stores==writes&&glink->unknown);
    }
    glink_setup(0);put(sm_shadow+channel->item[1].data+8,8,4);CHECK(!pmsg_step(glink)&&glink->unknown); /* Never take over nonfresh consumer. */
    glink_setup(0);unsigned rx_header=rx_offset-16;put(sm_shadow+rx_header+2,481,2);
    CHECK(pmsg_step(glink)==1&&!glink->transport);advance_to(glink->started+PMSY_TOTAL+1);CHECK(!pmsg_step(glink)&&glink->unknown);
    glink_setup(0);void*large=pwfg_alloc(0x300000);CHECK(large&&!pwfg_alloc(0x200000));pwfg_free(large,0x300000);
    CHECK(!glink->unknown);large=pwfg_alloc(0x400000);CHECK(large&&!pwfg_alloc(1));pwfg_free(large,0x400000);
    CHECK(pmsg_step(glink)==2);CHECK(!pmsg_write(glink,glink->layout.descriptor.offset,8)&&glink->unknown);
    glink_setup(0);CHECK(pmsg_step(glink)==2);sm_shadow[glink->entry_offset+16]^=32;
    unsigned before=channel_stores;CHECK(polaris_wifi_glink_poll_once(glink->transport)&&glink->unknown&&channel_stores==before);
    auth_test_close();free(sm_original);free(sm_shadow);printf("PASS %u native GLINK checks, %u scenarios; software leaves/peer only\n",checks,glink_scenarios);return 0;
}

static void data_target_tx(unsigned,const unsigned char*,unsigned);
#define EFI_XNU_WIFI_HTT_DATA_AVAILABLE 1
#define PMHT_TEST_TX_HOOK data_target_tx
#define PMHT_TEST_ENTRY unused_htt_suite
#include "polaris-wifi-htt-native-test.c"
#include "uefi-wifi-htt-data.h"
static struct pmhd_state*data;
static unsigned data_fault,data_scenarios,data_commands;
static void data_event(unsigned pipe,const uint8_t*p,unsigned bytes)
{
    uint8_t frame[256]={0};CHECK(bytes+8<=sizeof(frame));frame[0]=(uint8_t)htc->client.htt;phtc_put(frame+2,bytes);memcpy(frame+8,p,bytes);target_frame(pipe,frame,bytes+8);
}
static void data_target_tx(unsigned pipe,const unsigned char*frame,unsigned bytes)
{
    CHECK(data&&pmhd_live(data)&&pipe==4&&bytes==80);data_commands++;const uint8_t*p=frame+8;
    unsigned id=phtr_u16(p+6);CHECK(id==data->rings.tx_id&&data->rings.tx_owner[id]==1&&p[0]==1&&p[1]==0x40&&phtr_u16(p+4)==100);
    uint64_t address=phtr_u64(p+8);CHECK(address==HTT_ALLOCATION+htt->layout.fragments+72u*id);
    const uint8_t*fragment=htt_device+address-HTT_ALLOCATION;uint64_t buffer=pwmi_get(fragment+24)|((uint64_t)phtr_u16(fragment+28)<<32);
    CHECK(buffer==HTT_ALLOCATION+htt->layout.transmit+2048u*id&&phtr_u16(fragment+30)==100);
    for(unsigned n=0;n<100;n++)CHECK(htt_device[buffer-HTT_ALLOCATION+n]==(uint8_t)(0xa0+n));
    uint8_t completion[8]={7,0,1,0,0,0,0xff,0xff};phtt_put16(completion+4,id);data_event(1,completion,sizeof(completion));
}
static void data_indicate(unsigned pipe,unsigned slot,unsigned offload)
{
    uint8_t*buffer=htt_device+htt->layout.receive+2048u*slot;memset(buffer,0,2048);
    unsigned offset=offload?7:360;
    if(offload){phtt_put16(buffer,100);phtt_put16(buffer+2,7);}
    else{pwmi_put(buffer+4,data_fault==3?0:1u<<31);pwmi_put(buffer+36,1u<<8);}
    for(unsigned n=0;n<100;n++)buffer[offset+n]=(uint8_t)(0x40+n);
    uint8_t indication[20]={0x12,0,7,0,0,0,1,0};if(offload)indication[1]=0x20;
    phtt_put64(indication+8,HTT_ALLOCATION+htt->layout.receive+2048u*slot);phtt_put16(indication+16,100);data_event(pipe,indication,sizeof(indication));
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    htt_cpu=aligned_alloc(4096,PHTM_BYTES);htt_device=aligned_alloc(4096,PHTM_BYTES);CHECK(htt_cpu&&htt_device);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned kind=0;kind<5;kind++){
        data=0;htt=0;wmi=0;htc_setup(0);wmi=(void*)(arena+0x7340000);memset(wmi,0,sizeof(*wmi));wmi_fault=wmi_requests=0;CHECK(pmwi_begin(wmi,htc));
        for(unsigned n=0;n<40&&htc->client.phase!=8;n++){CHECK(pmwi_step(wmi)==1);advance_to(owner->last+19200);}
        CHECK(htc->client.phase==8);wmi_service();int result=1;
        for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmwi_step(wmi);}CHECK(result==3);
        htt=(void*)(arena+0x7380000);memset(htt,0,sizeof(*htt));memset(htt_cpu,0xa5,PHTM_BYTES);memset(htt_device,0xa5,PHTM_BYTES);
        htt_fault=htt_commands=htt_copies=htt_caches=0;CHECK(pmht_begin(htt,htt_memory,wmi));result=1;
        for(unsigned n=0;n<2200&&result==1;n++){if(htt->prepared)advance_to(owner->last+19200);result=pmht_step(htt);}CHECK(result==3);
        data=(void*)(arena+0x73a0000);CHECK(sizeof(*data)<0x20000);memset(data,0,sizeof(*data));data_fault=kind;data_commands=0;data_scenarios++;
        CHECK(pmhd_begin(data,htt));for(unsigned n=0;n<100;n++)data->send[n]=(uint8_t)(0xa0+n);
        if(kind==1){htt_fault=2;CHECK(pmhd_send(data,100,2,0,0,0)==-1&&!data_commands&&data->rings.tx_owner[0]==1);}
        else if(kind==2){transport_fault=3;CHECK(pmhd_send(data,100,2,0,0,0)==-1&&data_commands==1&&data->rings.tx_owner[0]==1);}
        else if(kind==3){
            data_indicate(1,0,0);result=1;for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmhd_poll(data);}
            CHECK(result==-1&&data->rings.rx_owner[0]==2&&!data->frame_ready);
        }else{
            for(unsigned cycle=0;cycle<(kind==4?1u:6u);cycle++){
                unsigned id=data->rings.tx_cursor;CHECK(pmhd_send(data,100,2,0,0,0)==1&&data->rings.tx_owner[id]==2);
                for(unsigned n=0;n<30&&data->rings.tx_owner[id]!=3;n++){advance_to(owner->last+19200);CHECK(pmhd_poll(data)==1);}
                unsigned status=99;CHECK(pmhd_tx_ack(data,id,&status)&&!status);
                unsigned slot=cycle;data_indicate(cycle&1?5:1,slot,cycle==5);result=1;
                for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmhd_poll(data);}
                CHECK(result==3&&data->frame_ready&&data->rx_bytes==100&&data->rx_offset==(cycle==5?7u:360u)&&data->rx_format==1&&!data->rx_bad);
                for(unsigned n=0;n<100;n++)CHECK(data->receive[data->rx_offset+n]==(uint8_t)(0x40+n));
                CHECK(!pmhd_send(data,100,2,0,0,0));
                if(kind==4){htt_fault=2;CHECK(!pmhd_ack(data)&&data->unknown&&!data->rings.rx_owner[slot]&&data->rings.busy==2);break;}
                CHECK(pmhd_ack(data)&&data->rings.rx_owner[slot]==1&&data->rings.rx_posted==2047&&!data->frame_ready);
                CHECK(pwmi_get(htt_device+htt->layout.index)==data->rings.rx_index&&pwmc_zero(htt_device+htt->layout.receive+2048*slot,2048));
            }
            if(!kind)fprintf(stderr,"native HTT data:6 DMA TX/completion/RX/recycle, CE1/CE5 fast path, offload metadata PASS\n");
        }
        if(kind){CHECK(data->unknown&&data->error&&owner->held);unsigned calls=htt_copies+htt_caches+transport_writes;CHECK(pmhd_poll(data)==-1&&calls==htt_copies+htt_caches+transport_writes);}
    }
    wlan_unprotect();free(htt_cpu);free(htt_device);free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native HTT data checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual IP traffic\n",checks+nv_checks,data_scenarios);return 0;
}

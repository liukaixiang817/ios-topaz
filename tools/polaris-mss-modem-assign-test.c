/* Own120MiB startup wire profile plus the complete protected continuation suite. */
#include "polaris-wifi-mem-transaction.h"
static unsigned modem_exclusive;
#define PWMT_TEST_MODEM 1
#define pwmt_begin pwmt_begin_modem
#define main transaction_suite
#include "polaris-wifi-mem-transaction-test.c"
#undef main
#undef pwmt_begin
static struct pwma_page descriptor;
int main(void)
{
    for(modem_exclusive=0;modem_exclusive<2;modem_exclusive++){
        struct pwma_spec s=input();struct pwma_registers regs={0};
        memset(&descriptor,0,sizeof(descriptor));
        CHECK(!pwma_encode(&descriptor,&regs,&s));
        CHECK(pwma_encode_modem(&descriptor,&regs,&s));
        CHECK(regs.x[3]==16&&!memcmp(descriptor.data+64,&s.region_pa,8)&&
              !memcmp(descriptor.data+72,&s.region_bytes,8));
        for(unsigned bad=0;bad<15;bad++){
            s=input();memset(&descriptor,0,sizeof(descriptor));regs=(struct pwma_registers){0};
            switch(bad){
            case 0:s.region_bytes=0x200000;break;case 1:s.region_bytes+=4096;break;
            case 2:s.region_pa+=4096;break;case 3:s.region_pa=0xf8900000;break;
            case 4:s.descriptor_pa=s.region_pa;break;
            case 5:s.descriptor_pa=s.region_pa+s.region_bytes-4096;break;
            case 6:s.source[0]=PWMA_MSS_MSA;break;case 7:s.destination[0].vmid=PWMA_WLAN;break;
            case 8:s.destination[0].permissions=PWMA_RWX;break;case 9:s.source[2]=PWMA_WLAN;break;
            case 10:s.destination[2].permissions=PWMA_RW;break;case 11:s.sources=3;break;
            case 12:s.destinations=3;break;case 13:s.region_pa=0x7ff00000;break;
            case 14:s.descriptor_pa=UINT64_MAX-4095;break;
            }
            CHECK(!pwma_encode_modem(&descriptor,&regs,&s));
            CHECK(pwmt_zero(&descriptor,sizeof(descriptor))&&pwmt_zero(&regs,sizeof(regs)));
        }
        CHECK(transaction_suite()==0);
    }
    printf("PASS %u own modem profile/transaction checks; no native SMC or ownership claim\n",checks);return 0;
}

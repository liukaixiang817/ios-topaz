/* Separate exact120MiB return wire profile and protected continuation suite.
 * This encoder does not authorize handback; actual parent retirement does. */
#include "polaris-wifi-mem-transaction.h"
#define PWMT_TEST_MODEM_RETURN 1
#define pwmt_begin pwmt_begin_modem_return
#define main transaction_suite
#include "polaris-wifi-mem-transaction-test.c"
#undef main
#undef pwmt_begin
static struct pwma_page descriptor;
int main(void)
{
    struct pwma_spec s=input();struct pwma_registers regs={0};
    CHECK(!pwma_encode(&descriptor,&regs,&s)&&!pwma_encode_modem(&descriptor,&regs,&s));
    CHECK(pwma_encode_modem_return(&descriptor,&regs,&s));
    CHECK(regs.x[3]==16&&!memcmp(descriptor.data+64,&s.region_pa,8)&&!memcmp(descriptor.data+72,&s.region_bytes,8));
    for(unsigned bad=0;bad<15;bad++){
        s=input();memset(&descriptor,0,sizeof(descriptor));regs=(struct pwma_registers){0};
        switch(bad){
        case 0:s.region_bytes=0x200000;break;case 1:s.region_bytes+=4096;break;
        case 2:s.region_pa+=4096;break;case 3:s.region_pa=0xf8900000;break;
        case 4:s.descriptor_pa=s.region_pa;break;case 5:s.descriptor_pa=s.region_pa+s.region_bytes-4096;break;
        case 6:s.source[0]=PWMA_HLOS;break;case 7:s.destination[0].vmid=PWMA_WLAN;break;
        case 8:s.destination[0].permissions=PWMA_RW;break;case 9:s.source[1]=PWMA_WLAN;break;
        case 10:s.destination[1].permissions=PWMA_RW;break;case 11:s.sources=2;break;
        case 12:s.destinations=2;break;case 13:s.region_pa=0x7ff00000;break;
        case 14:s.descriptor_pa=UINT64_MAX-4095;break;
        }
        CHECK(!pwma_encode_modem_return(&descriptor,&regs,&s)&&pwmt_zero(&descriptor,sizeof(descriptor))&&pwmt_zero(&regs,sizeof(regs)));
    }
    CHECK(transaction_suite()==0);
    printf("PASS %u modem return profile/transaction checks; SOFTWARE only\n",checks);return 0;
}

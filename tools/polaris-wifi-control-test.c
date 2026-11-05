/* Exercise the real client with a private ioctl peer; never touch host en0. */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
static int test_socket(int,int,int);
static int test_close(int);
static int test_ioctl(int,unsigned long,...);
#define socket test_socket
#define close test_close
#define ioctl test_ioctl
#define main client_main
#include "../userland/wifi/polaris-wifi-ctl.c"
#undef main
#undef ioctl
#undef close
#undef socket
static unsigned mode,sets,queries,operation,checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static unsigned ip_calls;
int polaris_wifi_dhcp(int fd,unsigned flags)
{CHECK(fd==42&&flags==33);ip_calls++;errno=ENETDOWN;return -1;}
int polaris_wifi_addresses(void){ip_calls++;return 0;}
static int test_socket(int domain,int type,int protocol)
{CHECK(domain==AF_INET&&type==SOCK_DGRAM&&!protocol);return 42;}
static int test_close(int fd){CHECK(fd==42);return 0;}
static int test_ioctl(int fd,unsigned long command,...)
{
    va_list ap;va_start(ap,command);struct pwctl_driver*d=va_arg(ap,struct pwctl_driver*);va_end(ap);
    CHECK(fd==42&&!strcmp(d->name,"en0")&&d->command==PWIF_COMMAND&&d->bytes==PWIF_BYTES);
    uint8_t*p=(void*)(uintptr_t)d->pointer;
    if(command==PWCTL_SET){CHECK(pwif_request_valid(p));sets++;operation=pwmb_u32(p+4);return 0;}
    CHECK(command==PWCTL_GET);queries++;pwmb_clear(p,PWIF_BYTES);pwmb_put32(p,PWIF_VERSION);
    pwmb_put32(p+4,33);pwmb_put64(p+16,8+sets+(sets&&mode==1));
    if(!sets)return 0;
    if(mode==4){pwmb_put32(p+4,37);return 0;}
    pwmb_put64(p+24,9);uint8_t*r=p+64;
    pwmb_put64(r,1);pwmb_put32(r+8,operation);unsigned n=16;
    if(mode==2)pwmb_put32(r+8,PWMB_JOIN);
    if(operation==PWMB_STATE){n+=56;pwmb_put32(r+16,1);if(mode==3)pwmb_put32(r+16,2);}
    if(operation==PWMB_SCAN_ENTRY){
        n+=66;uint8_t*b=r+16;pwmb_put32(b+4,2412);pwmb_put32(b+8,(uint32_t)-7);
        pwmb_put32(b+12,1);pwcb_put16(b+20,2);b[25]=2;b[26]=1;
    }
    if(mode==5){pwmb_put32(r+12,EACCES);n=16;}
    pwmb_put32(p+12,n);return 0;
}
static void reset(unsigned selected)
{mode=selected;sets=queries=operation=0;pwmb_clear(input,sizeof(input));pwmb_clear(output,sizeof(output));}
int main(int argc,char**argv)
{
    if(argc==2&&!strcmp(argv[1],"--secret")){
        uint8_t value[64]={0};unsigned n=0;int result=secret(value,&n);
        if(result)CHECK(pwmb_zero(value,64));pwmb_clear(value,64);
        printf("secret_result=%d bytes=%u\n",result,n);return result?1:0;
    }
    char*state[]={"ctl","state",NULL},*scan[]={"ctl","scan",NULL},*entry[]={"ctl","entry","0",NULL};
    reset(0);CHECK(!client_main(2,state)&&sets==1&&queries==2);
    reset(0);CHECK(!client_main(2,scan)&&sets==1&&queries==2);
    reset(0);CHECK(!client_main(3,entry)&&sets==1&&queries==2);
    char*dhcp[]={"ctl","dhcp",NULL},*ip[]={"ctl","ip",NULL};
    reset(0);CHECK(client_main(2,dhcp)==1&&ip_calls==1&&!sets&&queries==1);
    reset(0);CHECK(!client_main(2,ip)&&ip_calls==2&&!sets&&queries==1);
    for(unsigned m=1;m<=5;m++){reset(m);CHECK(client_main(2,state)==1&&sets==1&&pwmb_zero(input,sizeof(input)));}
    uint8_t b[PWCB_BSS_HEADER+PWCB_IES]={0};
    pwmb_put32(b+4,2412);pwmb_put32(b+12,1);b[25]=2;
    CHECK(pwcb_bss_valid(b,64));b[24]=33;CHECK(!pwcb_bss_valid(b,64));b[24]=0;
    for(unsigned n=1;n<=768;n++){
        pwcb_put16(b+20,n);memset(b+64,0,768);
        CHECK(pwcb_bss_valid(b,64+n)==!(n&1));
    }
    b[25]=1;CHECK(!pwcb_bss_valid(b,832));
    uint8_t s[56]={0};CHECK(pwcb_state_valid(s,56));pwmb_put32(s,2);CHECK(!pwcb_state_valid(s,56));
    pwmb_put32(s,3);pwmb_put32(s+12,2412);s[16]=2;s[22]=1;s[24]='x';CHECK(pwcb_state_valid(s,56));
    for(unsigned bit=4;bit<=32;bit*=2){pwmb_put32(s,3|bit);CHECK(!pwcb_state_valid(s,56));}
    printf("PASS %u control client/wire checks; software ioctl only\n",checks);return 0;
}

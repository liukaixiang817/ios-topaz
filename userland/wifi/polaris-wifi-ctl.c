/* Root-only bring-up client for the actual Polaris BSD mailbox frontend.
 * No hardware/firmware call or persistent file write. A JOIN secret is read
 * from stdin (one ASCII line), never accepted in argv or printed. */
#include "../../tools/polaris-wifi-interface.h"
#include "../../tools/polaris-wifi-control-wire.h"
#include "polaris-wifi-ip.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
struct pwctl_driver {char name[16];uint64_t command,bytes,pointer;};
_Static_assert(sizeof(struct pwctl_driver)==40,"actual XNU ifdrv64 ABI");
#define PWCTL_SET _IOW('i',123,struct pwctl_driver)
#define PWCTL_GET _IOWR('i',123,struct pwctl_driver)
static uint8_t input[PWIF_BYTES],output[PWIF_BYTES];
static volatile sig_atomic_t stopped;
static void stop_secret(int signal_number){stopped=signal_number;}
static int control(int fd,unsigned set,uint8_t*record)
{
    struct pwctl_driver d={.name="en0",.command=PWIF_COMMAND,.bytes=PWIF_BYTES,.pointer=(uintptr_t)record};
    if(ioctl(fd,set?PWCTL_SET:PWCTL_GET,&d))return -1;
    if(!set&&(pwmb_u32(record)!=PWIF_VERSION||pwmb_u32(record+12)>PWMB_DATA)){
        errno=EPROTO;return -1;
    }return 0;
}
static uint64_t now_ms(void)
{struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000+(unsigned)t.tv_nsec/1000000;}
static void status(const uint8_t*p)
{
    unsigned flags=pwmb_u32(p+4);
    printf("radio=%u link=%u fault=%u sealed=%u pending=%u attached=%u error=%u request=%llu completed=%llu tx=%llu rx=%llu tx_drops=%llu rx_drops=%llu\n",
        flags&1,(flags>>1)&1,(flags>>2)&1,(flags>>3)&1,(flags>>4)&1,(flags>>5)&1,pwmb_u32(p+8),
        (unsigned long long)pwmb_u64(p+16),(unsigned long long)pwmb_u64(p+24),
        (unsigned long long)pwmb_u64(p+32),(unsigned long long)pwmb_u64(p+40),
        (unsigned long long)pwmb_u64(p+48),(unsigned long long)pwmb_u64(p+56));
}
static void escaped(const uint8_t*p,unsigned n)
{
    putchar('"');for(unsigned k=0;k<n;k++){
        if(p[k]>=32&&p[k]<127&&p[k]!='"'&&p[k]!='\\')putchar(p[k]);else printf("\\x%02x",p[k]);
    }putchar('"');
}
static int result(const uint8_t*p,unsigned n,unsigned op)
{
    if(!pwcb_reply_valid(p,n)||pwmb_u32(p+8)!=op){errno=EPROTO;return -1;}
    if(pwmb_u32(p+12)){errno=(int)pwmb_u32(p+12);return -1;}
    p+=16;
    if(op==PWMB_STATE){
        printf("native_flags=%u error=%u scan_count=%u frequency=%u ssid=",pwmb_u32(p),pwmb_u32(p+4),pwmb_u32(p+8),pwmb_u32(p+12));
        escaped(p+24,p[22]);putchar('\n');
    }else if(op==PWMB_SCAN_ENTRY){
        printf("index=%u frequency=%u snr=%d observations=%u capability=0x%04x beacon_interval=%u ie_bytes=%u ssid=",
            pwmb_u32(p),pwmb_u32(p+4),(int32_t)pwmb_u32(p+8),pwmb_u32(p+12),pwcb_u16(p+16),pwcb_u16(p+18),pwcb_u16(p+20));
        escaped(p+32,p[24]);putchar('\n');
    }else if(op==PWMB_POWER_OFF)puts("Whole-system power-off request accepted; shutdown completion is not confirmed.");
    return 0;
}
static int secret(uint8_t*out,unsigned*bytes)
{
    struct termios saved,hidden;int terminal=isatty(STDIN_FILENO),changed=0,ok=0;
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGTSTP};struct sigaction previous[4],action;
    sigset_t mask,previous_mask,pending;sigemptyset(&mask);
    for(unsigned k=0;k<4;k++)sigaddset(&mask,signals[k]);
    if(sigprocmask(SIG_BLOCK,&mask,&previous_mask))return -1;
    memset(&action,0,sizeof(action));action.sa_handler=stop_secret;sigemptyset(&action.sa_mask);
    unsigned installed=0;stopped=0;
    for(;installed<4;installed++)if(sigaction(signals[installed],&action,&previous[installed]))goto done;
    if(terminal){
        if(tcgetattr(STDIN_FILENO,&saved))goto done;hidden=saved;hidden.c_lflag&=~ECHO;
        if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&hidden))goto done;changed=1;
    }
    unsigned n=0;uint8_t c=0;
    /* Avoid stdio buffering: no second copy of the secret may remain in a
     * libc FILE buffer after the explicit input wipe. */
    while(!stopped){
        fd_set readable;FD_ZERO(&readable);FD_SET(STDIN_FILENO,&readable);
        /* Atomically unblock while waiting: a signal cannot arrive between
         * checking stopped and entering a blocking input call. */
        int ready=pselect(STDIN_FILENO+1,&readable,NULL,NULL,NULL,&previous_mask);
        if(ready<0){if(errno==EINTR)continue;goto done;}
        ssize_t count=read(STDIN_FILENO,&c,1);
        if(count<0){if(errno==EINTR&&!stopped)continue;goto done;}
        if(!count||c=='\n')break;
        if(c<32||c>126||n==63){errno=EINVAL;goto done;}out[n++]=c;
    }
    c=0;
    if(stopped||n<8){errno=stopped?EINTR:EINVAL;goto done;}
    *bytes=n;ok=1;
done:
    if(changed&&tcsetattr(STDIN_FILENO,TCSAFLUSH,&saved)){ok=0;}
    if(!sigpending(&pending))for(unsigned k=0;k<4;k++)
        if(sigismember(&pending,signals[k])&&!sigismember(&previous_mask,signals[k])){ok=0;break;}
    if(stopped)ok=0;
    while(installed){installed--;if(sigaction(signals[installed],&previous[installed],NULL))ok=0;}
    if(!ok)pwmb_clear(out,64);
    if(sigprocmask(SIG_SETMASK,&previous_mask,NULL)){pwmb_clear(out,64);return -1;}
    if(stopped)raise(stopped);
    return ok?0:-1;
}
int main(int argc,char**argv)
{
    unsigned op=0;
    if(argc==2&&!strcmp(argv[1],"status"))op=0;
    else if(argc==2&&!strcmp(argv[1],"state"))op=PWMB_STATE;
    else if(argc==2&&!strcmp(argv[1],"scan"))op=PWMB_SCAN;
    else if(argc==2&&!strcmp(argv[1],"disconnect"))op=PWMB_DISCONNECT;
    else if(argc==2&&!strcmp(argv[1],"power-off"))op=PWMB_POWER_OFF;
    else if(argc==2&&!strcmp(argv[1],"dhcp"))op=256;
    else if(argc==2&&!strcmp(argv[1],"ip"))op=257;
    else if(argc==3&&!strcmp(argv[1],"entry")){
        char*end=NULL;errno=0;unsigned long n=strtoul(argv[2],&end,10);
        if(errno||!argv[2][0]||!end||*end||n>=32)goto usage;
        op=PWMB_SCAN_ENTRY;pwmb_put32(input+8,4);pwmb_put32(input+64,(unsigned)n);
    }else if(argc==3&&!strcmp(argv[1],"join")){
        size_t n=strlen(argv[2]);if(!n||n>32)goto usage;
        op=PWMB_JOIN;pwmb_put32(input+8,112);uint8_t*j=input+64;
        pwmb_put32(j,2);j[4]=(uint8_t)n;j[6]=1;memcpy(j+16,argv[2],n);
        unsigned count=0;if(secret(j+48,&count))goto failed;j[5]=(uint8_t)count;
    }else goto usage;
    pwmb_put32(input,PWIF_VERSION);pwmb_put32(input+4,op);
    int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)goto failed;
    if(control(fd,0,output)){close(fd);goto failed;}
    if(op>=256){
        int done=op==256?polaris_wifi_dhcp(fd,pwmb_u32(output+4)):polaris_wifi_addresses();
        int error=errno;close(fd);if(done){errno=error;goto failed;}return 0;
    }
    if(!op){status(output);close(fd);return 0;}
    uint64_t before=pwmb_u64(output+16),started=now_ms();
    if(!started||before==UINT64_MAX||!pwif_request_valid(input)||control(fd,1,input)){close(fd);goto failed;}
    pwmb_clear(input,sizeof(input));
    for(;;){
        if(control(fd,0,output)){close(fd);goto failed;}
        if(pwmb_u64(output+16)!=before+1){errno=EBUSY;close(fd);goto failed;}
        if(pwmb_u64(output+24)==before+1){
            if(result(output+64,pwmb_u32(output+12),op)){close(fd);goto failed;}
            status(output);close(fd);return 0;
        }
        if(pwmb_u32(output+4)&12){errno=ENETDOWN;close(fd);goto failed;}
        uint64_t now=now_ms();if(now<started||now-started>60000){errno=ETIMEDOUT;close(fd);goto failed;}
        struct timespec pause={0,20000000};nanosleep(&pause,NULL);
    }
usage:
    fprintf(stderr,"usage: polaris-wifi-ctl status|state|scan|entry INDEX|join SSID|disconnect|dhcp|ip|power-off\nJOIN reads one passphrase line from stdin.\npower-off requests shutdown of the entire phone.\n");
    pwmb_clear(input,sizeof(input));return 2;
failed:
    {int error=errno?errno:EIO;pwmb_clear(input,sizeof(input));pwmb_clear(output,sizeof(output));
     fprintf(stderr,"polaris-wifi-ctl: %s (%d)\n",strerror(error),error);return 1;}
}

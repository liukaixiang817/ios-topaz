/* User-authorized RAM payload and reset commands. No storage APIs linked.
 * Ordinary read-only inventory retains its separate parser and restrictions. */
#include "uefi-usb.h"
#define PAYLOAD_LIMIT (128u*1024u*1024u)
/* One firmware command loop; keep the transfer scratch out of the UEFI
 * thread's small stack and within the admitted driver image allocation. */
static uint8_t receive_buffer[65536];
static int same(const uint8_t *p,uint64_t n,const char *s)
{uint64_t i=0;while(i<n&&s[i]){if(p[i]!=(uint8_t)s[i])return 0;i++;}return i==n&&!s[i];}
static int reply(struct polaris_usb_diag *d,const char *s)
{uint64_t n=0;while(s[n])n++;return n<=64&&d->transmit(d->context,(const uint8_t*)s,n);}
static int hexadecimal(const uint8_t *p,uint64_t *out)
{
    uint64_t n=0;
    for(unsigned i=0;i<8;i++){
        unsigned c=p[i],v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;
        if(v>15)return 0;n=n*16+v;
    }*out=n;return 1;
}
static int reset_reply(struct polaris_usb_diag *d,struct polaris_usb_control *c,unsigned mode)
{
    if(!c->reset_receipt)return reply(d,"OKAY");
    const uint8_t *data=0;uint64_t bytes=0;
    if(!c->reset_receipt(c->context,mode,&data,&bytes)||!data||!bytes||bytes>60)
        return reply(d,"FAILreset witness unavailable")?2:0;
    uint8_t response[64]={'O','K','A','Y'};
    for(uint64_t n=0;n<bytes;n++)response[4+n]=data[n];
    return d->transmit(d->context,response,4+bytes);
}
int polaris_usb_control_command(struct polaris_usb_diag *d,struct polaris_usb_control *c,const uint8_t *p,uint64_t n)
{
    if(!d||!d->transmit||!c)return 0;
    if(!p||!n||n>64)return reply(d,"FAILinvalid command length");
    for(uint64_t i=0;i<n;i++)if(p[i]<32||p[i]>126)return reply(d,"FAILinvalid command bytes");
    if(same(p,n,"getvar:kernel-state")){
        const char *s=c->state?c->state(c->context):"unavailable";uint8_t b[64]={'O','K','A','Y'};uint64_t i=0;
        while(s[i]&&i<60){b[4+i]=(uint8_t)s[i];i++;}return d->transmit(d->context,b,4+i);
    }
    if(same(p,n,"getvar:max-download-size"))return reply(d,"OKAY0x08000000");
    if(same(p,n,"oem boot-options")){
        const uint8_t *data=0;uint64_t bytes=0;d->staged=0;d->staged_bytes=0;
        if(!c->boot_options||!c->boot_options(c->context,&data,&bytes)||!data||bytes<32||bytes>65536)
            return reply(d,"FAILboot inventory unavailable");
        d->staged=data;d->staged_bytes=bytes;return reply(d,"OKAY");
    }
    if(same(p,n,"oem shutdown-state")){
        const uint8_t *data=0;uint64_t bytes=0;d->staged=0;d->staged_bytes=0;
        if(!c->shutdown_status||!c->shutdown_status(c->context,&data,&bytes)||!data||bytes!=128)
            return reply(d,"FAILshutdown state unavailable");
        d->staged=data;d->staged_bytes=bytes;return reply(d,"OKAY");
    }
    if(same(p,n,"oem wled-journal")){
        const uint8_t *data=0;uint64_t bytes=0;d->staged=0;d->staged_bytes=0;
        if(!c->wled_journal||!c->wled_journal(c->context,&data,&bytes)||!data||bytes<68||bytes>1348)
            return reply(d,"FAILWLED journal unavailable");
        d->staged=data;d->staged_bytes=bytes;return reply(d,"OKAY");
    }
    static const char runtime_page[]="oem wled-runtime-page:";
    if(n==sizeof(runtime_page)-1+8){
        unsigned match=1;for(unsigned i=0;i<sizeof(runtime_page)-1;i++)
            if(p[i]!=(uint8_t)runtime_page[i])match=0;
        if(match){
            uint64_t page=0;const uint8_t *data=0;uint64_t bytes=0;
            d->staged=0;d->staged_bytes=0;
            if(!hexadecimal(p+sizeof(runtime_page)-1,&page)||page>=2048||
               !c->wled_runtime_page||!c->wled_runtime_page(c->context,(uint32_t)page,&data,&bytes)||
               !data||bytes<84||bytes>1348)return reply(d,"FAILruntime WLED page unavailable");
            d->staged=data;d->staged_bytes=bytes;return reply(d,"OKAY");
        }
    }
    /* One bounded response: DATA/footer, then actual fresh readbacks in
     * OKAY/receipt, then guarded reset. Never finalize after failed delivery. */
    static const char exit_prefix[]="oem wled-exit:",recover_prefix[]="oem wled-recover:";
    unsigned prefix=0,recover=0;
    if(n==sizeof(exit_prefix)-1+34) {
        prefix=sizeof(exit_prefix)-1;
        for(unsigned i=0;i<prefix;i++)if(p[i]!=(uint8_t)exit_prefix[i])prefix=0;
    }
    if(!prefix&&n==sizeof(recover_prefix)-1+34) {
        prefix=sizeof(recover_prefix)-1;recover=1;
        for(unsigned i=0;i<prefix;i++)if(p[i]!=(uint8_t)recover_prefix[i])prefix=0;
    }
    if(prefix) {
        uint64_t hi=0,lo=0,count=0,crc=0,bytes=0;const uint8_t *data=0;
        if(p[prefix+16]!=':'||p[prefix+25]!=':'||
           !hexadecimal(p+prefix,&hi)||!hexadecimal(p+prefix+8,&lo)||
           !hexadecimal(p+prefix+17,&count)||!hexadecimal(p+prefix+26,&crc)||
           !c->wled_exit_begin||!c->wled_exit_finish||!c->wled_exit_abort||!c->reset||
           !c->wled_exit_begin(c->context,(int)recover,(hi<<32)|lo,(uint32_t)count,(uint32_t)crc,&data,&bytes)||
           !data||bytes<100||bytes>212)
            return reply(d,"FAILnative WLED exit unavailable");
        uint8_t header[12]={'D','A','T','A'};
        for(unsigned i=0;i<8;i++)header[4+i]="0123456789abcdef"[(bytes>>(28-i*4))&15];
        if(!d->transmit(d->context,header,12)||!d->transmit(d->context,data,bytes)) {
            c->wled_exit_abort(c->context,1);return 0;
        }
        data=0;bytes=0;
        if(!c->wled_exit_finish(c->context,&data,&bytes)||!data||bytes!=60) {
            c->wled_exit_abort(c->context,1);return reply(d,"FAILfresh WLED exit witness unavailable");
        }
        uint8_t response[64]={'O','K','A','Y'};
        for(unsigned i=0;i<60;i++)response[4+i]=data[i];
        if(!d->transmit(d->context,response,sizeof(response))) {
            c->wled_exit_abort(c->context,1);return 0;
        }
        c->reset(c->context,2);
        /* Real reset cannot return. A freshness/PON refusal may return and
         * permits only the one separate, newly inventoried read-only recovery. */
        c->wled_exit_abort(c->context,2);return 1;
    }
    unsigned shutdown=same(p,n,"oem shutdown:1")?1:same(p,n,"oem shutdown:2")?2:0;
    if(shutdown){
        if(!c->shutdown_begin||!c->shutdown_begin(c->context,shutdown))
            return reply(d,"FAILnative shutdown unavailable or refused");
        /* ACK means request sent only. No reset, and no safe/durable claim. */
        return reply(d,"OKAY");
    }
    unsigned drained=same(p,n,"oem drained-reboot:1")?1:same(p,n,"oem drained-reboot:2")?2:0;
    if(drained){
        if(!c->shutdown_reset_ready||!c->shutdown_reset_ready(c->context,drained)||
           !c->prepare_reset||!c->reset||!c->prepare_reset(c->context,drained))
            return reply(d,"FAILnative shutdown not complete");
        int sent=reset_reply(d,c,drained);if(sent!=1)return sent==2;
        c->reset(c->context,drained);return 1;
    }
    if(same(p,n,"getvar:input")){
        struct polaris_uefi_input_status s={0};
        if(!c->input_status||!c->input_status(c->context,&s))return reply(d,"FAILinput unavailable");
        uint8_t b[32]={'O','K','A','Y'};unsigned at=4;b[at++]=s.ready?'1':'0';
        uint32_t words[]={s.request,s.acknowledged,s.error};
        for(unsigned i=0;i<3;i++){b[at++]='/';for(unsigned j=0;j<8;j++)b[at++]="0123456789abcdef"[(words[i]>>(28-j*4))&15];}
        return d->transmit(d->context,b,at);
    }
    if(n>=15&&same(p,10,"oem touch:")){
        unsigned values[3]={0},at=10;
        for(unsigned i=0;i<3;i++){
            unsigned digits=0;
            while(at<n&&p[at]>='0'&&p[at]<='9'){
                if(++digits>4)return reply(d,"FAILinvalid touch");values[i]=values[i]*10+p[at++]-'0';
            }
            if(!digits||(i<2&&(at>=n||p[at++]!=':')))return reply(d,"FAILinvalid touch");
        }
        if(at!=n||!polaris_uefi_input_valid(values[0],values[1],values[2])||!c->touch||
           !c->touch(c->context,values[0],values[1],values[2]))return reply(d,"FAILtouch unavailable or busy");
        return reply(d,"OKAY");
    }
    if(n==17 && p[0]=='d'&&p[1]=='o'&&p[2]=='w'&&p[3]=='n'&&p[4]=='l'&&p[5]=='o'&&p[6]=='a'&&p[7]=='d'&&p[8]==':'){
        uint64_t count=0;
        if(!hexadecimal(p+9,&count)||!count||count>PAYLOAD_LIMIT||!c->begin||!c->write||!c->finish||!c->receive)
            return reply(d,"FAILinvalid RAM payload");
        if(!c->begin(c->context,count))return reply(d,"FAILRAM payload admission refused");
        d->staged=0;d->staged_bytes=0;
        uint8_t header[12]={'D','A','T','A'};for(unsigned i=0;i<8;i++)header[4+i]=p[9+i];
        if(!d->transmit(d->context,header,12))return 0;
        uint64_t at=0;
        while(at<count){
            uint64_t wanted=count-at;if(wanted>sizeof(receive_buffer))wanted=sizeof(receive_buffer);uint64_t got=0;
            if(!c->receive(d->context,receive_buffer,wanted,&got)||!got||got>wanted)return 0;
            if(!c->write(c->context,at,receive_buffer,got))return reply(d,"FAILRAM copy refused");at+=got;
        }
        return reply(d,c->finish(c->context)?"OKAY":"FAILRAM payload validation failed");
    }
    if(same(p,n,"oem boot")){
        if(!c->prepare_boot||!c->boot||!c->prepare_boot(c->context))return reply(d,"FAILkernel admission refused");
        if(!reply(d,"OKAY"))return 0;c->boot(c->context);return 1;
    }
    unsigned reset=same(p,n,"reboot")?1:same(p,n,"reboot-bootloader")?2:0;
    if(reset){
        if(!c->prepare_reset||!c->reset||!c->prepare_reset(c->context,reset))return reply(d,"FAILreset unavailable");
        int sent=reset_reply(d,c,reset);if(sent!=1)return sent==2;
        c->reset(c->context,reset);return 1;
    }
    return polaris_usb_command(d,p,n);
}

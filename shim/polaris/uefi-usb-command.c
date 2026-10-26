/* Read-only fastboot subset. Exact command matches; no download, erase, flash,
 * raw-memory reads, filesystem writes or reboot commands. Host uploads are
 * only prevalidated RAM logs, the EFI map snapshot, or a bounded GOP image. */
#include "uefi-usb.h"
#define STAGED_LIMIT (16u*1024u*1024u)
static int eq(const uint8_t *p,uint64_t n,const char *s)
{
    uint64_t i=0;while(s[i] && i<n){if(p[i]!=(uint8_t)s[i])return 0;i++;}
    return i==n && !s[i];
}
static int send_text(struct polaris_usb_diag *d,const char *s)
{
    uint64_t n=0;while(s[n])n++;
    return d->transmit(d->context,(const uint8_t*)s,n);
}
int polaris_usb_command(struct polaris_usb_diag *d,const uint8_t *p,uint64_t n)
{
    if(!d || !d->transmit || !d->stage)return 0;
    if(!p || !n || n>64)return send_text(d,"FAILinvalid command length");
    for(uint64_t i=0;i<n;i++)if(p[i]<32 || p[i]>126)return send_text(d,"FAILinvalid command bytes");
    if(eq(p,n,"getvar:product"))return send_text(d,"OKAYpolaris-uefi-diag");
    if(eq(p,n,"getvar:version"))return send_text(d,"OKAY0.4");
    if(eq(p,n,"getvar:version-bootloader"))return send_text(d,"OKAYpolaris-uefi-diag-0.1");
    if(eq(p,n,"getvar:serialno"))return send_text(d,"OKAYpolaris-uefi");
    if(eq(p,n,"getvar:max-download-size"))return send_text(d,"OKAY0x00000000");
    unsigned selection=eq(p,n,"oem logs")?1:eq(p,n,"oem memmap")?2:eq(p,n,"oem screenshot")?3:0;
    if(selection){
        const uint8_t *data=0;uint64_t bytes=0;
        if(!d->stage(d->context,selection,&data,&bytes) || !data || !bytes || bytes>STAGED_LIMIT)
            return send_text(d,"FAILcapture unavailable");
        d->staged=data;d->staged_bytes=bytes;
        return send_text(d,"OKAY");
    }
    if(eq(p,n,"upload")){
        if(!d->staged || !d->staged_bytes || d->staged_bytes>STAGED_LIMIT)
            return send_text(d,"FAILnothing staged");
        uint8_t header[12]={'D','A','T','A'};
        for(unsigned i=0;i<8;i++)header[4+i]="0123456789abcdef"[(d->staged_bytes>>(28-i*4))&15];
        if(!d->transmit(d->context,header,12))return 0;
        for(uint64_t at=0;at<d->staged_bytes;){
            uint64_t count=d->staged_bytes-at;if(count>65536)count=65536;
            if(!d->transmit(d->context,d->staged+at,count))return 0;
            at+=count;
        }
        return send_text(d,"OKAY");
    }
    return send_text(d,"FAILread-only diagnostics");
}
static unsigned decimal(uint8_t *p,uint32_t value)
{
    uint8_t tmp[10];unsigned n=0;do{tmp[n++]=(uint8_t)('0'+value%10);value/=10;}while(value);
    for(unsigned i=0;i<n;i++)p[i]=tmp[n-1-i];return n;
}
int polaris_usb_ppm(const struct polaris_gop_mode *m,uint8_t *out,uint64_t capacity,uint64_t *written)
{
    if(!m || !m->info || m->info_bytes<sizeof(*m->info) || !out || !written)return 0;
    const struct polaris_gop_info *i=m->info;
    if(!i->width || !i->height || i->width>4096 || i->height>4096 || i->stride<i->width ||
       i->stride>8192 || i->format>1 || !m->base || (m->base&3) || m->bytes>UINT64_MAX-m->base)return 0;
    uint64_t source=((uint64_t)(i->height-1)*i->stride+i->width)*4;
    uint64_t pixels=(uint64_t)i->width*i->height;
    if(source>m->bytes || pixels>(STAGED_LIMIT-32)/3 || capacity<pixels*3+32)return 0;
    unsigned n=0;out[n++]='P';out[n++]='6';out[n++]='\n';n+=decimal(out+n,i->width);
    out[n++]=' ';n+=decimal(out+n,i->height);out[n++]='\n';out[n++]='2';out[n++]='5';out[n++]='5';out[n++]='\n';
    const volatile uint32_t *fb=(const volatile uint32_t*)(uintptr_t)m->base;
    for(uint32_t y=0;y<i->height;y++)for(uint32_t x=0;x<i->width;x++){
        uint32_t pixel=fb[(uint64_t)y*i->stride+x];
        out[n++]=(uint8_t)(pixel>>(i->format==0?0:16));out[n++]=(uint8_t)(pixel>>8);
        out[n++]=(uint8_t)(pixel>>(i->format==0?16:0));
    }
    *written=n;return 1;
}

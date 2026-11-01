/* Default-OFF terminal evidence, never a power/access lease or an exit path.
 * GOP grants boot software direct access to this existing linear framebuffer.
 * Bind its actual headers/map before Wi-Fi work; after UNKNOWN use only local
 * RAM/AT/cache instructions. No GOP method, allocation, console, USB or reset.
 * Failure leaves the original terminal hold in force, including partial draws.
 */
#ifndef POLARIS_WIFI_TERMINAL_GOP_H
#define POLARIS_WIFI_TERMINAL_GOP_H
#include <stdint.h>
#include <stddef.h>
#ifndef EFI_XNU_WIFI_TERMINAL_GOP_OWN_WT
#define EFI_XNU_WIFI_TERMINAL_GOP_OWN_WT 0
#endif
#define PWTG_BASE UINT64_C(0x9d400000)
#define PWTG_WIDTH 1080u
#define PWTG_HEIGHT 2160u
#define PWTG_X 48u
#define PWTG_Y 96u
#define PWTG_COLS 32u
#define PWTG_ROWS 16u
#define PWTG_PIXEL_WIDTH (PWTG_COLS*18u)
#define PWTG_PIXEL_HEIGHT (PWTG_ROWS*24u)
#define PWTG_BEGIN (PWTG_BASE+4u*(PWTG_Y*PWTG_WIDTH+PWTG_X))
#define PWTG_END (PWTG_BASE+4u*((PWTG_Y+PWTG_PIXEL_HEIGHT-1u)*PWTG_WIDTH+PWTG_X+PWTG_PIXEL_WIDTH))
#define PWTG_FIRST (PWTG_BEGIN&~UINT64_C(4095))
#define PWTG_PAGES ((PWTG_END-PWTG_FIRST+4095u)/4096u)
#define PWTG_LIMIT UINT64_C(960000) /* terminal-only 50ms, NOT a new private ticket */
struct pwtg_arch {uint64_t el,mpidr,ttbr0,ttbr1,tcr,sctlr,mair,cpacr,sre,daif,group1,frequency,ticks,line;};
struct pwtg_at {uint64_t page,saved,read,write,restored;uint32_t issued,returned;};
struct pwtg_headers {
    uint64_t address[3];struct polaris_gop protocol;struct polaris_gop_mode mode;struct polaris_gop_info info;
};
struct pwtg_result {
    uint32_t attempted,error,armed,terminal_attempted,complete,outstanding;
    uint32_t pages_bound,pages_checked,pages_written,pixels_written,cleaned_lines,native_before,native_after,map_version;
    uint64_t native_address,self_base,self_bytes,map_bytes,map_stride,map_key,map_status;
    struct pwtg_arch before,terminal,last;
    struct pwtg_headers headers,current;
    struct pwtg_at header[2][6],pages[3][PWTG_PAGES];
    char text[PWTG_ROWS][PWTG_COLS];uint8_t map[65536];
};
enum pwtg_error {PWTG_OK,PWTG_ARGUMENT,PWTG_ARCH,PWTG_NATIVE,PWTG_MAP,PWTG_HEADER,
    PWTG_TRANSLATION,PWTG_CHANGED,PWTG_TIME,PWTG_REENTRY};
static inline int pwtg_fail(struct pwtg_result *r,unsigned e)
{if(!r->error)r->error=e;return 0;}
static inline int pwtg_equal(const void *a,const void *b,size_t n)
{const uint8_t*x=a,*y=b;for(size_t k=0;k<n;k++)if(x[k]!=y[k])return 0;return 1;}
static inline int pwtg_inside(uint64_t base,uint64_t bytes,uint64_t at,uint64_t n)
{return n&&bytes>=n&&at>=base&&at-base<=bytes-n;}
static inline int pwtg_normal(const struct pwtg_arch *a)
{return a->el==4&&!(a->mpidr&0xffffff)&&a->frequency==19200000&&a->cpacr==0x300000&&
    (a->sctlr&1)&&(a->sre&1)&&a->daif==0&&a->group1==1&&(a->line==64||a->line==128);}
static inline int pwtg_same_arch(const struct pwtg_arch *a,const struct pwtg_arch *b,unsigned terminal)
{return a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&a->ttbr1==b->ttbr1&&a->tcr==b->tcr&&
    a->sctlr==b->sctlr&&a->mair==b->mair&&a->cpacr==b->cpacr&&a->sre==b->sre&&a->frequency==b->frequency&&
    a->line==b->line&&b->ticks>=a->ticks&&b->daif==(terminal?0x3c0u:0)&&b->group1==(terminal?0:1);}
/* Hardware leaves have fixed meanings, not an authority-returning callback.
 * The software peer replaces them only in a separate test translation unit. */
#if defined(PWTG_SOFTWARE_PEER)
static int pwtg_arch_read(struct pwtg_arch *);
static int pwtg_translate(struct pwtg_at *);
static void pwtg_pixel(uint64_t,uint32_t);
static void pwtg_clean(uint64_t);
static uint32_t pwtg_native(uint64_t);
static void pwtg_order(void);
#else
static inline int pwtg_arch_read(struct pwtg_arch *a)
{
    __asm__ volatile("mrs %0,CurrentEL":"=r"(a->el));if(a->el!=4)return 0;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(a->mpidr));
    __asm__ volatile("mrs %0,ttbr0_el1":"=r"(a->ttbr0));
    __asm__ volatile("mrs %0,ttbr1_el1":"=r"(a->ttbr1));
    __asm__ volatile("mrs %0,tcr_el1":"=r"(a->tcr));
    __asm__ volatile("mrs %0,sctlr_el1":"=r"(a->sctlr));
    __asm__ volatile("mrs %0,mair_el1":"=r"(a->mair));
    __asm__ volatile("mrs %0,cpacr_el1":"=r"(a->cpacr));
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(a->sre));if(!(a->sre&1))return 0;
    __asm__ volatile("mrs %0,daif":"=r"(a->daif));
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(a->group1));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(a->frequency));
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));a->line=UINT64_C(4)<<((ctr>>16)&15);
    __asm__ volatile("isb; mrs %0,cntvct_el0":"=r"(a->ticks)::"memory");return 1;
}
static inline int pwtg_translate(struct pwtg_at *t)
{
    uint64_t saved,rd,wr,restored;t->issued=1;
    __asm__ volatile("mrs %0,par_el1; at s1e1r,%4; isb; mrs %1,par_el1; at s1e1w,%4; isb; mrs %2,par_el1; msr par_el1,%0; isb; mrs %3,par_el1"
        :"=&r"(saved),"=&r"(rd),"=&r"(wr),"=&r"(restored):"r"(t->page):"memory");
    t->saved=saved;t->read=rd;t->write=wr;t->restored=restored;t->returned=1;return 1;
}
static inline void pwtg_pixel(uint64_t at,uint32_t v){*(volatile uint32_t*)(uintptr_t)at=v;}
static inline void pwtg_clean(uint64_t at){__asm__ volatile("dc cvac,%0"::"r"(at):"memory");}
static inline uint32_t pwtg_native(uint64_t at){return *(const volatile uint32_t*)(uintptr_t)at;}
static inline void pwtg_order(void){__asm__ volatile("dsb sy; isb":::"memory");}
#endif
static inline int pwtg_at_valid(const struct pwtg_at *t,unsigned header)
{
    unsigned attr=(unsigned)(t->read>>56);
    return t->issued==1&&t->returned==1&&t->saved==t->restored&&!(t->read&1)&&t->write==t->read&&
        (t->read&0x200)&&(t->read&UINT64_C(0x0000fffffffff000))==t->page&&
        (attr==0xff||(!header&&(attr==0x44
#if EFI_XNU_WIFI_TERMINAL_GOP_OWN_WT
        /* Actual0177 first GOP page: BA0000009D465B80. PAR AttrH=B,
         * AttrL=A are Normal WT (outer RA/WA, inner RA/noWA). This is
         * confined to the existing GOP pixel pages, never headers/RSC.
         * No MAIR, TTBR, permissions or cache policy is changed here. */
        ||attr==0xba
#endif
        )));
}
static inline int pwtg_owned(const struct pwtg_result *r,uint64_t at,uint64_t n)
{
    return polaris_efi_range_owned(r->map,r->map_bytes,r->map_stride,at,n,3)||
        polaris_efi_range_owned(r->map,r->map_bytes,r->map_stride,at,n,4);
}
static inline int pwtg_header_copy(struct pwtg_result *r,uint64_t at,void *out,size_t n,unsigned slot,unsigned object)
{
    if(!at||n>4096||at>UINT64_MAX-n||!pwtg_owned(r,at,n)||
       (at<PWTG_BASE+UINT64_C(9331200)&&PWTG_BASE<at+n)||
       (at<r->self_base+r->self_bytes&&r->self_base<at+n))return pwtg_fail(r,PWTG_HEADER);
    unsigned k=object*2;
    for(uint64_t p=at&~UINT64_C(4095);p<at+n;p+=4096){
        if(k>=object*2+2)return pwtg_fail(r,PWTG_HEADER);
        struct pwtg_at*t=&r->header[slot][k];t->page=p;
        if(!pwtg_translate(t)||!pwtg_at_valid(t,1)||(slot&&t->read!=r->header[0][k].read))return pwtg_fail(r,PWTG_TRANSLATION);
        k++;
    }
    for(size_t j=0;j<n;j++)((uint8_t*)out)[j]=((const volatile uint8_t*)(uintptr_t)at)[j];return 1;
}
static inline int pwtg_headers_read(struct pwtg_result *r,uint64_t at,unsigned slot)
{
    struct pwtg_headers*h=slot?&r->current:&r->headers;h->address[0]=at;
    if(!pwtg_header_copy(r,at,&h->protocol,sizeof(h->protocol),slot,0))return 0;
    h->address[1]=(uintptr_t)h->protocol.mode;
    if(slot&&h->address[1]!=r->headers.address[1])return pwtg_fail(r,PWTG_CHANGED);
    if(!pwtg_header_copy(r,h->address[1],&h->mode,sizeof(h->mode),slot,1))return 0;
    h->address[2]=(uintptr_t)h->mode.info;
    if(slot&&h->address[2]!=r->headers.address[2])return pwtg_fail(r,PWTG_CHANGED);
    if(!pwtg_header_copy(r,h->address[2],&h->info,sizeof(h->info),slot,2))return 0;
    if(h->mode.base!=PWTG_BASE||h->mode.bytes<UINT64_C(9331200)||h->mode.info_bytes<sizeof(h->info)||
       h->mode.mode>=h->mode.max_mode||h->info.width!=PWTG_WIDTH||h->info.height!=PWTG_HEIGHT||
       h->info.stride!=PWTG_WIDTH||h->info.format>1)return pwtg_fail(r,PWTG_HEADER);
    if(slot&&!pwtg_equal(&r->headers,&r->current,sizeof(r->headers)))return pwtg_fail(r,PWTG_CHANGED);return 1;
}
/* Caller supplies the original GetMemoryMap bytes captured with its FP/context
 * guard in normal admission. This function cannot call any firmware method. */
static inline int pwtg_arm(struct pwtg_result *r,uint64_t gop_address,uint64_t native_address,uint64_t self_base,uint64_t self_bytes)
{
    if(r->attempted||r->error||r->armed||r->terminal_attempted||r->outstanding||r->complete||
       r->pages_bound||r->pages_checked||r->pages_written||r->pixels_written||r->cleaned_lines)return pwtg_fail(r,PWTG_REENTRY);
    r->attempted=1;
    r->native_address=native_address;r->self_base=self_base;r->self_bytes=self_bytes;
    struct polaris_efi_memory checked;
    if(!self_base||self_base>UINT64_MAX-self_bytes||r->map_status||r->map_version!=1||
       !polaris_efi_memory_check(r->map,r->map_bytes,sizeof(r->map),r->map_stride,&checked))return pwtg_fail(r,PWTG_MAP);
    if(!pwtg_inside(self_base,self_bytes,(uintptr_t)r,sizeof(*r))||
       !pwtg_owned(r,(uintptr_t)r,sizeof(*r))||!pwtg_inside(self_base,self_bytes,native_address,4)||!pwtg_owned(r,native_address,4)||
       r->map_status||!r->map_bytes||r->map_bytes>sizeof(r->map)||r->map_stride<40||r->map_bytes%r->map_stride)
        return pwtg_fail(r,PWTG_ARGUMENT);
    if(!pwtg_arch_read(&r->before)||!pwtg_normal(&r->before))return pwtg_fail(r,PWTG_ARCH);
    r->native_before=pwtg_native(native_address);if(r->native_before)return pwtg_fail(r,PWTG_NATIVE);
    if(!pwtg_headers_read(r,gop_address,0))return 0;
    for(unsigned k=0;k<PWTG_PAGES;k++){
        struct pwtg_at*t=&r->pages[0][k];t->page=PWTG_FIRST+4096u*k;
        if(!pwtg_translate(t)||!pwtg_at_valid(t,0))return pwtg_fail(r,PWTG_TRANSLATION);r->pages_bound++;
    }
    if(!pwtg_arch_read(&r->last)||!pwtg_same_arch(&r->before,&r->last,0))return pwtg_fail(r,PWTG_ARCH);
    r->native_after=pwtg_native(native_address);if(r->native_after)return pwtg_fail(r,PWTG_NATIVE);
    r->armed=1;pwtg_order();return 1;
}
/* Fixed 5x7 glyphs: numeric raw fields and a small, literal diagnostic legend.
 * Both supported GOP formats share black/white byte values. */
static inline uint64_t pwtg_glyph(unsigned c)
{
    static const uint8_t digits[16][7]={
        {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},{30,1,1,14,1,1,30},
        {2,6,10,18,31,2,2},{31,16,16,30,1,1,30},{14,16,16,30,17,17,14},{31,1,2,4,8,8,8},
        {14,17,17,14,17,17,14},{14,17,17,15,1,1,14},{14,17,17,31,17,17,17},{30,17,17,30,17,17,30},
        {14,17,16,16,16,17,14},{30,17,17,17,17,17,30},{31,16,16,30,16,16,31},{31,16,16,30,16,16,16}};
    if(c==' ')return 0;unsigned d=c>='0'&&c<='9'?c-'0':c>='A'&&c<='F'?c-'A'+10:16;
    uint64_t v=0;if(d<16){for(unsigned j=0;j<7;j++)v|=(uint64_t)digits[d][j]<<(j*5);return v;}
    switch(c){
    case 'G':return UINT64_C(0x3a31e461f);case 'H':return UINT64_C(0x4631fc631);
    case 'I':return UINT64_C(0x38842108e);case 'K':return UINT64_C(0x4654c5651);
    case 'L':return UINT64_C(0x7e1084210);case 'M':return UINT64_C(0x4631ad771);
    case 'N':return UINT64_C(0x46319d731);case 'O':return UINT64_C(0x3a318c62e);
    case 'P':return UINT64_C(0x4210f463e);case 'R':return UINT64_C(0x4654f463e);
    case 'S':return UINT64_C(0x78217043f);case 'T':return UINT64_C(0x10842109f);
    case 'U':return UINT64_C(0x3a318c631);case 'V':return UINT64_C(0x11518c631);
    case 'W':return UINT64_C(0x2ab5ac631);case 'Y':return UINT64_C(0x108422a31);
    default:return 0;
    }
}
static inline void pwtg_line(struct pwtg_result*r,unsigned row,const char *label,uint32_t a,uint32_t b)
{
    if(row>=PWTG_ROWS)return;unsigned at=0;
    for(;label[at]&&at<13;at++)r->text[row][at]=label[at];
    while(at<13)r->text[row][at++]=' ';
    for(unsigned k=0;k<8;k++)r->text[row][at++]="0123456789ABCDEF"[(a>>(28-4*k))&15];r->text[row][at++]=' ';
    for(unsigned k=0;k<8;k++)r->text[row][at++]="0123456789ABCDEF"[(b>>(28-4*k))&15];
    while(at<PWTG_COLS)r->text[row][at++]=' ';
}
static inline int pwtg_live(struct pwtg_result *r)
{
    if(!pwtg_arch_read(&r->last)||!pwtg_same_arch(&r->before,&r->last,1))return pwtg_fail(r,PWTG_ARCH);
    if(r->last.ticks<r->terminal.ticks||r->last.ticks-r->terminal.ticks>PWTG_LIMIT)return pwtg_fail(r,PWTG_TIME);
    r->native_after=pwtg_native(r->native_address);return r->native_after?pwtg_fail(r,PWTG_NATIVE):1;
}
static inline int pwtg_draw(struct pwtg_result *r)
{
    if(r->terminal_attempted)return pwtg_fail(r,PWTG_REENTRY);r->terminal_attempted=1;
    if(!r->armed||r->attempted!=1||r->error||r->outstanding||r->complete||r->pages_bound!=PWTG_PAGES)return 0;
    if(r->pages_checked||r->pages_written||r->pixels_written||r->cleaned_lines||r->map_version!=1)return pwtg_fail(r,PWTG_REENTRY);
    struct polaris_efi_memory checked;
    if(!pwtg_normal(&r->before)||!r->self_base||r->self_base>UINT64_MAX-r->self_bytes||
       !pwtg_inside(r->self_base,r->self_bytes,(uintptr_t)r,sizeof(*r))||
       !pwtg_inside(r->self_base,r->self_bytes,r->native_address,4)||
       !polaris_efi_memory_check(r->map,r->map_bytes,sizeof(r->map),r->map_stride,&checked))return pwtg_fail(r,PWTG_ARGUMENT);
    if(!pwtg_arch_read(&r->terminal)||!pwtg_same_arch(&r->before,&r->terminal,1))return pwtg_fail(r,PWTG_ARCH);
    if(!pwtg_live(r)||!pwtg_headers_read(r,r->headers.address[0],1))return 0;
    /* All mappings are checked before the FIRST store, then each page is
     * checked again immediately before its bounded stores. Partial failure
     * retains the exact prefix and never publishes completion or restoration. */
    for(unsigned k=0;k<PWTG_PAGES;k++){
        struct pwtg_at*t=&r->pages[1][k];t->page=PWTG_FIRST+4096u*k;
        if(!pwtg_live(r)||!pwtg_translate(t)||!pwtg_at_valid(t,0)||t->read!=r->pages[0][k].read)return pwtg_fail(r,PWTG_TRANSLATION);
        r->pages_checked++;
    }
    for(unsigned k=0;k<PWTG_PAGES;k++){
        struct pwtg_at*t=&r->pages[2][k];t->page=PWTG_FIRST+4096u*k;
        if(!pwtg_live(r)||!pwtg_translate(t)||!pwtg_at_valid(t,0)||t->read!=r->pages[0][k].read)return pwtg_fail(r,PWTG_TRANSLATION);
        r->outstanding=k+1;pwtg_order();
        for(uint64_t at=t->page;at<t->page+4096;at+=4){
            uint64_t pixel=(at-PWTG_BASE)/4;unsigned x=(unsigned)(pixel%PWTG_WIDTH),y=(unsigned)(pixel/PWTG_WIDTH);
            if(x<PWTG_X||x>=PWTG_X+PWTG_PIXEL_WIDTH||y<PWTG_Y||y>=PWTG_Y+PWTG_PIXEL_HEIGHT)continue;
            unsigned dx=x-PWTG_X,dy=y-PWTG_Y,gx=dx%18/3,gy=dy%24/3;
            unsigned c=(uint8_t)r->text[dy/24][dx/18];uint64_t glyph=pwtg_glyph(c);
            uint32_t value=gx<5&&gy<7&&((glyph>>(gy*5+4-gx))&1)?0x00ffffff:0;
            pwtg_pixel(at,value);r->pixels_written++;
        }
        /* All cache operations stay inside the same freshly checked GOP page. */
        for(uint64_t at=t->page;at<t->page+4096;at+=r->before.line){pwtg_clean(at);r->cleaned_lines++;}
        pwtg_order();r->pages_written++;r->outstanding=0;
    }
    if(!pwtg_live(r))return 0;r->complete=1;pwtg_order();return 1;
}
#endif

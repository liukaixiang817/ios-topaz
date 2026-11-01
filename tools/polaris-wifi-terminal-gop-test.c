/* SOFTWARE framebuffer/hardware peers. No firmware, USB or phone access. */
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shim/polaris/uefi-usb.h"
#include "../shim/polaris/uefi-memory.h"
#define PWTG_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-wifi-terminal-gop.h"
static struct {struct pwtg_result r;uint32_t native;} *self;
static struct {struct polaris_gop g;struct polaris_gop_mode m;struct polaris_gop_info i;} *headers;
static unsigned terminal,fault,at_calls,fail_at,phase_at,writes,cleans,arch_calls,render_pixels;
static unsigned framebuffer_attr=0xff;
static uint32_t *pixels;
static struct pwtg_arch arch;
static int pwtg_arch_read(struct pwtg_arch *a)
{
    *a=arch;a->ticks=++arch_calls*100u;a->daif=terminal?0x3c0:0;a->group1=terminal?0:1;
    if(terminal&&fault==7)a->ttbr0^=4096;
    if(terminal&&fault==8)a->cpacr=0;
    if(terminal&&fault==9)a->daif=0xc0;
    if(terminal&&fault==10)a->group1=1;
    if(terminal&&fault==11&&arch_calls>3)a->ticks+=UINT64_C(100000000);
    if(terminal&&fault==12&&self->r.pages_written)a->ticks+=UINT64_C(100000000);
    return 1;
}
static int pwtg_translate(struct pwtg_at*t)
{
    t->issued=t->returned=1;t->saved=t->restored=0x1234;
    t->read=t->write=UINT64_C(0xff00000000000b80)|t->page;at_calls++;
    if(t->page>=PWTG_FIRST&&t->page<PWTG_FIRST+PWTG_PAGES*4096)
        t->read=t->write=(t->read&UINT64_C(0x00ffffffffffffff))|((uint64_t)framebuffer_attr<<56);
    if(terminal&&t->page>=PWTG_FIRST&&t->page<PWTG_FIRST+PWTG_PAGES*4096){
        phase_at++;
        if(phase_at==fail_at){
            if(fault==1)return 0;
            if(fault==2)t->restored^=1;
            if(fault==3)t->write^=4096;
            if(fault==4)t->read=t->write=(t->read&UINT64_C(0x00ffffffffffffff))|UINT64_C(0x4400000000000000);
        }
    }
    return 1;
}
static void pwtg_pixel(uint64_t at,uint32_t value)
{
    assert(at>=PWTG_BASE&&at<PWTG_BASE+9331200&&(at&3)==0);
    unsigned offset=(unsigned)(at-PWTG_BASE)/4,x=offset%PWTG_WIDTH,y=offset/PWTG_WIDTH;
    assert(x>=PWTG_X&&x<PWTG_X+PWTG_PIXEL_WIDTH&&y>=PWTG_Y&&y<PWTG_Y+PWTG_PIXEL_HEIGHT);
    unsigned k=(unsigned)((at-PWTG_FIRST)/4096);assert(self->r.outstanding==k+1);
    assert(self->r.pages[2][k].returned&&pwtg_at_valid(&self->r.pages[2][k],0));
    assert(terminal&&self->native==0&&(value==0||value==0x00ffffff));
    if(render_pixels)pixels[offset]=value;writes++;
}
static void pwtg_clean(uint64_t at)
{assert(at>=PWTG_FIRST&&at<PWTG_FIRST+PWTG_PAGES*4096&&at%64==0);cleans++;}
static uint32_t pwtg_native(uint64_t at)
{assert(at==(uintptr_t)&self->native);if(terminal&&fault==21&&writes)self->native=1;return self->native;}
static void pwtg_order(void){}
static void setup(void)
{
    memset(self,0,sizeof(*self));memset(headers,0,sizeof(*headers));
    terminal=fault=at_calls=fail_at=phase_at=writes=cleans=arch_calls=0;framebuffer_attr=0xff;
    arch=(struct pwtg_arch){.el=4,.mpidr=0x80000000,.ttbr0=0x1000,.ttbr1=0x2000,.tcr=0x1234,.sctlr=1,
        .mair=0xff4400,.cpacr=0x300000,.sre=1,.frequency=19200000,.line=64};
    headers->g.mode=&headers->m;headers->m=(struct polaris_gop_mode){1,0,&headers->i,sizeof(headers->i),PWTG_BASE,9331200};
    headers->i=(struct polaris_gop_info){.width=PWTG_WIDTH,.height=PWTG_HEIGHT,.stride=PWTG_WIDTH,.format=0};
    struct efi_memory *m=(void*)self->r.map;
    m[0]=(struct efi_memory){.type=4,.physical=(uintptr_t)self,.pages=(sizeof(*self)+4095)/4096,.attributes=8};
    m[1]=(struct efi_memory){.type=4,.physical=(uintptr_t)headers,.pages=1,.attributes=8};
    self->r.map_bytes=2*sizeof(*m);self->r.map_stride=sizeof(*m);self->r.map_version=1;
}
static int arm(void)
{return pwtg_arm(&self->r,(uintptr_t)&headers->g,(uintptr_t)&self->native,(uintptr_t)self,(sizeof(*self)+4095)&~(size_t)4095);}
#ifndef PWTG_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(!posix_memalign((void**)&self,4096,(sizeof(*self)+4095)&~(size_t)4095));
    assert(!posix_memalign((void**)&headers,4096,4096));pixels=malloc(9331200);assert(pixels);
    unsigned checks=0;setup();assert(arm()&&!writes&&!cleans);terminal=1;
    pwtg_line(&self->r,0,"0177 HOLD",1,2);pwtg_line(&self->r,1,"BODY E U",6,1);
    for(unsigned row=2;row<PWTG_ROWS;row++)pwtg_line(&self->r,row,"DB0 A BYTES",1,0x20000);
    render_pixels=1;memset(pixels,0x55,9331200);assert(pwtg_draw(&self->r));render_pixels=0;
    assert(self->r.complete&&!self->r.outstanding&&self->r.pages_checked==PWTG_PAGES&&self->r.pages_written==PWTG_PAGES);
    assert(writes==PWTG_PIXEL_WIDTH*PWTG_PIXEL_HEIGHT&&cleans==PWTG_PAGES*64&&self->r.pixels_written==writes);
    for(unsigned y=0;y<PWTG_HEIGHT;y++)for(unsigned x=0;x<PWTG_WIDTH;x++)
        if(x<PWTG_X||x>=PWTG_X+PWTG_PIXEL_WIDTH||y<PWTG_Y||y>=PWTG_Y+PWTG_PIXEL_HEIGHT)assert(pixels[y*PWTG_WIDTH+x]==0x55555555);
    if(argc==2){FILE*f=fopen(argv[1],"wb");assert(f);fprintf(f,"P6\n%u %u\n255\n",PWTG_PIXEL_WIDTH,PWTG_PIXEL_HEIGHT);
        for(unsigned y=PWTG_Y;y<PWTG_Y+PWTG_PIXEL_HEIGHT;y++)for(unsigned x=PWTG_X;x<PWTG_X+PWTG_PIXEL_WIDTH;x++){
            unsigned char v=pixels[y*PWTG_WIDTH+x]?255:0;assert(fwrite(&v,1,1,f)==1&&fwrite(&v,1,1,f)==1&&fwrite(&v,1,1,f)==1);}
        assert(!fclose(f));}
    unsigned old_writes=writes;assert(!pwtg_draw(&self->r)&&writes==old_writes&&self->r.error==PWTG_REENTRY);checks++;
    for(unsigned f=1;f<=4;f++)for(unsigned k=1;k<=PWTG_PAGES;k++){
        setup();assert(arm());terminal=1;fault=f;fail_at=k;assert(!pwtg_draw(&self->r)&&!writes&&!cleans&&!self->r.complete);checks++;
    }
    for(unsigned k=1;k<=PWTG_PAGES;k++){
        setup();assert(arm());terminal=1;fault=2;fail_at=PWTG_PAGES+k;
        assert(!pwtg_draw(&self->r)&&!self->r.complete&&self->r.pages_written==k-1);checks++;
    }
    for(unsigned f=5;f<=22;f++){
        setup();assert(arm());terminal=1;fault=f;
        if(f==5)self->native=1;
        if(f==6)headers->i.width++;
        if(f==13)headers->m.info=(void*)1;
        if(f==14)headers->g.mode=(void*)1;
        if(f==15)self->r.map_stride=0;
        if(f==16)self->r.before.line=0;
        if(f==17)self->r.native_address=1;
        if(f==18)self->r.pages_bound--;
        if(f==19)headers->m.base+=4096;
        if(f==20)headers->i.format=2;
        if(f==22)self->r.self_bytes=UINT64_MAX;
        int ok=pwtg_draw(&self->r);if(ok||self->r.complete)fprintf(stderr,"fault%u returned%d complete%u error%u\n",f,ok,self->r.complete,self->r.error);
        assert(!ok&&!self->r.complete);
        if(f!=12&&f!=21)assert(!writes&&!cleans);else assert(writes&&self->r.pages_written==1);
        checks++;
    }
    setup();self->native=1;assert(!arm()&&!writes&&!cleans);checks++;
    setup();headers->m.bytes--;assert(!arm()&&!writes&&!cleans);checks++;
    setup();((struct efi_memory*)self->r.map)[1].type=7;assert(!arm()&&!writes&&!cleans);checks++;
    setup();((struct efi_memory*)self->r.map)[1].attributes|=UINT64_C(0x8000000000000000);assert(!arm()&&!writes&&!cleans);checks++;
    setup();self->r.map_version=2;assert(!arm()&&!writes&&!cleans);checks++;
    setup();self->r.error=PWTG_TRANSLATION;assert(!arm()&&!writes&&!cleans&&self->r.error==PWTG_TRANSLATION);checks++;
    for(unsigned f=0;f<4;f++){
        setup();assert(arm());terminal=1;
        uint32_t*counts[]={&self->r.pages_checked,&self->r.pages_written,&self->r.pixels_written,&self->r.cleaned_lines};
        *counts[f]=1;assert(!pwtg_draw(&self->r)&&!writes&&!cleans&&self->r.error==PWTG_REENTRY);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"pages\":%u,\"raw_bytes\":%zu,\"pixel_rectangle\":[%u,%u,%u,%u],\"SOFTWARE_only\":true}\n",checks,(unsigned)PWTG_PAGES,sizeof(struct pwtg_result),PWTG_X,PWTG_Y,PWTG_PIXEL_WIDTH,PWTG_PIXEL_HEIGHT);
    free(pixels);free(headers);free(self);return 0;
}
#endif

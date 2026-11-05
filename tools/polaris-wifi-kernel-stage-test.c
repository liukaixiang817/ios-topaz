/* Actual destination bytes, including BSS and reordered segments. No hardware. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shim/polaris/uefi-wifi-kernel-stage.h"
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);exit(1);}} while(0)
static _Alignas(16) unsigned char source[4096],target[4096];
static struct pwks_image state;
static struct polaris_payload *fixture(void)
{
    memset(source,0,sizeof(source));memset(target,0,sizeof(target));memset(&state,0,sizeof(state));
    struct polaris_payload*p=(void*)source;memcpy(p->magic,"SWEETXNU",8);p->version=1;p->nsegs=3;
    p->virt_base=0x100000;p->kernel_end=p->virt_base+sizeof(target);p->entry_va=p->virt_base+512;
    p->phys_base=(uintptr_t)target;p->mem_size=sizeof(target);
    p->segs[0]=(struct polaris_segment){p->virt_base+512,512,1024,256};
    p->segs[1]=(struct polaris_segment){p->virt_base,256,1280,128};
    p->segs[2]=(struct polaris_segment){p->virt_base+2048,256,1408,0};
    for(unsigned n=1024;n<1408;n++)source[n]=(unsigned char)(n*31+7);
    return p;
}
static void copy_segment(struct polaris_payload*p,unsigned n)
{
    struct polaris_segment*q=&p->segs[n];unsigned char*t=target+(q->vmaddr-p->virt_base);
    memcpy(t,source+q->file_off,q->file_size);memset(t+q->file_size,0,q->vmsize-q->file_size);
}
int main(void)
{
    struct polaris_payload*p=fixture();CHECK(pwks_begin(&state,p,sizeof(source)));
    struct pwfi_sha256 hash;pwfi_init(&hash);
    for(unsigned n=0;n<3;n++){copy_segment(p,n);CHECK(pwks_verify(&state,n));
        for(unsigned j=0;j<p->segs[n].vmsize;j++)pwfi_byte(&hash,target[p->segs[n].vmaddr-p->virt_base+j]);}
    unsigned char digest[32];pwfi_final(&hash,digest);
    CHECK(state.complete&&state.completed==3&&state.verified_bytes==1024);
    CHECK(!memcmp(digest,state.image_digest,32));CHECK(!pwks_verify(&state,2));CHECK(!pwks_begin(&state,p,sizeof(source)));
    for(unsigned byte=0;byte<512;byte++){
        p=fixture();CHECK(pwks_begin(&state,p,sizeof(source)));copy_segment(p,0);target[512+byte]^=1;
        CHECK(!pwks_verify(&state,0));CHECK(state.unknown&&state.error==3&&!state.complete);CHECK(!pwks_verify(&state,0));
    }
    for(unsigned byte=0;byte<sizeof(*p)+3*sizeof(p->segs[0]);byte++){
        p=fixture();CHECK(pwks_begin(&state,p,sizeof(source)));copy_segment(p,0);source[byte]^=1;
        CHECK(!pwks_verify(&state,0));CHECK(state.unknown&&state.error==2);
    }
    p=fixture();CHECK(pwks_begin(&state,p,sizeof(source)));CHECK(!pwks_verify(&state,1));CHECK(state.unknown&&state.error==4);
    p=fixture();p->segs[1].vmaddr=p->segs[0].vmaddr;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->segs[1].file_off=sizeof(source)+1;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->segs[1].vmsize=UINT64_MAX;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->segs[1].file_size=p->segs[1].vmsize+1;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->phys_base=(uintptr_t)source;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->phys_base=(uintptr_t)&state;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();p->nsegs=65;CHECK(!pwks_begin(&state,p,sizeof(source)));
    p=fixture();CHECK(!pwks_begin(&state,p,sizeof(*p)-1));
    p=fixture();p->phys_base=UINT64_MAX-8;CHECK(!pwks_begin(&state,p,sizeof(source)));
    printf("kernel-stage: %u checks PASS (actual host memory)\n",checks);return 0;
}

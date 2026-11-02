/* SOFTWARE metadata/AT peers only: no firmware instruction or device action. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uefi-wifi-parent-images.h"
static uint8_t*arena;static struct ppli_result*r;
static uint64_t*handles;static struct efi_loaded*images[PPLI_MAX];
static uint8_t map[PPLI_MAP_CAP] __attribute__((aligned(8)));
static unsigned count,page_calls,fault,mutate,byte;
static uint64_t ticks=100;
static int page(struct ppli_at*a)
{
    page_calls++;a->saved=0x123400;a->par=UINT64_C(0xff00000000000b80)|a->page;a->restored=a->saved;a->issued=a->returned=1;
    if(fault==1)return 0;if(fault==2)a->returned=0;if(fault==3)a->par^=0x200;
    if(fault==4)a->restored++;if(fault==5)a->page+=4096;
    if(fault==6)*(uint32_t*)(arena+0x100)=1;
    if(mutate)((uint8_t*)r)[byte]^=1;
    return 1;
}
static void setup(unsigned n,unsigned cross)
{
    memset(arena,0,0x300000);memset(map,0,sizeof(map));r=(void*)(arena+0x180000);handles=(void*)(arena+0x200);
    count=n;page_calls=fault=mutate=byte=0;
    struct efi_memory*d=(void*)map;
    d[0]=(struct efi_memory){3,0,(uintptr_t)arena,0,0x300,8};
    d[1]=(struct efi_memory){4,0,0x10000000,0,0x1000,8};
    for(unsigned k=0;k<n;k++){
        handles[k]=0x100+k;images[k]=(void*)(arena+0x2000+k*4096+(cross?4056:0));
        *images[k]=(struct efi_loaded){.revision=0x1000,.system=(void*)0x123000,.base=(void*)(uintptr_t)(0x10000000+k*4096),.bytes=4096,.code_type=3,.data_type=4};
    }
    if(n){images[0]->base=arena;images[0]->bytes=0x300000;}
    assert(ppli_bind(r,(void*)(arena+0x100),0x100));
}
static int start(void)
{return ppli_start(r,0x123000,(uintptr_t)handles,count,map,80,40,123,ticks,page);}
static int first(void)
{for(unsigned n=0;n<count;n++)if(!ppli_capture(r,0,n,handles[n],(uintptr_t)images[n],page))return 0;return 1;}
static int second(void)
{
    if(!ppli_second(r,map,80,40,123,page))return 0;
    for(unsigned n=0;n<count;n++)if(!ppli_capture(r,1,n,handles[n],(uintptr_t)images[n],page))return 0;return 1;
}
static void stopped(void)
{unsigned calls=page_calls;assert(!ppli_capture(r,0,0,handles[0],(uintptr_t)images[0],page)&&page_calls==calls);}
int main(int argc,char**argv)
{
    assert(argc<=2&&!posix_memalign((void**)&arena,4096,0x300000));unsigned checks=0;
    for(unsigned n=1;n<=256;n++)for(unsigned cross=0;cross<2;cross++){
        setup(n,cross);assert(start()&&first()&&second()&&ppli_finish(r,ticks+100));
        assert(r->complete&&!r->unknown&&r->next[0]==n&&r->next[1]==n&&r->own_matches==1&&r->native_issued==15&&r->native_returned==15);
        assert(page_calls==n*2*(cross?2:1)+2);checks++;
    }
    for(unsigned pass=0;pass<2;pass++)for(unsigned n=0;n<256;n++)for(unsigned bad=1;bad<=6;bad++){
        setup(256,1);assert(start());if(pass)assert(first()&&ppli_second(r,map,80,40,123,page));
        for(unsigned k=0;k<n;k++)assert(ppli_capture(r,pass,k,handles[k],(uintptr_t)images[k],page));
        fault=bad;unsigned before=page_calls;
        assert(!ppli_capture(r,pass,n,handles[n],(uintptr_t)images[n],page)&&r->unknown&&r->error&&!r->complete);
        assert(page_calls==before+1&&r->entry[n].AT[pass][0].issued==1);stopped();checks++;
    }
    /* Every retained byte of each populated entry, both maps and all fixed
     * binding inputs: a later pass cannot relabel or accept a changed prefix. */
    setup(3,1);assert(start()&&first()&&second());struct ppli_result*saved=malloc(sizeof(*r));assert(saved);memcpy(saved,r,sizeof(*r));
    size_t ranges[][2]={{0,offsetof(struct ppli_result,map)},{offsetof(struct ppli_result,entry),3*sizeof(r->entry[0])},
        {offsetof(struct ppli_result,maps),2*PPLI_MAP_CAP}};
    for(unsigned area=0;area<3;area++)for(size_t off=0;off<ranges[area][1];off+=area==2?4093:1){
        memcpy(r,saved,sizeof(*r));((uint8_t*)r)[ranges[area][0]+off]^=1;
        assert(!ppli_finish(r,ticks+100)&&r->unknown&&!r->complete);checks++;
    }
    for(unsigned pass=0;pass<2;pass++)for(unsigned bad=1;bad<=6;bad++){
        setup(3,1);if(pass)assert(start()&&first());fault=bad;
        assert(!(pass?ppli_second(r,map,80,40,123,page):start())&&r->error&&r->unknown);
        assert(r->handles_AT[pass][0].issued==1);checks++;
    }
    for(unsigned runtime=0;runtime<2;runtime++){
        setup(3,1);for(unsigned n=1;n<3;n++){images[n]->code_type=runtime?5:1;images[n]->data_type=runtime?6:2;}
        ((struct efi_memory*)map)[1].type=runtime?6:2;
        ((struct efi_memory*)map)[1].attributes=runtime?UINT64_C(0x8000000000000008):8;
        assert(start()&&first()&&second()&&ppli_finish(r,ticks+100));checks++;
    }
    for(unsigned off=0;off<offsetof(struct ppli_result,map);off++){
        setup(2,1);assert(start());mutate=1;byte=off;
        assert(!ppli_capture(r,0,0,handles[0],(uintptr_t)images[0],page)&&r->unknown);checks++;
    }
    for(unsigned field=0;field<3;field++){
        setup(3,1);assert(start()&&first()&&second());
        ((uint64_t*)&r->map[0])[field]^=1;((uint64_t*)&r->map[1])[field]^=1;
        assert(!ppli_finish(r,ticks+100)&&r->unknown);checks++;
    }
    for(unsigned bad=0;bad<18;bad++){
        setup(3,1);
        switch(bad){case 0:count=0;break;case 1:count=257;break;case 2:((struct efi_memory*)map)[0].type=7;break;
        case 3:*(uint32_t*)(arena+0x100)=1;break;case 4:r->native_flag=8;break;
        case 5:images[1]->revision=0;break;case 6:images[1]->bytes=UINT64_MAX;break;case 7:images[1]->data_type=7;break;
        case 8:images[1]->system=(void*)8;break;case 9:images[1]->base=(void*)8;break;case 10:handles[1]=handles[0];break;
        case 11:images[1]=images[0];break;case 12:images[0]->bytes=4096;break;
        case 13:((struct efi_memory*)map)[1].attributes=0x8000000000000008ULL;break;
        case 14:((struct efi_memory*)map)[1].attributes=1;break;case 15:images[1]->bytes=67108865;break;
        case 16:images[1]->code_type=0;break;case 17:images[1]->base=(void*)0x10000001;break;}
        assert(!(start()&&first()&&second()&&ppli_finish(r,ticks+100))&&r->unknown);checks++;
    }
    for(unsigned bad=0;bad<8;bad++){
        setup(3,1);assert(start()&&first());
        switch(bad){case 0:handles[2]++;break;case 1:images[2]->bytes--;break;
        case 2:((struct efi_memory*)map)[1].attributes=0x18;break;case 3:r->entry[0].AT[0][0].par^=1;break;
        case 4:*(uint32_t*)(arena+0x100)=1;break;case 5:r->map[0].key++;break;
        case 6:r->maps[0][65535]^=1;break;case 7:images[2]->unload=(void*)8;break;}
        assert(!(second()&&ppli_finish(r,ticks+100))&&r->unknown);checks++;
    }
    setup(3,1);assert(start()&&first()&&second()&&!ppli_finish(r,ticks+3840001)&&r->unknown);checks++;
    setup(3,1);assert(start()&&first()&&second()&&ppli_finish(r,ticks+100));
    if(argc==2){FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&!fclose(f));}
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"entry_bytes\":%zu,\"entry_offset\":%zu,\"maps_offset\":%zu,\"digest_offset\":%zu,\"SOFTWARE_only\":true,\"firmware_executed\":false}\n",checks,sizeof(*r),sizeof(r->entry[0]),offsetof(struct ppli_result,entry),offsetof(struct ppli_result,maps),offsetof(struct ppli_result,digest));
    free(saved);free(arena);return 0;
}

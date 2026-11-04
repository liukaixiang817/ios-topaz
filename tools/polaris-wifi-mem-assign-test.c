#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "polaris-wifi-mem-assign.h"
static struct pwma_page page;
static struct pwma_registers regs;
static struct pwma_spec spec(unsigned kind)
{
    struct pwma_spec s={.descriptor_pa=UINT64_C(0x17e000000),.region_pa=0x90001000,
        .region_bytes=0x200000,.sources=1,.destinations=2,.source={PWMA_HLOS},
        .destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
    if(kind){
        s.region_pa=0x90400000;s.region_bytes=0x100000;
        s.destination[0]=(struct pwma_destination){PWMA_MSS_MSA,PWMA_RW};
        s.destination[1]=(struct pwma_destination){PWMA_WLAN,PWMA_RW};
        if(kind==2||kind==4){s.destinations=3;s.destination[2]=(struct pwma_destination){PWMA_WLAN_CE,PWMA_RW};}
        if(kind>=3){
            s.sources=s.destinations;
            for(unsigned k=0;k<s.sources;k++)s.source[k]=s.destination[k].vmid;
            s.destinations=1;memset(s.destination,0,sizeof(s.destination));
            s.destination[0]=(struct pwma_destination){PWMA_HLOS,PWMA_RWX};
        }
    }return s;
}
static uint64_t get(const uint8_t*p,unsigned n)
{uint64_t v=0;for(unsigned k=0;k<n;k++)v|=(uint64_t)p[k]<<(8*k);return v;}
static void clear(void){memset(&page,0,sizeof(page));memset(&regs,0,sizeof(regs));}
int main(int argc,char**argv)
{
    assert(argc==1||argc==2);FILE*out=argc==2?fopen(argv[1],"wb"):NULL;if(argc==2)assert(out);
    unsigned checks=0;
    for(unsigned kind=0;kind<5;kind++){
        clear();struct pwma_spec s=spec(kind);assert(pwma_encode(&page,&regs,&s));
        assert(regs.x[0]==0x42000c16&&regs.x[1]==0x1117&&regs.x[2]==s.descriptor_pa+64&&
            regs.x[3]==16&&regs.x[4]==s.descriptor_pa&&regs.x[5]==s.descriptor_pa+256&&!regs.x[6]);
        assert(get(page.data+64,8)==s.region_pa&&get(page.data+72,8)==s.region_bytes);
        for(unsigned k=0;k<s.sources;k++)assert(get(page.data+4*k,4)==s.source[k]);
        for(unsigned k=0;k<s.destinations;k++){
            const uint8_t*d=page.data+128+24*k;
            assert(get(d,4)==s.destination[k].vmid&&get(d+4,4)==s.destination[k].permissions);
            for(unsigned n=8;n<24;n++)assert(!d[n]);
        }
        assert(get(page.data+256,8)==4*s.sources&&get(page.data+264,8)==s.descriptor_pa+128&&
            get(page.data+272,8)==24*s.destinations);
        for(unsigned n=280;n<sizeof(page);n++)assert(!page.data[n]);
        if(out)assert(fwrite(&regs,1,sizeof(regs),out)==sizeof(regs)&&fwrite(&page,1,sizeof(page),out)==sizeof(page));
        struct pwma_registers saved=regs;assert(!pwma_encode(&page,&regs,&s)&&!memcmp(&saved,&regs,sizeof(regs)));checks+=2;
    }
    for(unsigned bad=0;bad<24;bad++){
        clear();struct pwma_spec s=spec(0);
        switch(bad){
        case 0:s.descriptor_pa=0;break;case 1:s.descriptor_pa++;break;
        case 2:s.descriptor_pa=UINT64_MAX-4095;break;case 3:s.descriptor_pa=s.region_pa;break;
        case 4:s.descriptor_pa=s.region_pa+s.region_bytes-4096;break;
        case 5:s.region_pa=0;break;case 6:s.region_pa++;break;case 7:s.region_pa=0x7ffff000;break;
        case 8:s.region_pa=UINT64_C(0x100000000);break;case 9:s.region_pa=0xfffff000;break;
        case 10:s.region_bytes=0;break;case 11:s.region_bytes--;break;case 12:s.region_bytes+=4096;break;
        case 13:s.sources=0;break;case 14:s.sources=4;break;case 15:s.destinations=0;break;
        case 16:s.destinations=4;break;case 17:s.source[0]=14;break;
        case 18:s.sources=2;s.source[1]=s.source[0];break;
        case 19:s.source[2]=15;break;case 20:s.destination[0].vmid=14;break;
        case 21:s.destination[1].vmid=s.destination[0].vmid;break;
        case 22:s.destination[1].permissions=7;break;case 23:s.destination[2].permissions=6;break;
        }
        assert(!pwma_encode(&page,&regs,&s));
        for(unsigned n=0;n<sizeof(page);n++)assert(!page.data[n]);
        for(unsigned n=0;n<7;n++)assert(!regs.x[n]);checks++;
    }
    for(unsigned byte=0;byte<sizeof(page);byte++){
        clear();page.data[byte]=1;struct pwma_spec s=spec(0);assert(!pwma_encode(&page,&regs,&s));
        assert(page.data[byte]==1);for(unsigned n=0;n<7;n++)assert(!regs.x[n]);checks++;
    }
    for(unsigned reg=0;reg<7;reg++){
        clear();regs.x[reg]=1;struct pwma_spec s=spec(0);assert(!pwma_encode(&page,&regs,&s));
        assert(regs.x[reg]==1);for(unsigned n=0;n<sizeof(page);n++)assert(!page.data[n]);checks++;
    }
    clear();struct pwma_spec s=spec(0);
    assert(!pwma_encode(NULL,&regs,&s)&&!pwma_encode(&page,NULL,&s)&&!pwma_encode(&page,&regs,NULL));checks++;
    assert(!pwma_encode((void*)(page.data+1),&regs,&s));checks++;
    assert(!pwma_encode(&page,(void*)page.data,&s));checks++;
    assert(!pwma_encode(&page,&regs,(void*)page.data));checks++;
    assert(!pwma_encode(&page,&regs,(void*)&regs));checks++;
    const uint64_t responses[][2]={{0,0},{0,1},{1,0},{1,99},{UINT64_MAX,0},{(uint64_t)-12,0},{2,0}};
    for(unsigned n=0;n<sizeof(responses)/sizeof(*responses);n++){
        regs=(struct pwma_registers){{responses[n][0],responses[n][1],2,3,4,5,6}};
        struct pwma_registers saved=regs;
        assert(pwma_classify(&regs)==(n==0?PWMA_RETURN_ZERO:n==2||n==3?PWMA_RETURN_INTERRUPTED:PWMA_RETURN_UNKNOWN));
        assert(!memcmp(&regs,&saved,sizeof(regs)));checks++;
    }
    assert(pwma_classify(NULL)==PWMA_RETURN_UNKNOWN);checks++;
    if(out)assert(!fclose(out));
    printf("{\"passed\":true,\"checks\":%u,\"encoded_cases\":5,\"SMC_executed\":false,\"ownership_proven\":false}\n",checks);
}

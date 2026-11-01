/* New cache-type branch only. The historical binary is DATA, never a lease. */
#define EFI_XNU_WIFI_TERMINAL_GOP_OWN_WT 1
#define PWTG_FIXTURE_ONLY 1
#include "polaris-wifi-terminal-gop-test.c"
int main(int argc,char**argv)
{
    assert(argc==2&&!posix_memalign((void**)&self,4096,(sizeof(*self)+4095)&~(size_t)4095));
    assert(!posix_memalign((void**)&headers,4096,4096));pixels=malloc(9331200);assert(pixels);
    struct pwtg_result *historical=malloc(sizeof(*historical));assert(historical&&sizeof(*historical)==125664);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(historical,1,sizeof(*historical),f)==sizeof(*historical));
    assert(!fseek(f,0,SEEK_END)&&ftell(f)==126096&&!fclose(f));
    assert(historical->attempted==1&&historical->error==PWTG_TRANSLATION&&!historical->armed&&!historical->terminal_attempted);
    assert(historical->pages[0][0].read==UINT64_C(0xba0000009d465b80));
    assert(pwtg_at_valid(&historical->pages[0][0],0)&&!pwtg_at_valid(&historical->pages[0][0],1));unsigned checks=1;
    for(unsigned a=0;a<256;a++){
        struct pwtg_at t=historical->pages[0][0];t.read=t.write=(t.read&UINT64_C(0x00ffffffffffffff))|((uint64_t)a<<56);
        assert(pwtg_at_valid(&t,0)==(a==0xff||a==0x44||a==0xba));checks++;
        assert(pwtg_at_valid(&t,1)==(a==0xff));checks++;
    }
    for(unsigned a=0;a<3;a++){
        setup();framebuffer_attr=(unsigned[]){0xff,0x44,0xba}[a];assert(arm()&&!writes&&!cleans);terminal=1;
        for(unsigned row=0;row<PWTG_ROWS;row++)pwtg_line(&self->r,row,"V1 HOLD",1,0xba);
        assert(pwtg_draw(&self->r)&&self->r.complete&&writes==PWTG_PIXEL_WIDTH*PWTG_PIXEL_HEIGHT&&self->r.pages_written==PWTG_PAGES);checks++;
    }
    for(unsigned k=0;k<9;k++){
        struct pwtg_at t=historical->pages[0][0];
        switch(k){
        case 0:t.issued=0;break;case 1:t.returned=0;break;case 2:t.saved^=1;break;
        case 3:t.read|=1;t.write=t.read;break;case 4:t.write^=4096;break;
        case 5:t.read&=~UINT64_C(0x200);t.write=t.read;break;
        case 6:t.page+=4096;break;case 7:t.write^=UINT64_C(1)<<56;break;
        case 8:t.restored^=1;break;
        }
        assert(!pwtg_at_valid(&t,0));checks++;
    }
    setup();framebuffer_attr=0xba;assert(arm());terminal=1;fault=4;fail_at=1;
    assert(!pwtg_draw(&self->r)&&!writes&&!cleans&&!self->r.complete);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"historical0177_raw_predicate_only\":true,\"current_permission_or_physical_draw_proven\":false,\"SOFTWARE_only\":true}\n",checks);
    free(historical);free(pixels);free(headers);free(self);return 0;
}

/* Host synthetic-reader fixture. Reads only an already captured cache file as
 * input data. Target addresses are numeric constants, NEVER dereferenced. */
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void text(const char *s){(void)s;}
static void report(const char *s,uint64_t v){(void)s;(void)v;}
#include "../shim/polaris/uefi-wifi-firstread-normal-nc.h"
static struct pwfc_result witness;
static struct pwnc_result *result;
static uint8_t captured[632];
static unsigned fault,loads,translations,orders,architectures,owned_calls;
static uint64_t now;
static int system_marker;
static const uint32_t good[9]={0xc0000,1,0x434f5424,1,12,0x54525024,0x7c000,0x20,0x7c000};
static int arch(void *ctx,struct pwfc_arch *a)
{
    (void)ctx;architectures++;*a=witness.after;a->ticks=++now;
    if(fault==1)a->ttbr0++;
    if(fault==2)a->ticks=witness.after.ticks+PWNC_MAX_AGE_TICKS+1;
    if(fault==3&&loads==5)a->mair++;
    if(fault==4&&loads==5)a->ticks=witness.after.ticks;
    return 1;
}
static int owned(void *ctx,uint64_t address,uint64_t bytes)
{
    (void)ctx;owned_calls++;
    if(fault==5)return 0;
    return (address==(uintptr_t)result&&bytes==sizeof(*result))||
        (address==(uintptr_t)&witness&&bytes==sizeof(witness))||
        (address==witness.image&&bytes==PWFI_IMAGE_BYTES);
}
static int translate(void *ctx,uint64_t address,uint64_t *raw)
{
    (void)ctx;translations++;unsigned found=0;
    for(unsigned n=0;n<3;n++)found+=address==pwnc_pages[n];assert(found==1);
    *raw=address|PWNC_PAR_CLASS;
    if(fault==6)*raw=0x80b;
    if(fault==7)*raw&=~UINT64_C(0x200);
    if(fault==8)*raw|=UINT64_C(0xff)<<56;
    if(fault==9)*raw&=~(UINT64_C(0xff)<<56); /* OldDevice0 is NOT NC. */
    if(fault==10&&translations==4)*raw^=0x80;
    if(fault==11){*raw=0xdecaf;return 0;}
    if(fault==18)*raw^=UINT64_C(0x80); /* InnerShareable refuses. */
    if(fault==19)*raw&=~UINT64_C(0x180); /* Nonshareable refuses. */
    if(fault==20)*raw^=UINT64_C(0x1000); /* ForeignPA refuses. */
    if(fault==21&&translations==2){*raw=0xdecaf;return 0;}
    if(fault==22&&translations==2)*raw&=~(UINT64_C(0xff)<<56);
    if(fault==23&&translations==3)*raw&=~(UINT64_C(0xff)<<56);
    if(fault==24&&translations==3)*raw&=~UINT64_C(0x200);
    return 1;
}
static void order(void *ctx){(void)ctx;orders++;}
static int load(void *ctx,uint64_t address,uint32_t *value)
{
    (void)ctx;unsigned n=result->index,pass=result->pass;
    assert(n<9&&pass<2&&address==pwnc_addresses[n]&&result->phase==2);
    assert(result->issued[pass]&(1u<<n));assert(!(result->completed[pass]&(1u<<n)));
    assert(result->error==PWNC_OUTSTANDING);
    assert(orders>loads);loads++;*value=good[n];
    if(fault==12&&loads==4){*value=0xdeadcafe;return 0;}
    if(fault==13&&loads==1)*value=0xb0000;
    if(fault==14&&n==4)*value=21;
    if(fault==15&&n==6)*value=0x7d000;
    if(fault==16&&n==7)*value=0x21;
    if(fault==17&&pass==1&&n==4)*value=13;
    return 1;
}
static void reset(void)
{
    memset(&witness,0,sizeof(witness));memset(result,0,sizeof(*result));
    loads=translations=orders=architectures=owned_calls=0;
    witness.attempted=1;witness.owner_matches=1;witness.hash_count=4;
    witness.image=pwfi_le(captured+32,8)-0x5cb0;witness.protocol=witness.image+0x7090;
    witness.protocol_after=witness.protocol;witness.release_attempted=1;
    witness.cache_consistent=1;witness.mpss_cached=1;witness.map_key[0]=witness.map_key[1]=0x108e;
    witness.snapshot_bytes[0]=witness.snapshot_bytes[1]=632;
    memcpy(witness.snapshot[0],captured,632);memcpy(witness.snapshot[1],captured,632);
    for(unsigned n=0;n<4;n++)memcpy(witness.hashes[n],pwfi_ranges[n].sha256,32);
    witness.owner=(struct efi_loaded){.revision=0x1000,.base=(void*)(uintptr_t)witness.image,
        .bytes=PWFI_IMAGE_BYTES,.system=(void*)&system_marker,.code_type=3,.data_type=4};
    witness.smem_descriptor=(struct efi_memory){.physical=0x86000000,.pages=512,.type=0,.attributes=1};
    witness.smem_descriptor_matches=1;
    witness.before=(struct pwfc_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x13ffe8000,.tcr=0x280803518,
        .sctlr=0xc0180d,.mair=0xffbb4400,.sre=1,.group1=1,.frequency=19200000,.ticks=10000000};
    witness.after=witness.before;witness.after.ticks+=53570;witness.cookie=witness.before.ticks|1;now=witness.after.ticks;
    struct efi_loaded self={.revision=0x1000,.base=result,.bytes=4096,.system=(void*)&system_marker,.code_type=3,.data_type=4};
    assert(pwnc_bind(result,&self));assert(!pwnc_bind(result,&self));
}
static int run(unsigned enabled,unsigned stage)
{const struct pwnc_io io={0,arch,owned,translate,load,order};return pwnc_collect(enabled,stage,&witness,&io,result);}
int main(int argc,char **argv)
{
    assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(fread(captured,1,632,f)==632);assert(!fclose(f));
    assert(!posix_memalign((void**)&result,4096,4096));assert(sizeof(*result)<=4096);
    unsigned checks=0;reset();assert(run(1,2)&&result->error==0&&result->phase==4&&loads==18&&translations==12&&
        result->issued[0]==0x1ff&&result->issued[1]==0x1ff&&result->completed[0]==0x1ff&&result->completed[1]==0x1ff);checks++;
    for(unsigned pass=0;pass<2;pass++)for(unsigned after=0;after<2;after++)for(unsigned n=0;n<3;n++)
        assert(result->par[pass][after][n]==(PWNC_PAR_CLASS|pwnc_pages[n]));
    unsigned previous=loads;assert(!run(1,2)&&loads==previous);checks++;
    reset();assert(!run(0,2)&&result->error==PWNC_DISABLED&&!loads&&!translations&&!architectures&&!owned_calls);checks++;
    reset();assert(!run(1,4)&&result->error==PWNC_LIFETIME&&!loads&&!translations&&!architectures&&!owned_calls);checks++;
    for(unsigned n=1;n<=24;n++){
        fault=n;reset();assert(!run(1,2)&&result->error&&loads<=18&&translations<=12);
        if(n<=2||(n>=5&&n<=9)||n==11||n>=18)assert(!loads);
        if(n==1||n==3)assert(result->error==PWNC_ARCH);
        if(n==2||n==4)assert(result->error==PWNC_STALE);
        if(n==3||n==4)assert(loads==5&&result->completed[0]==0x1f);
        if(n==5)assert(result->error==PWNC_SELF&&!translations);
        if(n==7||n==8||n==9)assert(result->error==PWNC_ATTRIBUTES);
        if(n==10)assert(result->error==PWNC_ATTRIBUTES&&loads==9&&!result->issued[1]);
        if(n==11)assert(result->last_par==0xdecaf&&result->error==PWNC_TRANSLATION);
        if(n==12)assert(loads==4&&result->issued[0]==15&&result->completed[0]==7&&result->raw[0][3]==0xdeadcafe);
        if(n==13)assert(loads==1&&result->error==PWNC_VALUE);
        if(n==14)assert(loads==5&&result->error==PWNC_VALUE);
        if(n==15)assert(loads==7&&result->error==PWNC_VALUE);
        if(n==16)assert(loads==8&&result->error==PWNC_VALUE);
        if(n==17)assert(loads==18&&result->error==PWNC_MISMATCH);
        if(n==18||n==19||n==22||n==23||n==24)assert(result->error==PWNC_ATTRIBUTES);
        if(n==20||n==21)assert(result->error==PWNC_TRANSLATION);
        if(n==22)assert(translations==2&&result->par[0][0][0]==(PWNC_PAR_CLASS|pwnc_pages[0]));
        if(n==23||n==24)assert(translations==3&&result->par[0][0][1]==(PWNC_PAR_CLASS|pwnc_pages[1]));
        previous=loads;unsigned at=translations;assert(!run(1,2)&&loads==previous&&translations==at);checks++;
    }
    fault=0;
    for(unsigned bad=0;bad<13;bad++){
        reset();
        switch(bad){
        case 0:witness.hashes[0][0]^=1;break;
        case 1:witness.hash_count=3;break;
        case 2:witness.snapshot[1][0]^=1;break;
        case 3:witness.snapshot[0][24]=witness.snapshot[1][24]=0x66;break;
        case 4:witness.snapshot[0][20]=witness.snapshot[1][20]=1;break;
        case 5:witness.snapshot[0][99]^=1;witness.snapshot[1][99]^=1;break;
        case 6:witness.cookie++;break;
        case 7:witness.protocol_after++;break;
        case 8:witness.map_key[1]++;break;
        case 9:witness.before.mpidr=witness.after.mpidr=0x81000700;break;
        case 10:witness.smem_descriptor.attributes=8;break;
        case 11:result->self_bound=0;break;
        case 12:witness.before.mair=witness.after.mair=0xffbb0000;break;
        }
        assert(!run(1,2)&&!loads&&!translations&&result->error);checks++;
    }
    free(result);printf("{\"checks\":%u,\"synthetic_architectural_target_LDR32_positive\":18,\"NormalNC_exact44_NS_OuterShareable\":true,\"physical_bus_transaction_cap\":false,\"hardware_executed\":false,\"no_SMC_or_BS\":true,\"may_transmit\":false}\n",checks);return 0;
}

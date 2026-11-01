/* Host-only differential test against the committed pre-optimization verifier.
 * The original Core PE is DATA. No original code, AT, SMC or MMIO executes. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void text(const char *);void report(const char *,uint64_t);
#include "gcd-core-identity.h"
#include "pgci-committed-reference.h"
static uint8_t *original,*image;
static unsigned checks;
static volatile unsigned consume;
static void put64(uint8_t *p,uint64_t v){for(unsigned k=0;k<8;k++)p[k]=(uint8_t)(v>>(8*k));}
static void relocate(uint64_t base,int update_header)
{
    memcpy(image,original,PGCI_IMAGE_BYTES);
    for(unsigned k=0;k<PGCI_RELOC_COUNT;k++){unsigned at=pgci_relocations[k];put64(image+at,pwfi_le(image+at,8)+base-PGCI_ORIGINAL_BASE);}
    if(update_header)put64(image+PGCI_IMAGEBASE_RVA,base);
}
static void equal_result(const uint8_t *data,uint64_t base,uint64_t bytes,int expected)
{
    uint8_t old[5][32]={{0}},now[5][32]={{0}};unsigned of=0xabc,oc=0xdef,nf=of,nc=oc;
    int a=pgci_verify_reference(data,base,bytes,old,&of,&oc),b=pgci_verify(data,base,bytes,now,&nf,&nc);
    assert(a==b&&of==nf&&oc==nc&&!memcmp(old,now,sizeof(old)));
    if(expected>=0)assert(b==expected);checks++;
}
static int hashed(unsigned at)
{for(unsigned k=0;k<PGCI_RANGE_COUNT;k++)if(at>=pgci_ranges[k].rva&&at<pgci_ranges[k].rva+pgci_ranges[k].bytes)return 1;return 0;}
static void patch_boundaries(void)
{
    const unsigned lengths[]={16,40,64};
    for(unsigned l=0;l<3;l++)for(unsigned width=4;width<=8;width+=4)for(unsigned off=4088;off<=4168;off++){
        uint8_t guarded[80],want[80];memset(guarded,0xa5,sizeof(guarded));memcpy(want,guarded,sizeof(want));
        for(unsigned k=0;k<lengths[l];k++)if(4096+k>=off&&4096+k<off+width)want[8+k]=(uint8_t)(UINT64_C(0x1122334455667788)>>(8*(4096+k-off)));
        pgci_patch_chunk(guarded+8,4096,lengths[l],off,width,UINT64_C(0x1122334455667788));
        assert(!memcmp(want,guarded,sizeof(want)));checks++;
    }
}
static uint32_t random_word(uint32_t *x){*x^=*x<<13;*x^=*x>>17;*x^=*x<<5;return *x;}
static void compression_states(void)
{
    uint32_t seed=0x6d646367;
    for(unsigned test=0;test<514;test++){
        struct pwfi_sha256 old={0},now;uint8_t block[64];pwfi_init(&old);
        for(unsigned k=0;k<8;k++)old.h[k]=random_word(&seed);
        for(unsigned k=0;k<64;k++)block[k]=test==512?0:test==513?255:(uint8_t)random_word(&seed);
        now=old;pwfi_transform(&old,block);pgci_transform_blocks(&now,block);
        assert(!memcmp(&old,&now,sizeof(old)));checks++;
    }
}
static uint64_t nanoseconds(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
static uint64_t benchmark(int old)
{
    uint64_t begin=nanoseconds();uint8_t raw[5][32];unsigned failed,count;
    for(unsigned k=0;k<64;k++){
        __asm__ volatile(""::"r"(image):"memory");
        int ok=old?pgci_verify_reference(image,0x13b480000,PGCI_IMAGE_BYTES,raw,&failed,&count):pgci_verify(image,0x13b480000,PGCI_IMAGE_BYTES,raw,&failed,&count);
        assert(ok&&count==5&&!failed);consume+=raw[0][0]+raw[4][31];
    }return nanoseconds()-begin;
}
int main(int argc,char **argv)
{
    assert(argc==2||argc==3);original=malloc(PGCI_IMAGE_BYTES);image=malloc(PGCI_IMAGE_BYTES);assert(original&&image);
    FILE *f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&fgetc(f)==EOF&&!fclose(f));
    const uint64_t bases[]={0,0x1000,0x13b480000,0xffff000000000000ULL};
    for(unsigned b=0;b<4;b++)for(unsigned header=0;header<2;header++){relocate(bases[b],header);equal_result(image,bases[b],PGCI_IMAGE_BYTES,1);}
    for(unsigned r=0;r<PGCI_RANGE_COUNT;r++){
        const struct pgci_range *s=&pgci_ranges[r];unsigned offsets[]={s->rva,s->rva+s->bytes/2,s->rva+s->bytes-1};
        for(unsigned k=0;k<3;k++){relocate(0x13b480000,1);image[offsets[k]]^=1;equal_result(image,0x13b480000,PGCI_IMAGE_BYTES,0);}
    }
    for(unsigned r=0;r<PGCI_RELOC_COUNT;r++)for(unsigned k=0;k<8;k++){
        relocate(0x13b480000,1);unsigned at=pgci_relocations[r]+k;image[at]^=0x40;
        equal_result(image,0x13b480000,PGCI_IMAGE_BYTES,!hashed(at));
    }
    /* The hash canonicalizes CRC; the separate existing owner/table guard
     * checks zero-or-valid CRC. Hash optimization cannot change that division. */
    for(unsigned k=0;k<4;k++){relocate(0x13b480000,1);image[0x1bb28+k]^=0x80;equal_result(image,0x13b480000,PGCI_IMAGE_BYTES,1);}
    for(unsigned k=0;k<24;k++){relocate(0x13b480000,1);image[0x1bd48+k]^=0x55;equal_result(image,0x13b480000,PGCI_IMAGE_BYTES,1);}
    relocate(0x13b480000,1);put64(image+PGCI_IMAGEBASE_RVA,0xdead000);equal_result(image,0x13b480000,PGCI_IMAGE_BYTES,0);
    equal_result(0,0x13b480000,PGCI_IMAGE_BYTES,0);equal_result(image,0x13b480000,PGCI_IMAGE_BYTES-1,0);
    equal_result(image,UINT64_MAX-16,PGCI_IMAGE_BYTES,0);patch_boundaries();compression_states();
    relocate(0x13b480000,1);uint64_t old=0,now=0;if(argc==3){old=benchmark(1);now=benchmark(0);}
    printf("{\"passed\":true,\"checks\":%u,\"Core_hashes_each\":5,\"all_relocation_bytes_tested\":%u,\"host_benchmark_only\":true,\"host_old_ns\":%llu,\"host_new_ns\":%llu,\"phone_timing_proven\":false,\"original_firmware_executed\":false}\n",checks,PGCI_RELOC_COUNT*8,(unsigned long long)old,(unsigned long long)now);
    free(image);free(original);return 0;
}

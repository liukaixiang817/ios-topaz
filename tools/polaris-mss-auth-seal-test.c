/* Byte-for-byte reference equivalence and inaccessible descriptor granules.
 * No firmware, native CPU or device operation is executed by this test. */
#define PMSN_TEST_ENTRY unused_auth_main
#include "polaris-mss-auth-native-test.c"
#include <time.h>
/* Never touch any descriptor or its protection-granule tail, even after a
 * completed transition. This is also the only valid raw-state seal/export. */
static void reference_seal(const struct pmsn_state*s,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);uintptr_t a=(uintptr_t)out,b=a+bytes;
    for(size_t n=0;n<sizeof(*s);n++){
        uintptr_t p=(uintptr_t)s+n;if((p>=a&&p<b)||(n>=offsetof(struct pmsn_state,rmtfs)&&n<offsetof(struct pmsn_state,rmtfs)+8))continue;unsigned skip=0;
        for(unsigned k=0;k<PMSN_ASSIGNMENTS;k++){
            uintptr_t start=(uintptr_t)&s->assignment[k].page,end=(uintptr_t)(&s->assignment[k]+1);
            if(p>=start&&p<end){skip=1;break;}
        }
        if(!skip)pwfi_byte(&hash,*(const uint8_t*)p);
    }pwfi_final(&hash,digest);
}

static double seconds(void){struct timespec t;CHECK(!clock_gettime(CLOCK_MONOTONIC,&t));return t.tv_sec+t.tv_nsec/1e9;}
int main(void)
{
    size_t hp=(size_t)sysconf(_SC_PAGESIZE);CHECK(hp&&hp<=16384&&!(hp&(hp-1)));
    size_t length=(sizeof(struct pmsn_state)+4*hp+hp-1)&~(hp-1);
    uint8_t*mem=mmap(0,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(mem!=MAP_FAILED);
    uintptr_t at=(uintptr_t)mem+hp;at+=(-(at+offsetof(struct pmsn_state,assignment)+offsetof(struct pmsn_assignment,page)))&(hp-1);
    struct pmsn_state*s=(void*)at;CHECK(at+sizeof(*s)<(uintptr_t)mem+length);
    uint32_t rng=0x13579bdf;for(size_t n=0;n<sizeof(*s);n++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;((uint8_t*)s)[n]=(uint8_t)rng;}
    for(unsigned n=0;n<PMSN_ASSIGNMENTS;n++){CHECK(!((uintptr_t)&s->assignment[n].page&(hp-1)));CHECK(!mprotect(&s->assignment[n].page,16384,PROT_NONE));}
    unsigned cases=0;uint8_t expected[32],actual[32];
    /* All state/descriptor boundaries, zero-sized, wrapping and disjoint outputs. */
    uintptr_t boundaries[16]={at,at+sizeof(*s),(uintptr_t)&s->rmtfs,(uintptr_t)&s->rmtfs+8,0,UINTPTR_MAX-8};
    for(unsigned n=0;n<5;n++){boundaries[6+2*n]=(uintptr_t)&s->assignment[n].page;boundaries[7+2*n]=(uintptr_t)(&s->assignment[n]+1);}
    for(unsigned n=0;n<16;n++)for(unsigned width=0;width<5;width++){
        uintptr_t out=boundaries[n];size_t bytes=width==0?0:width==1?1:width==2?8:width==3?65:sizeof(*s);
        reference_seal(s,(const void*)out,bytes,expected);pmsn_seal(s,(const void*)out,bytes,actual);CHECK(!memcmp(expected,actual,32));cases++;
    }
    for(unsigned n=0;n<160;n++){
        rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;uintptr_t out=at-hp+rng%(sizeof(*s)+2*hp);
        rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;size_t bytes=rng%(sizeof(*s)+hp);
        reference_seal(s,(const void*)out,bytes,expected);pmsn_seal(s,(const void*)out,bytes,actual);CHECK(!memcmp(expected,actual,32));cases++;
    }
    /* Included control mutation must still change the seal; rmtfs remains excluded. */
    pmsn_seal(s,0,0,expected);s->attempted^=1;pmsn_seal(s,0,0,actual);CHECK(memcmp(expected,actual,32));s->attempted^=1;
    s->rmtfs^=1;pmsn_seal(s,0,0,actual);CHECK(!memcmp(expected,actual,32));s->rmtfs^=1;
    double start=seconds();for(unsigned n=0;n<100;n++)reference_seal(s,0,0,expected);double original=seconds()-start;
    start=seconds();for(unsigned n=0;n<100;n++)pmsn_seal(s,0,0,actual);double revised=seconds()-start;CHECK(!memcmp(expected,actual,32));
    printf("PASS %u auth seal reference/guarded-granule cases; state=%zu; host100 original=%.6fs spans=%.6fs ratio=%.3f; not phone timing\n",cases,sizeof(*s),original,revised,original/revised);
    CHECK(!munmap(mem,length));return 0;
}

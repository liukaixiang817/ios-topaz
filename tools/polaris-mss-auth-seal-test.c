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
    /* CPU owner coverage and all exclusion edge cases match its old seal. */
    struct pmsc_owner*owner=malloc(sizeof(*owner));CHECK(owner);
    for(size_t n=0;n<sizeof(*owner);n++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;((uint8_t*)owner)[n]=(uint8_t)rng;}
    unsigned owner_cases=0;
    uintptr_t owner_boundary[]={0,UINTPTR_MAX-8,(uintptr_t)owner,(uintptr_t)owner+sizeof(*owner),
        (uintptr_t)&owner->peer[0][0].raw,(uintptr_t)&owner->source[8],(uintptr_t)&owner->effects};
    for(unsigned n=0;n<7;n++)for(unsigned w=0;w<5;w++){
        size_t bytes=w==0?0:w==1?1:w==2?8:w==3?65:sizeof(*owner);
        pmsc_seal(owner,(void*)owner_boundary[n],bytes,expected);
        pmsn_owner_seal(owner,(void*)owner_boundary[n],bytes,actual);CHECK(!memcmp(expected,actual,32));owner_cases++;
    }
    for(unsigned n=0;n<160;n++){
        rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;uintptr_t out=(uintptr_t)owner-128+rng%(sizeof(*owner)+256);
        rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;size_t bytes=rng%(sizeof(*owner)+128);
        pmsc_seal(owner,(void*)out,bytes,expected);pmsn_owner_seal(owner,(void*)out,bytes,actual);CHECK(!memcmp(expected,actual,32));owner_cases++;
    }
    pmsn_owner_seal(owner,0,0,expected);owner->effects^=1;pmsn_owner_seal(owner,0,0,actual);CHECK(memcmp(expected,actual,32));
    /* Arbitrary chaining words catch transform errors beyond the standard IV. */
    unsigned transform_cases=0;uint8_t block[65];
    for(unsigned n=0;n<1024;n++){
        struct pwfi_sha256 ref,got;pwfi_init(&ref);
        for(unsigned j=0;j<8;j++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;ref.h[j]=rng;}
        for(unsigned j=0;j<sizeof(block);j++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;block[j]=(uint8_t)rng;}
        got=ref;pwfi_transform(&ref,block+(n&1));pmsn_hash_transform(&got,block+(n&1));CHECK(!memcmp(ref.h,got.h,sizeof(ref.h)));transform_cases++;
    }
    printf("PASS %u owner seal and %u arbitrary-chain SHA compression differential cases; owner=%zu\n",owner_cases,transform_cases,sizeof(*owner));free(owner);
    double start=seconds();for(unsigned n=0;n<100;n++)reference_seal(s,0,0,expected);double original=seconds()-start;
    start=seconds();for(unsigned n=0;n<100;n++)pmsn_seal(s,0,0,actual);double revised=seconds()-start;CHECK(!memcmp(expected,actual,32));
    printf("PASS %u auth seal reference/guarded-granule cases; state=%zu; host100 original=%.6fs spans=%.6fs ratio=%.3f; not phone timing\n",cases,sizeof(*s),original,revised,original/revised);
    CHECK(!munmap(mem,length));return 0;
}

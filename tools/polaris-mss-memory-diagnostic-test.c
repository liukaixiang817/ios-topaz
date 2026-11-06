/* Actual MSS producer supplies the maps; pure diagnostic must neither change
 * them nor turn any rejected delta into accepted ownership. SOFTWARE only. */
#define PMMN_TEST_ENTRY unused_mss_memory_suite
#include "polaris-mss-memory-test.c"
#include "uefi-mss-memory-diagnostic.h"
static struct pmme_memory baseline,probe,sealed;
static unsigned scenarios;
static struct efi_memory*at(struct pwea_map*m,uint64_t address)
{
    for(uint64_t n=0;n<m->map.bytes;n+=m->map.stride){struct efi_memory*d=(void*)(m->data+n);
        if(d->physical<=address&&address<d->physical+d->pages*4096)return d;}
    CHECK(0);return 0;
}
static struct pmmd_difference capture(unsigned reason)
{
    struct pmmd_difference d={0};sealed=probe;pmmd_capture(&probe,&d);scenarios++;
    CHECK(!memcmp(&sealed,&probe,sizeof(probe)));CHECK(d.reason==reason);return d;
}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned stride=40;stride<=48;stride+=8){
        mss_setup(0,0,stride);CHECK(mss_run());baseline=mss->memory;baseline.error=PWEA_DELTA;
        probe=baseline;CHECK(capture(9).kind==2);
        const unsigned fields[]={0,4,16,32,40};
        for(unsigned n=0;n<5;n++){
            unsigned byte=fields[n];if(byte>=stride)continue;probe=baseline;probe.map[3].data[byte]^=1;
            struct pmmd_difference d=capture(6);CHECK(d.byte==byte&&d.direction==0&&d.kind==2&&d.old_index==0&&d.new_index==0);
            CHECK(d.address==(uintptr_t)arena);CHECK((d.old_word^d.new_word)==1);
            CHECK(!pmme_delta(&probe,2,&probe.map[2],&probe.map[3]));
        }
        probe=baseline;((struct efi_memory*)probe.map[3].data)->physical+=4096;CHECK(capture(7).direction==0);
        probe=baseline;((struct efi_memory*)probe.map[3].data)->pages++;CHECK(capture(7).direction==1);
        probe=baseline;probe.map[3].map.key=probe.map[2].map.key;capture(3);
        probe=baseline;probe.map[3].map.bytes=PGCD_MAP_CAP+1;capture(3);
        probe=baseline;probe.map[3].map.stride=0;capture(3);
        probe=baseline;probe.map[3].map.valid=0;capture(3);
        probe=baseline;at(&probe.map[2],probe.claim[2].requested)->type=2;capture(4);
        probe=baseline;at(&probe.map[3],probe.claim[2].requested)->type=7;capture(5);
        probe=baseline;probe.claim[2].status=1;capture(2);
        probe=baseline;probe.claim[2].returned_address+=4096;capture(2);
        probe=baseline;probe.claim[0].retained=0;CHECK(capture(8).old_index==0);
        probe=baseline;probe.command.index=PMME_MAPS;capture(1);
        probe=baseline;probe.command.operation=PWEA_ALLOCATE;capture(1);
        probe=baseline;probe.calls=1;capture(1);
    }
    free(original);free(arena);printf("PASS %u MSS map diagnostic checks / %u scenarios; SOFTWARE maps only\n",checks,scenarios);return 0;
}

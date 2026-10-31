/* Execute CmdDb public-ABI queries -> ARC index selection -> bounded two-
 * request transaction -> restored votes/registers. SOFTWARE peers only;
 * this does not implement/certify the physical ownership/critical section. */
#define POLARIS_CMDDB_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-test.c"
#include "polaris-wifi-rsc-transaction.h"
static struct pwrsc_transaction transaction;
static uint32_t hardware[0x3000/4],initial[0x3000/4],actual_votes[3];
static unsigned pending_tcs,requests,acknowledgements;
static int combined_clock(void *ctx,uint64_t *ticks,uint64_t *frequency)
{struct paic_arch a;if(!cd_arch(ctx,&a))return 0;*ticks=a.ticks;*frequency=a.frequency;return 1;}
static int combined_read(void *ctx,uint64_t at,uint32_t *v)
{
    (void)ctx;assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(hardware));
    *v=hardware[(at-PWRSC_BASE)/4];return 1;
}
static int combined_write(void *ctx,uint64_t at,uint32_t v)
{
    (void)ctx;assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(hardware));unsigned o=(unsigned)(at-PWRSC_BASE);
    assert(o!=0&&transaction.outstanding);
    if(o==8){
        assert(v==(1u<<pending_tcs)&&transaction.completed==acknowledgements+1);
        hardware[1]&=~v;acknowledgements++;return 1;
    }
    hardware[o/4]=v;
    if(o%PWRSC_STRIDE==0x14&&(v&PWRSC_TRIGGER)){
        pending_tcs=o/PWRSC_STRIDE;requests++;unsigned t=PWRSC_STRIDE*pending_tcs;
        for(unsigned k=0;k<3;k++){
            unsigned resource=requests==1?k:2-k;
            assert(hardware[(t+0x34+20*k)/4]==cd->resources[1][resource].address);
            actual_votes[resource]=hardware[(t+0x38+20*k)/4];
            hardware[(t+0x3c+20*k)/4]=PWRSC_DONE;
        }
        hardware[1]|=1u<<pending_tcs;hardware[(t+0x14)/4]&=~PWRSC_TRIGGER;
    }
    return 1;
}
int main(int argc,char **argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);cd_original=malloc(PWCDI_IMAGE_BYTES);assert(original&&cd_original);
    FILE *f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");assert(f&&fread(cd_original,1,PWCDI_IMAGE_BYTES,f)==PWCDI_IMAGE_BYTES&&!fclose(f));
    struct pwcd_io queries=cd_reset(0);assert(pwcd_collect(&queries,enumeration,c,cd,work)&&cd->stable&&api_calls==6);
    uint32_t desired_indices[3];for(unsigned k=0;k<3;k++)desired_indices[k]=cd->resources[1][k].index;
    assert(desired_indices[0]==7&&desired_indices[1]==4&&desired_indices[2]==7);
    /* Saved vote values are explicit SOFTWARE cache fixtures. No absent
     * live resource is interpreted as zero or as a physical baseline. */
    const uint32_t saved_indices[3]={8,2,1};memcpy(actual_votes,saved_indices,sizeof(actual_votes));
    hardware[0]=0xff;
    for(unsigned k=0;k<8;k++){
        unsigned t=PWRSC_STRIDE*k;hardware[(t+0x18)/4]=1;hardware[(t+0x10)/4]=0x100;
        for(unsigned j=0;j<3;j++)for(unsigned q=0;q<3;q++)hardware[(t+0x30+20*j+4*q)/4]=0xabc000+j*0x10+q;
    }
    hardware[0x1c/4]=1; /* TCS0 unavailable; dynamically choose TCS2 in mask5 */
    memcpy(initial,hardware,sizeof(initial));
    const struct pwrsc_io io={0,combined_read,combined_write,combined_clock,order};
    assert(pwrsc_begin(&io,&transaction,5,saved_indices,desired_indices)&&transaction.tcs==2);
    int result=0;for(unsigned i=0;i<12&&!result;i++)result=pwrsc_step(&io,&transaction);
    assert(result==1&&transaction.restored&&pwrsc_retired(&transaction)&&!transaction.unknown&&!transaction.outstanding&&requests==2&&acknowledgements==2);
    assert(!memcmp(actual_votes,saved_indices,sizeof(actual_votes)));
    unsigned t=PWRSC_STRIDE*transaction.tcs;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)assert(hardware[(t+0x30+20*k+4*j)/4]==initial[(t+0x30+20*k+4*j)/4]);
    assert(hardware[(t+0x10)/4]==initial[(t+0x10)/4]&&hardware[0]==initial[0]&&!hardware[1]);
    assert(pwrph_context_ready(c)&&ticket->spent==1&&r->phase==1&&!r->pre_mask&&!r->outstanding);
    assert(!memcmp(db,cd->database_raw[1],sizeof(db)));
    printf("{\"checks\":1,\"SOFTWARE_CmdDb_to_RSC_integration\":true,\"API_queries\":%u,\"requests\":%u,\"acks\":%u,\"saved_vote_restore\":true,\"physical_lease_established\":false,\"parent_registered\":false,\"hardware_MMIO_executed\":false,\"radio\":false}\n",api_calls,requests,acknowledgements);
    free(cd_original);free(original);free(arena);return 0;
}

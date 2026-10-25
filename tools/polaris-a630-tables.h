/* A630 legacy HFI tables. Derived from the original polaris SDM845v2 DT,
 * GPUCC voltage/frequency maps and cmdDB, checked against MiCode c7cb50c1
 * kgsl_gmu.c, kgsl_hfi.h and msm_bus_{arb,fabric}_rpmh.c. No MMIO here.
 *
 * Each bus path is independently resolved on polaris. CNOC is SH2/SN15/SN3,
 * not the single CN0 resource of newer reference devices. Commands are in
 * ascending VCD order; completion is requested at the end of each domain.
 * Wait masks index COMMANDS, not bandwidth levels (old vendor BIT(i) typo).
 * Duplicate MX level16 entries are retained, keeping native index identities.
 */
#ifndef POLARIS_A630_TABLES_H
#define POLARIS_A630_TABLES_H
#include "polaris-a630-hfi.h"
#define A630_PERF_WORDS 43u
#define A630_BW_WORDS 160u
#define A630_NATIVE_PERF_INDEX 1u
#define A630_NATIVE_BUS_INDEX 4u
static inline bool a630_hfi_tables(uint32_t *perf,uint32_t *bw,
    unsigned perf_sequence,unsigned bw_sequence)
{
    if(!perf||!bw||perf_sequence>4095||bw_sequence>4095)return false;
    /* Ascending native power levels; votes = VLVL<<16 | MXidx<<8 | railidx.
     * Original raw regulator levels are encoded minus the OPP offset1. */
    static const uint32_t gx[][2]={
        {0,0},{0x00400303,257000},{0x00800304,342000},
        {0x00c00305,414000},{0x01000306,520000},
        {0x01400407,596000},{0x01800408,675000},{0x01a00409,710000}
    };
    static const uint32_t cx[][2]={
        {0,0},{0x00300302,200000},{0x00800304,500000}
    };
    static const uint32_t ib_kbps[]={0,400000,600000,800000,1200000,
        1648000,2188000,2724000,3072000,4068000,5184000,6220000,7216000};
    __builtin_memset(perf,0,A630_PERF_WORDS*4);
    __builtin_memset(bw,0,A630_BW_WORDS*4);
    a630_hfi_header(4,A630_PERF_WORDS,0,perf_sequence,&perf[0]);
    perf[1]=8;perf[2]=3;
    for(unsigned i=0;i<8;i++){perf[3+i*2]=gx[i][0];perf[4+i*2]=gx[i][1];}
    for(unsigned i=0;i<3;i++){perf[35+i*2]=cx[i][0];perf[36+i*2]=cx[i][1];}
    a630_hfi_header(3,A630_BW_WORDS,0,bw_sequence,&bw[0]);
    bw[1]=13;bw[2]=3;bw[3]=3;bw[4]=5;bw[5]=7;
    /* CNOC path: VCD1 SH2; VCD3 SN15 then SN3, commit only on SN3. */
    bw[6]=0x50034;bw[7]=0x5007c;bw[8]=0x5004c;
    bw[12]=0x40000000;bw[13]=0;bw[14]=0x40000000;
    /* Native100KB/s: positive sub-unit requests round up to one. */
    bw[18]=0x60000001;bw[19]=0x20000001;bw[20]=0x60000001;
    /* DDR path: VCD0 MC0, VCD1 SH0, VCD11 ACV. Each commits. */
    bw[24]=0x50000;bw[25]=0x5003c;bw[26]=0x5000c;
    for(unsigned i=0;i<13;i++){
        uint32_t ib=ib_kbps[i];
        /* Exact native two-stage division: IB*width/buswidth/unit.
         * MC0 16/4/2000000; SH0 64/16/4000000. AB is zero. */
        uint32_t mc=ib/500,sh=ib/1000;
        if(mc>0x3fff||sh>0x3fff)return false;
        uint32_t valid=ib?0x20000000:0;
        bw[32+i*8]=0x40000000|valid|mc;
        bw[33+i*8]=0x40000000|valid|sh;
        /* Original apps-RSC ACV mask8, derived from the path's MC vote. */
        bw[34+i*8]=0x40000000|valid|(ib?8:0);
    }
    return true;
}
#endif

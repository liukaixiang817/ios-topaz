/* Own Polaris TSENS0: DT TM0xc263000/0x1ff, gold sensors7..10,
 * GPU sensors11..12. Pinned MiCode c7cb50c1 tsens2xxx.c: status0xa0+4*ID,
 * valid bit21, signed12-bit temperatures in100millidegreesC.
 * Pure bounded READ callbacks only; no mapping, enabling, IRQ/threshold or
 * performance writes. A local observation timestamp is not sensor freshness.
 * This component alone never authorizes removing the existing30s/10s policy.
 */
#ifndef POLARIS_TSENS_READONLY_H
#define POLARIS_TSENS_READONLY_H
#include <stdint.h>
#include <stdbool.h>
struct polaris_tsens_io {
    void *context;
    bool (*read)(void *,uint32_t,uint32_t *);
    uint64_t (*now_us)(void *);
};
struct polaris_tsens_sample {
    uint32_t raw[2][6];
    int32_t temperature_mC[6],max_gold_mC,max_gpu_mC;
    uint64_t began_us,ended_us;
};
enum { PTS_OK=0,PTS_ARGUMENT,PTS_TIME,PTS_READ,PTS_VALID,
       PTS_RANGE,PTS_CRITICAL,PTS_CHANGED_TOO_FAST };
static inline unsigned polaris_tsens_decode(uint32_t raw,int32_t *mC)
{
    if(!mC)return PTS_ARGUMENT;
    if(!(raw&(1u<<21)))return PTS_VALID;
    int32_t code=(int32_t)(raw&0xfff);
    if(code&0x800)code-=4096;
    int32_t value=code*100;
    if(value < -40000 || value > 150000)return PTS_RANGE;
    if(raw&(1u<<19))return PTS_CRITICAL;
    *mC=value;return PTS_OK;
}
static inline unsigned polaris_tsens_observe(const struct polaris_tsens_io *io,
    struct polaris_tsens_sample *out)
{
    if(!io||!io->read||!io->now_us||!out)return PTS_ARGUMENT;
    struct polaris_tsens_sample sample={0};
    sample.began_us=io->now_us(io->context);
    if(!sample.began_us)return PTS_TIME;
    int32_t first[6]={0};
    for(unsigned pass=0;pass<2;pass++)for(unsigned n=0;n<6;n++) {
        uint32_t raw=0;int32_t value=0;
        if(!io->read(io->context,0xa0+(7+n)*4,&raw))return PTS_READ;
        unsigned error=polaris_tsens_decode(raw,&value);
        if(error)return error;
        sample.raw[pass][n]=raw;
        if(!pass)first[n]=value;
        else {
            int32_t delta=value-first[n];
            if(delta < -2000 || delta > 2000)return PTS_CHANGED_TOO_FAST;
            sample.temperature_mC[n]=value>first[n]?value:first[n];
        }
    }
    sample.ended_us=io->now_us(io->context);
    if(sample.ended_us<sample.began_us || sample.ended_us-sample.began_us>1000)
        return PTS_TIME;
    sample.max_gold_mC=sample.temperature_mC[0];
    sample.max_gpu_mC=sample.temperature_mC[4];
    for(unsigned n=1;n<4;n++)if(sample.temperature_mC[n]>sample.max_gold_mC)
        sample.max_gold_mC=sample.temperature_mC[n];
    if(sample.temperature_mC[5]>sample.max_gpu_mC)
        sample.max_gpu_mC=sample.temperature_mC[5];
    *out=sample;return PTS_OK;
}
#endif

/* Default-OFF experiment for inconsistent, but individually VALID, TSENS
 * words. This is an independent conservative estimator, not an OEM algorithm
 * or a sensor-freshness proof. Never majority-vote away a hotter observation.
 *
 * Keep the ordinary two-pass result byte-identical when it agrees. Only a
 * >2000mC disagreement permits up to TWO extra reads of that SAME status.
 * Accept two actual observed words within2000mC only when they include the
 * hottest VALID word seen for that sensor. Critical/range/read/clock failures
 * refuse immediately. The complete observation must still fit1000us.
 * At most24 logical status reads /72 physical reads; no writes or delays.
 * Sample output commits only on complete success. Audit is diagnostic-only
 * on both success and failure and MUST NOT authorize a performance request.
 */
#ifndef POLARIS_TSENS_PAIR_WITNESS_H
#define POLARIS_TSENS_PAIR_WITNESS_H
#include "polaris-tsens-readonly.h"
struct polaris_tsens_pair_audit {
    uint64_t began_us,ended_us;
    uint32_t raw[6][4],count[6],selected[6][2];
    uint32_t physical_reads,logical_reads,retry_mask,disagreement_mask,repaired_mask;
    uint32_t failed_offset,last_raw,error;
};
static inline unsigned polaris_tsens_pair_failure(const struct polaris_tsens_io *io,
    struct polaris_tsens_pair_audit *audit,unsigned error,
    struct polaris_tsens_pair_audit *out)
{
    audit->ended_us=io->now_us(io->context);
    audit->error=error;*out=*audit;return error;
}
static inline unsigned polaris_tsens_pair_read(const struct polaris_tsens_io *io,
    struct polaris_tsens_pair_audit *audit,unsigned sensor,uint32_t *raw)
{
    if(sensor>=6 || audit->logical_reads>=24 || audit->physical_reads>=72)
        return PTS_ARGUMENT;
    uint32_t slot=audit->logical_reads++,offset=0xbc+4*sensor;
    audit->failed_offset=offset;
    for(unsigned attempt=0;attempt<3;attempt++) {
        uint32_t word=0;int32_t value=0;
        audit->physical_reads++;
        if(!io->read(io->context,offset,&word))return PTS_READ;
        audit->last_raw=word;
        if(word&(1u<<19))return PTS_CRITICAL; /* even when VALID is clear */
        unsigned error=polaris_tsens_decode(word,&value);
        if(!error){*raw=word;return PTS_OK;}
        if(error!=PTS_VALID)return error;
        audit->retry_mask|=1u<<slot;
    }
    return PTS_VALID;
}
static inline bool polaris_tsens_pair_choose(const uint32_t *raw,unsigned count,
    uint32_t *first,uint32_t *second,int32_t *maximum)
{
    if(!raw || count<2 || count>4 || !first || !second || !maximum)return false;
    int32_t value[4]={0};unsigned peak=0;
    for(unsigned i=0;i<count;i++) {
        if(polaris_tsens_decode(raw[i],&value[i]))return false;
        if(value[i]>value[peak])peak=i;
    }
    /* Prefer the latest corroborating word; preserve actual read order. */
    for(unsigned i=count;i-->0;)if(i!=peak && value[peak]-value[i]<=2000) {
        *first=peak<i?peak:i;*second=peak<i?i:peak;
        *maximum=value[peak];return true;
    }
    return false;
}
static inline unsigned polaris_tsens_observe_pair_witness(
    const struct polaris_tsens_io *io,struct polaris_tsens_sample *out,
    struct polaris_tsens_pair_audit *evidence)
{
    if(!io || !io->read || !io->now_us || !out || !evidence)return PTS_ARGUMENT;
    struct polaris_tsens_sample sample={0};
    struct polaris_tsens_pair_audit audit={0};
    audit.began_us=io->now_us(io->context);sample.began_us=audit.began_us;
    if(!audit.began_us){audit.error=PTS_TIME;*evidence=audit;return PTS_TIME;}
    for(unsigned n=0;n<6;n++) {
        unsigned error=polaris_tsens_pair_read(io,&audit,n,&audit.raw[n][0]);
        if(error)return polaris_tsens_pair_failure(io,&audit,error,evidence);
        audit.count[n]=1;
    }
    for(unsigned n=0;n<6;n++) {
        unsigned error=polaris_tsens_pair_read(io,&audit,n,&audit.raw[n][1]);
        if(error)return polaris_tsens_pair_failure(io,&audit,error,evidence);
        audit.count[n]=2;
        uint32_t a=0,b=0;int32_t maximum=0;
        bool matched=polaris_tsens_pair_choose(audit.raw[n],2,&a,&b,&maximum);
        if(!matched) {
            audit.disagreement_mask|=1u<<n;
            for(unsigned extra=0;extra<2 && !matched;extra++) {
                unsigned slot=audit.count[n];
                error=polaris_tsens_pair_read(io,&audit,n,&audit.raw[n][slot]);
                if(error)return polaris_tsens_pair_failure(io,&audit,error,evidence);
                audit.count[n]++;
                matched=polaris_tsens_pair_choose(audit.raw[n],audit.count[n],&a,&b,&maximum);
            }
            if(!matched)return polaris_tsens_pair_failure(io,&audit,PTS_CHANGED_TOO_FAST,evidence);
            audit.repaired_mask|=1u<<n;
        }
        audit.selected[n][0]=a;audit.selected[n][1]=b;
        sample.raw[0][n]=audit.raw[n][a];sample.raw[1][n]=audit.raw[n][b];
        sample.temperature_mC[n]=maximum;
    }
    audit.ended_us=io->now_us(io->context);sample.ended_us=audit.ended_us;
    if(audit.ended_us<audit.began_us || audit.ended_us-audit.began_us>1000) {
        audit.error=PTS_TIME;*evidence=audit;return PTS_TIME;
    }
    sample.max_gold_mC=sample.temperature_mC[0];
    sample.max_gpu_mC=sample.temperature_mC[4];
    for(unsigned n=1;n<4;n++)if(sample.temperature_mC[n]>sample.max_gold_mC)
        sample.max_gold_mC=sample.temperature_mC[n];
    if(sample.temperature_mC[5]>sample.max_gpu_mC)sample.max_gpu_mC=sample.temperature_mC[5];
    *out=sample;*evidence=audit;return PTS_OK;
}
#endif

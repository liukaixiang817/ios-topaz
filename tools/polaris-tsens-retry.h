/* Own tsens2xxx_get_temp re-reads a status register up to three times when
 * VALID is clear. Keep that bounded read sequence, but never use its final
 * invalid-code/majority fallback for performance admission. Every accepted
 * word must be VALID; all original two-pass/delta/time checks still apply.
 * This pure adapter adds no mapping, register writes, delay or policy change.
 */
#ifndef POLARIS_TSENS_RETRY_H
#define POLARIS_TSENS_RETRY_H
#include "polaris-tsens-readonly.h"
struct polaris_tsens_retry_evidence { uint32_t reads,retry_mask; };
struct polaris_tsens_retry_context {
    const struct polaris_tsens_io *source;
    struct polaris_tsens_retry_evidence evidence;
    uint32_t logical_reads,error;
};
static inline bool polaris_tsens_retry_read(void *context,uint32_t offset,
    uint32_t *out)
{
    struct polaris_tsens_retry_context *s=(struct polaris_tsens_retry_context *)context;
    if(!s || !out || s->logical_reads>=12 ||
       offset!=0xbc+(s->logical_reads%6)*4) {
        if(s)s->error=PTS_ARGUMENT;
        return false;
    }
    unsigned slot=s->logical_reads++;
    for(unsigned attempt=0;attempt<3;attempt++) {
        uint32_t raw=0;int32_t value=0;
        s->evidence.reads++;
        if(!s->source->read(s->source->context,offset,&raw)) {
            s->error=PTS_READ;return false;
        }
        /* A critical indication is never hidden by retries, even if VALID
         * is simultaneously clear. Never synthesize a valid temperature. */
        if(raw&(1u<<19)){s->error=PTS_CRITICAL;return false;}
        unsigned error=polaris_tsens_decode(raw,&value);
        if(!error){*out=raw;return true;}
        if(error!=PTS_VALID){s->error=error;return false;}
        s->evidence.retry_mask|=1u<<slot;
    }
    s->error=PTS_VALID;return false;
}
static inline uint64_t polaris_tsens_retry_now(void *context)
{
    struct polaris_tsens_retry_context *s=(struct polaris_tsens_retry_context *)context;
    return s->source->now_us(s->source->context);
}
static inline unsigned polaris_tsens_observe_retry(
    const struct polaris_tsens_io *io,struct polaris_tsens_sample *out,
    struct polaris_tsens_retry_evidence *evidence)
{
    if(!io || !io->read || !io->now_us || !out || !evidence)return PTS_ARGUMENT;
    struct polaris_tsens_retry_context state={0};state.source=io;
    const struct polaris_tsens_io bounded={&state,polaris_tsens_retry_read,
        polaris_tsens_retry_now};
    struct polaris_tsens_sample sample={0};
    unsigned error=polaris_tsens_observe(&bounded,&sample);
    if(error)return state.error?state.error:error;
    if(state.logical_reads!=12 || state.evidence.reads<12 ||
       state.evidence.reads>36)return PTS_ARGUMENT;
    *out=sample;*evidence=state.evidence;return PTS_OK;
}
#endif

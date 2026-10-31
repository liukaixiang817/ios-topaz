/* Exact own MiCode c7cb50c1 scm_is_call_available(IO,READ) protocol, not IO_READ.
 * Value parameters only. No firmware buffer, address, permission or radio call.
 * Native source supplies the real SMC backend; host fixtures never execute it. */
#ifndef POLARIS_WIFI_SCM_INFO_H
#define POLARIS_WIFI_SCM_INFO_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define PWI_INFO_FN UINT64_C(0x42000601) /* non-fast, SMC64, SIP INFO command1 */
#define PWI_ARGINFO UINT64_C(1)        /* SCM_ARGS(1), one plain value */
#define PWI_TARGET_FN UINT64_C(0x02000501) /* own SCM_SIP_FNID(IO,READ), no64/fast */
#define PWI_MAX_CALLS 4u
#define PWI_TICK_BUDGET UINT64_C(384000) /*20ms at verified19.2MHz */
enum pwi_error {PWI_OK,PWI_GATE,PWI_CLOCK,PWI_TRANSPORT,PWI_RESULT,PWI_RESUME_LIMIT,PWI_DEADLINE};
struct pwi_round {uint64_t before,after,raw[7];};
struct pwi_report {
    uint32_t error,calls;
    bool issued,complete,available;
    uint64_t begin,end;
    struct pwi_round rounds[PWI_MAX_CALLS];
};
struct pwi_io {
    void *context;
    bool (*ready)(void *);
    uint64_t (*counter)(void *);
    void (*invoke)(void *,uint64_t [7]);
};
/* One logical INFO query. x0==1 resumes the SAME request with x1..x6 exactly
 * preserved (x6 is the secure resume context). No EBUSY retry/SMC32/fastcall
 * fallback/new INFO submission. Budget bounds returned protocol steps, not a
 * firmware call that never returns; this architectural limit is not hidden. */
static inline void polaris_wifi_scm_info_query(const struct pwi_io *io,struct pwi_report *r)
{
    if(!r)return;
    uint8_t *zero=(uint8_t *)r;for(size_t i=0;i<sizeof(*r);i++)zero[i]=0;
    r->error=PWI_GATE;
    if(!io||!io->ready||!io->counter||!io->invoke||!io->ready(io->context))return;
    uint64_t raw[7]={PWI_INFO_FN,PWI_ARGINFO,PWI_TARGET_FN,0,0,0,0};
    uint64_t begin=io->counter(io->context),last=begin;
    if(!begin){r->error=PWI_CLOCK;return;}
    r->begin=begin;
    for(unsigned i=0;i<PWI_MAX_CALLS;i++) {
        if(!io->ready(io->context)){r->error=PWI_GATE;return;}
        uint64_t before=io->counter(io->context);
        if(before<last){r->error=PWI_CLOCK;return;}
        if(before-begin>PWI_TICK_BUDGET){r->error=PWI_DEADLINE;return;}
        r->rounds[i].before=before;r->issued=true;
        io->invoke(io->context,raw);
        uint64_t after=io->counter(io->context);r->end=after;
        r->rounds[i].after=after;r->calls=i+1;
        for(unsigned n=0;n<7;n++)r->rounds[i].raw[n]=raw[n];
        if(after<before){r->error=PWI_CLOCK;return;}
        if(after-begin>PWI_TICK_BUDGET){r->error=PWI_DEADLINE;return;}
        last=after;
        if(raw[0]==1)continue;
        if(raw[0]){r->error=PWI_TRANSPORT;return;}
        if(raw[1]>1){r->error=PWI_RESULT;return;}
        r->complete=true;r->available=raw[1]==1;r->error=PWI_OK;return;
    }
    r->error=PWI_RESUME_LIMIT;
}
#endif

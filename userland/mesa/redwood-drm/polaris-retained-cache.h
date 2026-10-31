/* A bounded cache of a fact already returned by the SAME native GPU client.
 * No object is created, freed, mapped, submitted or declared GPU-complete here.
 * Mi8's repeated-MADVISE optimization motivated this narrower implementation:
 * a new/closed/imported object starts a new generation, and unknown handles
 * always obtain their first WILLNEED answer from the native driver.
 */
#ifndef POLARIS_RETAINED_CACHE_H
#define POLARIS_RETAINED_CACHE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PDRC_CAPACITY 256u
#define PDRC_MADVISE 0x48u
#define PDRC_WILLNEED 0u
struct pdrc_state {
    uint64_t generation,epoch,owner,connection,hits,native_queries,full,inflight;
    uint32_t handles[PDRC_CAPACITY];
    uint32_t count;
    bool enabled,failed;
};
struct pdrc_madvise {uint32_t handle,madv,retained;};
struct pdrc_ticket {
    uint64_t generation,epoch,owner,connection;
    uint32_t handle;
    bool tracked,learn,mutating;
};
static inline void pdrc_clear(struct pdrc_state *s)
{
    s->count=0;
    if(s->generation==UINT64_MAX){s->enabled=false;s->failed=true;}
    else s->generation++;
}
static inline void pdrc_failed(struct pdrc_state *s)
{pdrc_clear(s);s->failed=true;s->enabled=false;}
static inline void pdrc_connect(struct pdrc_state *s,uint64_t owner,
    uint64_t connection,bool eligible)
{
    /* A connection is the only explicit new lifetime. An error in an existing
     * lifetime is never cleared by a successful query or a cache miss. */
    uint64_t inflight=s->inflight,generation=s->generation,epoch=s->epoch;
    memset(s,0,sizeof(*s));s->inflight=inflight;s->generation=generation;
    if(epoch==UINT64_MAX)s->failed=true;
    else s->epoch=epoch+1;
    pdrc_clear(s);s->owner=owner;s->connection=connection;
    s->enabled=eligible&&owner&&connection;
    if(s->failed)s->enabled=false;
}
static inline bool pdrc_owner(struct pdrc_state *s,uint64_t owner,uint64_t connection)
{
    if(s->owner!=owner||s->connection!=connection){pdrc_failed(s);return false;}
    return s->enabled&&!s->failed;
}
static inline bool pdrc_known(const struct pdrc_state *s,uint32_t handle)
{
    if(!handle)return false;
    for(uint32_t n=0;n<s->count;n++)if(s->handles[n]==handle)return true;
    return false;
}
static inline bool pdrc_willneed(unsigned number,const void *data,size_t size,
    struct pdrc_madvise *request)
{
    if(number!=PDRC_MADVISE||!data||size!=sizeof(*request))return false;
    memcpy(request,data,sizeof(*request));
    return request->handle&&request->madv==PDRC_WILLNEED;
}
static inline bool pdrc_before(struct pdrc_state *s,uint64_t owner,
    uint64_t connection,unsigned number,void *data,size_t size,struct pdrc_ticket *ticket)
{
    memset(ticket,0,sizeof(*ticket));
    bool eligible=pdrc_owner(s,owner,connection);
    struct pdrc_madvise request;
    bool willneed=eligible&&pdrc_willneed(number,data,size,&request);
    if(willneed) {
        if(!s->inflight&&pdrc_known(s,request.handle)) {
            if(s->hits==UINT64_MAX){pdrc_failed(s);return false;}
            request.retained=1;memcpy(data,&request,sizeof(request));s->hits++;return true;
        }
        if(s->native_queries==UINT64_MAX)pdrc_failed(s);
        else s->native_queries++;
    }
    if(eligible&&!willneed)switch(number) {
    /* Exactly the existing lifetime-neutral native request selectors. They
     * still reach IOKit, including every submit, CPU preparation and fence. */
    case 0x40: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: case 0x4a:
        break;
    default:
        /* NEW(42), CLOSE(09), surface import/describe(7e), DONTNEED(48),
         * malformed MADVISE and every unknown operation invalidate BEFORE
         * the native request, even when that request subsequently fails. */
        pdrc_clear(s);ticket->mutating=true;break;
    }
    if(s->inflight==UINT64_MAX){pdrc_failed(s);return false;}
    ticket->tracked=true;ticket->generation=s->generation;
    ticket->epoch=s->epoch;
    ticket->owner=owner;ticket->connection=connection;
    ticket->learn=willneed;ticket->handle=willneed?request.handle:0;
    s->inflight++;return false;
}
static inline void pdrc_after(struct pdrc_state *s,uint64_t owner,
    uint64_t connection,unsigned number,const void *data,size_t size,
    int native_result,size_t returned,const struct pdrc_ticket *ticket)
{
    if(!ticket->tracked)return;
    if(!s->inflight){pdrc_failed(s);return;}
    s->inflight--;
    if(ticket->owner!=owner||ticket->connection!=connection||
       ticket->owner!=s->owner||ticket->connection!=s->connection||ticket->epoch!=s->epoch)return;
    if(!pdrc_owner(s,owner,connection))return;
    /* A query that overlapped an in-flight CLOSE may have received its answer
     * before the native CLOSE removed that object. Invalidate on BOTH sides
     * of a lifetime operation, so that answer cannot escape after completion. */
    if(ticket->mutating)pdrc_clear(s);
    if(native_result||returned!=size){pdrc_failed(s);return;}
    if(ticket->generation!=s->generation||!ticket->learn)return;
    struct pdrc_madvise request;
    if(!pdrc_willneed(number,data,size,&request)||request.handle!=ticket->handle) {
        pdrc_failed(s);return;
    }
    if(request.retained!=1)return;
    if(pdrc_known(s,request.handle))return;
    if(s->count==PDRC_CAPACITY) {
        if(s->full!=UINT64_MAX)s->full++;
        return; /* A full table is an ordinary native-query path, not success. */
    }
    s->handles[s->count++]=request.handle;
}
#endif

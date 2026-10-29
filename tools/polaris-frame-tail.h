/* Default-off EAGL wall-time diagnostics. No GPU/DMA/clock control.
 * A sample closes only at the NEXT real frame begin in the SAME context.
 * Ended->wrapper-returned is library tail; returned->next begin also includes
 * caller GL setup and scheduling, NOT a measurement of pure compositor wait.
 * Diagnostic output cost belongs to the next closed sample; never subtract it.
 */
#ifndef POLARIS_FRAME_TAIL_H
#define POLARIS_FRAME_TAIL_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define PGPU_TAIL_WINDOW 64u
#define PGPU_TAIL_ACTIVE_PERIOD_US 100000u
enum { PGT_OK, PGT_ARGUMENT, PGT_CLOCK, PGT_SEQUENCE, PGT_OVERFLOW, PGT_PARTS };
struct pgpu_tail_window {
    uint64_t from_us,end_us,gap,tail,outside,render,log,observer,report;
    uint64_t active_gap,active_tail,active_outside,active_render;
    uint64_t active_log,active_observer,active_report;
    uint64_t max_gap,max_tail,max_observer;
    uint64_t api,active_api,calls,active_calls,max_api;
    uint32_t frames,active,over_budget,first,last;
};
struct pgpu_frame_tail {
    struct pgpu_tail_window window;
    uint64_t began,ended,returned,log,observer,report,active_began;
    uint64_t api_began,api,api_calls;
    uint32_t frame,active_frame,sequence,fault;
    bool active,pending,api_open;
};
static inline bool pgpu_tail_fail(struct pgpu_frame_tail *s,unsigned error)
{if(s && !s->fault)s->fault=error;return false;}
static inline bool pgpu_tail_add(uint64_t *sum,uint64_t value)
{if(UINT64_MAX-*sum<value)return false;*sum+=value;return true;}
/* Only pre-first-draw API work intersects returned->next begin. Close the
 * first draw's partial entry at frame_begin; never double-count its GPU work. */
static inline bool pgpu_tail_api_enter(struct pgpu_frame_tail *s,uint64_t now)
{
    if(!s || s->fault)return false;
    if(s->active || !s->pending)return true;
    if(s->api_open)return pgpu_tail_fail(s,PGT_SEQUENCE);
    if(now<s->returned)return pgpu_tail_fail(s,PGT_CLOCK);
    s->api_began=now;s->api_open=true;return true;
}
static inline bool pgpu_tail_api_leave(struct pgpu_frame_tail *s,uint64_t now)
{
    if(!s || s->fault)return false;
    if(!s->api_open)return true;
    if(now<s->api_began)return pgpu_tail_fail(s,PGT_CLOCK);
    if(!pgpu_tail_add(&s->api,now-s->api_began) || s->api_calls==UINT64_MAX)
        return pgpu_tail_fail(s,PGT_OVERFLOW);
    s->api_calls++;s->api_open=false;return true;
}

/* Exact standalone token, no substring activation. Duplicate/unknown settings
 * disable the new diagnostic; the original touch_lat=1 path is unchanged. */
static inline unsigned pgpu_tail_mode(const char *args)
{
    unsigned mode=0,seen=0;
    if(!args)return 0;
    while(*args) {
        while(*args==' ' || *args=='\t' || *args=='\n')args++;
        const char *end=args;while(*end && *end!=' ' && *end!='\t' && *end!='\n')end++;
        size_t n=(size_t)(end-args);
        if(n>=10 && !memcmp(args,"touch_lat=",10)) {
            if(seen++)return 0;
            if(n!=11 || args[10]<'1' || args[10]>'3')return 0;
            mode=args[10]=='1'?0u:(unsigned)(args[10]-'0');
        }
        args=end;
    }
    return mode;
}
static inline bool pgpu_tail_begin(struct pgpu_frame_tail *s,uint32_t frame,uint64_t began)
{
    if(!s)return false;
    if(s->fault)return false;
    if(!frame || !began || s->active)return pgpu_tail_fail(s,PGT_ARGUMENT);
    if(s->pending) {
        if(s->api_open && !pgpu_tail_api_leave(s,began))return false;
        if(s->frame==UINT32_MAX || frame!=s->frame+1 || s->window.frames>=PGPU_TAIL_WINDOW)
            return pgpu_tail_fail(s,PGT_SEQUENCE);
        if(began<s->returned)return pgpu_tail_fail(s,PGT_CLOCK);
        struct pgpu_tail_window w=s->window;
        uint64_t render=s->ended-s->began,gap=began-s->ended;
        uint64_t tail=s->returned-s->ended,outside=began-s->returned;
        if(s->api>outside)return pgpu_tail_fail(s,PGT_PARTS);
        if(!w.frames){w.from_us=s->began;w.first=s->frame;}
        else if(w.end_us!=s->began)return pgpu_tail_fail(s,PGT_SEQUENCE);
        w.end_us=began;w.last=s->frame;w.frames++;
        bool ok=pgpu_tail_add(&w.render,render)&&pgpu_tail_add(&w.gap,gap)&&
            pgpu_tail_add(&w.tail,tail)&&pgpu_tail_add(&w.outside,outside)&&
            pgpu_tail_add(&w.log,s->log)&&pgpu_tail_add(&w.observer,s->observer)&&
            pgpu_tail_add(&w.report,s->report)&&pgpu_tail_add(&w.api,s->api)&&
            pgpu_tail_add(&w.calls,s->api_calls);
        if(began-s->began<=PGPU_TAIL_ACTIVE_PERIOD_US) {
            w.active++;w.over_budget+=(began-s->began)>16667;
            ok=ok && pgpu_tail_add(&w.active_render,render)&&pgpu_tail_add(&w.active_gap,gap)&&
                pgpu_tail_add(&w.active_tail,tail)&&pgpu_tail_add(&w.active_outside,outside)&&
                pgpu_tail_add(&w.active_log,s->log)&&pgpu_tail_add(&w.active_observer,s->observer)&&
                pgpu_tail_add(&w.active_report,s->report)&&pgpu_tail_add(&w.active_api,s->api)&&
                pgpu_tail_add(&w.active_calls,s->api_calls);
        }
        if(!ok)return pgpu_tail_fail(s,PGT_OVERFLOW);
        if(gap>w.max_gap)w.max_gap=gap;
        if(tail>w.max_tail)w.max_tail=tail;
        if(s->observer>w.max_observer)w.max_observer=s->observer;
        if(s->api>w.max_api)w.max_api=s->api;
        s->window=w;s->pending=false;
        s->api=s->api_calls=0;
    }
    s->active=true;s->active_frame=frame;s->active_began=began;return true;
}
static inline bool pgpu_tail_end(struct pgpu_frame_tail *s,uint32_t frame,
    uint64_t began,uint64_t ended,uint64_t returned,uint64_t log,
    uint64_t observer,uint64_t report)
{
    if(!s || s->fault)return false;
    if(!s->active || s->pending || frame!=s->active_frame || began!=s->active_began)
        return pgpu_tail_fail(s,PGT_SEQUENCE);
    if(ended<began || returned<ended)return pgpu_tail_fail(s,PGT_CLOCK);
    uint64_t tail=returned-ended;
    if(log>tail || observer>tail-log || report>log)return pgpu_tail_fail(s,PGT_PARTS);
    s->frame=frame;s->began=began;s->ended=ended;s->returned=returned;
    s->log=log;s->observer=observer;s->report=report;
    s->active=false;s->pending=true;return true;
}
/* Called after EAGL_LEAVE, so its real cost remains in library tail. */
static inline bool pgpu_tail_returned(struct pgpu_frame_tail *s,uint32_t frame,uint64_t now)
{
    if(!s || s->fault)return false;
    if(!s->pending || s->frame!=frame)return pgpu_tail_fail(s,PGT_SEQUENCE);
    if(now<s->returned)return pgpu_tail_fail(s,PGT_CLOCK);
    s->returned=now;return true;
}
static inline bool pgpu_tail_take(struct pgpu_frame_tail *s,struct pgpu_tail_window *out,
    uint32_t *sequence)
{
    if(!s || !out || !sequence || s->fault || s->window.frames!=PGPU_TAIL_WINDOW)return false;
    if(s->sequence==UINT32_MAX)return pgpu_tail_fail(s,PGT_OVERFLOW);
    *out=s->window;*sequence=++s->sequence;s->window=(struct pgpu_tail_window){0};return true;
}
#endif

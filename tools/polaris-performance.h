/* Diagnostic wall times, not hardware GPU utilisation. Never admission. */
#ifndef POLARIS_PERFORMANCE_H
#define POLARIS_PERFORMANCE_H
#include <stdint.h>
struct pgpu_perf_notice {
    uint32_t frames,window_us,frame_us,wait_us,readback_us,upload_us,hash_us;
    uint32_t cpu_busy,cpus,reserved;
};
struct pgpu_perf_window {
    uint64_t began,frames,frame_us,wait_us,readback_us,upload_us,hash_us;
};
static inline uint32_t pgpu_perf_u32(uint64_t n)
{return n>UINT32_MAX?UINT32_MAX:(uint32_t)n;}
static inline uint32_t pgpu_perf_cpu(const uint32_t before[4],const uint32_t after[4])
{
    uint64_t total=0,idle=(uint32_t)(after[2]-before[2]);
    for(unsigned i=0;i<4;i++)total+=(uint32_t)(after[i]-before[i]);
    return total?(uint32_t)((total-idle)*10000/total):10001;
}
static inline int pgpu_perf_add(struct pgpu_perf_window *w,uint64_t began,
    uint64_t ended,uint64_t wait,uint64_t readback,uint64_t upload,uint64_t hash,
    struct pgpu_perf_notice *out)
{
    if(ended<began)return 0;
    if(!w->frames)w->began=began;
    w->frames++;w->frame_us+=ended-began;w->wait_us+=wait;
    w->readback_us+=readback;w->upload_us+=upload;w->hash_us+=hash;
    uint64_t elapsed=ended-w->began;
    if(elapsed<1000000)return 0;
    out->frames=pgpu_perf_u32(w->frames);out->window_us=pgpu_perf_u32(elapsed);
    out->frame_us=pgpu_perf_u32(w->frame_us/w->frames);
    out->wait_us=pgpu_perf_u32(w->wait_us/w->frames);
    out->readback_us=pgpu_perf_u32(w->readback_us/w->frames);
    out->upload_us=pgpu_perf_u32(w->upload_us/w->frames);
    out->hash_us=pgpu_perf_u32(w->hash_us/w->frames);
    out->cpu_busy=10001;out->cpus=out->reserved=0;
    *w=(struct pgpu_perf_window){0};return 1;
}
#ifdef __cplusplus
static_assert(sizeof(struct pgpu_perf_notice)==40,"performance ABI");
#else
_Static_assert(sizeof(struct pgpu_perf_notice)==40,"performance ABI");
#endif
#endif

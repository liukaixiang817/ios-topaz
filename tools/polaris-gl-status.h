/* Fixed diagnostic ABI shared by the verified window server and kernel.
 * Reporting never establishes GPU completion or permits another writer. */
#ifndef POLARIS_GL_STATUS_H
#define POLARIS_GL_STATUS_H
#include <stdint.h>
#define PGPU_EAGL_METHOD_COUNT 8u
#define PGPU_EAGL_METHOD_MASK 0xffu
#define PGPU_ACCEPTANCE_TIMEOUT_MS 180000u
/* Diagnostic-only snapshot from the verified desktop, selector0x7a. */
struct pgpu_render_notice {
    uint32_t frames,errors,shaders,images,missing,kind,arg,slot;
};
/* Diagnostic-only AMFI5c. Actor1 is the shader test, actor3 the activated
 * wrapper; neither role gains dyld flags or another GPU writer from this. */
enum {PGPU_TEST_BEGIN=1,PGPU_TEST_EXIT,PGPU_TEST_SIGNAL,PGPU_TEST_TIMEOUT,
      PGPU_TEST_SPAWN_ERROR,PGPU_TEST_WAIT_ERROR,PGPU_TEST_STEP};
struct pgpu_test_notice {uint32_t event,value,elapsed_ms,reserved;};
static inline int pgpu_test_notice_valid(unsigned actor,const struct pgpu_test_notice *p)
{
    if(!p || p->reserved || p->elapsed_ms>600000u)return 0;
    if(actor==1)return p->event==PGPU_TEST_STEP && p->value && p->value<=63;
    if(actor!=3 || p->event<PGPU_TEST_BEGIN || p->event>PGPU_TEST_WAIT_ERROR)return 0;
    if(p->event==PGPU_TEST_BEGIN)return !p->value && !p->elapsed_ms;
    if(p->event==PGPU_TEST_SIGNAL)return p->value && p->value<64;
    if(p->event==PGPU_TEST_TIMEOUT)return p->value==9 && p->elapsed_ms>=PGPU_ACCEPTANCE_TIMEOUT_MS;
    return p->value<=255;
}
struct pgpu_crash {
    uint32_t signal,code;
    uint64_t pc,lr,address;
    uint32_t pc_image,lr_image;
};
/* image0 raw,1 cache preferredVA,2 reporting image (injector/test),3 bridge,4 Mesa offset. */
struct pgpu_image {uint64_t base,bytes;uint32_t kind;};
static inline int pgpu_desktop_allowed(uint32_t kind,uint32_t attempts)
{return kind!=2 || attempts==0;}
static inline uint64_t pgpu_pc(uint64_t pc,const struct pgpu_image *images,unsigned count,uint32_t *kind)
{
    *kind=0;
    for(unsigned i=0;i<count;i++)if(images[i].base && pc>=images[i].base && pc-images[i].base<images[i].bytes) {
        *kind=images[i].kind;
        return pc-images[i].base+(*kind==1?UINT64_C(0x180000000):0);
    }
    return pc;
}
static inline int pgpu_crash_valid(const struct pgpu_crash *p)
{
    return p && (p->signal==4 || p->signal==5 || p->signal==6 || p->signal==10 || p->signal==11) &&
        p->pc && p->pc_image<=4 && p->lr_image<=4;
}
#ifdef __cplusplus
static_assert(sizeof(struct pgpu_crash)==40,"crash ABI");
#else
_Static_assert(sizeof(struct pgpu_crash)==40,"crash ABI");
#endif
#endif

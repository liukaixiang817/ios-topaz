/* Polaris calendar metadata only. No physical clock, RTC, storage or reset API.
 * Firmware produces the first 128B; native owns the other 128B. */
#ifndef POLARIS_CLOCK_SYNC_H
#define POLARIS_CLOCK_SYNC_H
#include <stdbool.h>
#include <stdint.h>
#define PC_MAGIC UINT64_C(0x50434c4f434b3031)
#define PC_FREQUENCY UINT64_C(19200000)
#define PC_MIN_UTC_US UINT64_C(1577836800000000) /* 2020-01-01 UTC inclusive */
#define PC_MAX_UTC_US UINT64_C(4102444800000000) /* 2100-01-01 UTC exclusive */
#define PC_MAX_AGE_TICKS (PC_FREQUENCY*10)
#define PC_MAX_UNCERTAINTY_US UINT64_C(150000)
#define PC_SOURCE_HOST_UTC UINT64_C(1)
enum { PC_OFF=0,PC_READY=1,PC_APPLIED=2,PC_REJECTED=3,PC_SEALED=4 };
enum { PC_OK=0,PC_BAD_WIRE=1,PC_BAD_SOURCE=2,PC_BAD_SEQUENCE=3,
    PC_BAD_TIME=4,PC_BAD_COUNTER=5,PC_BAD_UNCERTAINTY=6,PC_READBACK=7 };
struct polaris_clock_request {
    uint64_t magic,cookie,sequence,utc_us,anchor_ticks,uncertainty_us,frequency_hz,source;
    uint64_t reserved[8];
};
struct polaris_clock_status {
    uint64_t magic,cookie,sequence,status,error,actual_utc_us,actual_ticks,uncertainty_us;
    uint64_t applied_count,frequency_hz,revision,reserved[5];
};
struct polaris_clock_slot {
    struct polaris_clock_request firmware;
    struct polaris_clock_status kernel;
} __attribute__((aligned(128)));
#if defined(__cplusplus)
static_assert(sizeof(struct polaris_clock_request)==128,"clock producer cacheline");
static_assert(sizeof(struct polaris_clock_status)==128,"clock consumer cacheline");
static_assert(sizeof(struct polaris_clock_slot)==256,"bounded clock mailbox");
#else
_Static_assert(sizeof(struct polaris_clock_request)==128,"clock producer cacheline");
_Static_assert(sizeof(struct polaris_clock_status)==128,"clock consumer cacheline");
_Static_assert(sizeof(struct polaris_clock_slot)==256,"bounded clock mailbox");
_Static_assert(__builtin_offsetof(struct polaris_clock_slot,kernel)==128,"independent cacheline owners");
#endif
static inline bool pc_utc_valid(uint64_t utc)
{ return utc>=PC_MIN_UTC_US && utc<PC_MAX_UTC_US; }
/* Division before multiplication keeps the full counter range representable.
 * This reads the counter's fixed frequency; it never changes that frequency. */
static inline bool pc_elapsed_us(uint64_t anchor,uint64_t now,uint64_t *elapsed)
{
    if(now<anchor)return false;
    uint64_t delta=now-anchor,whole=delta/PC_FREQUENCY;
    if(whole>UINT64_MAX/1000000)return false;
    *elapsed=whole*1000000+(delta%PC_FREQUENCY)*1000000/PC_FREQUENCY;
    return true;
}
static inline unsigned pc_validate(const struct polaris_clock_request *r,
    uint64_t cookie,uint64_t previous,uint64_t now,uint64_t frequency,uint64_t *utc)
{
    if(r->magic!=PC_MAGIC || !cookie || r->cookie!=cookie)return PC_BAD_WIRE;
    for(unsigned i=0;i<8;i++)if(r->reserved[i])return PC_BAD_WIRE;
    if(r->source!=PC_SOURCE_HOST_UTC)return PC_BAD_SOURCE;
    if(previous>=UINT32_MAX || r->sequence!=previous+1)return PC_BAD_SEQUENCE;
    if(frequency!=PC_FREQUENCY || r->frequency_hz!=PC_FREQUENCY ||
       !r->anchor_ticks || now<r->anchor_ticks || now-r->anchor_ticks>PC_MAX_AGE_TICKS)
        return PC_BAD_COUNTER;
    if(!r->uncertainty_us || r->uncertainty_us>PC_MAX_UNCERTAINTY_US)
        return PC_BAD_UNCERTAINTY;
    uint64_t elapsed=0;
    if(!pc_utc_valid(r->utc_us) || !pc_elapsed_us(r->anchor_ticks,now,&elapsed) ||
       elapsed>=PC_MAX_UTC_US || r->utc_us>=PC_MAX_UTC_US-elapsed)return PC_BAD_TIME;
    *utc=r->utc_us+elapsed;return PC_OK;
}
static inline uint64_t pc_distance(uint64_t a,uint64_t b)
{ return a>b?a-b:b-a; }
static inline void pc_put32(uint8_t *p,uint32_t v)
{ for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i)); }
static inline void pc_put64(uint8_t *p,uint64_t v)
{ for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i)); }
#endif

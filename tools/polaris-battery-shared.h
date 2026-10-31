/* Polaris PMI8998 telemetry, firmware writes / XNU reads only.
 * This is not a charger-control ABI. No voltage curve, nominal capacity,
 * current-sign guess from USB presence, or synthetic fallback is permitted.
 * Producer publishes odd sequence + clean, payload + clean, then even + clean.
 * Consumer invalidates, copies, then invalidates/rechecks sequence. Both use
 * the same CNTVCT/CNTFRQ domain; a domain mismatch must keep data invalid. */
#ifndef POLARIS_BATTERY_SHARED_H
#define POLARIS_BATTERY_SHARED_H
#include <stdint.h>
#include <stdbool.h>
#define PBAT_MAGIC UINT64_C(0x50424d4938393938)
#define PBAT_VERSION 1u
#define PBAT_SOURCE_PMI8998_FG3_SMB2 1u
#define PBAT_MAX_AGE_US UINT64_C(15000000)
/* UI telemetry quality ceiling, NOT a PMIC/charger/thermal hardware limit.
 * The actual transaction budget must be explicitly admitted by the parent;
 * there is no implicit firmware default. Timestamp the oldest and newest read. */
#define PBAT_UI_MAX_SPAN_US UINT64_C(1000000)
enum { PBAT_SOC=1u,PBAT_VOLTAGE=2u,PBAT_CURRENT=4u,PBAT_TEMP=8u,
       PBAT_PRESENT=16u,PBAT_EXTERNAL=32u,PBAT_CHARGING=64u,PBAT_FULL=128u,
       PBAT_CAPABLE=256u,PBAT_ALL=511u };
enum { PBAT_E_ARGUMENT=1,PBAT_E_IDENTITY,PBAT_E_MAPPING,PBAT_E_CLOCK,
       PBAT_E_TIMEOUT,PBAT_E_RESPONSE,PBAT_E_UNSTABLE,PBAT_E_NOT_READY,
       PBAT_E_ABSENT,PBAT_E_RANGE,PBAT_E_STALE,PBAT_E_WIRE };
struct polaris_battery_sample {
    uint64_t magic,sequence,began_us,sampled_us,counter_hz,cookie;
    uint32_t version,bytes,source,valid,error,reads,span_limit_us;
    int32_t soc_percent,voltage_uv,current_ua,temperature_centi_c;
    uint32_t present,external,charging,full,capable;
    uint8_t raw[64]; /* exact acquisition bytes, including errors/partial data */
    uint8_t reserved[80];
} __attribute__((aligned(128)));
#if defined(__cplusplus)
static_assert(sizeof(struct polaris_battery_sample)==256,"battery producer span");
#else
_Static_assert(sizeof(struct polaris_battery_sample)==256,"battery producer span");
#endif
/* Explicit native activation is immutable SecureDT metadata, not another
 * boot argument. Properties are exact u32 LE=1 and compatible is a bounded,
 * completely NUL-terminated string list containing our actual board. */
static inline bool pbat_runtime_authorized(const void *compatible,unsigned compatible_bytes,
    const void *version,unsigned version_bytes,const void *enabled,unsigned enabled_bytes,
    uint32_t uefi)
{
    if(uefi!=1||!compatible||!compatible_bytes||compatible_bytes>256||
       !version||version_bytes!=4||!enabled||enabled_bytes!=4)return false;
    const uint8_t *v=(const uint8_t *)version,*e=(const uint8_t *)enabled;
    if(v[0]!=1||v[1]||v[2]||v[3]||e[0]!=1||e[1]||e[2]||e[3])return false;
    const uint8_t *p=(const uint8_t *)compatible;
    static const char board[]="xiaomi,polaris";bool matched=false;
    for(unsigned i=0;i<compatible_bytes;) {
        unsigned n=0;while(i+n<compatible_bytes&&p[i+n])n++;
        if(!n||i+n==compatible_bytes)return false;
        if(n==sizeof(board)-1) {
            bool same=true;
            for(unsigned j=0;j<n;j++)if(p[i+j]!=(uint8_t)board[j])same=false;
            matched|=same;
        }
        i+=n+1;
    }
    return matched;
}
static inline bool pbat_sample_valid(const struct polaris_battery_sample *s,
    uint64_t now_us,uint64_t counter_hz)
{
    if(!s||s->magic!=PBAT_MAGIC||s->version!=PBAT_VERSION||s->bytes!=sizeof(*s)||
       s->source!=PBAT_SOURCE_PMI8998_FG3_SMB2||!s->cookie||!s->sequence||
       (s->sequence&1)||s->valid!=PBAT_ALL||s->error||!s->began_us||
       s->sampled_us<s->began_us||!s->span_limit_us||
       s->span_limit_us>PBAT_UI_MAX_SPAN_US||s->sampled_us-s->began_us>s->span_limit_us||
       !counter_hz||s->counter_hz!=counter_hz||now_us<s->sampled_us||
       now_us-s->began_us>PBAT_MAX_AGE_US||s->soc_percent<0||s->soc_percent>100||
       s->voltage_uv<2000000||s->voltage_uv>5000000||
       s->current_ua< -16000000||s->current_ua>16000000||
       s->temperature_centi_c< -4000||s->temperature_centi_c>10000||
       s->present!=1||s->external>1||s->charging>1||s->full>1||s->capable>1||
       (s->charging&&(!s->external||!s->capable||s->full))||
       (s->full&&(!s->external||!s->capable)))return false;
    for(unsigned i=0;i<sizeof(s->reserved);i++)if(s->reserved[i])return false;
    return true;
}
#endif

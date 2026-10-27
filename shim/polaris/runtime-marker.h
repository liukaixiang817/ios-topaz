/* Physical small-file trial admission. No MMIO, writes or frequency changes.
 * Geometry/frequency are this phone's DT and actual0071 two-core observations.
 * This does not admit a persistent iOS root or prove physical UFS persistence.
 */
#ifndef POLARIS_RUNTIME_MARKER_H
#define POLARIS_RUNTIME_MARKER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define POLARIS_MARKER_BLOCKS 2048u
#define POLARIS_DURABLE_MARKER_GUARD 0x50470001u
#define POLARIS_DURABLE_QEMU_GUARD 0x50470002u
/* The incoming template must NEVER supply this token. The resident firmware
 * inserts it into the final boot args only after disabling raw reset/lease,
 * before CPU_ON. Older loaders therefore cannot accidentally enable writes.
 * This is an accidental-mismatch guard, not cryptographic attestation. */
static inline bool polaris_marker_template(const char *s,size_t bytes)
{
    static const char key[]="polarisdurableguard=";
    if(!s)return false;
    size_t used=0;while(used<bytes&&s[used])used++;
    if(used==bytes)return false;
    for(size_t at=0;at<used;at++){
        size_t n=0;while(n<sizeof(key)-1&&n<used-at&&s[at+n]==key[n])n++;
        if(n==sizeof(key)-1)return false;
    }
    return true;
}
static inline bool polaris_marker_append_guard(char *s,size_t bytes,bool physical)
{
    const char *suffix=physical?" polarisdurableguard=0x50470001":" polarisdurableguard=0x50470002";
    if(!polaris_marker_template(s,bytes))return false;
    size_t used=0,n=0;while(s[used])used++;while(suffix[n])n++;
    if(n>=bytes-used)return false;
    for(size_t i=0;i<=n;i++)s[used+i]=suffix[i];
    return true;
}
struct polaris_marker_identity {
    uint64_t actual_cpu,timer,base,bytes,reg[2];
    uint32_t mode,core,count,file_root,rootrw,cow,ram_mib,rw;
    uint32_t probe_present,virtual_present,marker,guard;
};
static inline bool polaris_marker_allowed(const struct polaris_marker_identity *i)
{
    if(!i)return false;
    uint64_t cpu=i->actual_cpu&~(UINT64_C(1)<<31|UINT64_C(1)<<24);
    return (cpu==0x700||cpu==0x600)&&i->timer==19200000&&
        i->base==UINT64_C(0x180000000)&&i->bytes==UINT64_C(0xfc8a0000)&&
        i->reg[0]==0x1d84000&&i->reg[1]==0x2500&&i->mode==1&&
        i->core==0x700&&i->count==2&&i->file_root==1&&i->rootrw==1&&
        i->cow==1&&i->ram_mib==512&&!i->rw&&!i->probe_present&&
        !i->virtual_present&&i->marker==1&&i->guard==POLARIS_DURABLE_MARKER_GUARD;
}
static inline bool polaris_marker_base_matches(const void *provided,uint32_t bytes,uint64_t blocks,
    const void *expected,uint32_t expected_bytes,uint64_t expected_blocks,uint64_t marker_blocks)
{
    if(!provided||!expected||!bytes||bytes%24||bytes>4096u*24u||bytes!=expected_bytes||
       blocks!=expected_blocks||expected_blocks!=4194304||marker_blocks!=POLARIS_MARKER_BLOCKS)return false;
    const uint8_t *a=provided,*b=expected;
    for(uint32_t at=0;at<bytes;at++)if(a[at]!=b[at])return false;
    return true;
}
#endif

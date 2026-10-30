/* Polaris PMI8998 LCD WLED power sequencer. No caller-selected PMIC address.
 * Derived from own MiCode c7cb50c1 qpnp_wled_module_en and qpnpint_irq_unmask.
 * Only d846 bit7 and the d814/15/16 OVP notification bit1 may change. The
 * protection circuit, brightness, PSM, IRQ type/route and arb permissions stay
 * untouched. Own live DT does NOT request lcd-psm-ctrl. Caller owns CPU0's
 * serialized SPMI bus; a successful PMIC readback is not optical evidence.
 */
#ifndef POLARIS_EFI_WLED_POWER_H
#define POLARIS_EFI_WLED_POWER_H
#include "uefi-wled-readonly.h"
#include "uefi-wled-status.h"

enum pwp_phase { PWP_UNINITIALIZED, PWP_ON, PWP_OFF_MODULE, PWP_OFF_IRQ,
    PWP_OFF, PWP_ON_MODULE, PWP_SOFTSTART, PWP_ON_IRQ, PWP_VERIFY_ON, PWP_FAILED };
enum { PWP_E_SCOPE=32, PWP_E_CONFIG, PWP_E_REQUEST, PWP_E_WRITE,
       PWP_E_WRITE_TIMEOUT, PWP_E_READBACK, PWP_E_CLOCK };
enum pwp_command { PWP_DISABLE_MODULE, PWP_DISABLE_OVP, PWP_ENABLE_MODULE,
                   PWP_RESTORE_OVP };
enum pwp_status_policy { PWP_STRICT_SNAPSHOT, PWP_OEM_STATUS_WITNESS };
struct polaris_wled_power {
    struct polaris_wled_read_bus *bus;
    void *write_context;
    /* RW channel, NOT observer: CMD offset 0x10000*APID, WDATA0 +0x10.
     * Issuer stores WDATA, barrier, CMD, barrier. No implicit retries. */
    void (*issue)(void *, uint32_t, uint32_t, uint32_t);
    uint32_t (*status)(void *, uint32_t);
    struct polaris_wled_snapshot saved;
    uint64_t previous_us, softstart_us, request, acknowledged;
    uint32_t error, phase, issued, completed, last_status, polls, frozen_polls;
    uint8_t module, irq;
    bool desired_on, actual_on, uncertain;
    enum pwp_status_policy status_policy;
    struct polaris_wled_status_witness witness;
};
static inline bool pwp_fail(struct polaris_wled_power *p,unsigned error)
{
    if(p){if(!p->error)p->error=error;p->phase=PWP_FAILED;}
    return false;
}
static inline bool pwp_equal(const void *a,const void *b,unsigned count)
{
    const uint8_t *x=a,*y=b;
    for(unsigned n=0;n<count;n++)if(x[n]!=y[n])return false;
    return true;
}
static inline uint64_t pwp_now(struct polaris_wled_power *p)
{
    uint64_t now=p->bus->now_us(p->bus->context);
    if(!now||now<p->previous_us){pwp_fail(p,PWP_E_CLOCK);return 0;}
    p->previous_us=now;return now;
}
static inline bool pwp_scope(struct polaris_wled_power *p)
{
    struct polaris_wled_read_bus *b=p->bus;
    if(!pw_map(b))return pwp_fail(p,b->fault);
    /* Exact v5 ownership established by the source-bound physical inventory.
     * Mock fixtures use these same numbers, never grant generic MMIO access. */
    if(b->version!=0x50000000||b->apid[0]!=253||b->apid[1]!=254||
       b->owner[0]||b->owner[1]||b->map[0]!=0x0103d800||b->map[1]!=0x0103d900)
        return pwp_fail(p,PWP_E_SCOPE);
    return true;
}
static inline bool pwp_verify(struct polaris_wled_power *p)
{
    struct polaris_wled_snapshot s={0},expected=p->saved;
    if(!pwp_scope(p))return false;
    expected.ctrl[2]=p->module;expected.irq_enable=p->irq;
    if(p->status_policy==PWP_OEM_STATUS_WITNESS) {
        if(!pws_verify(&p->witness,p->bus,&expected))
            return pwp_fail(p,p->witness.error);
        return true;
    }
    if(p->status_policy!=PWP_STRICT_SNAPSHOT)return pwp_fail(p,PWP_E_SCOPE);
    if(!polaris_wled_inventory(p->bus,&s))return pwp_fail(p,p->bus->fault);
    if(!pwp_equal(&s,&expected,sizeof(s)))return pwp_fail(p,PWP_E_CONFIG);
    return true;
}
static inline bool pwp_init_policy(struct polaris_wled_power *p,
    struct polaris_wled_read_bus *bus,
    const struct polaris_wled_snapshot *source_bound_expected,
    bool own_DT_has_lcd_psm_ctrl,enum pwp_status_policy policy)
{
    static const uint8_t ctrl_rev[8]={0,3,1,3,0x17,0x10,0,0};
    static const uint8_t sink_rev[8]={1,1,0,1,0x17,0x11,0,0};
    static const uint8_t sink_config[6]={0xf0,0x0f,0,0,0x4c,3};
    static const uint8_t string_config[9]={0x80,2,8,0,0,0,0x80,0xff,7};
    if(!p||p->error||p->phase!=PWP_UNINITIALIZED||!bus||!source_bound_expected||
       own_DT_has_lcd_psm_ctrl||!p->issue||!p->status||p->issued||p->completed||
       p->request||p->witness.count||p->witness.error||
       (policy!=PWP_STRICT_SNAPSHOT&&policy!=PWP_OEM_STATUS_WITNESS))
        return pwp_fail(p,PWP_E_SCOPE);
    const struct polaris_wled_snapshot *s=source_bound_expected;
    if(!pwp_equal(s->revision[0],ctrl_rev,8)||!pwp_equal(s->revision[1],sink_rev,8)||
       s->ctrl[0]||s->ctrl[1]||s->ctrl[2]!=0x80||s->irq_enable!=2||
       ((s->faults[0]|s->faults[1])&~(policy==PWP_OEM_STATUS_WITNESS?1u:0u))||
       s->psm[0]!=0x80||s->psm[1]!=0x84||
       !pwp_equal(s->sink,sink_config,6))return pwp_fail(p,PWP_E_CONFIG);
    for(unsigned n=0;n<4;n++)if(!pwp_equal(s->string[n],string_config,9))
        return pwp_fail(p,PWP_E_CONFIG);
    p->status_policy=policy;
    p->bus=bus;p->saved=*s;p->module=0x80;p->irq=2;
    if(!pwp_verify(p)||!pwp_now(p))return false;
    p->phase=PWP_ON;p->desired_on=p->actual_on=true;return true;
}
/* Existing callers retain strict equality/zero-status behavior. The separate
 * entry is for explicit offline/model integration, not a runtime switch after
 * refusal. No image flag or physical admission is granted by this header. */
static inline bool pwp_init(struct polaris_wled_power *p,
    struct polaris_wled_read_bus *b,const struct polaris_wled_snapshot *expected,
    bool psm)
{return pwp_init_policy(p,b,expected,psm,PWP_STRICT_SNAPSHOT);}
static inline bool pwp_init_oem_status(struct polaris_wled_power *p,
    struct polaris_wled_read_bus *b,const struct polaris_wled_snapshot *expected,
    bool psm)
{return pwp_init_policy(p,b,expected,psm,PWP_OEM_STATUS_WITNESS);}
static inline bool pwp_write(struct polaris_wled_power *p,enum pwp_command command)
{
    uint32_t reg,data,count=1;
    if(!p||p->error||!p->bus)return false;
    if((command==PWP_DISABLE_MODULE&&p->phase!=PWP_OFF_MODULE)||
       (command==PWP_DISABLE_OVP&&p->phase!=PWP_OFF_IRQ)||
       (command==PWP_ENABLE_MODULE&&p->phase!=PWP_ON_MODULE)||
       (command==PWP_RESTORE_OVP&&p->phase!=PWP_ON_IRQ))
        return pwp_fail(p,PWP_E_REQUEST);
    switch(command) {
    case PWP_DISABLE_MODULE:reg=0x46;data=p->saved.ctrl[2]&~0x80u;break;
    case PWP_DISABLE_OVP:reg=0x16;data=2;break;
    case PWP_ENABLE_MODULE:reg=0x46;data=p->saved.ctrl[2];break;
    /* Own irqchip clears the pending OVP notification and enables that same
     * bit with a two-byte write. Other IRQ bits are never written with ones. */
    case PWP_RESTORE_OVP:reg=0x14;data=0x0202;count=2;break;
    default:return pwp_fail(p,PWP_E_WRITE);
    }
    if(!pwp_verify(p)||!pwp_scope(p))return false;
    uint64_t start=pwp_now(p);if(!start)return false;
    if(command==PWP_RESTORE_OVP&&(!p->softstart_us||
       start-p->softstart_us<10000))return pwp_fail(p,PWP_E_CLOCK);
    uint32_t offset=0x10000u*p->bus->apid[0];
    p->last_status=0;p->polls=0;p->issued++;p->uncertain=true;
    p->issue(p->write_context,offset,(reg<<4)|(count-1),data);
    for(unsigned n=0;n<4096;n++) {
        uint32_t status=p->status(p->write_context,offset+8);
        p->last_status=status;p->polls=n+1;
        uint64_t now=pwp_now(p);if(!now)return false;
        if(status&~1u)return pwp_fail(p,PWP_E_WRITE);
        if(status==1) {
            p->completed++;
            if(command==PWP_DISABLE_MODULE)p->module=p->saved.ctrl[2]&~0x80u;
            else if(command==PWP_ENABLE_MODULE)p->module=p->saved.ctrl[2];
            else if(command==PWP_DISABLE_OVP)p->irq=p->saved.irq_enable&~2u;
            else p->irq=p->saved.irq_enable;
            if(!pwp_verify(p))return false;
            p->uncertain=false;return true;
        }
        if(now-start>=100)return pwp_fail(p,PWP_E_WRITE_TIMEOUT);
    }
    return pwp_fail(p,PWP_E_WRITE_TIMEOUT);
}
/* Monotonic mailbox requests; one acknowledged transition at a time. A newer
 * desired state can replace an intermediate target without clearing errors or
 * skipping the >=10ms enable softstart. No acknowledgement for an old target. */
static inline bool pwp_request(struct polaris_wled_power *p,uint64_t sequence,bool on)
{
    if(!p||p->error||p->phase==PWP_UNINITIALIZED)return false;
    if(!sequence||sequence!=p->request+1||p->request==UINT64_MAX)
        return pwp_fail(p,PWP_E_REQUEST);
    p->request=sequence;p->desired_on=on;return true;
}
/* At most one PMIC WRITE per call. Long softstart is cooperative and polls no
 * bus; caller continues serving USB and keys between calls. */
static inline bool pwp_poll(struct polaris_wled_power *p)
{
    if(!p||p->error||p->phase==PWP_UNINITIALIZED)return false;
    uint64_t now=pwp_now(p);if(!now)return false;
    switch(p->phase) {
    case PWP_ON:
        if(!p->desired_on){p->phase=PWP_OFF_MODULE;break;}
        if(p->request!=p->acknowledged) {
            if(!pwp_verify(p))return false;p->acknowledged=p->request;
        }break;
    case PWP_OFF_MODULE:
        if(!pwp_write(p,PWP_DISABLE_MODULE))return false;
        p->phase=PWP_OFF_IRQ;break;
    case PWP_OFF_IRQ:
        if(!pwp_write(p,PWP_DISABLE_OVP))return false;
        p->actual_on=false;p->phase=PWP_OFF;break;
    case PWP_OFF:
        if(p->desired_on){p->phase=PWP_ON_MODULE;break;}
        if(p->request!=p->acknowledged) {
            if(!pwp_verify(p))return false;p->acknowledged=p->request;
        }break;
    case PWP_ON_MODULE:
        if(!pwp_write(p,PWP_ENABLE_MODULE))return false;
        /* Start AFTER successful module readback, never before issue. */
        p->softstart_us=pwp_now(p);if(!p->softstart_us)return false;
        p->frozen_polls=0;p->phase=PWP_SOFTSTART;break;
    case PWP_SOFTSTART:
        if(now==p->softstart_us&&++p->frozen_polls>=4096)
            return pwp_fail(p,PWP_E_CLOCK);
        if(now-p->softstart_us>=10000)p->phase=PWP_ON_IRQ;
        break;
    case PWP_ON_IRQ:
        if(!pwp_write(p,PWP_RESTORE_OVP))return false;
        p->phase=PWP_VERIFY_ON;break;
    case PWP_VERIFY_ON:
        if(!pwp_verify(p))return false;p->actual_on=true;p->phase=PWP_ON;break;
    default:return pwp_fail(p,PWP_E_REQUEST);
    }
    return true;
}
static inline bool pwp_restored(struct polaris_wled_power *p)
{
    if(!p||p->error||p->phase!=PWP_ON||!p->actual_on||!p->desired_on||
       p->uncertain||p->request!=p->acknowledged)return false;
    return pwp_verify(p); /* Independent last readback, never a host ACK. */
}
#endif

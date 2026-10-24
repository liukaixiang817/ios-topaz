#ifndef POLARIS_TOUCH_MODE_H
#define POLARIS_TOUCH_MODE_H

#include <stdint.h>
#include <stddef.h>

/* F01 is the only writable RMI register here. Configure once, then observe
 * readiness for at most100ms without issuing another write, reset or command.
 * RMI4 spec511-000136-01 RevE section3.1.1: Ctrl0 bit7 is a command,
 * reads as zero; Data0 bit7 (Unconfigured) is the actual state to verify.
 * The polaris vendor driver uses bit7=CONFIGURED and status6=CRC in progress.
 * CRC/flash/fatal status is denied here: discovery may need repeating after
 * such a transition, so no coordinates from the old layout may be emitted.
 */
enum { PM_OK, PM_ARGUMENT, PM_IO, PM_STATUS, PM_VERIFY };
enum { PM_STATUS_BEFORE=1, PM_CONTROL_BEFORE, PM_WRITE,
       PM_CONTROL_AFTER, PM_STATUS_AFTER, PM_READY };
struct polaris_touch_mode {
    void *ctx;
    int (*read)(void *, uint16_t, uint8_t *, size_t);
    int (*write)(void *, uint16_t, uint8_t);
    void (*sleep_ms)(void *, unsigned);
    uint16_t control_reg, status_reg;
    unsigned step, error, io, valid, writes, checks, waited_ms;
    uint8_t status_before, status_after, control_before, control_after, want;
};
static inline int pm_fail(struct polaris_touch_mode *m, unsigned error, int io)
{ m->error=error; m->io=(unsigned)io; return (int)error; }
static inline int pm_status_bad(uint8_t status)
{ return (status & 0x40u) || (status & 15u)>1u; }
static inline int polaris_touch_mode(struct polaris_touch_mode *m)
{
    if (!m) { return PM_ARGUMENT; }
    m->step=m->error=m->io=m->valid=m->writes=m->checks=m->waited_ms=0;
    m->status_before=m->status_after=m->control_before=m->control_after=m->want=0;
    if (!m->read || !m->write || !m->sleep_ms ||
        (m->control_reg & 255u)==255u || (m->status_reg & 255u)==255u ||
        m->control_reg==m->status_reg) { return pm_fail(m,PM_ARGUMENT,0); }
    int e;
    m->step=PM_STATUS_BEFORE;
    e=m->read(m->ctx,m->status_reg,&m->status_before,1);
    if (e) { return pm_fail(m,PM_IO,e); }
    m->valid|=1u;
    if (pm_status_bad(m->status_before)) { return pm_fail(m,PM_STATUS,0); }
    m->step=PM_CONTROL_BEFORE;
    e=m->read(m->ctx,m->control_reg,&m->control_before,1);
    if (e) { return pm_fail(m,PM_IO,e); }
    m->valid|=2u;
    m->want=(uint8_t)((m->control_before & ~3u) | 0x80u);
    if (m->want!=m->control_before) {
        m->step=PM_WRITE; m->writes=1;
        e=m->write(m->ctx,m->control_reg,m->want);
        if (e) { return pm_fail(m,PM_IO,e); }
    }
    for (unsigned i=0;i<6;i++) {
        m->step=PM_CONTROL_AFTER; ++m->checks;
        e=m->read(m->ctx,m->control_reg,&m->control_after,1);
        if (e) { return pm_fail(m,PM_IO,e); }
        m->valid|=4u;
        m->step=PM_STATUS_AFTER;
        e=m->read(m->ctx,m->status_reg,&m->status_after,1);
        if (e) { return pm_fail(m,PM_IO,e); }
        m->valid|=8u;
        if (pm_status_bad(m->status_after)) { return pm_fail(m,PM_STATUS,0); }
        /* Never require Ctrl0 bit7 to echo the configured command. */
        if (!(m->control_after & 3u) && !(m->status_after & 0x80u)) {
            m->step=PM_READY; return PM_OK;
        }
        if (i<5) { m->sleep_ms(m->ctx,20); m->waited_ms+=20; }
    }
    return pm_fail(m,PM_VERIFY,0);
}
#endif

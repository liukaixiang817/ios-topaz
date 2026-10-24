/* SDM845 GMU200MHz/bus lease. Original c7cb50c1 gcc-sdm845.c,
 * gpucc-sdm845.c, clk-alpha-pll.c and clk-branch.c. Never reprogram a PLL.
 * Caller holds CX power, GMU_BCR, CM3_SYSRESET and the existing CXO/GMU
 * clock lease. All mutations are restored only while these are held.
 */
#ifndef POLARIS_A630_BUS_H
#define POLARIS_A630_BUS_H
#ifndef POLARIS_A630_POWER_H
#error Include the Polaris power definitions first
#endif
enum a630_bus_error { A630_BUS_DISABLED, A630_BUS_IO, A630_BUS_LEASE,
    A630_BUS_PLL, A630_BUS_ACK, A630_BUS_TIMEOUT, A630_BUS_READY };
struct a630_bus_snapshot {
    uint32_t error,start_error,stage,changed,restored,restore_error;
    uint32_t pll[5],before[5],live[5],config,command,source,bank,offset,expected,actual,polls;
};
/* Retain GPLL0 as well as its GPU main output. Source5/HID5 divides the
 * inherited600MHz by3, yielding200MHz independently of the even divider.
 * Do not change USER_CTL, OPMODE, PLL rate or any other client's votes. */
static const uint32_t a630_bus_offsets[5]={0x52000,0x52004,0x44038,0x7100c,0x71018};
static const uint32_t a630_bus_masks[5]={1,1u<<15,1,1,1};
struct a630_bus_io {a630_read read;a630_write write;a630_wait_us wait;
    bool (*held)(void *);void *ctx;};
static inline bool a630_bus_read(const struct a630_bus_io *io,struct a630_bus_snapshot *s,
                                unsigned region,uint32_t off,uint32_t *v)
{
    if(!io->held(io->ctx)){s->error=A630_BUS_LEASE;return false;}
    if(io->read(io->ctx,region,off,v))return true;
    s->error=A630_BUS_IO;s->bank=region;s->offset=off;return false;
}
static inline bool a630_bus_write(const struct a630_bus_io *io,struct a630_bus_snapshot *s,
                                 unsigned region,uint32_t off,uint32_t v,uint32_t mask)
{
    uint32_t current;
    if(!a630_bus_read(io,s,region,off,&current))return false;
    v=(current&~mask)|(v&mask);
    if(!io->write(io->ctx,region,off,v)){s->error=A630_BUS_IO;s->bank=region;s->offset=off;return false;}
    if(!a630_bus_read(io,s,region,off,&current))return false;
    if((current^v)&mask){s->error=A630_BUS_ACK;s->bank=region;s->offset=off;s->expected=v;s->actual=current;return false;}
    return true;
}
static inline bool a630_bus_poll(const struct a630_bus_io *io,struct a630_bus_snapshot *s,
                                unsigned region,uint32_t off,uint32_t mask,uint32_t value)
{
    uint32_t actual=0;
    for(unsigned n=0;n<500;n++){
        s->polls++;
        if(!a630_bus_read(io,s,region,off,&actual))return false;
        if((actual&mask)==value)return true;
        io->wait(io->ctx,1);
    }
    s->error=A630_BUS_TIMEOUT;s->bank=region;s->offset=off;s->expected=value;s->actual=actual;return false;
}
static inline bool a630_bus_source(const struct a630_bus_io *io,struct a630_bus_snapshot *s,uint32_t cfg)
{
    if(!a630_bus_write(io,s,1,0x1124,cfg,0x371f))return false;
    uint32_t cmd;
    if(!a630_bus_read(io,s,1,0x1120,&cmd) ||
       !io->write(io->ctx,1,0x1120,cmd|1)) {s->error=A630_BUS_IO;return false;}
    return a630_bus_poll(io,s,1,0x1120,1,0);
}
static inline enum a630_bus_error a630_bus_begin(bool enabled,const struct a630_bus_io *io,
                                                struct a630_bus_snapshot *s)
{
    if(!s)return A630_BUS_IO;
    *s=(struct a630_bus_snapshot){0};
    if(!enabled)return A630_BUS_DISABLED;
    if(!io||!io->read||!io->write||!io->wait||!io->held){s->error=A630_BUS_IO;goto done;}
    s->stage=1;
    /* Fabia PLL: mode,L,USER_CTL_LO,OPMODE,16-bit fractional numerator.
     * Original clk_fabia_pll_enable distinguishes FSM from manual control:
     * FSM needs ACTIVE; OPMODE/output setup is only for the manual path.
     * In either mode require a locked, enabled inherited600MHz source. */
    const uint32_t off[5]={0,4,0xc,0x2c,0x38};
    for(unsigned n=0;n<5;n++)if(!a630_bus_read(io,s,0,off[n],&s->pll[n]))goto done;
    bool fsm=(s->pll[0]&(1u<<20))!=0;
    if((s->pll[0]&0x80000001u)!=0x80000001u ||
       (s->pll[1]&0xffff)!=31 || (s->pll[4]&0xffff)!=0x4000 ||
       (fsm ? !(s->pll[0]&(1u<<30)) : (!(s->pll[2]&1) || s->pll[3]!=1))){
        s->error=A630_BUS_PLL;goto done;
    }
    s->source=0x505;
    for(unsigned n=0;n<5;n++)if(!a630_bus_read(io,s,0,a630_bus_offsets[n],&s->before[n]))goto done;
    if(!a630_bus_read(io,s,1,0x1124,&s->config)||!a630_bus_read(io,s,1,0x1120,&s->command))goto done;
    if((s->config&0x371f)>1 || (s->command&1)){s->error=A630_BUS_LEASE;goto done;}
    s->stage=2;
    for(unsigned n=0;n<5;n++){
        s->changed|=1u<<n;
        if(!a630_bus_write(io,s,0,a630_bus_offsets[n],a630_bus_masks[n],a630_bus_masks[n]))goto done;
        if(!n) {
            if(!a630_bus_poll(io,s,0,0,(1u<<31)|(fsm ? 1u<<30 : 0),
                                      (1u<<31)|(fsm ? 1u<<30 : 0)))goto done;
        } else if(n==1)io->wait(io->ctx,500); /* Original gate2 settling. */
        else if(!a630_bus_poll(io,s,0,a630_bus_offsets[n],1u<<31,0))goto done;
        if(!a630_bus_read(io,s,0,a630_bus_offsets[n],&s->live[n]))goto done;
    }
    s->stage=3;s->changed|=32;
    if(!a630_bus_source(io,s,s->source))goto done;
    s->stage=4;s->error=A630_BUS_READY;
done:
    s->start_error=s->error;return (enum a630_bus_error)s->error;
}
static inline bool a630_bus_end(const struct a630_bus_io *io,struct a630_bus_snapshot *s)
{
    if(!s||!io||!io->held)return false;
    if(!s->changed)return true;
    struct a630_bus_snapshot r=*s;r.error=0;
    /* Never withdraw a source or bus with a live bus master. */
    if(!io->held(io->ctx)){r.error=A630_BUS_LEASE;goto failed;}
    if((s->changed&32)&&!a630_bus_source(io,&r,s->config))goto failed;
    for(int n=4;n>=0;n--)if(s->changed&(1u<<n)){
        if(!a630_bus_write(io,&r,0,a630_bus_offsets[n],s->before[n],a630_bus_masks[n]))goto failed;
        io->wait(io->ctx,10); /* Voted-clock OFF is request-only, as Linux. */
    }
    s->restored=1;s->restore_error=0;return true;
failed:
    s->restored=0;s->restore_error=r.error?r.error:A630_BUS_IO;return false;
}
#endif

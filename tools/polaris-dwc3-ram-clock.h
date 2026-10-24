/* Original SDM845 dwc3_msm_qscratch_reg_init(), MiCode c7cb50c1:
 * CGCTL(QSCRATCH+0x28) bits3/4 enable master clocks for controller RAMs.
 * Keep only our newly asserted requests; never withdraw them under an
 * outstanding endpoint command. No reset, PHY/lane or storage operation.
 */
#ifndef POLARIS_DWC3_RAM_CLOCK_H
#define POLARIS_DWC3_RAM_CLOCK_H
#ifndef POLARIS_DWC3_HS_CLOCK_H
#error Include Polaris HS clock definitions first
#endif
#define PDWC3_RAM_CGCTL 0x28u
#define PDWC3_RAM_MASK 0x18u
enum pdwc3_ram_error { PDWC3_RAM_OK,PDWC3_RAM_ARGUMENT,PDWC3_RAM_UNSAFE,
    PDWC3_RAM_ACK,PDWC3_RAM_BUSY };
struct pdwc3_ram_clock {
    uint32_t error,start_error,stage,before,live,after,attempted,changed,restored;
    uint32_t polls,restore_polls,writes,restore_error,busy_ep,busy_command;
};
static inline bool pdwc3_ram_idle(const struct pdwc3_io *core,struct pdwc3_ram_clock *s)
{
    struct pdwc3_hs_clock check={0};
    if(pdwc3_hs_idle(core,&check))return true;
    s->error=check.error==PDWC3_HS_BUSY?PDWC3_RAM_BUSY:PDWC3_RAM_UNSAFE;
    s->busy_ep=check.busy_ep;s->busy_command=check.busy_command;return false;
}
static inline bool pdwc3_ram_update(const struct pdwc3_io *qs,struct pdwc3_ram_clock *s,
    uint32_t value,uint32_t mask,bool restoring)
{
    uint32_t current=qs->read(qs->ctx,PDWC3_RAM_CGCTL);
    s->writes++;qs->write(qs->ctx,PDWC3_RAM_CGCTL,(current&~mask)|(value&mask));
    for(unsigned n=0;n<PDWC3_COMMAND_POLLS;n++){
        if(restoring)s->restore_polls++;else s->polls++;
        s->after=qs->read(qs->ctx,PDWC3_RAM_CGCTL);
        if(!((s->after^value)&mask))return true;
        qs->wait_us(qs->ctx,1);
    }
    s->error=PDWC3_RAM_ACK;return false;
}
static inline enum pdwc3_ram_error polaris_dwc3_ram_clock_begin(
    const struct pdwc3_io *qs,const struct pdwc3_io *core,bool admitted,
    struct pdwc3_ram_clock *s)
{
    if(!s)return PDWC3_RAM_ARGUMENT;
    *s=(struct pdwc3_ram_clock){.error=PDWC3_RAM_ARGUMENT,.busy_ep=UINT32_MAX};
    if(!pdwc3_hs_io(qs)||!pdwc3_hs_io(core))goto done;
    if(!admitted){s->error=PDWC3_RAM_UNSAFE;goto done;}
    s->stage=1;if(!pdwc3_ram_idle(core,s))goto done;
    s->attempted=1;s->before=qs->read(qs->ctx,PDWC3_RAM_CGCTL);s->after=s->before;
    s->changed=~s->before&PDWC3_RAM_MASK;
    s->stage=2;
    if(s->changed&&!pdwc3_ram_update(qs,s,PDWC3_RAM_MASK,PDWC3_RAM_MASK,false))goto done;
    s->stage=3;s->error=PDWC3_RAM_OK;
done:
    s->live=s->after;s->start_error=s->error;return (enum pdwc3_ram_error)s->error;
}
static inline bool polaris_dwc3_ram_clock_restore(const struct pdwc3_io *qs,
    const struct pdwc3_io *core,struct pdwc3_ram_clock *s)
{
    if(!s)return false;
    s->restored=s->restore_polls=s->restore_error=0;
    if(!pdwc3_hs_io(qs)||!pdwc3_hs_io(core)){s->restore_error=PDWC3_RAM_ARGUMENT;return false;}
    if(!s->attempted||!s->changed){s->restored=1;return true;}
    if(!pdwc3_ram_idle(core,s))goto fail;
    if(!pdwc3_ram_update(qs,s,s->before,s->changed,true))goto fail;
    s->restored=1;s->error=s->start_error;return true;
fail:
    s->restore_error=s->error;return false;
}
#endif

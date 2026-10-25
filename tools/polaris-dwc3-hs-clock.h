/* Original SDM845 dwc3-msm.c CONTROLLER_POST_RESET_EVENT, c7cb50c1:
 * HS/full-speed mode gates PIPE, selects UTMI and software PHY status,
 * waits2us per transition, then ungates PIPE. No PHY/lane/reset writes.
 * Admitted caller owns a halted HS gadget and serializes all commands.
 */
#ifndef POLARIS_DWC3_HS_CLOCK_H
#define POLARIS_DWC3_HS_CLOCK_H
#ifndef POLARIS_DWC3_COMMAND_H
#error Include Polaris DWC3 command definitions first
#endif
#include <stdbool.h>
#define PDWC3_HS_GENERAL 8u
#define PDWC3_HS_PIPE 0xc2c0u
#define PDWC3_HS_PIPE_SUSPHY (1u<<17)
#define PDWC3_HS_SELECT 9u
#define PDWC3_HS_DISABLE (1u << 8)
#define PDWC3_HS_MASK (PDWC3_HS_SELECT | PDWC3_HS_DISABLE)
enum pdwc3_hs_error { PDWC3_HS_OK, PDWC3_HS_ARGUMENT, PDWC3_HS_UNSAFE,
    PDWC3_HS_ACK, PDWC3_HS_BUSY };
struct pdwc3_hs_clock {
    uint32_t error,start_error,stage,before,live,after,attempted,changed,restored;
    uint32_t polls,writes,restore_error,restore_polls,busy_ep,busy_command;
    uint32_t pipe_before,pipe_live,pipe_after,pipe_changed,pipe_polls,pipe_restore_polls;
};
static inline bool pdwc3_hs_io(const struct pdwc3_io *io)
{return io&&io->read&&io->write&&io->wait_us;}
static inline bool pdwc3_hs_idle(const struct pdwc3_io *core,struct pdwc3_hs_clock *s)
{
    uint32_t control=core->read(core->ctx,0xc704),status=core->read(core->ctx,0xc70c);
    uint32_t global=core->read(core->ctx,0xc110);
    if((control&0xc0000000u)||!(status&(1u<<22))||((global>>12)&3)!=2||
       (global&(1u<<11))){s->error=PDWC3_HS_UNSAFE;return false;}
    for(unsigned ep=0;ep<6;ep++){
        uint32_t command=core->read(core->ctx,0xc80c+16*ep);
        if(command&PDWC3_CMDACT){s->busy_ep=ep;s->busy_command=command;
            s->error=PDWC3_HS_BUSY;return false;}
    }
    return true;
}
static inline bool pdwc3_hs_update(const struct pdwc3_io *qs,struct pdwc3_hs_clock *s,
                                 uint32_t value,uint32_t mask,bool restoring)
{
    uint32_t current=qs->read(qs->ctx,PDWC3_HS_GENERAL);
    s->writes++;
    qs->write(qs->ctx,PDWC3_HS_GENERAL,(current&~mask)|(value&mask));
    for(unsigned n=0;n<PDWC3_COMMAND_POLLS;n++){
        if(restoring)s->restore_polls++;else s->polls++;
        s->after=qs->read(qs->ctx,PDWC3_HS_GENERAL);
        if(!((s->after^value)&mask)){qs->wait_us(qs->ctx,2);return true;}
        qs->wait_us(qs->ctx,1);
    }
    s->error=PDWC3_HS_ACK;return false;
}
/* Original core.c dwc3_phy_setup: >1.94a must assert PIPE.SUSPHY
 * after core initialization. Native polaris3.30a has no dis_u3_susphy
 * quirk. This is the digital core interface, no PHY reset or lane write. */
static inline bool pdwc3_hs_pipe_update(const struct pdwc3_io *core,
    struct pdwc3_hs_clock *s,uint32_t value,bool restoring)
{
    uint32_t v=core->read(core->ctx,PDWC3_HS_PIPE);
    core->write(core->ctx,PDWC3_HS_PIPE,
        (v&~PDWC3_HS_PIPE_SUSPHY)|(value&PDWC3_HS_PIPE_SUSPHY));
    for(unsigned n=0;n<PDWC3_COMMAND_POLLS;n++){
        if(restoring)s->pipe_restore_polls++;else s->pipe_polls++;
        s->pipe_after=core->read(core->ctx,PDWC3_HS_PIPE);
        if(!((s->pipe_after^value)&PDWC3_HS_PIPE_SUSPHY))return true;
        core->wait_us(core->ctx,1);
    }
    s->error=PDWC3_HS_ACK;return false;
}
static inline enum pdwc3_hs_error polaris_dwc3_hs_clock_begin(
    const struct pdwc3_io *qs,const struct pdwc3_io *core,bool admitted,
    struct pdwc3_hs_clock *s)
{
    if(!s)return PDWC3_HS_ARGUMENT;
    *s=(struct pdwc3_hs_clock){.error=PDWC3_HS_ARGUMENT,.busy_ep=UINT32_MAX};
    if(!pdwc3_hs_io(qs)||!pdwc3_hs_io(core))goto done;
    if(!admitted){s->error=PDWC3_HS_UNSAFE;goto done;}
    if(!pdwc3_hs_idle(core,s))goto done;
    s->attempted=1;s->before=qs->read(qs->ctx,PDWC3_HS_GENERAL);s->after=s->before;
    /* An inherited disabled PIPE has no admitted running source to borrow. */
    if(s->before&PDWC3_HS_DISABLE){s->error=PDWC3_HS_UNSAFE;goto done;}
    s->changed=((s->before&PDWC3_HS_MASK)!=PDWC3_HS_SELECT);
    if(s->changed){
        s->stage=1;
        if(!pdwc3_hs_update(qs,s,PDWC3_HS_DISABLE,PDWC3_HS_DISABLE,false))goto done;
        s->stage=2;
        if(!pdwc3_hs_update(qs,s,PDWC3_HS_SELECT,PDWC3_HS_SELECT,false))goto done;
        s->stage=3;
        if(!pdwc3_hs_update(qs,s,0,PDWC3_HS_DISABLE,false))goto done;
    }
    s->stage=4;s->pipe_before=core->read(core->ctx,PDWC3_HS_PIPE);
    s->pipe_after=s->pipe_before;s->pipe_changed=!(s->pipe_before&PDWC3_HS_PIPE_SUSPHY);
    if(s->pipe_changed && !pdwc3_hs_pipe_update(core,s,PDWC3_HS_PIPE_SUSPHY,false))goto done;
    s->stage=5;s->error=PDWC3_HS_OK;
done:
    s->pipe_live=s->pipe_after;s->live=s->after;s->start_error=s->error;return (enum pdwc3_hs_error)s->error;
}
static inline bool polaris_dwc3_hs_clock_restore(const struct pdwc3_io *qs,
    const struct pdwc3_io *core,struct pdwc3_hs_clock *s)
{
    if(!s)return false;
    s->restored=s->restore_polls=s->restore_error=0;
    if(!pdwc3_hs_io(qs)||!pdwc3_hs_io(core)){s->restore_error=PDWC3_HS_ARGUMENT;return false;}
    if(!s->attempted||(!s->changed&&!s->pipe_changed)){s->restored=1;return true;}
    /* A timed-out command may still own the PIPE clock. Retain the source;
     * never switch or gate it underneath that command, even while halted. */
    if(!pdwc3_hs_idle(core,s))goto fail;
    if(s->changed && (!pdwc3_hs_update(qs,s,PDWC3_HS_DISABLE,PDWC3_HS_DISABLE,true)||
       !pdwc3_hs_update(qs,s,s->before,PDWC3_HS_SELECT,true)||
       !pdwc3_hs_update(qs,s,s->before,PDWC3_HS_DISABLE,true)))goto fail;
    if(s->pipe_changed && !pdwc3_hs_pipe_update(core,s,s->pipe_before,true))goto fail;
    s->restored=1;s->error=s->start_error;return true;
fail:
    s->restore_error=s->error;return false;
}
#endif

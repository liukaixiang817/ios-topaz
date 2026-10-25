/* Original SDM845 HFI_USE_REG post-start DCVS and GPU OOB lifetime.
 * MiCode c7cb50c1 gmu_start/a6xx_gmu_dcvs_nohfi and kgsl_gmu.h.
 * Requires all five cold HFI ACKs; default257MHz/perf1, DDRbus4.
 */
#ifndef POLARIS_A630_POST_H
#define POLARIS_A630_POST_H
#include "polaris-a630-channel.h"
#define A630_POST_ACK 0x8ff0u
#define A630_POST_PERF 0x8ff4u
#define A630_POST_BW 0x8ff8u
#define A630_POST_RETURN 0x8ffcu
struct a630_post_snapshot {
    uint32_t error,stage,offset,expected,actual,dcvs_requested,dcvs_done;
    uint32_t gpu_requested,gpu_ready,gpu_released,dcvs_return,status,sp_status;
};
static inline bool a630_post_oob(const struct a630_channel_io *io,
    struct a630_channel_snapshot *r,unsigned set,unsigned ack)
{
    uint32_t before;
    if(!a630_ch_read(io,r,2,A630_CH_INTR_INFO,&before))return false;
    if(before&(1u<<ack)){r->error=A630_CH_PROTOCOL;r->actual=before;return false;}
    if(!a630_ch_write(io,r,2,A630_CH_INTR_SET,1u<<set)||
       !a630_ch_poll(io,r,A630_CH_INTR_INFO,1u<<ack,1u<<ack,10000))return false;
    return a630_ch_write(io,r,2,A630_CH_INTR_CLEAR,1u<<ack);
}
static inline bool a630_post_begin(bool enabled,const struct a630_channel_io *io,
    const struct a630_channel_snapshot *h,struct a630_post_snapshot *s)
{
    if(!s)return false;*s=(struct a630_post_snapshot){0};if(!enabled)return false;
    if(!io||!io->owned||!io->read||!io->write||!io->sync||!io->wait||!h||h->error!=A630_CH_READY||h->tables_done!=7||h->acks!=5){
        s->error=A630_CH_ARGUMENT;return false;}
    struct a630_channel_snapshot r={0};s->stage=1;
    if(!a630_ch_write(io,&r,2,A630_POST_ACK,0)||
       !a630_ch_write(io,&r,2,A630_POST_PERF,0x30000001)||
       !a630_ch_write(io,&r,2,A630_POST_BW,4))goto failed;
    s->dcvs_requested=1;
    if(!a630_post_oob(io,&r,23,31)||
       !a630_ch_read(io,&r,2,A630_POST_RETURN,&s->dcvs_return))goto failed;
    if(s->dcvs_return){r.error=A630_CH_FW_ERROR;r.actual=s->dcvs_return;goto failed;}
    if(!a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<31))goto failed;
    s->dcvs_done=1;s->stage=2;s->gpu_requested=1;
    if(!a630_post_oob(io,&r,16,24)||
       !a630_ch_read(io,&r,2,A630_CH_SPTP_STATUS,&s->sp_status))goto failed;
    if(s->sp_status&0xc4){r.error=A630_CH_RUNNING;r.actual=s->sp_status;goto failed;}
    s->gpu_ready=1;s->stage=3;s->error=A630_CH_READY;return true;
failed:
    s->error=r.error?r.error:A630_CH_IO;s->offset=r.failed_offset;
    s->expected=r.expected;s->actual=r.actual;return false;
}
/* Only after CP and all rendering engines are proven idle/halted. Native
 * clear is a write-only request; never call it proof of GX power-off. */
static inline bool a630_post_end(const struct a630_channel_io *io,
    struct a630_post_snapshot *s)
{
    if(!io||!s||!io->owned||!io->write||!io->sync)return false;
    struct a630_channel_snapshot r={0};
    if(s->gpu_requested&&!a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<24))return false;
    if(s->dcvs_requested&&!a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<31))return false;
    s->gpu_released=1;return true;
}
#endif

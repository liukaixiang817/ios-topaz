/* Original A630 HFI_USE_REG bootstrap, from MiCode c7cb50c1
 * adreno_a6xx.c and kgsl_hfi.{c,h}. Mode7 probes INIT/FW_VER.
 * Mode8 completes original PERF/BW/TEST; no SQE/CP/3D/rendering is admitted.
 * Caller owns powered/clocks/bus/SMMU and a freshly booted BABEFACE GMU.
 * Shared HFI/dump memory MUST be Normal noncacheable on both processors;
 * cleaning a cached header that the GMU also updates is not sufficient.
 */
#ifndef POLARIS_A630_CHANNEL_H
#define POLARIS_A630_CHANNEL_H
#include "polaris-a630-hfi.h"
#include "polaris-a630-tables.h"
#define A630_CH_HFI_IOVA 0x60000000u
#define A630_CH_DUMP_IOVA 0x60004000u
#define A630_CH_INTR_SET 0x14650u
#define A630_CH_INTR_CLEAR 0x14644u
#define A630_CH_INTR_INFO 0x14648u
#define A630_CH_INTR_MASK 0x1464cu
#define A630_CH_BOOT_OPTION 0x8fe0u
#define A630_CH_GX_VOTE 0x8fe4u
#define A630_CH_MX_VOTE 0x8fe8u
#define A630_CH_SPTP_CONTROL 0x204u
#define A630_CH_SPTP_STATUS 0x14340u
#define A630_CH_POWER_STATE 0x143b0u
#define A630_CH_HFI_INIT 0x14618u
#define A630_CH_HFI_STATUS 0x14600u
#define A630_CH_AO_BUSY 0x24c30u
#define A630_CH_RSC_REQUEST 0x24c1cu
#define A630_CH_RSC_STATUS 0x23010u
#define A630_CH_RSC_BUSY 0x23404u
#define A630_CH_FW_FAULTS 0x00ff0000u
enum a630_channel_error {A630_CH_DISABLED,A630_CH_ARGUMENT,A630_CH_IO,
    A630_CH_LEASE,A630_CH_RUNNING,A630_CH_TIMEOUT,A630_CH_PROTOCOL,
    A630_CH_FW_ERROR,A630_CH_READY};
struct a630_channel_io {
    bool (*owned)(void *);a630_read read;a630_write write;
    bool (*sync)(void *);a630_wait_us wait;void *ctx;
};
struct a630_channel_snapshot {
    uint32_t error,start_error,stage,failed_offset,expected,actual,polls;
    uint32_t gx_requested,sptp_requested,hfi_requested,irq_saved,irq_before;
    uint32_t gx_before,retention_attempted,slumber,restore_error,restored;
    uint32_t restore_offset,restore_expected,restore_actual;
    uint32_t status,sp_status,power_state,commands,acks,version,last_id,async_messages;
    uint32_t response[4],cmd_read,cmd_write,rsp_read,rsp_write;
    uint32_t full_requested,tables_done,slumber_stage,rsc_requested,rsc_before,rsc_status;
};
static inline bool a630_ch_owned(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s)
{
    if(!io->owned(io->ctx)){s->error=A630_CH_LEASE;return false;}return true;
}
static inline bool a630_ch_read(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s,unsigned bank,uint32_t off,uint32_t *v)
{
    if(!a630_ch_owned(io,s))return false;
    if(io->read(io->ctx,bank,off,v))return true;
    s->error=A630_CH_IO;s->failed_offset=off;return false;
}
static inline bool a630_ch_write(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s,unsigned bank,uint32_t off,uint32_t v)
{
    if(!a630_ch_owned(io,s))return false;
    if(!io->write(io->ctx,bank,off,v)||!io->sync(io->ctx)){
        s->error=A630_CH_IO;s->failed_offset=off;return false;
    }return true;
}
static inline bool a630_ch_poll(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s,uint32_t off,uint32_t value,uint32_t mask,
    unsigned iterations)
{
    uint32_t actual=0;
    for(unsigned n=0;n<iterations;n++){
        s->polls++;
        if(!a630_ch_read(io,s,2,off,&actual))return false;
        if((actual&mask)==value)return true;
        io->wait(io->ctx,10);
    }
    s->error=A630_CH_TIMEOUT;s->failed_offset=off;s->expected=value;s->actual=actual;return false;
}
static inline bool a630_ch_oob(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s)
{
    uint32_t status;
    if(!a630_ch_read(io,s,2,A630_CH_INTR_INFO,&status))return false;
    if(status&((1u<<30)|A630_CH_FW_FAULTS)){
        s->error=A630_CH_PROTOCOL;s->failed_offset=A630_CH_INTR_INFO;s->actual=status;return false;
    }
    if(!a630_ch_write(io,s,2,A630_CH_INTR_SET,1u<<22))return false;
    bool ack=a630_ch_poll(io,s,A630_CH_INTR_INFO,1u<<30,1u<<30,10000);
    if(!ack)return false;
    if(!a630_ch_read(io,s,2,A630_CH_INTR_INFO,&status))return false;
    if(status&A630_CH_FW_FAULTS){s->error=A630_CH_FW_ERROR;s->actual=status;return false;}
    return a630_ch_write(io,s,2,A630_CH_INTR_CLEAR,1u<<30);
}
/* Serialized cold command transport. No stale or unrelated ACK is consumed
 * as success. CPU publication and the doorbell have a full DMA barrier. */
static inline bool a630_ch_command(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s,void *memory,uint32_t *command,unsigned words)
{
    if(!command||!words||words>A630_HFI_MAX_WORDS){s->error=A630_CH_ARGUMENT;return false;}
    if(!a630_ch_owned(io,s)||!io->sync(io->ctx)){if(!s->error)s->error=A630_CH_IO;return false;}
    struct a630_hfi_queue *q=a630_hfi_queue(memory,A630_HFI_BYTES,A630_CH_HFI_IOVA,0);
    struct a630_hfi_queue *r=a630_hfi_queue(memory,A630_HFI_BYTES,A630_CH_HFI_IOVA,1);
    if(!q||!r||__atomic_load_n(&q->read_index,__ATOMIC_ACQUIRE)!=
                   __atomic_load_n(&q->write_index,__ATOMIC_ACQUIRE)){
        s->error=A630_CH_PROTOCOL;return false;
    }
    uint32_t header=command[0];s->last_id=header&255;
    if(a630_hfi_push(memory,A630_HFI_BYTES,A630_CH_HFI_IOVA,command,words)!=(int)words){
        s->error=A630_CH_PROTOCOL;return false;
    }
    s->commands++;
    if(!io->sync(io->ctx)||!a630_ch_write(io,s,2,A630_CH_INTR_SET,1)){
        if(!s->error)s->error=A630_CH_IO;return false;
    }
    for(unsigned n=0;n<100000;n++){
        uint32_t status;
        if(!a630_ch_read(io,s,2,A630_CH_INTR_INFO,&status)||!io->sync(io->ctx)){
            if(!s->error)s->error=A630_CH_IO;return false;
        }
        s->status=status;s->polls++;
        if(status&A630_CH_FW_FAULTS){s->error=A630_CH_FW_ERROR;s->actual=status;return false;}
        uint32_t message[A630_HFI_MAX_WORDS];
        int got=a630_hfi_pop(memory,A630_HFI_BYTES,A630_CH_HFI_IOVA,1,message,A630_HFI_MAX_WORDS);
        s->cmd_read=__atomic_load_n(&q->read_index,__ATOMIC_ACQUIRE);
        s->cmd_write=__atomic_load_n(&q->write_index,__ATOMIC_ACQUIRE);
        s->rsp_read=__atomic_load_n(&r->read_index,__ATOMIC_ACQUIRE);
        s->rsp_write=__atomic_load_n(&r->write_index,__ATOMIC_ACQUIRE);
        if(got<0){s->error=A630_CH_PROTOCOL;return false;}
        if(got){
            for(unsigned k=0;k<4;k++)s->response[k]=k<(unsigned)got?message[k]:0;
            if(!io->sync(io->ctx)||!a630_ch_write(io,s,2,A630_CH_INTR_CLEAR,1)){
                if(!s->error)s->error=A630_CH_IO;return false;
            }
            if((message[0]&255)==100){
                if(got<2){s->error=A630_CH_PROTOCOL;return false;}
                s->error=A630_CH_FW_ERROR;s->actual=message[1];return false;
            }
            if((message[0]&255)==101 && ((message[0]>>16)&15)==1 &&
                ++s->async_messages<=16)continue;
            if(got<3||(message[0]&255)!=126||((message[0]>>16)&15)!=2||
                (message[1]&0xfff000ffu)!=(header&0xfff000ffu)||
                s->cmd_read!=s->cmd_write){s->error=A630_CH_PROTOCOL;return false;}
            if(message[2]){s->error=A630_CH_FW_ERROR;s->actual=message[2];return false;}
            if(s->last_id==1){
                if(got<4){s->error=A630_CH_PROTOCOL;return false;}
                s->version=message[3];
                if((s->version>>28)!=1||((s->version>>16)&4095)<1){
                    s->error=A630_CH_PROTOCOL;return false;
                }
            }
            s->acks++;return true;
        }
        io->wait(io->ctx,50);
    }
    s->error=A630_CH_TIMEOUT;return false;
}
static inline bool a630_channel_probe_complete(bool exact_board,bool normal_NC_ready,bool full,
    const struct a630_channel_io *io,void *memory,struct a630_channel_snapshot *s)
{
    if(!s)return false;*s=(struct a630_channel_snapshot){0};
    if(!exact_board)return false;
    s->full_requested=full;
    if(!normal_NC_ready||!io||!io->owned||!io->read||!io->write||!io->sync||!io->wait||
       !a630_hfi_memory(memory,A630_HFI_BYTES,A630_CH_HFI_IOVA)){
        s->error=A630_CH_ARGUMENT;goto done;
    }
    uint32_t reset,fw,state;
    s->stage=1;
    if(!a630_ch_read(io,s,2,0x14000,&reset)||!a630_ch_read(io,s,2,0x14070,&fw)||
       !a630_ch_read(io,s,2,A630_CH_HFI_STATUS,&state)||
       !a630_ch_read(io,s,1,0x100c,&s->gx_before))goto done;
    if(reset||fw!=0xbabeface||state||s->gx_before&0x80000000u){s->error=A630_CH_RUNNING;goto done;}
    if(!a630_ch_read(io,s,2,A630_CH_INTR_MASK,&s->irq_before))goto done;
    s->irq_saved=1;
    /* Polling adapter: do not deliver an unhandled HFI/OOB IRQ to XNU. */
    if(!a630_ch_write(io,s,2,A630_CH_INTR_MASK,UINT32_MAX))goto done;
    s->stage=2;
    if(!a630_ch_write(io,s,2,A630_CH_BOOT_OPTION,0)||
       !a630_ch_write(io,s,2,A630_CH_GX_VOTE,3)||
       !a630_ch_write(io,s,2,A630_CH_MX_VOTE,3))goto done;
    s->gx_requested=1;
    /* Keep the register-mode boot request asserted while initializing HFI,
     * as in the original driver. Slumber/error cleanup releases it. */
    if(!a630_ch_oob(io,s))goto done;
    s->stage=3;s->sptp_requested=1;
    if(!a630_ch_write(io,s,2,A630_CH_SPTP_CONTROL,0x778000)||
       !a630_ch_poll(io,s,A630_CH_SPTP_STATUS,8,8,1000))goto done;
    if(!a630_ch_read(io,s,2,A630_CH_SPTP_STATUS,&s->sp_status))goto done;
    s->stage=4;s->hfi_requested=1;
    if(!a630_ch_write(io,s,2,A630_CH_HFI_INIT,1)||
       !a630_ch_poll(io,s,A630_CH_HFI_STATUS,1,1,10000))goto done;
    s->stage=5;
    uint32_t init[5]={0,0,A630_CH_DUMP_IOVA,A630_HFI_BYTES,1};
    a630_hfi_header(0,5,0,1,&init[0]);
    if(!a630_ch_command(io,s,memory,init,5))goto done;
    s->stage=6;
    uint32_t version[2]={0,0x10010000};a630_hfi_header(1,2,0,2,&version[0]);
    if(!a630_ch_command(io,s,memory,version,2))goto done;
    if(full){
        uint32_t perf[A630_PERF_WORDS],bw[A630_BW_WORDS],test[1];
        if(!a630_hfi_tables(perf,bw,3,4)){s->error=A630_CH_ARGUMENT;goto done;}
        s->stage=8;
        if(!a630_ch_command(io,s,memory,perf,A630_PERF_WORDS))goto done;
        s->tables_done|=1;s->stage=9;
        if(!a630_ch_command(io,s,memory,bw,A630_BW_WORDS))goto done;
        s->tables_done|=2;s->stage=10;
        a630_hfi_header(5,1,0,5,&test[0]);
        if(!a630_ch_command(io,s,memory,test,1))goto done;
        s->tables_done|=4;s->stage=11;
    }else s->stage=7;
    s->error=A630_CH_READY;
done:
    s->start_error=s->error;return s->error==A630_CH_READY;
}
static inline bool a630_channel_probe(bool exact_board,bool normal_NC_ready,
    const struct a630_channel_io *io,void *memory,struct a630_channel_snapshot *s)
{return a630_channel_probe_complete(exact_board,normal_NC_ready,false,io,memory,s);}
/* Original register-mode slumber before containment. An uncertain GX state
 * MUST retain all mappings, clocks and power, even if CM3 is then reset. */
static inline bool a630_channel_slumber(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s)
{
    if(!s->gx_requested)return true;
    struct a630_channel_snapshot r=*s;r.error=0;r.failed_offset=r.expected=r.actual=0;
    if(s->full_requested && s->tables_done!=7){
        r.error=A630_CH_PROTOCOL;goto failed;
    }
    s->slumber_stage=1;
    if(!a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<30))goto failed;
    if(!a630_ch_write(io,&r,2,0x14100,0))goto failed;
    if(s->sptp_requested){
        uint32_t gx;
        if(!a630_ch_read(io,&r,1,0x100c,&gx))goto failed;
        s->retention_attempted=1;
        if(!a630_ch_write(io,&r,1,0x100c,gx|(1u<<11))||
           !a630_ch_write(io,&r,2,A630_CH_SPTP_CONTROL,0x778001)||
           !a630_ch_poll(io,&r,A630_CH_SPTP_STATUS,4,4,1000))goto failed;
    }
    s->slumber_stage=2;
    if(!a630_ch_write(io,&r,2,A630_CH_BOOT_OPTION,1)||
       !a630_ch_write(io,&r,2,A630_CH_GX_VOTE,s->tables_done==7?A630_NATIVE_PERF_INDEX:0)||
       !a630_ch_write(io,&r,2,A630_CH_MX_VOTE,s->tables_done==7?A630_NATIVE_BUS_INDEX:0)||!a630_ch_oob(io,&r)||
       !a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<30)||
       !a630_ch_read(io,&r,2,A630_CH_POWER_STATE,&s->power_state)||
       !a630_ch_read(io,&r,2,A630_CH_SPTP_STATUS,&s->sp_status)||
       !a630_ch_write(io,&r,2,0x24c40,0))goto failed;
    if(s->power_state!=15){r.error=A630_CH_PROTOCOL;
        r.failed_offset=A630_CH_POWER_STATE;r.expected=15;r.actual=s->power_state;goto failed;}
    if(s->full_requested){
        s->slumber_stage=3;
        if(!a630_ch_poll(io,&r,A630_CH_AO_BUSY,0,1u<<30,1000))goto failed;
        s->slumber_stage=4;
        if(!a630_ch_poll(io,&r,A630_CH_RSC_BUSY,0,UINT32_MAX,10000)||
           !a630_ch_read(io,&r,2,A630_CH_RSC_STATUS,&s->rsc_before))goto failed;
        s->rsc_requested=1;
        if(!a630_ch_write(io,&r,2,A630_CH_RSC_REQUEST,1)||
           !a630_ch_poll(io,&r,A630_CH_RSC_STATUS,1u<<16,1u<<16,10000)||
           !a630_ch_read(io,&r,2,A630_CH_RSC_STATUS,&s->rsc_status)||
           !a630_ch_write(io,&r,2,A630_CH_RSC_REQUEST,0))goto failed;
        s->slumber_stage=5;
        if(!a630_ch_poll(io,&r,A630_CH_SPTP_STATUS,0xc0,0xc0,10000)||
           !a630_ch_read(io,&r,2,A630_CH_SPTP_STATUS,&s->sp_status))goto failed;
    }
    if((s->sp_status&0xc0)!=0xc0){
        r.error=A630_CH_PROTOCOL;r.failed_offset=A630_CH_SPTP_STATUS;r.expected=0xc0;r.actual=s->sp_status;goto failed;
    }
    s->slumber_stage=6;s->slumber=1;return true;
failed:
    s->restore_error=r.error?r.error:A630_CH_IO;s->restore_offset=r.failed_offset;
    s->restore_expected=r.expected;s->restore_actual=r.actual;return false;
}
static inline bool a630_channel_restore(const struct a630_channel_io *io,
    struct a630_channel_snapshot *s)
{
    struct a630_channel_snapshot r=*s;r.error=0;r.failed_offset=r.expected=r.actual=0;
    uint32_t reset,bcr,gx;
    if(s->gx_requested&&!s->slumber){r.error=A630_CH_RUNNING;goto failed;}
    if(!a630_ch_read(io,&r,2,0x14000,&reset)||!a630_ch_read(io,&r,1,0x111c,&bcr)||
       !a630_ch_read(io,&r,1,0x100c,&gx))goto failed;
    if(reset!=1||!(bcr&1)||gx&0x80000000u){r.error=A630_CH_RUNNING;goto failed;}
    if(s->retention_attempted){
        uint32_t want=(gx&~(1u<<11))|(s->gx_before&(1u<<11)),actual;
        if(!a630_ch_write(io,&r,1,0x100c,want)||
           !a630_ch_read(io,&r,1,0x100c,&actual))goto failed;
        if((actual&(1u<<11))!=(want&(1u<<11))){r.error=A630_CH_PROTOCOL;
            r.failed_offset=0x100c;r.expected=want;r.actual=actual;goto failed;}
    }
    if(s->irq_saved&&!a630_ch_write(io,&r,2,A630_CH_INTR_MASK,s->irq_before))goto failed;
    s->restored=1;return true;
failed:
    s->restore_error=r.error?r.error:A630_CH_IO;s->restore_offset=r.failed_offset;
    s->restore_expected=r.expected;s->restore_actual=r.actual;return false;
}
#endif

/* A630 original32KiB GMU boot, not GPU3D readiness. MiCode c7cb50c1
 * adreno_a6xx.c:_load_gmu_rpmh_ucode/a6xx_gmu_fw_start/a6xx_gmu_start.
 * Caller owns CX/200MHz/bus/SMMU, resident HFI, halted3D and CM3 reset.
 * No OOB/GX request, HFI start, TZ authentication or CP command is sent.
 * A fresh BABEFACE is the only firmware-boot success criterion.
 */
#ifndef POLARIS_A630_BOOT_H
#define POLARIS_A630_BOOT_H
#ifndef POLARIS_A630_POWER_H
#error Include the Polaris register callbacks first
#endif
#define A630_BOOT_PROFILE 48u
struct a630_boot_register {unsigned bank;uint32_t offset,value,mask;};
static const struct a630_boot_register a630_boot_profile[A630_BOOT_PROFILE]={
    {2,0x23010,0x01000000,0x01000000}, /* A6XX_GPU_RSCC_RSC_STATUS0_DRV0 */
    {2,0x2302c,0x00000001,0xffffffff}, /* A6XX_RSCC_PDC_SLAVE_ID_DRV0 */
    {2,0x23038,0x00000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_DATA */
    {2,0x23034,0x00000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_ADDR */
    {2,0x23040,0x00000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_DATA+2 */
    {2,0x2303c,0x00000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_ADDR+2 */
    {2,0x23048,0x80000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_DATA+4 */
    {2,0x23044,0x00000000,0xffffffff}, /* A6XX_RSCC_HIDDEN_TCS_CMD0_ADDR+4 */
    {2,0x23400,0x00000000,0xffffffff}, /* A6XX_RSCC_OVERRIDE_START_ADDR */
    {2,0x23020,0x00004520,0xffffffff}, /* A6XX_RSCC_PDC_SEQ_START_ADDR */
    {2,0x23024,0x00004510,0xffffffff}, /* A6XX_RSCC_PDC_MATCH_VALUE_LO */
    {2,0x23028,0x00004514,0xffffffff}, /* A6XX_RSCC_PDC_MATCH_VALUE_HI */
    {2,0x23600,0xa7a506a0,0xffffffff}, /* A6XX_RSCC_SEQ_MEM_0_DRV0 */
    {2,0x23604,0xa1e6a6e7,0xffffffff}, /* A6XX_RSCC_SEQ_MEM_0_DRV0+1 */
    {2,0x23608,0xa2e081e1,0xffffffff}, /* A6XX_RSCC_SEQ_MEM_0_DRV0+2 */
    {2,0x2360c,0xe9a982e2,0xffffffff}, /* A6XX_RSCC_SEQ_MEM_0_DRV0+3 */
    {2,0x23610,0x0020e8a8,0xffffffff}, /* A6XX_RSCC_SEQ_MEM_0_DRV0+4 */
    {4,0x280000,0xfebea1e1,0xffffffff}, /* PDC_GPU_SEQ_MEM_0 */
    {4,0x280004,0xa5a4a3a2,0xffffffff}, /* PDC_GPU_SEQ_MEM_0+1 */
    {4,0x280008,0x8382a6e0,0xffffffff}, /* PDC_GPU_SEQ_MEM_0+2 */
    {4,0x28000c,0xbce3e284,0xffffffff}, /* PDC_GPU_SEQ_MEM_0+3 */
    {4,0x280010,0x002081fc,0xffffffff}, /* PDC_GPU_SEQ_MEM_0+4 */
    {4,0x855cc,0x00000007,0xffffffff}, /* PDC_GPU_TCS1_CMD_ENABLE_BANK */
    {4,0x855d0,0x00000000,0xffffffff}, /* PDC_GPU_TCS1_CMD_WAIT_FOR_CMPL_BANK */
    {4,0x855c8,0x00000000,0xffffffff}, /* PDC_GPU_TCS1_CONTROL */
    {4,0x855d4,0x00010108,0xffffffff}, /* PDC_GPU_TCS1_CMD0_MSGID */
    {4,0x855d8,0x00030010,0xffffffff}, /* PDC_GPU_TCS1_CMD0_ADDR */
    {4,0x855dc,0x00000001,0xffffffff}, /* PDC_GPU_TCS1_CMD0_DATA */
    {4,0x855e4,0x00010108,0xffffffff}, /* PDC_GPU_TCS1_CMD0_MSGID+4 */
    {4,0x855e8,0x00030000,0xffffffff}, /* PDC_GPU_TCS1_CMD0_ADDR+4 */
    {4,0x855ec,0x00000000,0xffffffff}, /* PDC_GPU_TCS1_CMD0_DATA+4 */
    {4,0x855f4,0x00010108,0xffffffff}, /* PDC_GPU_TCS1_CMD0_MSGID+8 */
    {4,0x855f8,0x00030080,0xffffffff}, /* PDC_GPU_TCS1_CMD0_ADDR+8 */
    {4,0x855fc,0x00000000,0xffffffff}, /* PDC_GPU_TCS1_CMD0_DATA+8 */
    {4,0x8575c,0x00000007,0xffffffff}, /* PDC_GPU_TCS3_CMD_ENABLE_BANK */
    {4,0x85760,0x00000000,0xffffffff}, /* PDC_GPU_TCS3_CMD_WAIT_FOR_CMPL_BANK */
    {4,0x85758,0x00000000,0xffffffff}, /* PDC_GPU_TCS3_CONTROL */
    {4,0x85764,0x00010108,0xffffffff}, /* PDC_GPU_TCS3_CMD0_MSGID */
    {4,0x85768,0x00030010,0xffffffff}, /* PDC_GPU_TCS3_CMD0_ADDR */
    {4,0x8576c,0x00000002,0xffffffff}, /* PDC_GPU_TCS3_CMD0_DATA */
    {4,0x85774,0x00010108,0xffffffff}, /* PDC_GPU_TCS3_CMD0_MSGID+4 */
    {4,0x85778,0x00030000,0xffffffff}, /* PDC_GPU_TCS3_CMD0_ADDR+4 */
    {4,0x8577c,0x00000003,0xffffffff}, /* PDC_GPU_TCS3_CMD0_DATA+4 */
    {4,0x85784,0x00010108,0xffffffff}, /* PDC_GPU_TCS3_CMD0_MSGID+8 */
    {4,0x85788,0x00030080,0xffffffff}, /* PDC_GPU_TCS3_CMD0_ADDR+8 */
    {4,0x8578c,0x00000003,0xffffffff}, /* PDC_GPU_TCS3_CMD0_DATA+8 */
    {4,0x84520,0x00000000,0xffffffff}, /* PDC_GPU_SEQ_START_ADDR */
    {4,0x84500,0x80000001,0x80000001}, /* PDC_GPU_ENABLE_PDC */
};
struct a630_boot_io {a630_read read;a630_write write;a630_wait_us wait;
    bool (*owned)(void *);bool (*sync)(void *);void *ctx;};
enum a630_boot_error {A630_BOOT_DISABLED,A630_BOOT_IO,A630_BOOT_LEASE,
    A630_BOOT_ACK,A630_BOOT_RUNNING,A630_BOOT_TIMEOUT,A630_BOOT_READY};
struct a630_boot_snapshot {
    uint32_t error,start_error,stage,changed,restored,restore_error,started,stopped;
    uint32_t before[A630_BOOT_PROFILE],fw,bcr,reset,busy,gx,hfi;
    uint32_t failed_bank,failed_offset,expected,actual,polls;
};
static inline bool a630_boot_read(const struct a630_boot_io *io,struct a630_boot_snapshot *s,
                                 unsigned bank,uint32_t off,uint32_t *v)
{
    if(!io->owned(io->ctx)){s->error=A630_BOOT_LEASE;return false;}
    if(io->read(io->ctx,bank,off,v))return true;
    s->error=A630_BOOT_IO;s->failed_bank=bank;s->failed_offset=off;return false;
}
static inline bool a630_boot_set(const struct a630_boot_io *io,struct a630_boot_snapshot *s,
                                unsigned bank,uint32_t off,uint32_t v,uint32_t mask)
{
    uint32_t actual;
    if(!a630_boot_read(io,s,bank,off,&actual))return false;
    v=(actual&~mask)|(v&mask);
    if(!io->write(io->ctx,bank,off,v)){
        s->error=A630_BOOT_IO;s->failed_bank=bank;s->failed_offset=off;return false;
    }
    for(unsigned n=0;n<500;n++){
        if(!a630_boot_read(io,s,bank,off,&actual))return false;
        if(!((actual^v)&mask))return true;
        io->wait(io->ctx,1);
    }
    s->error=A630_BOOT_ACK;s->failed_bank=bank;s->failed_offset=off;
    s->expected=v;s->actual=actual;return false;
}
static inline bool a630_boot_poll(const struct a630_boot_io *io,struct a630_boot_snapshot *s,
                                 unsigned bank,uint32_t off,uint32_t value,uint32_t mask,unsigned limit)
{
    uint32_t actual=0;
    for(unsigned n=0;n<limit;n++){
        s->polls++;
        if(!a630_boot_read(io,s,bank,off,&actual))return false;
        if((actual&mask)==value)return true;
        io->wait(io->ctx,1);
    }
    s->error=A630_BOOT_TIMEOUT;s->failed_bank=bank;s->failed_offset=off;
    s->expected=value;s->actual=actual;return false;
}
/* Set up sequencers while CM3 is held. These are the original A630 TCS
 * addresses/values, not SC7280's layout. This profile only configures them;
 * it does not issue a rail vote or trigger the sequencers. */
static inline bool a630_boot_configure(const struct a630_boot_io *io,struct a630_boot_snapshot *s)
{
    *s=(struct a630_boot_snapshot){0};s->stage=1;
    if(!io||!io->read||!io->write||!io->wait||!io->owned||!io->sync){s->error=A630_BOOT_IO;goto done;}
    if(!a630_boot_read(io,s,2,0x14000,&s->reset)||
       !a630_boot_read(io,s,2,0x14070,&s->fw)||
       !a630_boot_read(io,s,2,0x14600,&s->hfi)||
       !a630_boot_read(io,s,2,0x23404,&s->busy)||
       !a630_boot_read(io,s,1,0x100c,&s->gx))goto done;
    if(s->reset!=1||s->fw==0xbabeface||(s->hfi&1)||s->busy||(s->gx&0x80000000u)){s->error=A630_BOOT_RUNNING;goto done;}
    for(unsigned n=0;n<A630_BOOT_PROFILE;n++){
        const struct a630_boot_register *r=&a630_boot_profile[n];
        if(!a630_boot_read(io,s,r->bank,r->offset,&s->before[n]))goto done;
    }
    s->stage=2;s->changed=A630_BOOT_PROFILE;
    if(!a630_boot_set(io,s,4,0x84500,0,0x80000001))goto done;
    for(unsigned n=0;n<A630_BOOT_PROFILE;n++){
        const struct a630_boot_register *r=&a630_boot_profile[n];
        if(!a630_boot_set(io,s,r->bank,r->offset,r->value,r->mask))goto done;
    }
    if(!io->sync(io->ctx)){s->error=A630_BOOT_IO;goto done;}
    s->stage=3;return true;
done:
    s->start_error=s->error;return false;
}
/* Image must have just been copied and read back after BCR release; the
 * caller verifies its hash and actual SMMU/HFI allocation before invoking.
 * The HFI contents are clean/resident. No HFI/GX enable follows here. */
static inline bool a630_boot_start(const struct a630_boot_io *io,struct a630_boot_snapshot *s)
{
    if(s->stage!=3||s->error)return false;
    s->stage=4;
    const struct a630_boot_register config[]={
        {2,0x14730,1,0xffffffff}, /* GENERAL_7: TCM retention */
        {2,0x14070,0,0xffffffff}, /* Fresh FW_INIT_RESULT */
        {2,0x14004,2,0xffffffff}, /* Original TCM_BOOT enum */
        {2,0x14614,0x60000000,0xffffffff},
        {2,0x14610,1,0xffffffff},
        {2,0x24c44,0x80a008a0,0xffffffff}, /* Fence range */
        {2,0x14608,0x06030100,0xffffffff}, /* Original chip-id compression */
        {2,0x1303c,1,0xffffffff}, /* GMU_SYS_BUS_CONFIG */
        {2,0x14300,0x09c40400,0xffffffff}, /* GPU_HW_ACTIVE; no IFPC */
        {2,0x143a0,0xf11,0xf11}, /* RPMh capability, no OOB request */
    };
    for(unsigned n=0;n<sizeof(config)/sizeof(config[0]);n++){
        const struct a630_boot_register *r=&config[n];
        if(!a630_boot_set(io,s,r->bank,r->offset,r->value,r->mask))goto done;
    }
    if(!a630_boot_set(io,s,2,0x14000,1,0xffffffff)||!io->sync(io->ctx)){
        if(!s->error)s->error=A630_BOOT_IO;goto done;
    }
    s->stage=5;s->started=1; /* Includes a posted release whose callback fails. */
    if(!a630_boot_set(io,s,2,0x14000,0,0xffffffff)||!io->sync(io->ctx)){
        if(!s->error)s->error=A630_BOOT_IO;goto done;
    }
    if(!a630_boot_poll(io,s,2,0x14070,0xbabeface,0xffffffff,10000))goto done;
    if(!a630_boot_read(io,s,2,0x14070,&s->fw))goto done;
    s->stage=6;s->error=A630_BOOT_READY;
done:
    s->start_error=s->error;return s->error==A630_BOOT_READY;
}
/* Contain first, restore second. BCR confirmation also gates SMMU teardown.
 * Keep all allocations, power and clocks when containment is uncertain. */
static inline bool a630_boot_stop(const struct a630_boot_io *io,struct a630_boot_snapshot *s)
{
    struct a630_boot_snapshot r=*s;r.error=0;
    if(!a630_boot_set(io,&r,2,0x14000,1,0xffffffff)||
       !a630_boot_set(io,&r,1,0x111c,1,1)||
       !a630_boot_poll(io,&r,1,0x111c,1,1,1000))goto failed;
    io->wait(io->ctx,20);
    if(!a630_boot_poll(io,&r,2,0x23404,0,0xffffffff,1000))goto failed;
    s->stopped=1;
    if(s->changed&&!a630_boot_set(io,&r,4,0x84500,0,0x80000001))goto failed;
    for(unsigned n=s->changed?s->changed-1:0;n>0;n--){
        const struct a630_boot_register *p=&a630_boot_profile[n-1];
        if(!a630_boot_set(io,&r,p->bank,p->offset,s->before[n-1],p->mask))goto failed;
    }
    if(s->changed&&!a630_boot_set(io,&r,4,0x84500,s->before[A630_BOOT_PROFILE-1],0x80000001))goto failed;
    if(!io->sync(io->ctx)){r.error=A630_BOOT_IO;goto failed;}
    s->restored=1;s->restore_error=0;return true;
failed:
    s->restored=0;s->restore_error=r.error?r.error:A630_BOOT_IO;return false;
}
#endif

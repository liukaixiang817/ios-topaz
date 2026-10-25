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
    uint64_t attempted;
    uint32_t retained_hidden,hidden_before[3],hidden_after[3];
    uint32_t pdc_len_zero,pdc_msgid_after[6];
    uint32_t restore_bank,restore_offset,restore_expected,restore_actual;
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
/* The stock MiCode and mainline sequences issue zero to these three hidden
 * TCS address slots without treating them as ordinary retained-RAM words.
 * Polaris0036 read82204514 after the first zero request. Keep that observable
 * distinction: accept only the exact saved word remaining unchanged (or an
 * acknowledged zero); never accept an unexpected new word or an IO failure.
 * This establishes the issued request, NOT a cleared address. A fresh FW
 * handshake remains mandatory, and no HFI/GX operation is enabled here. */
static inline bool a630_boot_hidden_request(const struct a630_boot_io *io,
    struct a630_boot_snapshot *s,unsigned index)
{
    const struct a630_boot_register *r=&a630_boot_profile[index];
    unsigned slot=(r->offset-0x23034)/8;uint32_t actual;
    if(r->bank!=2 || r->value || slot>=3 || r->offset!=0x23034+8*slot){
        s->error=A630_BOOT_IO;return false;
    }
    s->hidden_before[slot]=s->before[index];
    if(!io->owned(io->ctx)){s->error=A630_BOOT_LEASE;return false;}
    if(!io->write(io->ctx,r->bank,r->offset,0)){
        s->error=A630_BOOT_IO;s->failed_bank=r->bank;s->failed_offset=r->offset;return false;
    }
    if(!a630_boot_read(io,s,r->bank,r->offset,&actual))return false;
    s->hidden_after[slot]=actual;
    if(actual==0)return true;
    if(actual==s->before[index]){s->retained_hidden|=1u<<slot;return true;}
    s->error=A630_BOOT_ACK;s->failed_bank=r->bank;s->failed_offset=r->offset;
    s->expected=0;s->actual=actual;return false;
}
/* MiCode and mainline write10108 to these six PDC MSGID slots, without a
 * retained-word poll. The original RPMh mailbox defines8 as LEN, not WRITE.
 * Polaris0037 returned10100. Issue the exact native request, require all
 * other fields to match, and record only that precise zero-length readback
 * alternative. This is not proof that a PDC sequence executed. CM3 stays
 * held throughout configuration; fresh firmware readiness is still required.
 * No HFI/GX/3D client is admitted by either readback form. */
static inline bool a630_boot_pdc_msgid(const struct a630_boot_io *io,
    struct a630_boot_snapshot *s,unsigned index)
{
    const struct a630_boot_register *r=&a630_boot_profile[index];
    unsigned slot=6;
    for(unsigned n=0;n<6;n++)
        if(r->bank==4 && r->offset==(n<3?0x855d4u+16*n:0x85764u+16*(n-3)))slot=n;
    if(slot>=6 || r->value!=0x10108u){s->error=A630_BOOT_IO;return false;}
    if(!io->owned(io->ctx)){s->error=A630_BOOT_LEASE;return false;}
    if(!io->write(io->ctx,r->bank,r->offset,r->value)){
        s->error=A630_BOOT_IO;s->failed_bank=r->bank;s->failed_offset=r->offset;return false;
    }
    uint32_t actual=0;
    for(unsigned n=0;n<500;n++){
        if(!a630_boot_read(io,s,r->bank,r->offset,&actual))return false;
        s->pdc_msgid_after[slot]=actual;
        if(actual==r->value)return true;
        if(actual==0x10100u){s->pdc_len_zero|=1u<<slot;return true;}
        io->wait(io->ctx,1);
    }
    s->error=A630_BOOT_ACK;s->failed_bank=r->bank;s->failed_offset=r->offset;
    s->expected=r->value;s->actual=actual;return false;
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
    s->attempted|=1ull<<(A630_BOOT_PROFILE-1);
    if(!a630_boot_set(io,s,4,0x84500,0,0x80000001))goto done;
    for(unsigned n=0;n<A630_BOOT_PROFILE;n++){
        const struct a630_boot_register *r=&a630_boot_profile[n];
        s->attempted|=1ull<<n;
        if(r->bank==2 && (r->offset==0x23034 || r->offset==0x2303c || r->offset==0x23044)){
            if(!a630_boot_hidden_request(io,s,n))goto done;
        }else if(r->bank==4 && r->value==0x10108u){
            if(!a630_boot_pdc_msgid(io,s,n))goto done;
        }else if(!a630_boot_set(io,s,r->bank,r->offset,r->value,r->mask))goto done;
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
    struct a630_boot_snapshot r=*s;r.error=0;r.failed_bank=r.failed_offset=r.expected=r.actual=0;
    if(!a630_boot_set(io,&r,2,0x14000,1,0xffffffff)||
       !a630_boot_set(io,&r,1,0x111c,1,1)||
       !a630_boot_poll(io,&r,1,0x111c,1,1,1000))goto failed;
    io->wait(io->ctx,20);
    if(!a630_boot_poll(io,&r,2,0x23404,0,0xffffffff,1000))goto failed;
    s->stopped=1;
    if(s->attempted&&!a630_boot_set(io,&r,4,0x84500,0,0x80000001))goto failed;
    for(int n=A630_BOOT_PROFILE-2;n>=0;n--){
        const struct a630_boot_register *p=&a630_boot_profile[n];
        if(!(s->attempted&(1ull<<n)))continue;
        if(p->bank==2 && (p->offset==0x23034 || p->offset==0x2303c || p->offset==0x23044)){
            uint32_t current;
            if(!a630_boot_read(io,&r,p->bank,p->offset,&current))goto failed;
            if(current==s->before[n])continue;
            /* A callback may fail after a posted zero. Only a zero target
             * permits restoring a known read/write slot. Unknown new words
             * are never written back as opaque control commands. */
            if(current!=0){r.error=A630_BOOT_ACK;r.failed_bank=p->bank;
                r.failed_offset=p->offset;r.expected=s->before[n];r.actual=current;goto failed;}
        }
        if(!a630_boot_set(io,&r,p->bank,p->offset,s->before[n],p->mask))goto failed;
    }
    if(s->attempted&&!a630_boot_set(io,&r,4,0x84500,s->before[A630_BOOT_PROFILE-1],0x80000001))goto failed;
    if(!io->sync(io->ctx)){r.error=A630_BOOT_IO;goto failed;}
    s->restored=1;s->restore_error=0;s->restore_bank=s->restore_offset=s->restore_expected=s->restore_actual=0;return true;
failed:
    s->restored=0;s->restore_error=r.error?r.error:A630_BOOT_IO;
    s->restore_bank=r.failed_bank;s->restore_offset=r.failed_offset;
    s->restore_expected=r.expected;s->restore_actual=r.actual;return false;
}
#endif

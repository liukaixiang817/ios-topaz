/* Resident CPU0 only. Own DT SID2 PMI8998 FG-gen3 + SMB2, not Redwood GLINK.
 * Provenance: MiCode/Xiaomi_Kernel_OpenSource c7cb50c1 qpnp-fg-gen3.c,
 * fg-reg.h, smb-lib.c/smb-reg.h and qpnp-revid.[ch].
 * Only observer EXT_READL commands; no RW channel, PMIC write, IRQ clear,
 * MEMIF/SRAM/HOLD/profile load, charger action, allocation or enable writes.
 * Runtime admission MUST establish original Polaris DT, CPU0/EL/DAIF/group,
 * mapped MMIO and serialization with all other EE0 observer clients. Caller
 * sets admitted only after that review. Original v5 READ APID selection is
 * first mapping, overridden by each later EE0 WRITE-owned mapping. Other
 * WRITE owners do not forbid observer reads; no write permission is granted.
 * The selected full map/WRITE-owner identities remain fixed this boot.
 * Offsets: CORE c440000, CONFIG c40a000, EE0 OBSERVER e600000 stride80.
 * Never use c600000 stride10000 (the PMIC write channels).
 */
#ifndef POLARIS_BATTERY_READONLY_H
#define POLARIS_BATTERY_READONLY_H
#include "polaris-battery-shared.h"
enum { PBAT_CORE=0,PBAT_CONFIG=1,PBAT_OBSERVER=2,PBAT_BANKS=8 };
enum { PBAT_MAP_VERSION=1,PBAT_MAP_SCAN,PBAT_MAP_SELECT,PBAT_MAP_VERIFY,
       PBAT_MAP_OWNER,PBAT_MAP_READY };
enum { PBAT_MAP_OK=0,PBAT_MAP_BAD_VERSION,PBAT_MAP_MISSING,
       PBAT_MAP_CHANGED,PBAT_MAP_OWNER_CHANGED };
struct polaris_battery_map_diag {
    uint32_t stage,reason,bank,apid,expected,actual,version,scanned;
    uint32_t matches[PBAT_BANKS],verified_map,verified_owner;
    uint32_t current_map[PBAT_BANKS],current_owner[PBAT_BANKS];
    /* Same first scan only. Zero owner words need their explicit valid bit;
     * nonmatching owners were never read and are never invented as zero. */
    uint32_t scan_map[512],scan_owner[512],owner_valid[16];
};
struct polaris_battery_bus {
    void *context;
    uint32_t (*read)(void *,unsigned,uint32_t);
    void (*read_command)(void *,uint32_t,uint32_t);
    uint64_t (*now_us)(void *);
    uint64_t cookie,counter_hz,last_us;
    uint32_t apid[PBAT_BANKS],map[PBAT_BANKS],owner[PBAT_BANKS],version;
    uint32_t fault,reads,last_bank,last_reg,last_status,last_polls,span_limit_us;
    bool admitted,initialized;
    struct polaris_battery_map_diag mapping;
};
static inline bool pbat_fault(struct polaris_battery_bus *b,unsigned error)
{ if(b&&!b->fault)b->fault=error;return false; }
static inline bool pbat_time(struct polaris_battery_bus *b,uint64_t *now)
{
    *now=b->now_us(b->context);
    if(!*now||*now<b->last_us)return pbat_fault(b,PBAT_E_CLOCK);
    b->last_us=*now;return true;
}
static inline bool pbat_map_fail(struct polaris_battery_bus *b,unsigned reason,
    unsigned bank,unsigned apid,uint32_t expected,uint32_t actual,unsigned error)
{
    if(!b->mapping.reason) {
        b->mapping.reason=reason;b->mapping.bank=bank;b->mapping.apid=apid;
        b->mapping.expected=expected;b->mapping.actual=actual;
    }
    return pbat_fault(b,error);
}
static inline bool pbat_map(struct polaris_battery_bus *b)
{
    static const unsigned ppid[PBAT_BANKS]={0x201,0x240,0x241,0x210,0x212,0x213,0x214,0x216};
    if(!b||b->fault||!b->admitted||!b->read||!b->read_command||!b->now_us||
       !b->cookie||!b->counter_hz||!b->span_limit_us||
       b->span_limit_us>PBAT_UI_MAX_SPAN_US)return pbat_fault(b,PBAT_E_ARGUMENT);
    if(!b->initialized)for(unsigned k=0;k<PBAT_BANKS;k++)b->apid[k]=UINT32_MAX;
    b->mapping.stage=PBAT_MAP_VERSION;
    uint32_t version=b->read(b->context,PBAT_CORE,0);b->mapping.version=version;
    if(version<0x50000000u||version>=0x60000000u||
       (b->initialized&&version!=b->version))return pbat_map_fail(b,PBAT_MAP_BAD_VERSION,
           UINT32_MAX,UINT32_MAX,b->initialized?b->version:0x50000000u,version,PBAT_E_IDENTITY);
    if(!b->initialized) {
        b->mapping.stage=PBAT_MAP_SCAN;
        for(unsigned a=0;a<512;a++) {
            uint32_t map=b->read(b->context,PBAT_CORE,0x900+4*a);
            b->mapping.scan_map[a]=map;b->mapping.scanned=a+1;
            for(unsigned k=0;k<PBAT_BANKS;k++)if(map&&((map>>8)&0xfff)==ppid[k]) {
                uint32_t owner=b->read(b->context,PBAT_CONFIG,0x700+4*a);
                b->mapping.scan_owner[a]=owner;b->mapping.owner_valid[a/32]|=1u<<(a%32);
                b->mapping.matches[k]++;
                /* Own c7cb50c1 read_apid_map_v5/mode_v2: first mapping or
                 * later local WRITE owner; READ0400 is granted regardless
                 * of WRITE owner. The EE0 observer command/status gates stay. */
                if(b->apid[k]==UINT32_MAX||(owner&7)==0) {
                    b->apid[k]=a;b->map[k]=map;b->owner[k]=owner;
                }
            }
        }
        b->mapping.stage=PBAT_MAP_SELECT;
        for(unsigned k=0;k<PBAT_BANKS;k++)if(b->apid[k]==UINT32_MAX)
            return pbat_map_fail(b,PBAT_MAP_MISSING,k,UINT32_MAX,ppid[k],0,PBAT_E_MAPPING);
        b->version=version;b->initialized=true;
    }
    b->mapping.verified_map=b->mapping.verified_owner=0;
    for(unsigned k=0;k<PBAT_BANKS;k++) {
        b->mapping.stage=PBAT_MAP_VERIFY;
        uint32_t map=b->read(b->context,PBAT_CORE,0x900+4*b->apid[k]);
        b->mapping.current_map[k]=map;b->mapping.verified_map|=1u<<k;
        if(map!=b->map[k])return pbat_map_fail(b,PBAT_MAP_CHANGED,k,b->apid[k],b->map[k],map,PBAT_E_MAPPING);
        b->mapping.stage=PBAT_MAP_OWNER;
        uint32_t owner=b->read(b->context,PBAT_CONFIG,0x700+4*b->apid[k]);
        b->mapping.current_owner[k]=owner;b->mapping.verified_owner|=1u<<k;
        if(owner!=b->owner[k])return pbat_map_fail(b,PBAT_MAP_OWNER_CHANGED,k,b->apid[k],b->owner[k],owner,PBAT_E_MAPPING);
    }
    b->mapping.stage=PBAT_MAP_READY;
    return true;
}
static inline bool pbat_allowed(unsigned bank,unsigned reg,unsigned bytes)
{
    if(bank==0)return reg==0&&bytes==6; /* actual PMIC revid */
    if(bank==1)return (reg==0&&bytes==6)||(reg==9&&bytes==2)||
        (reg==0x10&&bytes==1)||(reg==0x46&&bytes==1);
    if(bank==2)return (reg==0&&bytes==6)||(reg==6&&bytes==4)||
        (reg==0x50&&bytes==2)||(reg==0xa0&&bytes==4);
    if(bank==3)return (reg==6&&bytes==2)||(reg==0x0b&&bytes==3)||
        (reg==0x44&&bytes==1);
    if(bank==4||bank==5||bank==6)return reg==0x10&&bytes==1;
    return bank==7&&reg==0x0b&&bytes==1;
}
static inline bool pbat_read(struct polaris_battery_bus *b,unsigned bank,
    unsigned reg,uint8_t *out,unsigned bytes)
{
    if(!b||b->fault)return false;
    if(!out||!pbat_allowed(bank,reg,bytes)||!pbat_map(b))return pbat_fault(b,PBAT_E_ARGUMENT);
    b->last_bank=bank;b->last_reg=reg;b->last_status=0;b->last_polls=0;
    uint64_t start,now;
    if(!pbat_time(b,&start))return false;
    unsigned offset=0x80*b->apid[bank];
    b->read_command(b->context,offset,(1u<<27)|(reg<<4)|(bytes-1));
    for(unsigned n=0;n<4096;n++) {
        uint32_t status=b->read(b->context,PBAT_OBSERVER,offset+8);
        b->last_status=status;b->last_polls=n+1;
        if(!pbat_time(b,&now))return false;
        if(status&~1u)return pbat_fault(b,PBAT_E_RESPONSE);
        if(status==1) {
            uint32_t data[2]={b->read(b->context,PBAT_OBSERVER,offset+0x18),0};
            if(bytes>4)data[1]=b->read(b->context,PBAT_OBSERVER,offset+0x1c);
            for(unsigned i=0;i<bytes;i++)out[i]=(uint8_t)(data[i/4]>>(8*(i%4)));
            b->reads++;return pbat_map(b);
        }
        if(now-start>=100)return pbat_fault(b,PBAT_E_TIMEOUT);
    }
    return pbat_fault(b,PBAT_E_TIMEOUT); /* timeout/unknown stay sticky, no retry */
}
/* Coherent snapshot completion has no hardware effects. */
static inline bool pbat_decode_completed(struct polaris_battery_bus *b,
    struct polaris_battery_sample *s,uint64_t began,uint64_t ended)
{
    uint8_t *r=s->raw;
    unsigned v=0,i=0,temp=0,soc=0,phase=0;int signed_i=0;
    s->began_us=began;s->sampled_us=ended;s->reads=b->reads;
    if(ended==began){pbat_fault(b,PBAT_E_CLOCK);s->error=PBAT_E_CLOCK;return false;}
    if(ended-began>b->span_limit_us){s->error=PBAT_E_STALE;return false;}
    if(!(r[18]&2)||!(r[19]&0x80)||!(r[22]&1)){s->error=PBAT_E_NOT_READY;return false;}
    if((r[23]&0x17)||(r[38]&0x30)){s->error=PBAT_E_ABSENT;return false;}
    if((r[25]&0x80)){s->error=PBAT_E_NOT_READY;return false;}
    if(r[20]!=r[21]||r[53]!=r[54]||r[20]!=r[53]||
       __builtin_memcmp(r+26,r+42,4)||__builtin_memcmp(r+32,r+46,2)||
       __builtin_memcmp(r+34,r+48,3)||r[38]!=r[51]||r[41]!=r[52]||
       __builtin_memcmp(r+22,r+55,4)||r[39]!=r[59]||r[40]!=r[60]||
       r[37]!=r[61]||r[18]!=r[62]||r[19]!=r[63]) {
        s->error=PBAT_E_UNSTABLE;return false; /* later periodic sample, no spin */
    }
    v=r[3]<2?((unsigned)r[26]<<8)|r[27]:((unsigned)r[27]<<8)|r[26];
    i=r[3]<2?((unsigned)r[28]<<8)|r[29]:((unsigned)r[29]<<8)|r[28];
    signed_i=i&0x8000?(int)i-65536:(int)i;
    s->voltage_uv=(int32_t)((uint64_t)v*122070/1000);
    /* Own Linux gauge current is negative into battery; IOPM is positive. */
    s->current_ua=-(int32_t)((int64_t)signed_i*488281/1000);
    temp=(unsigned)r[30]|((unsigned)(r[31]&7)<<8);
    s->temperature_centi_c=((int)((temp+2)/4)-273)*100;
    soc=r[20];
    s->soc_percent=soc==255?100:soc?1+(int)(((soc-1)*98+126)/253):0;
    s->present=1;s->external=!!((r[39]|r[40])&0x10);
    s->capable=!!((r[41]&0x18)&&(r[41]&1));
    phase=r[32]&7;
    s->charging=s->external&&s->capable&&phase<=4&&!(r[33]&0x73)&&
        !(r[34]&0x60)&&(r[34]&0x10)&&((r[36]&0xf0)||(r[37]&1));
    /* INHIBIT/WARM/SOC100 are insufficient to assert FULL. */
    s->full=s->external&&s->capable&&phase==5&&!(r[33]&0x7f);
    s->valid=PBAT_ALL;
    /* Sequence belongs to publisher; validate with temporary even sentinel. */
    s->sequence=2;
    if(!pbat_sample_valid(s,ended,b->counter_hz)){s->valid=0;s->error=PBAT_E_RANGE;return false;}
    return true;
}
struct polaris_battery_transaction {
    struct polaris_battery_sample sample;
    uint64_t began_us,last_read_us;
    unsigned next;
    bool active,done;
};
static inline void pbat_transaction_error(struct polaris_battery_bus *b,
    struct polaris_battery_transaction *t,unsigned error)
{
    t->sample.valid=0;t->sample.error=error;
    t->sample.reads=b?b->reads:0;
    /* Last actual read time, never a newly dated copy of an old sample. */
    t->sample.sampled_us=t->last_read_us;t->active=false;t->done=true;
}
static inline bool pbat_transaction_begin(struct polaris_battery_bus *b,
    struct polaris_battery_transaction *t)
{
    if(!t)return pbat_fault(b,PBAT_E_ARGUMENT);
    *t=(struct polaris_battery_transaction){0};
    t->sample.magic=PBAT_MAGIC;t->sample.version=PBAT_VERSION;
    t->sample.bytes=sizeof(t->sample);t->sample.source=PBAT_SOURCE_PMI8998_FG3_SMB2;
    if(!b){pbat_transaction_error(b,t,PBAT_E_ARGUMENT);return false;}
    t->sample.cookie=b->cookie;t->sample.counter_hz=b->counter_hz;
    t->sample.span_limit_us=b->span_limit_us;
    if(!pbat_map(b)||!pbat_time(b,&t->began_us)) {
        pbat_transaction_error(b,t,b->fault?b->fault:PBAT_E_RESPONSE);return false;
    }
    t->sample.began_us=t->began_us;t->active=true;return true;
}
/* At most ONE complete observer command per call. Parent may interleave WLED,
 * USB and reset work, and must not call during their critical phases. Pauses
 * preserve the original transaction start; expired partial work is withdrawn,
 * never resumed with a new timestamp or silently started again. true=done
 * (including refusal), false=partial. No PMIC command is retried here. */
static inline bool pbat_transaction_step(struct polaris_battery_bus *b,
    struct polaris_battery_transaction *t)
{
    static const uint8_t plan[28][4]={
        {0,0,6,0},{1,0,6,6},{2,0,6,12},{1,0x10,1,18},
        {1,0x46,1,19},{1,9,2,20},{2,6,4,22},{2,0xa0,4,26},
        {2,0x50,2,30},{3,6,2,32},{3,0x0b,3,34},{3,0x44,1,37},
        {4,0x10,1,38},{5,0x10,1,39},{6,0x10,1,40},{7,0x0b,1,41},
        {2,0xa0,4,42},{3,6,2,46},{3,0x0b,3,48},{4,0x10,1,51},
        {7,0x0b,1,52},{1,9,2,53},{2,6,4,55},{5,0x10,1,59},
        {6,0x10,1,60},{3,0x44,1,61},{1,0x10,1,62},{1,0x46,1,63}};
    if(!t||!b)return true;
    if(t->done)return true;
    uint64_t now=0;
    if(!t->active||t->next>=28||!pbat_time(b,&now)) {
        pbat_transaction_error(b,t,b->fault?b->fault:PBAT_E_ARGUMENT);return true;
    }
    if(now-t->began_us>b->span_limit_us) {
        pbat_transaction_error(b,t,PBAT_E_STALE);return true;
    }
    const uint8_t *op=plan[t->next];
    if(!pbat_read(b,op[0],op[1],t->sample.raw+op[3],op[2])) {
        pbat_transaction_error(b,t,b->fault?b->fault:PBAT_E_RESPONSE);return true;
    }
    t->last_read_us=b->last_us;t->next++;
    if(t->next==3) {
        const uint8_t *r=t->sample.raw;
        if(r[4]!=0x51||r[5]!=0x15||r[3]>2||r[11]!=0x10||r[17]!=0x11) {
            pbat_fault(b,PBAT_E_IDENTITY);pbat_transaction_error(b,t,PBAT_E_IDENTITY);return true;
        }
    }
    if(b->last_us-t->began_us>b->span_limit_us) {
        pbat_transaction_error(b,t,PBAT_E_STALE);return true;
    }
    if(t->next<28)return false;
    if(!pbat_time(b,&now))pbat_transaction_error(b,t,b->fault);
    else {
        (void)pbat_decode_completed(b,&t->sample,t->began_us,t->last_read_us);
        t->active=false;t->done=true;
    }
    return true;
}
/* Synchronous convenience for offline tests only; physical resident runtime
 * must call begin/step on the existing cooperative loop, not this wrapper. */
static inline bool pbat_acquire(struct polaris_battery_bus *b,
    struct polaris_battery_sample *s)
{
    if(!s)return pbat_fault(b,PBAT_E_ARGUMENT);
    struct polaris_battery_transaction t;
    if(pbat_transaction_begin(b,&t))while(!pbat_transaction_step(b,&t)) {}
    *s=t.sample;return !s->error&&s->valid==PBAT_ALL;
}
#endif

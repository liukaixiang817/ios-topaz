/* Offline acquisition-to-publication checks using explicit synthetic PMIC
 * bytes. This never maps a device, opens USB or asserts hardware evidence. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-battery-producer.h"
struct fixture {
    uint8_t regs[PBAT_BANKS][256];
    unsigned bank,reg,bytes,commands,adc_reads,invalid_commands;
    unsigned owner_changed,timeout,frozen,unstable,command_delay_us;
    uint32_t version,maps[512],owners[512];
    unsigned map_reads,owner_reads;
    uint64_t us;
};
static const unsigned fixture_ppid[PBAT_BANKS]={0x201,0x240,0x241,0x210,0x212,0x213,0x214,0x216};
static uint32_t fixture_read(void *context,unsigned kind,uint32_t offset)
{
    struct fixture *f=context;
    if(kind==PBAT_CORE) {
        if(!offset)return f->version;
        assert(offset>=0x900&&offset<0x1100&&!(offset&3));f->map_reads++;
        return f->maps[(offset-0x900)/4];
    }
    if(kind==PBAT_CONFIG) {
        assert(offset>=0x700&&offset<0xf00&&!(offset&3));f->owner_reads++;
        return f->owner_changed?1:f->owners[(offset-0x700)/4];
    }
    assert(kind==PBAT_OBSERVER);
    unsigned local=offset-0x80*(100+f->bank);
    if(local==8)return f->timeout?0:1;
    assert(local==0x18||local==0x1c);
    unsigned reg=f->reg+(local==0x1c?4:0);uint32_t data=0;
    for(unsigned j=0;j<4;j++)data|=(uint32_t)f->regs[f->bank][reg+j]<<(8*j);
    if(f->unstable&&f->bank==2&&f->reg==0xa0&&f->adc_reads>1)data^=1;
    return data;
}
static void fixture_command(void *context,uint32_t offset,uint32_t command)
{
    struct fixture *f=context;
    f->bank=offset/0x80-100;f->reg=(command>>4)&255;f->bytes=(command&7)+1;
    if(f->bank>=PBAT_BANKS||(command>>27)!=1||
       command!=((1u<<27)|(f->reg<<4)|(f->bytes-1))||
       !pbat_allowed(f->bank,f->reg,f->bytes))f->invalid_commands++;
    assert(!f->invalid_commands);f->commands++;
    f->us+=f->command_delay_us;
    if(f->bank==2&&f->reg==0xa0)f->adc_reads++;
}
static uint64_t fixture_time(void *context)
{struct fixture *f=context;if(!f->frozen)f->us++;return f->us;}
static struct polaris_battery_bus make_bus(struct fixture *f,unsigned revision)
{
    memset(f,0,sizeof(*f));f->us=1000000;
    f->version=0x50000000;
    for(unsigned k=0;k<PBAT_BANKS;k++)f->maps[100+k]=0x01000000|(fixture_ppid[k]<<8);
    f->regs[0][3]=(uint8_t)revision;f->regs[0][4]=0x51;f->regs[0][5]=0x15;
    f->regs[1][5]=0x10;f->regs[2][5]=0x11;
    f->regs[1][0x10]=2;f->regs[1][0x46]=0x80;f->regs[1][9]=128;f->regs[1][10]=128;
    f->regs[2][6]=1;f->regs[2][0x50]=0xa8;f->regs[2][0x51]=4;
    f->regs[2][0xa0]=revision<2?0x80:0;f->regs[2][0xa1]=revision<2?0:0x80;
    f->regs[2][0xa2]=revision<2?0xfc:0;f->regs[2][0xa3]=revision<2?0:0xfc;
    f->regs[3][6]=2;f->regs[3][0x0b]=0x10;f->regs[3][0x0d]=0x20;
    f->regs[5][0x10]=0x10;f->regs[7][0x0b]=0x11;
    struct polaris_battery_bus b={0};b.context=f;b.read=fixture_read;
    b.read_command=fixture_command;b.now_us=fixture_time;b.cookie=42;
    b.counter_hz=19200000;b.span_limit_us=500000;b.admitted=true;return b;
}
static unsigned clean_calls;static uint64_t clean_sequence[3];
static void fixture_clean(void *address,unsigned bytes)
{
    assert(bytes==128||bytes==256);assert(clean_calls<3);
    clean_sequence[clean_calls++]=((struct polaris_battery_sample *)address)->sequence;
}
int main(void)
{
    struct fixture f;struct polaris_battery_sample s;
    struct polaris_battery_bus b=make_bus(&f,2);
    assert(pbat_acquire(&b,&s)&&s.soc_percent==50&&s.voltage_uv==3999989&&
        s.current_ua==499999&&s.temperature_centi_c==2500&&s.charging&&s.capable);
    assert(s.reads==28&&f.commands==28&&pbat_sample_valid(&s,s.sampled_us,b.counter_hz));
    assert(!pbat_sample_valid(&s,s.sampled_us+PBAT_MAX_AGE_US+1,b.counter_hz));
    assert(!pbat_sample_valid(&s,s.sampled_us,b.counter_hz+1));
    b=make_bus(&f,1);assert(pbat_acquire(&b,&s)&&s.voltage_uv==3999989&&s.current_ua==499999);
    b=make_bus(&f,2);assert(pbat_map(&b));f.owner_changed=1;
    assert(!pbat_acquire(&b,&s)&&s.error==PBAT_E_MAPPING&&f.commands==0);
    assert(b.mapping.reason==PBAT_MAP_OWNER_CHANGED&&b.mapping.stage==PBAT_MAP_OWNER&&
        b.mapping.bank==0&&b.mapping.apid==100&&b.mapping.expected==0&&b.mapping.actual==1);
    f.owner_changed=0;assert(!pbat_acquire(&b,&s)&&f.commands==0); /* sticky */
    /* Own v5 READ0400 permission does not require local WRITE ownership. */
    b=make_bus(&f,2);f.owners[100]=0x80000003;
    assert(pbat_acquire(&b,&s)&&s.valid==PBAT_ALL&&b.owner[0]==0x80000003&&f.commands==28);
    /* First mapping, each later EE0 mapping overrides; later foreign owner
     * does not override local. All raw words from this one scan are saved. */
    b=make_bus(&f,2);
    f.maps[20]=f.maps[110]=f.maps[120]=f.maps[130]=f.maps[100];
    f.owners[20]=7;f.owners[110]=0x80000000;f.owners[120]=4;f.owners[130]=0x40000000;
    assert(pbat_map(&b)&&b.apid[0]==130&&b.owner[0]==0x40000000&&b.mapping.matches[0]==5);
    assert(b.mapping.scanned==512&&f.map_reads==520&&f.owner_reads==20&&f.commands==0);
    assert(b.mapping.scan_map[130]==f.maps[130]&&b.mapping.scan_owner[130]==f.owners[130]&&
        (b.mapping.owner_valid[130/32]&(1u<<(130%32)))&&!(b.mapping.owner_valid[0]&1));
    b=make_bus(&f,2);f.maps[20]=f.maps[100];f.owners[20]=2;f.owners[100]=3;
    assert(pbat_map(&b)&&b.apid[0]==20&&b.owner[0]==2&&b.mapping.matches[0]==2);
    b=make_bus(&f,2);f.maps[102]=0;
    assert(!pbat_map(&b)&&b.fault==PBAT_E_MAPPING&&b.mapping.stage==PBAT_MAP_SELECT&&
        b.mapping.reason==PBAT_MAP_MISSING&&b.mapping.bank==2&&b.mapping.apid==UINT32_MAX&&
        b.mapping.expected==0x241&&b.mapping.scanned==512&&b.apid[2]==UINT32_MAX&&f.commands==0);
    b=make_bus(&f,2);assert(pbat_map(&b));unsigned old_owner_reads=f.owner_reads;
    uint32_t original_map=f.maps[100];f.maps[100]^=0x01000000;
    assert(!pbat_map(&b)&&b.fault==PBAT_E_MAPPING&&b.mapping.stage==PBAT_MAP_VERIFY&&
        b.mapping.reason==PBAT_MAP_CHANGED&&b.mapping.expected==original_map&&
        b.mapping.actual==f.maps[100]&&f.owner_reads==old_owner_reads&&f.commands==0);
    unsigned old_map_reads=f.map_reads;f.maps[100]=original_map;
    assert(!pbat_map(&b)&&f.map_reads==old_map_reads&&f.owner_reads==old_owner_reads); /* sticky, no reads */
    b=make_bus(&f,2);assert(pbat_map(&b));f.owners[100]=0x80000000; /* Same low3 owner; raw identity changed. */
    assert(!pbat_map(&b)&&b.mapping.reason==PBAT_MAP_OWNER_CHANGED&&
        b.mapping.actual==0x80000000&&b.mapping.expected==0&&f.commands==0);
    b=make_bus(&f,2);f.version=0x60000000;
    assert(!pbat_map(&b)&&b.fault==PBAT_E_IDENTITY&&b.mapping.reason==PBAT_MAP_BAD_VERSION&&
        b.mapping.version==f.version&&b.mapping.stage==PBAT_MAP_VERSION&&
        b.mapping.scanned==0&&b.apid[0]==UINT32_MAX&&!f.map_reads&&!f.owner_reads&&!f.commands);
    b=make_bus(&f,2);f.regs[0][5]=0x25;
    assert(!pbat_acquire(&b,&s)&&s.error==PBAT_E_IDENTITY&&f.commands==3);
    b=make_bus(&f,2);f.timeout=1;
    assert(!pbat_acquire(&b,&s)&&s.error==PBAT_E_TIMEOUT&&f.commands==1);
    f.timeout=0;assert(!pbat_acquire(&b,&s)&&f.commands==1);
    b=make_bus(&f,2);f.timeout=f.frozen=1;
    assert(!pbat_acquire(&b,&s)&&s.error==PBAT_E_TIMEOUT&&b.last_polls==4096);
    b=make_bus(&f,2);f.unstable=1;
    assert(!pbat_acquire(&b,&s)&&s.error==PBAT_E_UNSTABLE&&!s.valid&&!b.fault);
    b=make_bus(&f,2);f.regs[3][6]=6;
    assert(pbat_acquire(&b,&s)&&!s.charging&&!s.full); /* INHIBIT is not FULL */
    b=make_bus(&f,2);f.regs[3][6]=5;
    assert(pbat_acquire(&b,&s)&&!s.charging&&s.full);
    b=make_bus(&f,2);f.regs[3][6]=5;f.regs[3][7]=8;
    assert(pbat_acquire(&b,&s)&&!s.full); /* soft-temperature-limited */
    struct polaris_battery_transaction tx;
    b=make_bus(&f,2);assert(pbat_transaction_begin(&b,&tx));
    assert(!pbat_transaction_step(&b,&tx)&&f.commands==1);
    uint64_t actual_read_us=tx.last_read_us;f.us+=500001;
    assert(pbat_transaction_step(&b,&tx)&&f.commands==1&&tx.sample.error==PBAT_E_STALE&&
        !tx.sample.valid&&tx.sample.sampled_us==actual_read_us); /* no new timestamp */
    b=make_bus(&f,2);f.command_delay_us=15000;
    assert(pbat_transaction_begin(&b,&tx));
    unsigned calls=0;do {unsigned before=f.commands;
        (void)pbat_transaction_step(&b,&tx);assert(f.commands-before<=1);calls++;
    } while(!tx.done);
    assert(calls==28&&tx.sample.valid==PBAT_ALL&&tx.sample.sampled_us-tx.sample.began_us>=420000);
    struct polaris_battery_sample slot={0};
    struct polaris_battery_producer p={0};p.bus=b;p.slot=&slot;p.clean=fixture_clean;
    assert(!pbat_publish(&p,&s)&&clean_calls==0);
    p.span_admitted=p.native_bss_complete=p.counter_domain_admitted=true;
    assert(pbat_publish(&p,&s)&&slot.sequence==2&&clean_calls==3);
    assert(clean_sequence[0]==1&&clean_sequence[1]==1&&clean_sequence[2]==2);
    assert(!pbat_allowed(3,0x42,1)&&!pbat_allowed(2,0x4f,1)&&!pbat_allowed(1,0x48,1));
    /* Actual shared activation predicate used after SecureDT property reads.
     * It does not need another byte in the existing frozen boot arguments. */
    const uint8_t one[]={1,0,0,0},zero[]={0,0,0,0},be[]={0,0,0,1};
    const char board[]="qcom,sdm845\0xiaomi,polaris";
    assert(pbat_runtime_authorized(board,sizeof(board),one,4,one,4,1));
    assert(!pbat_runtime_authorized(board,sizeof(board),one,4,one,4,0));
    assert(!pbat_runtime_authorized(board,sizeof(board),zero,4,one,4,1));
    assert(!pbat_runtime_authorized(board,sizeof(board),one,4,zero,4,1));
    assert(!pbat_runtime_authorized(board,sizeof(board),be,4,one,4,1));
    assert(!pbat_runtime_authorized(board,sizeof(board),one,3,one,4,1));
    assert(!pbat_runtime_authorized(board,sizeof(board),one,4,one,5,1));
    assert(!pbat_runtime_authorized(board,sizeof(board)-1,one,4,one,4,1));
    assert(!pbat_runtime_authorized("xiaomi,dipper",14,one,4,one,4,1));
    assert(!pbat_runtime_authorized(NULL,0,one,4,one,4,1));
    puts("PASS: acquisition/publication + 10 runtime-DT + 8 canonical-v5 map/diagnostic cases; SOFTWARE fixture, no device access");
    return 0;
}

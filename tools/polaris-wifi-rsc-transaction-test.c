/* Software register peer only. No MMIO, IRQ, original code or radio runs. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-rsc-transaction.h"
static struct pwrsc_transaction r;
static uint32_t registers[0x3000/4],baseline[0x3000/4],votes[3],raised[3];
static unsigned fault,reads,writes,triggers,acks,polls,current_tcs,remaining;
static uint64_t now;
static int clock_peer(void *ctx,uint64_t *time,uint64_t *frequency)
{
    (void)ctx;
    if(fault!=28&&!(fault==14&&triggers))now+=100;
    *time=now;*frequency=(fault==12&&triggers)?1:19200000;
    if(fault==13&&triggers)*time=0;
    if((triggers&&(fault==6||fault==23||fault==25))||(triggers==2&&fault==16))now+=20000;
    return 1;
}
static unsigned offset(uint64_t at){assert(at>=PWRSC_BASE&&at<PWRSC_BASE+0x3000&&!(at&3));return (unsigned)(at-PWRSC_BASE);}
static void complete(void)
{
    unsigned t=PWRSC_STRIDE*current_tcs;
    registers[4/4]|=1u<<current_tcs;registers[(t+0x18)/4]=fault==25?0:1;
    registers[(t+0x14)/4]&=~PWRSC_TRIGGER;
    for(unsigned k=0;k<3;k++){
        registers[(t+0x3c+20*k)/4]=PWRSC_DONE;
        registers[(t+0x40+20*k)/4]=0x34560000+k;
        uint32_t address=registers[(t+0x34+20*k)/4];unsigned resource=0;
        while(resource<3&&address!=r.address[resource])resource++;
        assert(resource<3&&resource==(triggers==1?k:2-k));
        votes[resource]=registers[(t+0x38+20*k)/4];
        if(triggers==1)raised[resource]=votes[resource];
    }
    if(fault==7)registers[(t+0x3c+40)/4]&=~(1u<<16);
    if(fault==24)registers[(t+0x3c)/4]&=~(1u<<8);
    if(fault==8)registers[4/4]|=0x80;
    remaining=0;
}
static int read_peer(void *ctx,uint64_t at,uint32_t *value)
{
    (void)ctx;unsigned o=offset(at);reads++;
    if(o==4&&remaining){
        polls++;
        if(fault!=6&&fault!=14&&fault!=23&&!(fault==16&&triggers==2)&&polls>=remaining)complete();
    }
    *value=registers[o/4];
    if(fault==10&&r.phase==4&&r.acknowledged==2&&o==PWRSC_STRIDE*r.tcs+0x30)*value^=1;
    if(fault==17&&r.phase==4&&r.acknowledged==2&&o==PWRSC_STRIDE*r.tcs+0x10)*value^=1;
    return !(fault==26&&triggers&&o==4);
}
static int write_peer(void *ctx,uint64_t at,uint32_t value)
{
    (void)ctx;unsigned o=offset(at);writes++;
    assert(r.outstanding&&r.history[r.events-1].issued&&r.history[r.events-1].unknown);
    assert(o!=0); /* never change IRQ enable/type */
    if(fault==9&&writes==1)return 0;
    if(o==8){
        assert(value==(1u<<r.tcs));
        assert(r.completed>acks); /* no ACK without all3 fresh completions */
        if(fault==15)return 0;
        acks++;registers[4/4]&=~value;
        if(fault==11&&acks==1)registers[0]^=0x80;
        return 1;
    }
    registers[o/4]=value;
    if(fault==27&&writes==1)registers[o/4]^=1;
    if(o%PWRSC_STRIDE==0x14&&(value&PWRSC_TRIGGER)){
        triggers++;current_tcs=o/PWRSC_STRIDE;polls=0;remaining=fault==22?10:2;
        registers[(PWRSC_STRIDE*current_tcs+0x18)/4]=0;
        /* A new transaction invalidates old status even if it had COMPL. */
        if(fault!=23)for(unsigned k=0;k<3;k++)registers[(PWRSC_STRIDE*current_tcs+0x3c+20*k)/4]=0;
    }
    return 1;
}
static void order_peer(void *ctx){(void)ctx;}
static const struct pwrsc_io io={0,read_peer,write_peer,clock_peer,order_peer};
static const uint32_t saved[3]={8,2,1},desired[3]={7,4,7};
static void reset_peer(unsigned f)
{
    memset(&r,0,sizeof(r));memset(registers,0,sizeof(registers));fault=f;reads=writes=triggers=acks=polls=remaining=0;now=1000;
    memcpy(votes,saved,sizeof(votes));memset(raised,0,sizeof(raised));registers[0]=0xff;
    for(unsigned k=0;k<8;k++){
        unsigned t=PWRSC_STRIDE*k;registers[(t+0x14)/4]=0x40;registers[(t+0x10)/4]=0x80;registers[(t+0x18)/4]=1;
        for(unsigned j=0;j<3;j++){
            registers[(t+0x30+20*j)/4]=0x100+j;
            registers[(t+0x34+20*j)/4]=0x90000+j;
            registers[(t+0x38+20*j)/4]=0x200+j;
            if(f==23)registers[(t+0x3c+20*j)/4]=PWRSC_DONE;
        }
    }
    if(f==1)registers[4/4]=0x80;
    if(f==2)registers[0]=0;
    if(f==3||f==4)for(unsigned k=0;k<8;k++)registers[(PWRSC_STRIDE*k+(f==3?0x1c:0x18))/4]=f==3?1:0;
    if(f==5)registers[0x1c/4]=1;
    memcpy(baseline,registers,sizeof(baseline));
}
static int run(unsigned f)
{
    reset_peer(f);uint32_t mask=f==5?5:15;
    int ok=pwrsc_begin(&io,&r,mask,saved,desired);
    if(!ok)return -1;
    int result=0;for(unsigned k=0;k<300&&!result;k++)result=pwrsc_step(&io,&r);
    return result;
}
static void restored(void)
{
    assert(r.finished&&r.restored&&!r.error&&!r.unknown&&!r.outstanding&&pwrsc_retired(&r));
    assert(r.completed==2&&triggers==2&&r.triggers==2&&acks==2&&r.acknowledged==2);
    assert(!memcmp(votes,saved,sizeof(votes))&&raised[0]==8&&raised[1]==4&&raised[2]==7);
    assert(r.IRQ_OR==(1u<<r.tcs));
    for(unsigned k=0;k<8;k++){
        unsigned t=PWRSC_STRIDE*k;
        for(unsigned o=0x10;o<=0x1c;o+=4)assert(registers[(t+o)/4]==baseline[(t+o)/4]);
        for(unsigned j=0;j<3;j++)for(unsigned o=0;o<3;o++)assert(registers[(t+0x30+20*j+4*o)/4]==baseline[(t+0x30+20*j+4*o)/4]);
    }
    assert(registers[0]==baseline[0]&&!registers[4/4]);
    for(unsigned k=0;k<r.events;k++)assert(r.history[k].issued&&r.history[k].returned&&!r.history[k].unknown);
}
int main(void)
{
    unsigned checks=0;
    assert(run(0)==1);restored();checks++;
    unsigned total_reads=reads,total_writes=writes;
    assert(pwrsc_step(&io,&r)==1&&reads==total_reads&&writes==total_writes);checks++;
    assert(!pwrsc_begin(&io,&r,15,saved,desired)&&writes==total_writes);checks++;
    for(unsigned k=1;k<=28;k++){
        if(k==18||k==19||k==20||k==21)continue;
        int result=run(k);
        if(k==5||k==22){assert(result==1);restored();if(k==5)assert(r.tcs==2);}
        else{
            if(result!=-1||!r.error)fprintf(stderr,"fault%u result%d error%u phase%u irq%u triggers%u acks%u\n",k,result,r.error,r.phase,r.IRQ_OR,triggers,acks);
            assert(result==-1&&r.error&&!r.finished&&!r.restored);
            if(k<=4||k==28)assert(!writes&&!r.unknown);
            else {if(!r.unknown||!writes)fprintf(stderr,"fault%u missing unknown writes%u error%u phase%u\n",k,writes,r.error,r.phase);assert(r.unknown&&writes);}
            if(k==6||k==7||k==8||k==12||k==13||k==14||k==23||k==24||k==25||k==26)assert(!acks&&triggers==1);
            if(k==16)assert(acks==1&&triggers==2);
            if(k==9||k==15||k==26)assert(r.outstanding&&r.history[r.outstanding-1].unknown);
            unsigned was_read=reads,was_written=writes;
            assert(pwrsc_step(&io,&r)==-1&&reads==was_read&&writes==was_written);
        }checks++;
    }
    reset_peer(0);assert(!pwrsc_begin(&io,&r,0x100,saved,desired)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);uint32_t bad[3]={16,1,1};assert(!pwrsc_begin(&io,&r,15,bad,desired)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_step(&io,&r)==-1&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));
    assert(!pwrsc_store(&io,&r,PWRSC_BASE,0)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));
    uint32_t value=2;assert(!pwrsc_access(&io,&r,PWRSC_BASE+8,&value,1)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));
    assert(!pwrsc_store(&io,&r,pwrsc_tcs(&r)+0x34,0x50000)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));r.phase=3;
    assert(pwrsc_step(&io,&r)==-1&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));
    assert(!pwrsc_restore_registers(&io,&r)&&r.error==PWRSC_ARGUMENT&&!writes);checks++;
    reset_peer(0);assert(pwrsc_begin(&io,&r,15,saved,desired));r.events=PWRSC_HISTORY+1;
    assert(pwrsc_step(&io,&r)==-1&&r.error==PWRSC_HISTORY_FULL&&!writes);checks++;
    assert(run(0)==1&&pwrsc_retired(&r));r.writes--;assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));r.history[r.events-1].returned=0;assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));
    for(unsigned k=0;k<r.events;k++)if(r.history[k].operation==1&&r.history[k].address==pwrsc_tcs(&r)+0x3c&&r.history[k].phase==2)r.history[k].value=0;
    assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));
    for(unsigned k=0;k<r.events;k++)if(r.history[k].operation==2&&r.history[k].address==PWRSC_BASE+8){r.history[k].value=0x80;break;}
    assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));
    for(unsigned k=0;k<r.events;k++)if(r.history[k].operation==2&&r.history[k].address==pwrsc_tcs(&r)+0x34){r.history[k+1].value^=1;break;}
    assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));
    for(unsigned k=0;k<r.events;k++)if(r.history[k].operation==1&&r.history[k].address==PWRSC_BASE+4&&r.history[k].phase==2&&r.history[k].value){r.history[k].value=0;break;}
    assert(!pwrsc_retired(&r));checks++;
    assert(run(0)==1&&pwrsc_retired(&r));
    for(unsigned k=0;k<r.events;k++)if(r.history[k].operation==2&&r.history[k].address==pwrsc_tcs(&r)+0x38){r.history[k].operation=1;break;}
    assert(!pwrsc_retired(&r));checks++;
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"event_bytes\":%zu,\"SOFTWARE_register_peer\":true,\"physical_lease_established\":false,\"hardware_MMIO_executed\":false,\"radio\":false}\n",checks,sizeof(r),sizeof(struct pwrsc_event));
    return 0;
}

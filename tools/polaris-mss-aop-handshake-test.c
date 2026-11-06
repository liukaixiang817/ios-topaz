/* Own-QMP register peer driven by actual native deliveries and retained
 * namespace/CPU producers. Remote transitions follow registers, not the
 * implementation's internal phase. This is SOFTWARE evidence only. */
struct pmni_command;
static int qmp_peer(const struct pmni_command*,unsigned*);
#define PMAN_TEST_RAW_HOOK qmp_peer
#define PMAN_RESOURCE_ENTRY unused_aop_resource_suite
#include "polaris-mss-aop-resource-test.c"
static unsigned h_fault,h_calls,h_stop,h_writes,h_irqs,h_link,h_channel,h_reads,h_order;
static unsigned h_offsets[4],h_scenarios;
static int qmp_peer(const struct pmni_command*c,unsigned*v)
{
    (void)v;
    if(!aop_owner||!aop_owner->pending)return -1;
    h_calls++;if(h_stop&&h_calls==h_stop)return 0;
    if(c->kind==PMNI_FULL_ORDER){h_order++;return -1;}
    if(c->address==PMAQ_IRQ){
        if(pwfi_le(aop_memory+0x2000,4))return -1; /* real message peer */
        CHECK(c->kind==PMNI_WRITE&&c->value==1&&h_order&&h_irqs<3);
        h_order=0;h_irqs++;aop_writes++;
        CHECK(pwfi_le(aop_memory+12,4)==0xffff&&pwfi_le(aop_memory+16,4)==0xffff&&pwfi_le(aop_memory+36,4)==0xffff);
        if(h_irqs==1){CHECK(h_writes==2);h_link=1;}
        if(h_irqs==2){CHECK(h_writes==3&&pwfi_le(aop_memory+40,4)==0xffff);h_channel=1;h_reads=0;}
        if(h_irqs==3){CHECK(h_writes==4&&pwfi_le(aop_memory+20,4)==0xffff&&pwfi_le(aop_memory+24,4)==0xffff);}
        return 1;
    }
    if(c->address<PMAQ_BASE||c->address>=PMAQ_BASE+64)return -1;
    unsigned off=(unsigned)(c->address-PMAQ_BASE);
    if(c->kind==PMNI_WRITE){
        CHECK(owner->effects&PMSC_REMOTE);CHECK(h_writes<4&&c->value==0xffff);
        static const unsigned expected[]={16,36,44,24};CHECK(off==expected[h_writes]);
        CHECK(pwfi_le(aop_memory+off,4)==0xffff0000);
        h_offsets[h_writes++]=off;aop_writes++;put(aop_memory+off,c->value,4);
        if(h_fault==8&&off==36)put(aop_memory+off,0xffff0000,4);
        return 1;
    }
    if(off==0&&h_link){
        h_reads++;
        if(h_reads>=3&&h_fault!=1)put(aop_memory+40,0xffff,4);
        if(h_fault==9)put(aop_memory+20,0xffff,4);
        if(h_fault==10&&!h_channel)put(aop_memory+48,0xffff,4);
        if(h_fault==11)put(aop_memory+40,0,4);
        if(h_fault==12)put(aop_memory+16,0xffff0000,4);
        if(h_fault==4&&h_reads==2)put(aop_memory+56,0x3000,4);
        if(h_fault==5&&h_reads==2)put(aop_memory+12,0xffff0000,4);
        if(h_fault==6&&h_reads==2)put(aop_memory+0x1000,4,4);
        if(h_fault==7&&h_reads==2)put(aop_memory+0x2000,96,4);
        if(h_channel){
            if(h_fault!=2&&h_reads>=(h_fault==3?5u:2u))put(aop_memory+20,0xffff,4);
            if(h_reads>=(h_fault==3?2u:5u))put(aop_memory+48,0xffff,4);
        }
    }
    return -1;
}
static void h_setup(unsigned fault)
{
    dt_fault=0;h_fault=fault;h_calls=h_stop=h_writes=h_irqs=h_link=h_channel=h_reads=h_order=0;
    aop_setup();h_scenarios++;
    const unsigned down[]={4,5,6,9,10,11,12};
    for(unsigned k=0;k<7;k++)put(aop_memory+4*down[k],0xffff0000,4);
    memcpy(aop_original,aop_memory,0x100000);
}
int main(int argc,char**argv)
{
    aop_test_open(argc,argv);
    unsigned normal_calls=0,locations[64],location_count=0;unsigned seen[32][16]={{0}};
    for(unsigned ordering=0;ordering<3;ordering++){
        h_setup(ordering==2?9:ordering?3:0);int ok=aop_drive();
        if(!ok){const struct pmaq_notify*q=&aop_owner->notify[0];fprintf(stderr,"handshake failed phase%u step%u index%u err%u parent%u delivery%u stage%u calls%u writes%u irq%u ticks%llu delta%llu\n",q->connect_phase,q->step,q->index,q->error,aop_owner->error,aop_owner->pending,aop_owner->pending?aop_records[aop_owner->pending-1].reserved:0,h_calls,h_writes,h_irqs,(unsigned long long)q->last,(unsigned long long)(q->last-q->opening));}CHECK(ok);
        CHECK(h_writes==4&&h_irqs==3&&aop_doorbells==1&&aop_owner->notify[0].connected_at);
        if(!ordering){normal_calls=h_calls;
            for(unsigned n=0;n<aop_owner->deliveries;n++){
                const struct pmaq_command*c=&aop_records[n].command;
                if(c->step>PMAQ_DONE&&!seen[c->step][c->index]++){
                    CHECK(location_count<64);locations[location_count++]=n+1;
                }
            }
        }
        CHECK(pmaq_geometry((const void*)aop_memory));
        CHECK(!memcmp(aop_memory+64,aop_original+64,0x100000-64));
        memcpy(aop_original,aop_memory,0x100000);CHECK(aop_cycle());
        CHECK(h_writes==4&&h_irqs==3); /* OFF cannot reopen/renew */
    }
    for(unsigned fault=1;fault<=12;fault++){
        if(fault==3||fault==9)continue;h_setup(fault);CHECK(!aop_drive());
        CHECK(aop_owner->unknown&&owner->held&&!aop_doorbells);
        unsigned calls=h_calls;CHECK(pman_step(aop_owner)==PMAQ_FAILED&&calls==h_calls);
        CHECK(!memcmp(aop_memory+0x2004,aop_original+0x2004,96));
        if(fault==1||fault==2)CHECK(aop_owner->notify[0].error==1);
        if(fault==4||fault==5||fault>=10)CHECK(aop_owner->notify[0].error==5);
        if(fault==6||fault==7)CHECK(aop_owner->notify[0].error==6);
        if(fault==8)CHECK(aop_owner->notify[0].error==7);
    }
    fprintf(stderr,"handshake three remote orderings, on/off and ten protocol failures PASS; checking %u new delivery positions\n",location_count);
    /* Every new step/index, including each descriptor word, control write,
     * readback, order and IRQ. Existing message failure coverage is separate. */
    for(unsigned n=0;n<location_count;n++){
        unsigned stop=locations[n];h_setup(0);h_stop=stop;CHECK(!aop_drive());
        CHECK(aop_owner->unknown&&owner->held&&h_calls==stop);
        CHECK(!pman_off(aop_owner));CHECK(pman_step(aop_owner)==PMAQ_FAILED&&h_calls==stop);
    }
    for(unsigned bad=0;bad<5;bad++){
        h_setup(0);
        if(bad==0)put(aop_memory+0x1000,4,4);
        if(bad==1)put(aop_memory+0x2000,96,4);
        if(bad==2)put(aop_memory+44,0xffff,4);
        if(bad==3)put(aop_memory+36,0xffff,4);
        if(bad==4)put(aop_memory+52,96,4);
        CHECK(!aop_drive()&&!h_writes&&!h_irqs&&!aop_writes&&!owner->effects);
    }
    aop_test_close();printf("PASS %u QMP handshake checks, %u scenarios, %u injected delivery failures; SOFTWARE only\n",checks,h_scenarios,location_count);CHECK(normal_calls>location_count);return 0;
}

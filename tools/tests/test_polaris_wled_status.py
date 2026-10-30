"""OEM volatile-status integration, with an explicit SOFTWARE PMIC fixture.

No phone admission, electrical-darkness proof or fault-clear operation.
"""
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_wled_power import H

OEM_H = H.replace('unsigned foreign_owner,',
    'unsigned pulse, fault_count, rt_count, post_fault, post_rt;\n unsigned foreign_owner,').replace(
    'if(f->mutate_after_issue)',
    'if(f->post_fault)f->pmic[0][8]=(uint8_t)f->post_fault;\n '
    'if(f->post_rt)f->pmic[0][0x10]=(uint8_t)f->post_rt;\n '
    'if(f->mutate_after_issue)') + r'''
static void dynamic_command(void *ctx,uint32_t off,uint32_t cmd) {
 struct fake *f=ctx;unsigned reg=(cmd>>4)&255;
 if(f->pulse&&off==253*0x80) {
  if(reg==8)f->pmic[0][8]=(uint8_t)(++f->fault_count&1);
  if(reg==0x10)f->pmic[0][0x10]=(uint8_t)(++f->rt_count&1);
 }
 read_command(ctx,off,cmd);
}
void oem_start(struct fake *f,struct polaris_wled_read_bus *b,
 struct polaris_wled_power *p,unsigned pulse) {
 setup(f,b,p);struct polaris_wled_snapshot s;
 assert(polaris_wled_inventory(b,&s));
 f->pulse=pulse;b->read_command=dynamic_command;
 assert(pwp_init_oem_status(p,b,&s,false)&&!f->writes);
 assert(p->status_policy==PWP_OEM_STATUS_WITNESS);
}
void oem_cycle(struct fake *f,struct polaris_wled_power *p) {
 assert(pwp_request(p,1,false));until_ack(f,p,1);
 assert(!p->actual_on&&!pwp_restored(p));
 assert(pwp_request(p,2,true));until_ack(f,p,2);
 assert(pwp_restored(p)&&f->writes==4&&p->issued==p->completed&&!p->uncertain);
 assert(f->ovp_time-f->enable_time>=10000);
}
'''


class WledStatus(unittest.TestCase):
    def test_dynamic_ILIM_survives_exact_cycle_and_never_becomes_clean_health(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 oem_start(&f,&b,&p,1);oem_cycle(&f,&p);
 assert(!p.error&&!p.witness.error&&p.witness.count>=24);
 assert(p.witness.fault_or==1&&p.witness.rt_or==1);
 unsigned high=0,low=0;
 for(unsigned n=0;n<p.witness.count;n++) {
  const struct polaris_wled_status_record*r=&p.witness.record[n];
  assert(r->valid==3&&r->ended_us>r->began_us);
  high+=r->fault==1;low+=r->fault==0;
 }assert(high&&low&&p.saved.faults[0]==0&&p.saved.faults[1]==0);
 f.pmic[0][8]=f.pmic[0][0x10]=0;
 assert(!memcmp(f.original,f.pmic,sizeof(f.pmic)));
 assert(f.commands[0]==0x460&&f.data[0]==0&&f.commands[1]==0x160&&f.data[1]==2);
 assert(f.commands[2]==0x460&&f.data[2]==0x80&&f.commands[3]==0x141&&f.data[3]==0x0202);
 return 0;
}
''')

    def test_original_mode_refuses_changes_and_cannot_switch_after_refusal(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 setup(&f,&b,&p);struct polaris_wled_snapshot s;assert(polaris_wled_inventory(&b,&s));
 f.pulse=1;b.read_command=dynamic_command;
 assert(!pwp_init(&p,&b,&s,false)&&b.fault==PW_E_CHANGED&&!f.writes);
 unsigned error=p.error;
 assert(!pwp_init_oem_status(&p,&b,&s,false)&&p.error==error&&!f.writes);
 assert(p.status_policy==PWP_STRICT_SNAPSHOT&&!p.witness.count);
 return 0;
}
''')

    def test_every_serious_or_unknown_bit_is_retained_and_stops_at_every_write(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++)
 for(unsigned stage=0;stage<5;stage++) {
  oem_start(&f,&b,&p,0);
  if(stage) {
   assert(pwp_request(&p,1,false));
   while(f.writes<stage&&f.writes<2){f.time+=1000;assert(pwp_poll(&p));}
   if(stage>=3) {
    until_ack(&f,&p,1);assert(pwp_request(&p,2,true));
    while(f.writes<stage){f.time+=1000;assert(pwp_poll(&p));}
   }
  }
  unsigned before=f.writes,count=p.witness.count;
  f.pmic[0][bank?0x10:8]=(uint8_t)(1u<<bit);
  assert(!pwp_verify(&p)&&p.error==PWS_E_STATUS&&!pwp_restored(&p));
  assert(f.writes==before&&p.witness.count==count+1);
  const struct polaris_wled_status_record*r=&p.witness.record[count];
  assert((bank?r->rt:r->fault)==(1u<<bit));
  assert((bank?p.witness.rt_or:p.witness.fault_or)&(1u<<bit));
  for(unsigned n=0;n<10;n++)assert(!pwp_poll(&p));
  assert(f.writes==before&&!pwp_request(&p,3,true));
 }
 return 0;
}
''')

    def test_all_static_bytes_unchanged_and_status_never_sanitized(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 unsigned regs[66],banks[66],at=0;
 for(unsigned bank=0;bank<2;bank++)for(unsigned reg=0;reg<8;reg++)
  {banks[at]=bank;regs[at++]=reg;}
 for(unsigned reg=0x44;reg<=0x46;reg++){banks[at]=0;regs[at++]=reg;}
 banks[at]=0;regs[at++]=8;banks[at]=0;regs[at++]=0x10;
 banks[at]=0;regs[at++]=0x5a;banks[at]=0;regs[at++]=0x5b;
 banks[at]=0;regs[at++]=0x15;
 for(unsigned reg=0x46;reg<=0x4b;reg++){banks[at]=1;regs[at++]=reg;}
 for(unsigned n=0;n<4;n++)for(unsigned k=0;k<9;k++)
  {banks[at]=1;regs[at++]=0x50+0x10*n+k;}
 assert(at==sizeof(struct polaris_wled_snapshot));
 for(unsigned n=0;n<sizeof(struct polaris_wled_snapshot);n++)
 for(unsigned bit=0;bit<8;bit++) {
  if(n==19||n==20)continue;
  oem_start(&f,&b,&p,0);f.pmic[banks[n]][regs[n]]^=1u<<bit;
  assert(!pwp_verify(&p)&&p.error==PWS_E_CONFIG&&!f.writes);
 }
 for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++) {
  setup(&f,&b,&p);struct polaris_wled_snapshot s;assert(polaris_wled_inventory(&b,&s));
  s.faults[bank]=(uint8_t)(1u<<bit);
  assert(!pwp_init_oem_status(&p,&b,&s,false)&&!f.writes);
  assert(s.faults[bank]==(1u<<bit));
 }
 return 0;
}
''')

    def test_fault_appearing_after_issue_keeps_uncertainty_and_prevents_reset(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++)
 for(unsigned command=1;command<=4;command++) {
  oem_start(&f,&b,&p,0);assert(pwp_request(&p,1,false));
  while(f.writes<command-1&&f.writes<2){f.time+=1000;assert(pwp_poll(&p));}
  if(command>=3) {
   until_ack(&f,&p,1);assert(pwp_request(&p,2,true));
   while(f.writes<command-1){f.time+=1000;assert(pwp_poll(&p));}
  }
  if(bank)f.post_rt=1u<<bit;else f.post_fault=1u<<bit;
  for(unsigned n=0;n<32&&!p.error;n++){f.time+=1000;(void)pwp_poll(&p);}
  assert(p.error==PWS_E_STATUS&&p.uncertain&&f.writes==command);
  assert(p.completed==command&&!pwp_restored(&p));
  assert((bank?p.witness.rt_or:p.witness.fault_or)&(1u<<bit));
  for(unsigned n=0;n<100;n++)assert(!pwp_poll(&p));
  assert(f.writes==command&&!pwp_request(&p,3,true));
 }
 return 0;
}
''')

    def test_all_reads_fail_closed_partial_status_survives_and_history_is_bounded(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned read=1;read<=32;read++) {
  oem_start(&f,&b,&p,1);unsigned count=p.witness.count;
  f.fail_read=f.read_count+read;
  assert(!pwp_verify(&p)&&p.error==PW_E_RESPONSE&&!f.writes);
  assert(p.witness.count>count&&p.witness.error==PW_E_RESPONSE);
  if(read>1)assert(p.witness.record[count].valid&1);
  assert(p.witness.fault_or==1);
 }
 oem_start(&f,&b,&p,1);
 while(p.witness.count<PWS_RECORDS)assert(pwp_verify(&p));
 assert(!pwp_verify(&p)&&p.error==PWS_E_CAPACITY&&!f.writes&&!pwp_restored(&p));
 assert(p.witness.count==PWS_RECORDS&&p.witness.fault_or==1);
 return 0;
}
''')

    def test_owner_config_clock_and_uncertain_write_keep_reset_blocked(self):
        run(OEM_H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned bad=0;bad<7;bad++) {
  oem_start(&f,&b,&p,1);assert(pwp_request(&p,1,false));assert(pwp_poll(&p));
  if(bad==0)f.foreign_owner=1;
  if(bad==1)f.bad_map=1;
  if(bad==2)f.pmic[1][0x54]^=1;
  if(bad==3)f.backward=1;
  if(bad==4)f.frozen=1;
  if(bad==5){f.fail_write=1;f.status=0;}
  if(bad==6)f.mutate_after_issue=1;
  assert(!pwp_poll(&p)&&p.error&&!pwp_restored(&p));
  unsigned writes=f.writes;
  assert(writes==(bad>=5?1u:0u));
  if(bad>=5)assert(p.uncertain);
  for(unsigned n=0;n<100;n++)assert(!pwp_poll(&p));
  assert(f.writes==writes&&p.witness.fault_or==1);
 }
 return 0;
}
''')


if __name__=='__main__':
    unittest.main()

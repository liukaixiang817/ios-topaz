/* Suffix for the isolated EFI SOFTWARE PMIC runner. The fixture and serial
 * assertions precede this file. No SD845 MMIO, native OS, display or USB model.
 * Frame tokens below are synthetic; only softstart uses the real guest clock.
 */
static uint64_t runtime_clock(void *ctx)
{
    struct fake *fake=ctx;uint64_t ticks,freq;
    __asm__ volatile("mrs %0,cntvct_el0":"=r"(ticks));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(freq));
    assert(freq&&freq<=1000000000);
    return fake->time=ticks/freq*1000000+(ticks%freq)*1000000/freq;
}
static void runtime_begin(void)
{
    memset(&r,0,sizeof(r));memset(&n,0,sizeof(n));memset(&fw,0,sizeof(fw));
    setup(&f,&b,&p);b.now_us=runtime_clock;
    struct polaris_wled_snapshot expected;
    assert(polaris_wled_inventory(&b,&expected));
    f.pulse=1;b.read_command=dynamic_command;
    assert(pwp_init_oem_status(&p,&b,&expected,false));
    assert(pwr_init(&r,&p,archive,8192));
    struct polaris_wled_ack a;
    assert(pwm_firmware_init(&fw,0x123456789abcdef0,r.count,f.time,&a));
    assert(pwm_native_init(&n,&a,f.time));
}
static void runtime_target(struct efi_system *st,bool on)
{
    struct polaris_wled_request request;struct polaris_wled_ack a;
    assert(pwm_native_intent(&n,on));
    if(on)assert(pwm_native_presented(&n,n.last_frame+1)); /* Synthetic token. */
    assert(pwm_native_next(&n,runtime_clock(&f),&request));
    assert(pwm_firmware_request(&fw,&request));
    assert(pwr_request(&r,request.sequence,on)==PWR_ACCEPTED);
    uint64_t began=runtime_clock(&f);
    while(r.pending) {
        unsigned before=f.writes;
        assert(runtime_clock(&f)-began<1000000);
        assert(pwr_poll(&r)&&f.writes<=before+1);
        assert(pwm_native_tick(&n,runtime_clock(&f)));
        assert(!st->boot->stall(100));
    }
    assert(pwm_firmware_complete(&fw,p.actual_on,!p.error&&!p.uncertain,
        r.count,runtime_clock(&f),&a));
    assert(pwm_native_ack(&n,&a,runtime_clock(&f))&&n.actual_on==on);
}
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    (void)image;assert(st&&st->boot&&st->boot->stall);
    serial("WLED_POWER_MODEL_SOFTWARE_PMIC_ONLY\n");
    uint64_t el;__asm__ volatile("mrs %0,CurrentEL":"=r"(el));assert(el==4);
    number("WLED_POWER_CURRENT_EL=",el);
    runtime_begin();uint64_t min_softstart=UINT64_MAX;
    for(unsigned cycle=0;cycle<16;cycle++) {
        runtime_target(st,false);runtime_target(st,true);
        uint64_t soft=f.ovp_time-f.enable_time;
        assert(soft>=10000);if(soft<min_softstart)min_softstart=soft;
    }
    assert(r.count==386&&f.writes==64&&p.witness.count==0);
    assert(p.witness.fault_or==1&&p.witness.rt_or==1);
    assert(!memcmp(f.original[1],f.pmic[1],256));
    for(unsigned reg=0;reg<256;reg++)if(reg!=8&&reg!=0x10)
        assert(f.original[0][reg]==f.pmic[0][reg]);
    uint64_t last=0;
    for(unsigned k=0;k<r.count;k++) {
        assert(archive[k].raw.valid==3&&archive[k].raw.began_us>=last);
        last=archive[k].raw.ended_us;
    }
    number("WLED_POWER_RUNTIME_MIN_SOFTSTART_US=",min_softstart);
    serial("WLED_POWER_RUNTIME_REAL_CLOCK_16_CYCLES_PASS\n");
    assert(pwr_close(&r)&&pwr_seal(&r)&&r.count==390);
    assert(r.final_first==388&&r.final_last==390&&!pwr_seal(&r));
    serial("WLED_POWER_RUNTIME_FINAL_NEW_READS_PASS\n");
    /* Remaining fault cases use explicit synthetic timestamps, not elapsed
     * clock claims or a panel / PMIC hardware emulator. */
    begin(64,1);target(false);target(true);target(false);target(true);
    unsigned writes=f.writes;
    assert(pwr_request(&r,p.request+1,false)==PWR_CAPACITY);
    assert(p.actual_on&&f.writes==writes&&!r.error&&!p.error);
    assert(pwr_close(&r)&&pwr_seal(&r)&&r.count==54);
    serial("WLED_POWER_RUNTIME_CAPACITY_RESERVE_PASS\n");
    for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++) {
        begin(64,0);assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
        if(bank)f.post_rt=1u<<bit;else f.post_fault=1u<<bit;
        for(unsigned k=0;k<64&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
        assert(p.error==PWS_E_STATUS&&p.uncertain&&f.writes==1&&p.completed==1);
        assert(!pwr_close(&r)&&!pwr_seal(&r));
        const struct polaris_wled_status_record *raw=&archive[r.count-1].raw;
        assert((bank?raw->rt:raw->fault)==(1u<<bit));
    }
    serial("WLED_POWER_RUNTIME_ALL_SEVERE_PARTIAL_PASS\n");
    begin(64,0);f.fail_write=1;f.status=0;
    assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
    for(unsigned k=0;k<64&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
    assert(p.error==PWP_E_WRITE_TIMEOUT&&p.uncertain&&f.writes==1&&!p.completed);
    assert(!pwr_close(&r)&&!pwr_seal(&r));
    serial("WLED_POWER_RUNTIME_UNCERTAIN_PASS\n");
    begin(64,0);struct polaris_wled_request request;
    assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&request));
    assert(!pwm_native_tick(&n,n.sent_us+PWM_TIMEOUT_US)&&n.error==PWM_E_TIMEOUT);
    assert(!pwm_native_next(&n,++f.time,&request)&&!f.writes);
    serial("WLED_POWER_RUNTIME_MAILBOX_NO_RETRY_PASS\n");
    number("WLED_POWER_RUNTIME_ASSERTIONS=",checks);
    serial("WLED_POWER_MODEL_DONE\n");
    for(;;)__asm__ volatile("wfe");
}

/* Built-in Polaris IOPMPowerSource. Real firmware-owned PMI8998 telemetry only.
 * No PMIC MMIO, boot service calls, charger settings or guessed capacity.
 * The EFI builder must bind the exact BSS symbol, restrict firmware writes to
 * its 256 bytes and reserve the range like the existing WLED/input channels.
 */
#if defined(ARM64_BOARD_CONFIG_SWEET)
#include <device/device_types.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/pwr_mgt/IOPMPowerSource.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include "polaris-battery-shared.h"
extern "C" {
struct polaris_battery_sample polaris_uefi_battery;
bool polaris_ram_overlay_allowed(void);
bool polaris_gpu_overlay_ready(void);
int polaris_uefi_shutdown_pending(void);
}

class PolarisBattery : public IOPMPowerSource {
    OSDeclareDefaultStructors(PolarisBattery);
public:
    bool init(OSDictionary *dictionary=NULL) APPLE_KEXT_OVERRIDE;
    bool start(IOService *) APPLE_KEXT_OVERRIDE;
    void stop(IOService *) APPLE_KEXT_OVERRIDE;
    void free(void) APPLE_KEXT_OVERRIDE;
private:
    IOWorkLoop *fLoop;
    IOTimerEventSource *fTimer;
    bool fAdded,fRunning,fMeasured;
    uint64_t fCookie,fSequence,fSampleTime;
    unsigned fError;
    void number(const char *,uint64_t,unsigned bits=32);
    void flag(const char *,bool);
    void erase(const char *);
    void invalidate(unsigned,uint64_t);
    void poll(void);
    static void fired(OSObject *,IOTimerEventSource *);
    static IOReturn halt(OSObject *,void *,void *,void *,void *);
};
OSDefineMetaClassAndStructors(PolarisBattery,IOPMPowerSource);

static bool pbat_native_authorized(void)
{
    DTEntry root,node;const void *compatible=NULL,*version=NULL,*enabled=NULL;
    unsigned compatible_bytes=0,version_bytes=0,enabled_bytes=0;uint32_t uefi=0;
    PE_parse_boot_argn("polarisuefi",&uefi,sizeof(uefi));
    if(SecureDTLookupEntry(NULL,"/",&root)!=kSuccess||
       SecureDTGetProperty(root,"compatible",&compatible,&compatible_bytes)!=kSuccess||
       SecureDTLookupEntry(NULL,"/polaris-runtime-services",&node)!=kSuccess||
       SecureDTGetProperty(node,"version",&version,&version_bytes)!=kSuccess||
       SecureDTGetProperty(node,"battery-readonly",&enabled,&enabled_bytes)!=kSuccess)return false;
    return pbat_runtime_authorized(compatible,compatible_bytes,version,version_bytes,
        enabled,enabled_bytes,uefi);
}
static uint64_t pbat_native_time(uint64_t *frequency)
{
    uint64_t ticks,hz;
    __asm__ volatile("mrs %0,cntvct_el0":"=r"(ticks));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(hz));
    *frequency=hz;
    return hz?(ticks/hz)*1000000+(ticks%hz)*1000000/hz:0;
}
static void pbat_native_invalidate(void)
{
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    uint64_t line=UINT64_C(4)<<((ctr>>16)&15);
    uintptr_t base=(uintptr_t)&polaris_uefi_battery;
    for(uintptr_t at=base;at<base+sizeof(polaris_uefi_battery);at+=line)
        __asm__ volatile("dc ivac,%0"::"r"(at):"memory");
    __asm__ volatile("dsb sy":::"memory");
}
static bool pbat_native_copy(struct polaris_battery_sample *out)
{
    pbat_native_invalidate();
    uint64_t first=__atomic_load_n(&polaris_uefi_battery.sequence,__ATOMIC_ACQUIRE);
    if(!first||(first&1))return false;
    const volatile uint8_t *src=(const volatile uint8_t *)&polaris_uefi_battery;
    uint8_t *dst=(uint8_t *)out;
    for(unsigned i=0;i<sizeof(*out);i++)dst[i]=src[i];
    pbat_native_invalidate();
    uint64_t after=__atomic_load_n(&polaris_uefi_battery.sequence,__ATOMIC_ACQUIRE);
    return first==after&&out->sequence==first;
}
bool PolarisBattery::init(OSDictionary *dictionary)
{
    if(!IOPMPowerSource::init())return false;
    fLoop=NULL;fTimer=NULL;fAdded=fRunning=fMeasured=false;
    fCookie=fSequence=fSampleTime=0;fError=0;
    if(dictionary) {
        OSCollectionIterator *it=OSCollectionIterator::withCollection(dictionary);
        if(!it)return false;
        OSObject *object;bool ok=true;
        while((object=it->getNextObject())) {
            const OSSymbol *key=OSDynamicCast(OSSymbol,object);
            if(!key||!setProperty(key,dictionary->getObject(key))){ok=false;break;}
        }
        it->release();if(!ok)return false;
    }
    return true;
}
void PolarisBattery::number(const char *key,uint64_t value,unsigned bits)
{
    const OSSymbol *symbol=OSSymbol::withCString(key);
    OSNumber *n=OSNumber::withNumber(value,bits);
    if(symbol&&n)setPSProperty(symbol,n);
    OSSafeReleaseNULL(n);OSSafeReleaseNULL(symbol);
}
void PolarisBattery::flag(const char *key,bool value)
{
    const OSSymbol *symbol=OSSymbol::withCString(key);
    if(symbol)setPSProperty(symbol,value?kOSBooleanTrue:kOSBooleanFalse);
    OSSafeReleaseNULL(symbol);
}
void PolarisBattery::erase(const char *key)
{
    if(properties&&properties->getObject(key)) {
        properties->removeObject(key);removeProperty(key);settingsChangedSinceUpdate=true;
    }
}
void PolarisBattery::invalidate(unsigned error,uint64_t age)
{
    /* Remove old measurements rather than leaving a stale charging icon or
     * turning an unknown battery into a fictitious absent/empty battery. */
    const char *keys[]={"CurrentCapacity","MaxCapacity","Voltage","Amperage",
        "InstantAmperage","Temperature","ExternalConnected","ExternalChargeCapable",
        "BatteryInstalled","IsCharging","FullyCharged","AppleRawExternalConnected",
        "AtWarnLevel","AtCriticalLevel","TimeRemaining","LegacyBatteryInfo"};
    for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++)erase(keys[i]);
    const OSSymbol *condition=OSSymbol::withCString("TelemetryUnavailable");
    if(condition)setErrorCondition(const_cast<OSSymbol *>(condition));
    OSSafeReleaseNULL(condition);
    flag("PolarisBatteryDataValid",false);
    number("PolarisBatteryError",error);number("PolarisBatteryAgeUS",age,64);
    if(error!=fError)IOLog("POLARIS BATTERY: unavailable error=%u; no synthetic fallback\n",error);
    fError=error;fMeasured=false;updateStatus();
}
void PolarisBattery::poll(void)
{
    /* IOResources may start before the root overlay is installed. Keep the
     * timer/service alive and publish unknown until actual admission exists.
     * Native never reads PMIC, and must not even consume the firmware cache
     * before root/graphics ownership is ready or during native shutdown. */
    if(!polaris_ram_overlay_allowed()||!polaris_gpu_overlay_ready()||
       polaris_uefi_shutdown_pending()) {
        invalidate(PBAT_E_NOT_READY,UINT64_MAX);return;
    }
    struct polaris_battery_sample s={};uint64_t hz=0,now=pbat_native_time(&hz);
    if(!pbat_native_copy(&s)) {invalidate(PBAT_E_WIRE,UINT64_MAX);return;}
    uint64_t age=now>=s.began_us?now-s.began_us:UINT64_MAX;
    if(!pbat_sample_valid(&s,now,hz)) {
        invalidate(s.error?s.error:age>PBAT_MAX_AGE_US?PBAT_E_STALE:PBAT_E_WIRE,age);return;
    }
    if((fCookie&&s.cookie!=fCookie)||(fSequence&&s.sequence<fSequence)||
       (fSampleTime&&s.sampled_us<fSampleTime)) {
        invalidate(PBAT_E_WIRE,age);return;
    }
    fCookie=s.cookie;
    if(s.sequence==fSequence&&fMeasured) {
        number("PolarisBatteryAgeUS",age,64);updateStatus();return;
    }
    fSequence=s.sequence;fSampleTime=s.sampled_us;
    erase("ErrorCondition");
    setBatteryInstalled(true);
    /* Percentage units, as in pinned reference IOPMPowerSource. No invented
     * mAh, cycle count, remaining-time model or voltage-derived SOC. */
    setCurrentCapacity((unsigned)s.soc_percent);setMaxCapacity(100);
    setVoltage((unsigned)s.voltage_uv/1000);setAmperage(s.current_ua/1000);
    setExternalConnected(s.external);setExternalChargeCapable(s.capable);
    setIsCharging(s.charging);setTimeRemaining(-1);
    flag("FullyCharged",s.full);flag("AppleRawExternalConnected",s.external);
    number("InstantAmperage",(uint32_t)(s.current_ua/1000));
    number("Temperature",(uint32_t)s.temperature_centi_c);
    flag("PolarisBatteryDataValid",true);flag("PolarisBatterySOCEstimated",false);
    number("PolarisBatterySource",s.source);number("PolarisBatteryError",0);
    number("PolarisBatterySequence",s.sequence,64);number("PolarisBatteryAgeUS",age,64);
    number("PolarisBatteryBeganUS",s.began_us,64);
    number("PolarisBatterySpanUS",s.sampled_us-s.began_us,64);
    number("PolarisBatterySpanLimitUS",s.span_limit_us);
    number("PolarisBatterySampleUS",s.sampled_us,64);number("PolarisBatteryCounterHz",hz,64);
    number("PolarisBatteryVoltageUV",s.voltage_uv);
    number("PolarisBatteryCurrentUA",(uint32_t)s.current_ua);
    OSData *raw=OSData::withBytes(s.raw,sizeof(s.raw));
    const OSSymbol *key=OSSymbol::withCString("PolarisBatteryRaw");
    if(raw&&key)setPSProperty(key,raw);
    OSSafeReleaseNULL(raw);OSSafeReleaseNULL(key);
    if(!fMeasured)IOLog("POLARIS BATTERY: actual FG3/SMB2 sample %d%% %dmV charging=%u\n",
        s.soc_percent,s.voltage_uv/1000,s.charging);
    fMeasured=true;fError=0;updateStatus();
}
void PolarisBattery::fired(OSObject *owner,IOTimerEventSource *sender)
{
    PolarisBattery *self=OSDynamicCast(PolarisBattery,owner);
    if(self&&self->fRunning){self->poll();sender->setTimeoutMS(1000);}
}
bool PolarisBattery::start(IOService *provider)
{
    if(!pbat_native_authorized()) {
        IOLog("POLARIS BATTERY: not enabled by exact Polaris runtime DT/board; no synthetic fallback\n");
        return false;
    }
    if(!IOPMPowerSource::start(provider))return false;
    fLoop=IOWorkLoop::workLoop();fTimer=IOTimerEventSource::timerEventSource(this,&PolarisBattery::fired);
    if(!fLoop||!fTimer||fLoop->addEventSource(fTimer)!=kIOReturnSuccess)return false;
    fAdded=fRunning=true;poll();registerService();fTimer->setTimeoutMS(1000);return true;
}
IOReturn PolarisBattery::halt(OSObject *owner,void *,void *,void *,void *)
{
    PolarisBattery *self=OSDynamicCast(PolarisBattery,owner);
    if(!self)return kIOReturnBadArgument;
    self->fRunning=false;self->fTimer->cancelTimeout();self->fTimer->disable();return kIOReturnSuccess;
}
void PolarisBattery::stop(IOService *provider)
{
    if(fLoop&&fAdded){(void)fLoop->runAction(&PolarisBattery::halt,this);
        fLoop->removeEventSource(fTimer);fAdded=false;}
    IOPMPowerSource::stop(provider);
}
void PolarisBattery::free(void)
{
    OSSafeReleaseNULL(fTimer);OSSafeReleaseNULL(fLoop);IOPMPowerSource::free();
}
#endif

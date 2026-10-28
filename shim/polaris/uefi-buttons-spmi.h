/* Original Polaris PM8998 inputs, not the Redwood PMK8350/PM7325 map.
 * Register correspondence: MiCode c7cb50c1 spmi-pmic-arb.c (v5),
 * qpnp-power-on.c, pinctrl-spmi-gpio.c and the saved original live DT.
 * Only observer READ command words are written. No PMIC/config/IRQ writes.
 * Caller must own firmware CPU0's synchronous bus, with its IRQs masked and
 * no other selected kernel/firmware client of this EE's observer channels.
 * Injected callbacks allow identical command/identity/error code to be tested.
 */
#ifndef POLARIS_EFI_BUTTONS_SPMI_H
#define POLARIS_EFI_BUTTONS_SPMI_H
#include <stdbool.h>
#include <stdint.h>
#define PB_CORE 0u
#define PB_CONFIG 1u
#define PB_OBSERVER 2u
#define PB_CHANNELS 512u /* original core resource (0x1100-0x900)/4 */
struct polaris_button_bus {
    void *context;
    uint32_t (*read)(void *,unsigned,uint32_t);
    void (*read_command)(void *,uint32_t,uint32_t);
    uint64_t (*now_us)(void *);
    uint32_t version, map[2], owner[2], apid[2], fault, reads;
    uint32_t last_key,last_reg,last_status,last_polls;
    bool initialized, active;
    uint8_t pon_id[2],gpio_id[2],gpio_config[7],gpio_source;
};
enum { PB_E_ARGUMENT=1,PB_E_VERSION,PB_E_MAPPING,PB_E_TIME,
       PB_E_TIMEOUT,PB_E_RESPONSE,PB_E_IDENTITY,PB_E_INPUT };
static inline bool pb_error(struct polaris_button_bus *b,unsigned e)
{ if(b&&!b->fault)b->fault=e;return false; }
static inline bool pb_map(struct polaris_button_bus *b)
{
    if(!b||b->fault||!b->read||!b->read_command||!b->now_us)return pb_error(b,PB_E_ARGUMENT);
    uint32_t version=b->read(b->context,PB_CORE,0);
    if(version<0x50000000u||version>=0x60000000u||
       (b->initialized&&version!=b->version))return pb_error(b,PB_E_VERSION);
    uint32_t selected[2]={UINT32_MAX,UINT32_MAX},map[2]={0,0},owner[2]={0,0};
    const uint32_t ppid[2]={0x008,0x0c5}; /* SID0 PON0800 and physical GPIO6c500 */
    for(unsigned a=0;a<PB_CHANNELS;a++) {
        uint32_t v=b->read(b->context,PB_CORE,0x900+4*a);
        for(unsigned k=0;k<2;k++)if(v&&((v>>8)&0xfff)==ppid[k]) {
            uint32_t o=b->read(b->context,PB_CONFIG,0x700+4*a)&7;
            /* Exact v5 canonical choice: first, overridden by later EE0. */
            if(selected[k]==UINT32_MAX||o==0){selected[k]=a;map[k]=v;owner[k]=o;}
        }
    }
    for(unsigned k=0;k<2;k++) {
        if(selected[k]==UINT32_MAX)return pb_error(b,PB_E_MAPPING);
        if(b->initialized&&(b->apid[k]!=selected[k]||b->map[k]!=map[k]||b->owner[k]!=owner[k]))
            return pb_error(b,PB_E_MAPPING);
        b->apid[k]=selected[k];b->map[k]=map[k];b->owner[k]=owner[k];
    }
    b->version=version;b->initialized=true;return true;
}
static inline bool pb_read(struct polaris_button_bus *b,unsigned key,uint8_t reg,
    uint8_t *out,unsigned count)
{
    if(!b||b->fault)return false;
    if(key>1||!out||count<1||count>8||count>256u-reg)return pb_error(b,PB_E_ARGUMENT);
    b->last_key=key;b->last_reg=reg;b->last_status=0;b->last_polls=0;
    if(!pb_map(b))return false; /* refuse reassignment before every command */
    uint32_t offset=0x80*b->apid[key]; /* EE0 observer only */
    uint64_t start=b->now_us(b->context),previous=start;
    if(!start)return pb_error(b,PB_E_TIME);
    b->read_command(b->context,offset,(1u<<27)|((uint32_t)reg<<4)|(count-1));
    uint32_t status=0;
    for(unsigned n=0;n<4096;n++) {
        status=b->read(b->context,PB_OBSERVER,offset+8);
        b->last_status=status;b->last_polls=n+1;
        uint64_t now=b->now_us(b->context);
        if(now<previous)return pb_error(b,PB_E_TIME);
        previous=now;
        if(status&~1u)return pb_error(b,PB_E_RESPONSE); /* denied/fail/drop/unknown */
        if(status==1) {
            uint32_t data[2]={b->read(b->context,PB_OBSERVER,offset+0x18),0};
            if(count>4)data[1]=b->read(b->context,PB_OBSERVER,offset+0x1c);
            for(unsigned i=0;i<count;i++)out[i]=(uint8_t)(data[i/4]>>(8*(i%4)));
            b->reads++;return true;
        }
        if(now-start>=100)return pb_error(b,PB_E_TIMEOUT);
    }
    return pb_error(b,PB_E_TIMEOUT); /* frozen timer cannot hang USB */
}
static inline bool pb_gpio_input(const uint8_t id[2],const uint8_t cfg[7],uint8_t source)
{
    if(id[0]!=0x10||!(cfg[6]&0x80)||(cfg[2]&7)>=4)return false;
    if(id[1]==1||id[1]==5||id[1]==9||id[1]==13)
        return ((cfg[0]>>4)&7)==0&&((cfg[0]>>1)&7)==0;
    if(id[1]==0x10||id[1]==0x11)return (cfg[0]&3)==0&&(source&15)==0;
    return false;
}
static inline bool pb_start(struct polaris_button_bus *b)
{
    if(!b||b->fault||b->active)return false;
    if(!pb_read(b,0,4,b->pon_id,2)||!pb_read(b,1,4,b->gpio_id,2))return false;
    /* PON primary Gen2 identity; no reset/debounce configuration changes. */
    if(b->pon_id[0]!=8||b->pon_id[1]!=4)return pb_error(b,PB_E_IDENTITY);
    if(!pb_read(b,1,0x40,b->gpio_config,7))return false;
    if(b->gpio_id[1]==0x10||b->gpio_id[1]==0x11) {
        if(!pb_read(b,1,0x44,&b->gpio_source,1))return false;
    }
    if(!pb_gpio_input(b->gpio_id,b->gpio_config,b->gpio_source))return pb_error(b,PB_E_INPUT);
    b->active=true;return true;
}
static inline bool pb_levels(struct polaris_button_bus *b,uint8_t *pon,uint8_t *gpio)
{
    if(!b||!b->active||b->fault)return false;
    return pb_read(b,0,0x10,pon,1)&&pb_read(b,1,0x10,gpio,1);
}
#endif

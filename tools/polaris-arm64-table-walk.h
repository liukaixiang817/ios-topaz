/* Read-only 4 KiB EL1 TTBR0 table evidence. No mapping/access permission grant.
 * Reader must independently qualify each RAM address; no target PA is read. */
#ifndef POLARIS_ARM64_TABLE_WALK_H
#define POLARIS_ARM64_TABLE_WALK_H
#include <stdint.h>
struct pmpt_walk {
    uint64_t ttbr,tcr,address,entry[4],descriptor[4],physical;
    uint32_t attempted,error,first,levels,leaf,stable,complete,reserved;
};
typedef int (*pmpt_reader)(void*,unsigned,unsigned,uint64_t,uint64_t*);
static inline int pmpt_collect(struct pmpt_walk*w,uint64_t ttbr,uint64_t tcr,uint64_t address,
    pmpt_reader read,void*context)
{
    if(!w||!read)return 0;
    const uint8_t*z=(const void*)w;for(unsigned k=0;k<sizeof(*w);k++)if(z[k])return 0;
    w->attempted=1;w->ttbr=ttbr;w->tcr=tcr;w->address=address;
    unsigned size=(unsigned)tcr&63,bits=64-size;
    if(size<16||size>39||(tcr&((UINT64_C(3)<<14)|(UINT64_C(1)<<7)|(UINT64_C(1)<<59)))||
       ((tcr>>32)&7)>5||(address&4095)||(address>>bits)||(ttbr&4094)){
        w->error=1;return 0;
    }
    w->first=4-(bits-12+8)/9;
    uint64_t table=ttbr&UINT64_C(0x0000fffffffff000),tables[4]={0};
    if(!table){w->error=1;return 0;}
    for(unsigned level=w->first;level<4;level++){
        unsigned n=w->levels,shift=12+9*(3-level);uint64_t mask=(UINT64_C(1)<<shift)-1;
        for(unsigned j=0;j<n;j++)if(tables[j]==table){w->error=6;return 0;}
        tables[n]=table;w->entry[n]=table+8*((address>>shift)&511);w->levels++;
        if(!read(context,0,n,w->entry[n],&w->descriptor[n])){w->error=2;return 0;}
        uint64_t d=w->descriptor[n],base=d&UINT64_C(0x0000fffffffff000);unsigned kind=(unsigned)d&3;
        if((d&UINT64_C(0x000f000000000000))||!(d&1)||(!level&&kind==1)||
           (level==3&&kind!=3)){w->error=3;break;}
        if(level<3&&kind==3){if(!base){w->error=3;break;}table=base;continue;}
        if(base&mask){w->error=3;break;}
        w->physical=base|(address&mask);w->leaf=level;break;
    }
    for(unsigned n=0;n<w->levels;n++){
        uint64_t value=0;if(!read(context,1,n,w->entry[n],&value)){w->error=2;return 0;}
        if(value!=w->descriptor[n]){w->error=4;return 0;}
    }
    w->stable=1;w->complete=!w->error;return w->complete;
}
#endif

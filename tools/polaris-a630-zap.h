/* Signed original A630 PAS13. Native subsys-pil-tz.c/scm.{c,h},
 * MiCode c7cb50c1. Every transport and secure return must succeed.
 * A rejected signature NEVER means that an older image is usable.
 * Metadata remains resident, untouched after INIT_IMAGE, even on failure.
 */
#ifndef POLARIS_A630_ZAP_H
#define POLARIS_A630_ZAP_H
#include "polaris-a630-images.h"
struct a630_zap_io {
    bool (*owned)(void *);
    int32_t (*call)(void *,uint32_t,uint32_t,uint64_t,uint64_t,uint64_t,uint64_t *);
    bool (*publish)(void *);
    bool (*segment)(void *,const uint8_t *,uint32_t);
    void *ctx;
};
enum a630_zap_error {A630_ZAP_DISABLED,A630_ZAP_ARGUMENT,A630_ZAP_LEASE,
    A630_ZAP_TRANSPORT,A630_ZAP_SECURE,A630_ZAP_IO,A630_ZAP_READY};
struct a630_zap_snapshot {uint32_t error,stage,fn,transport,secure,calls,signature,region,authenticated;};
static inline bool a630_zap_call(const struct a630_zap_io *io,
    struct a630_zap_snapshot *s,uint32_t fn,uint32_t info,uint64_t a,uint64_t b,uint64_t c,uint64_t expected)
{
    if(!io->owned(io->ctx)){s->error=A630_ZAP_LEASE;return false;}
    uint64_t result=UINT64_MAX;s->fn=fn;s->calls++;
    int32_t status=io->call(io->ctx,fn,info,a,b,c,&result);
    s->transport=(uint32_t)status;s->secure=(uint32_t)result;
    if(status){s->error=A630_ZAP_TRANSPORT;return false;}
    if(result!=expected){s->error=A630_ZAP_SECURE;return false;}return true;
}
static inline bool a630_zap_start(bool exact_board,const struct a630_zap_io *io,
    const struct a630_image images[6],uint64_t metadata_pa,struct a630_zap_snapshot *s)
{
    if(!s)return false;*s=(struct a630_zap_snapshot){0};if(!exact_board)return false;
    if(!io||!io->owned||!io->call||!io->publish||!io->segment||
       !a630_images_valid(images)||!metadata_pa||(metadata_pa&0x3fff)||metadata_pa>=(UINT64_C(1)<<36)){
        s->error=A630_ZAP_ARGUMENT;return false;}
    s->stage=1;
    /* Original SMC64 availability discovery, then each required PAS call. */
    if(!a630_zap_call(io,s,0xc2000601,1,0x82000601,0,0,1))return false;
    const uint32_t functions[]={0x02000206,0x02000201,0x02000202,0x02000205};
    for(unsigned n=0;n<4;n++)
        if(!a630_zap_call(io,s,0xc2000601,1,functions[n],0,0,1))return false;
    s->stage=2;
    if(!a630_zap_call(io,s,0x42000206,1,13,0,0,0))return false;
    s->stage=3;
    if(!io->owned(io->ctx)){s->error=A630_ZAP_LEASE;return false;}
    if(!io->publish(io->ctx)){s->error=A630_ZAP_IO;return false;}
    if(!a630_zap_call(io,s,0x42000201,0x82,13,metadata_pa,0,0))return false;
    s->signature=1;s->stage=4;
    if(!a630_zap_call(io,s,0x42000202,3,13,0x8c415000,4096,0))return false;
    s->region=1;s->stage=5;
    if(!io->owned(io->ctx)){s->error=A630_ZAP_LEASE;return false;}
    if(!io->segment(io->ctx,images[5].data,images[5].bytes)){s->error=A630_ZAP_IO;return false;}
    s->stage=6;
    if(!a630_zap_call(io,s,0x42000205,1,13,0,0,0))return false;
    s->authenticated=1;s->stage=7;s->error=A630_ZAP_READY;return true;
}
#endif

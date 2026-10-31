/* Scoped userspace clock experiment. No hardware/refresh-rate control. */
#ifndef POLARIS_COMPOSITOR_CLOCK_H
#define POLARIS_COMPOSITOR_CLOCK_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "polaris-graphics-abi.h"

#define PCC_ENV "POLARIS_CA_CLOCK_TRIAL"
#define PCC_FORCE "CA_FORCE_TIMER"
/* 0 absent (unchanged), 1 explicit VBL request, 2 explicit control, -1 invalid. */
static inline int pcc_request(const char *args,size_t capacity)
{
    if(!args || !capacity || capacity>4096)return -1;
    size_t length=0;while(length<capacity && args[length])length++;
    if(length==capacity)return -1;
    int result=0;
    for(size_t at=0;at<length;) {
        while(at<length && (args[at]==' ' || args[at]=='\t' || args[at]=='\n'))at++;
        size_t end=at;while(end<length && args[end]!=' ' && args[end]!='\t' && args[end]!='\n')end++;
        size_t n=end-at;
        if(n>=7 && !memcmp(args+at,"ca_vbl=",7)) {
            if(result || n!=8 || (args[at+7]!='0' && args[at+7]!='1'))return -1;
            result=args[at+7]=='1'?1:2;
        }
        at=end;
    }
    return result;
}
/* Apply only after the actual GPU pixel test. Refuse inherited values rather
 * than overwriting them. On any failure the wrapper must not exec the trial.
 * Callback boundaries permit real POSIX and explicit failure-path tests. */
static inline int pcc_environment(const char *args,size_t capacity,int admitted,
    char *(*get)(const char *),int (*set)(const char *,const char *,int),int (*unset)(const char *))
{
    int request=pcc_request(args,capacity);
    if(request<0)return -1;
    if(!admitted || !request)return 0;
    if(!get || !set || !unset || get(PCC_FORCE) || get(PCC_ENV))return -2;
    int failed=0;
    if(request==1) {
        if(set(PCC_FORCE,"1",1))failed=1;
        char *value=get(PCC_FORCE);
        if(!value || strcmp(value,"1"))failed=1;
    }
    const char *mode=request==1?"1":"0";
    if(!failed && set(PCC_ENV,mode,1))failed=1;
    char *value=get(PCC_ENV);
    if(!value || strcmp(value,mode) || (request==2 && get(PCC_FORCE)))failed=1;
    if(failed) {
        int a=unset(PCC_ENV),b=unset(PCC_FORCE);
        return a || b || get(PCC_ENV) || get(PCC_FORCE)?-4:-3;
    }
    return request;
}

/* Exact build targets are selected at compile time, including UUID/code.
 * Only read the resulting cache addresses; never call/patch them. */
static inline int pcc_span(uint64_t address,uint64_t bytes,uint64_t start,uint64_t size)
{return bytes && address>=start && size>=bytes && address-start<=size-bytes;}
/* Parse only a bounded, caller-provided Mach-O header/commands snapshot. */
static inline int pcc_layout(const void *data,size_t bytes)
{
    const uint8_t *p=data;uint32_t magic,cpu,type,count,size;
    if(!p || bytes<32)return 0;
    memcpy(&magic,p,4);memcpy(&cpu,p+4,4);memcpy(&type,p+12,4);
    memcpy(&count,p+16,4);memcpy(&size,p+20,4);
    if(magic!=0xfeedfacf || cpu!=0x100000c || type!=6 || !count || count>256 || size>65536 || size>bytes-32)return 0;
    unsigned uuid=0,text=0,string=0,state=0,once=0;size_t at=32;
    static const uint8_t expected[16]=PCC_UUID_BYTES;
    for(uint32_t i=0;i<count;i++) {
        uint32_t cmd,n;if(at>32+size || 32+size-at<8)return 0;
        memcpy(&cmd,p+at,4);memcpy(&n,p+at+4,4);
        if(n<8 || (n&7) || n>32+size-at)return 0;
        if(cmd==0x1b) {
            if(n!=24 || uuid++ || memcmp(p+at+8,expected,16))return 0;
        }else if(cmd==0x19) {
            uint64_t va,vs;uint32_t prot;
            if(n<72)return 0;
            memcpy(&va,p+at+24,8);memcpy(&vs,p+at+32,8);memcpy(&prot,p+at+60,4);
            if(vs && va>UINT64_MAX-vs)return 0;
            if(prot&1) {
                text+=pcc_span(PCC_BLOCK,32,va,vs);
                string+=pcc_span(PCC_STRING,15,va,vs);
                state+=pcc_span(PCC_STATE,1,va,vs);
                once+=pcc_span(PCC_ONCE,8,va,vs);
            }
        }
        at+=n;
    }
    return at==32+size && uuid==1 && text==1 && string==1 && state==1 && once==1;
}
#endif

/* Payload page-tail exclusion regression. Synthetic resident memory only;
 * no firmware image, device, firmware call or allocation lifetime is tested. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void text(const char*s){(void)s;}
void report(const char*s,uint64_t n){(void)s;(void)n;}
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-current-map.h"
#include "uefi-wifi-current-graph.h"
static unsigned callbacks;
static int stop_arch(void*p,struct pgcd_arch*a)
{(void)p;(void)a;callbacks++;return 0;}
static int no_map(void*p,struct efi_system*s,struct pgcd_map*m,void*d)
{(void)p;(void)s;(void)m;(void)d;assert(0);return 0;}
static int no_fp(void*p,struct pgcd_fp_guard*g)
{(void)p;(void)g;assert(0);return 0;}
static void no_order(void*p){(void)p;assert(0);}
int main(void)
{
    uint8_t*memory;assert(!posix_memalign((void**)&memory,4096,0x200000));
    memset(memory,0,0x200000);
    struct efi_system system={0};system.boot=(void*)(memory+0x1b800);
    system.boot->get_map=(void*)(memory+0xd3ec); /* Numeric ABI identity only. */
    struct efi_loaded image={.revision=0x1000,.system=&system,.base=memory,
        .bytes=0x100000,.code_type=3,.data_type=4};
    struct pwmc_parent_map*record=(void*)(memory+0x40000);
    struct pgcd_io io={.system=&system,.arch=stop_arch,.map=no_map,
        .fp_save=no_fp,.fp_restore=no_fp,.order=no_order};
    unsigned checks=0;
    const uint64_t lengths[]={1,4095,4096,4097,36459872};
    const uint64_t extents[]={4096,4096,4096,8192,36462592};
    for(unsigned k=0;k<5;k++){
        assert(pwmc_parent_payload_extent(0x90000000,lengths[k])==extents[k]);checks++;
    }
    const uint64_t bad[][2]={{0,1},{0x90000001,1},{0x90000000,0},
        {0x90000000,UINT64_MAX},{UINT64_MAX-4095,1},{UINT64_MAX-8191,4097}};
    for(unsigned k=0;k<sizeof(bad)/sizeof(*bad);k++){
        assert(!pwmc_parent_payload_extent(bad[k][0],bad[k][1]));checks++;
    }
    assert(pwmc_parent_payload_extent(UINT64_MAX-8191,4096)==4096);checks++;
    for(unsigned phase=3;phase<=4;phase++)for(unsigned k=0;k<5;k++){
        uint64_t payload=0x90000000;
        const uint64_t log[]={payload+4096,payload+4097,payload+8191,payload+8192,payload-8};
        memset(record,0,sizeof(*record));callbacks=0;
        struct pwmc_parent_input in={.system=&system,.image=&image,
            .native_flag=(void*)(memory+0x80000),.output=memory+0x90000,
            .capacity=phase==3?PGCD_MAP_CAP:PWMC_PARENT_MAP_CAP,.image_handle=1,
            .phase=phase,.bank=0xc0000000,.bank_bytes=0x200000,
            .payload=payload,.payload_bytes=4097,.log_snapshot=log[k],.log_snapshot_bytes=8};
        assert(!pwmc_parent_map_call(record,&in,&io));
        /* The two adjacent ranges may reach the deliberate stopping leaf.
         * Every intersecting range must refuse before any callback. */
        assert(callbacks==(k>=3));
        if(k<3)assert(record->error==PWMC_ARGUMENT);checks++;
    }
    for(unsigned phase=3;phase<=4;phase++){
        memset(record,0,sizeof(*record));callbacks=0;
        struct efi_loaded tail_image=image;tail_image.base=memory+2048;tail_image.bytes-=2048;
        struct pwmc_parent_input in={.system=&system,.image=&tail_image,
            .native_flag=(void*)(memory+0x80000),.output=memory+0x90000,
            .capacity=phase==3?PGCD_MAP_CAP:PWMC_PARENT_MAP_CAP,.image_handle=1,
            .phase=phase,.bank=0xc0000000,.bank_bytes=0x200000,
            .payload=(uintptr_t)memory,.payload_bytes=1024,.log_snapshot=0xb0000000,.log_snapshot_bytes=8};
        assert(!pwmc_parent_map_call(record,&in,&io)&&!callbacks&&record->error==PWMC_ARGUMENT);checks++;
    }
    for(unsigned phase=3;phase<=4;phase++){
        memset(record,0,sizeof(*record));
        record->input=(struct pwmc_parent_input){.phase=phase,.capacity=PGCD_MAP_CAP,
            .bank=0xc0000000,.bank_bytes=0x200000,.payload=0x90000000,
            .payload_bytes=4097,.log_snapshot=0xb0000000,.log_snapshot_bytes=8};
        struct efi_memory rows[]={{2,0,0x90000000,0,2,8},{2,0,0xb0000000,0,1,8},
            {2,0,0xc0000000,0,512,8}};
        record->map=(struct pgcd_map){.key=1,.version=1,.bytes=sizeof(rows),.stride=sizeof(rows[0])};
        memcpy(record->data,rows,sizeof(rows));
        assert(pwmc_parent_map_valid(record));checks++;
        ((struct efi_memory*)record->data)->pages=1;
        assert(!pwmc_parent_map_valid(record));checks++;
        record->input.payload=UINT64_MAX-4095;
        assert(!pwmc_parent_map_valid(record));checks++;
    }
    struct pcmp_result*frame=calloc(1,sizeof(*frame));assert(frame);
    struct pgcd_context context={0};struct pcmp_input caller={0};
    struct pcmp_live live={.r=frame,.caller_input=&caller,.caller_io=&io,.original_io=io,
        .input={.context=&context,.image=&image}};
    frame->payload=(uintptr_t)(memory+0x90000);frame->payload_count=1024;
    assert(!pcmg_output_storage(memory+0x90400,8,&live));checks++;
    assert(!pcmg_output_storage(memory+0x90fff,1,&live));checks++;
    assert(pcmg_output_storage(memory+0x91000,8,&live));checks++;
    frame->payload=UINT64_MAX-4095;
    assert(!pcmg_output_storage(memory+0x91000,8,&live));checks++;
    free(frame);free(memory);
    printf("{\"passed\":true,\"checks\":%u,\"synthetic_memory_only\":true,\"firmware_executed\":false}\n",checks);
    return 0;
}

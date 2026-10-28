/* Original Polaris ICNSS WLFW capability wire format, not a radio driver.
 * Verified MiCode c7cb50c1 wlan_firmware_service_v01.{h,c}:
 * header96c03d62 / descriptor96e7d689 / qmi_encdec d7221d89.
 * Independent bounded codec; no Linux implementation or hardware addresses.
 * Transport must authenticate the discovered service/node/port separately.
 * Parsing a response is never firmware boot, scan, association or DMA proof.
 */
#ifndef POLARIS_WLFW_H
#define POLARIS_WLFW_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define PW_SERVICE 0x45u
#define PW_VERSION 1u
#define PW_INSTANCE 0u
#define PW_CAP_MESSAGE 0x24u
#define PW_CAP_MAX_BODY 203u
struct polaris_wlfw_cap {
    uint32_t valid,chip_id,chip_family,board_id,soc_id,firmware_version;
    uint16_t result,error;
    char timestamp[33],build_id[129];
};
static inline uint16_t pw_le16(const uint8_t *p)
{return (uint16_t)p[0]|(uint16_t)((uint16_t)p[1]<<8);}
static inline uint32_t pw_le32(const uint8_t *p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline bool polaris_wlfw_cap_request(uint16_t transaction,uint8_t *out,size_t n)
{
    if(!transaction||!out||n<7)return false;
    out[0]=0;out[1]=(uint8_t)transaction;out[2]=(uint8_t)(transaction>>8);
    out[3]=PW_CAP_MESSAGE;out[4]=out[5]=out[6]=0;return true;
}
static inline bool pw_text(char *out,size_t capacity,const uint8_t *p,size_t n)
{
    if(n>=capacity)return false;
    for(size_t i=0;i<n;i++) {
        /* Firmware identifiers are diagnostics, never commands or paths. */
        if(p[i]<0x20||p[i]>0x7e)return false;
        out[i]=(char)p[i];
    }
    out[n]=0;return true;
}
static inline bool polaris_wlfw_cap_response(uint32_t service,uint32_t version,
    uint32_t instance,uint16_t transaction,const uint8_t *p,size_t n,
    struct polaris_wlfw_cap *out)
{
    if(!out||!p||!transaction||service!=PW_SERVICE||version!=PW_VERSION||instance!=PW_INSTANCE||
       n<7||n>7+PW_CAP_MAX_BODY||p[0]!=2||pw_le16(p+1)!=transaction||
       pw_le16(p+3)!=PW_CAP_MESSAGE||pw_le16(p+5)!=n-7)return false;
    struct polaris_wlfw_cap c={0};uint8_t seen[32]={0};bool result_seen=false;
    for(size_t at=7;at<n;) {
        if(n-at<3)return false;
        unsigned type=p[at];size_t len=pw_le16(p+at+1);at+=3;
        if(len>n-at||(seen[type/8]&(1u<<(type%8))))return false;
        seen[type/8]|=(uint8_t)(1u<<(type%8));const uint8_t *v=p+at;
        switch(type) {
        case 2:
            if(len!=4)return false;
            c.result=pw_le16(v);c.error=pw_le16(v+2);result_seen=true;
            if(c.result>1||(!c.result&&c.error))return false;
            break;
        case 0x10:
            if(len!=8)return false;
            c.chip_id=pw_le32(v);c.chip_family=pw_le32(v+4);c.valid|=1;break;
        case 0x11:
            if(len!=4)return false;
            c.board_id=pw_le32(v);c.valid|=2;break;
        case 0x12:
            if(len!=4)return false;
            c.soc_id=pw_le32(v);c.valid|=4;break;
        case 0x13:
            /* Nested QMI_STRING has a one-byte length. Top-level build-id
             * below instead obtains its length directly from the TLV. */
            if(len<5||len!=(size_t)5+v[4]||!pw_text(c.timestamp,sizeof(c.timestamp),v+5,v[4]))return false;
            c.firmware_version=pw_le32(v);c.valid|=8;break;
        case 0x14:
            if(!pw_text(c.build_id,sizeof(c.build_id),v,len))return false;
            c.valid|=16;break;
        default:
            if(type<0x10)return false; /* Unknown mandatory field. */
            break; /* Unknown bounded optional TLV is forward compatible. */
        }
        at+=len;
    }
    if(!result_seen)return false;
    *out=c;return true; /* Caller must separately check result and valid bits. */
}
static inline bool polaris_wlfw_cap_has_identity(const struct polaris_wlfw_cap *c)
{return c&&!c->result&&!c->error&&(c->valid&9)==9;}
#endif

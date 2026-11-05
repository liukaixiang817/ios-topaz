/* Freestanding WPA2-PSK primitives, original implementation of SHA-1/HMAC and
 * PBKDF2 (FIPS180/RFC2104/RFC8018). SHA-1 is used only as required by WPA2's
 * key derivation and descriptor-version2 MIC. No entropy is generated here.
 * PBKDF2 is incremental so the native RMTFS/transport service can keep running.
 */
#ifndef POLARIS_WIFI_WPA_CRYPTO_H
#define POLARIS_WIFI_WPA_CRYPTO_H
#include <stdint.h>
#include <stddef.h>
static inline void pwch_wipe(void*p,size_t n)
{volatile uint8_t*q=p;while(n--)*q++=0;}
static inline void pwch_copy(void*d,const void*s,unsigned n)
{uint8_t*q=d;const uint8_t*p=s;for(unsigned i=0;i<n;i++)q[i]=p[i];}
static inline uint32_t pwch_rot(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
struct pwch_sha1 {uint32_t h[5];uint64_t bytes;uint8_t block[64];};
static inline void pwch_block(struct pwch_sha1*s)
{
    uint32_t w[16];for(unsigned n=0;n<16;n++){const uint8_t*p=s->block+4*n;w[n]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4];
    for(unsigned n=0;n<80;n++){
        if(n>=16)w[n&15]=pwch_rot(w[(n-3)&15]^w[(n-8)&15]^w[(n-14)&15]^w[n&15],1);
        uint32_t f=n<20?((b&c)|(~b&d)):n<40?(b^c^d):n<60?((b&c)|(b&d)|(c&d)):(b^c^d);
        uint32_t k=n<20?0x5a827999:n<40?0x6ed9eba1:n<60?0x8f1bbcdc:0xca62c1d6;
        uint32_t t=pwch_rot(a,5)+f+e+k+w[n&15];e=d;d=c;c=pwch_rot(b,30);b=a;a=t;
    }s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;pwch_wipe(w,sizeof(w));
}
static inline void pwch_sha_init(struct pwch_sha1*s)
{
    pwch_wipe(s,sizeof(*s));s->h[0]=0x67452301;s->h[1]=0xefcdab89;s->h[2]=0x98badcfe;s->h[3]=0x10325476;s->h[4]=0xc3d2e1f0;
}
static inline void pwch_sha_add(struct pwch_sha1*s,const uint8_t*p,unsigned n)
{
    for(unsigned i=0;i<n;i++){s->block[s->bytes&63]=p[i];s->bytes++;if(!(s->bytes&63))pwch_block(s);}
}
static inline void pwch_sha_final(struct pwch_sha1*s,uint8_t digest[20])
{
    uint64_t bits=s->bytes*8;uint8_t byte=128;pwch_sha_add(s,&byte,1);byte=0;
    while((s->bytes&63)!=56)pwch_sha_add(s,&byte,1);
    for(unsigned n=0;n<8;n++){byte=(uint8_t)(bits>>(56-8*n));pwch_sha_add(s,&byte,1);}
    for(unsigned n=0;n<20;n++)digest[n]=(uint8_t)(s->h[n/4]>>(24-8*(n&3)));pwch_wipe(s,sizeof(*s));
}
struct pwch_hmac {struct pwch_sha1 inner,outer;};
static inline void pwch_hmac_init(struct pwch_hmac*h,const uint8_t*key,unsigned bytes)
{
    uint8_t pad[64],digest[20];struct pwch_sha1 sha;
    if(bytes>64){pwch_sha_init(&sha);pwch_sha_add(&sha,key,bytes);pwch_sha_final(&sha,digest);key=digest;bytes=20;}
    for(unsigned n=0;n<64;n++)pad[n]=(uint8_t)((n<bytes?key[n]:0)^0x36);
    pwch_sha_init(&h->inner);pwch_sha_add(&h->inner,pad,64);
    for(unsigned n=0;n<64;n++)pad[n]^=0x6a;
    pwch_sha_init(&h->outer);pwch_sha_add(&h->outer,pad,64);pwch_wipe(pad,sizeof(pad));pwch_wipe(digest,sizeof(digest));
}
static inline int pwch_hmac_parts(const struct pwch_hmac*h,const uint8_t*const*parts,const unsigned*lengths,unsigned count,uint8_t digest[20])
{
    if(!h||!parts||!lengths||!digest||count>8)return 0;
    for(unsigned n=0;n<count;n++)if(!parts[n]&&lengths[n])return 0;
    struct pwch_sha1 sha=h->inner;
    for(unsigned n=0;n<count;n++)pwch_sha_add(&sha,parts[n],lengths[n]);pwch_sha_final(&sha,digest);
    sha=h->outer;pwch_sha_add(&sha,digest,20);pwch_sha_final(&sha,digest);return 1;
}
struct pwch_pmk {
    struct pwch_hmac hmac;uint8_t salt[36],u[20],sum[20],pmk[32];
    uint32_t opened,done,round,block,salt_bytes;
};
static inline int pwch_pmk_open(struct pwch_pmk*s,const uint8_t*pass,unsigned pass_bytes,const uint8_t*ssid,unsigned ssid_bytes)
{
    if(!s||!pass||!ssid||pass_bytes<8||pass_bytes>63||!ssid_bytes||ssid_bytes>32)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    for(unsigned n=0;n<pass_bytes;n++)if(pass[n]<32||pass[n]>126)return 0;
    pwch_hmac_init(&s->hmac,pass,pass_bytes);pwch_copy(s->salt,ssid,ssid_bytes);s->salt_bytes=ssid_bytes+4;s->block=1;s->opened=1;return 1;
}
/* 0=invalid,1=more work,2=complete PMK. A call performs <=32 HMACs; no secret
 * or timing value is logged. Caller wipes the whole state after consuming PMK. */
static inline int pwch_pmk_step(struct pwch_pmk*s,unsigned budget)
{
    if(!s||s->opened!=1||!budget||budget>32)return 0;if(s->done)return 2;
    if((s->block!=1&&s->block!=2)||s->round>=4096||s->salt_bytes<5||s->salt_bytes>36)return 0;
    while(budget--){
        const uint8_t*p;unsigned bytes;
        if(!s->round){s->salt[s->salt_bytes-1]=(uint8_t)s->block;p=s->salt;bytes=s->salt_bytes;}
        else{p=s->u;bytes=20;}
        if(!pwch_hmac_parts(&s->hmac,&p,&bytes,1,s->u))return 0;
        for(unsigned n=0;n<20;n++)s->sum[n]=s->round?(s->sum[n]^s->u[n]):s->u[n];s->round++;
        if(s->round==4096){
            pwch_copy(s->pmk+(s->block==1?0:20),s->sum,s->block==1?20:12);
            if(s->block==2){s->done=1;pwch_wipe(&s->hmac,sizeof(s->hmac));pwch_wipe(s->u,sizeof(s->u));pwch_wipe(s->sum,sizeof(s->sum));return 2;}
            s->block=2;s->round=0;
        }
    }return 1;
}
/* AES-128 inverse and RFC3394 unwrap. The byte substitutions are computed
 * with fixed arithmetic rather than secret-indexed lookup tables. This avoids
 * table-cache accesses dependent on keys; it is not a claim of a whole-system
 * side-channel audit. Unwrap work is also incremental and keeps plaintext
 * private until the RFC3394 integrity value has been verified. */
static inline uint8_t pwch_mul(uint8_t a,uint8_t b)
{
    uint8_t r=0;for(unsigned n=0;n<8;n++){
        r^=(uint8_t)(a&(uint8_t)(0u-(b&1u)));
        a=(uint8_t)((a<<1)^(0x1b&(0u-(a>>7))));b>>=1;
    }return r;
}
static inline uint8_t pwch_inverse(uint8_t a)
{
    uint8_t r=1;for(unsigned n=0;n<8;n++){
        uint8_t product=pwch_mul(r,a),mask=(uint8_t)(0u-((254u>>n)&1));
        r=(uint8_t)((r&~mask)|(product&mask));a=pwch_mul(a,a);
    }return r;
}
static inline uint8_t pwch_rot8(uint8_t a,unsigned n){return (uint8_t)((a<<n)|(a>>(8-n)));}
static inline uint8_t pwch_sub(uint8_t a)
{uint8_t b=pwch_inverse(a);return (uint8_t)(b^pwch_rot8(b,1)^pwch_rot8(b,2)^pwch_rot8(b,3)^pwch_rot8(b,4)^0x63);}
static inline uint8_t pwch_invsub(uint8_t a)
{return pwch_inverse((uint8_t)(pwch_rot8(a,1)^pwch_rot8(a,3)^pwch_rot8(a,6)^5));}
static inline void pwch_aes_key(const uint8_t key[16],uint8_t schedule[176])
{
    pwch_copy(schedule,key,16);uint8_t rcon=1;
    for(unsigned at=16;at<176;at+=4){
        uint8_t a=schedule[at-4],b=schedule[at-3],c=schedule[at-2],d=schedule[at-1];
        if(!(at&15)){uint8_t first=a;a=pwch_sub(b)^rcon;b=pwch_sub(c);c=pwch_sub(d);d=pwch_sub(first);rcon=pwch_mul(rcon,2);}
        schedule[at]=schedule[at-16]^a;schedule[at+1]=schedule[at-15]^b;schedule[at+2]=schedule[at-14]^c;schedule[at+3]=schedule[at-13]^d;
    }
}
static inline void pwch_aes_decrypt(const uint8_t schedule[176],uint8_t block[16])
{
    uint8_t tmp[16];for(unsigned n=0;n<16;n++)block[n]^=schedule[160+n];
    for(int round=9;round>=0;round--){
        for(unsigned c=0;c<4;c++)for(unsigned r=0;r<4;r++)tmp[4*c+r]=pwch_invsub(block[4*((c+4-r)&3)+r]);
        for(unsigned n=0;n<16;n++)block[n]=tmp[n]^schedule[16*(unsigned)round+n];
        if(round)for(unsigned n=0;n<16;n+=4){
            uint8_t a=block[n],b=block[n+1],c=block[n+2],d=block[n+3];
            block[n]=pwch_mul(a,14)^pwch_mul(b,11)^pwch_mul(c,13)^pwch_mul(d,9);
            block[n+1]=pwch_mul(a,9)^pwch_mul(b,14)^pwch_mul(c,11)^pwch_mul(d,13);
            block[n+2]=pwch_mul(a,13)^pwch_mul(b,9)^pwch_mul(c,14)^pwch_mul(d,11);
            block[n+3]=pwch_mul(a,11)^pwch_mul(b,13)^pwch_mul(c,9)^pwch_mul(d,14);
        }
    }pwch_wipe(tmp,sizeof(tmp));
}
struct pwch_unwrap {
    uint8_t schedule[176],plain[512],a[8];
    uint32_t opened,done,valid,blocks,index,round,bytes;
};
static inline int pwch_unwrap_open(struct pwch_unwrap*s,const uint8_t key[16],const uint8_t*cipher,unsigned bytes)
{
    if(!s||!key||!cipher||bytes<24||bytes>520||(bytes&7))return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    pwch_aes_key(key,s->schedule);pwch_copy(s->a,cipher,8);pwch_copy(s->plain,cipher+8,bytes-8);
    s->bytes=bytes-8;s->blocks=s->index=(bytes-8)/8;s->round=5;s->opened=1;return 1;
}
/* -1=integrity failure (plaintext wiped),0=invalid,1=more work,2=verified.
 * The caller may inspect plain[] only after2. No partial unwrapped GTK is
 * installable, even when the MIC was valid. */
static inline int pwch_unwrap_step(struct pwch_unwrap*s,unsigned budget)
{
    if(!s||s->opened!=1||!budget||budget>4)return 0;if(s->done)return s->valid?2:-1;
    if(s->blocks<2||s->blocks>64||s->bytes!=8*s->blocks||!s->index||s->index>s->blocks||s->round>5)return 0;
    uint8_t block[16];
    while(budget--){
        uint64_t t=s->blocks*s->round+s->index;
        for(unsigned n=0;n<8;n++)block[n]=s->a[n]^(uint8_t)(t>>(56-8*n));
        pwch_copy(block+8,s->plain+8*(s->index-1),8);pwch_aes_decrypt(s->schedule,block);
        pwch_copy(s->a,block,8);pwch_copy(s->plain+8*(s->index-1),block+8,8);
        if(--s->index==0){
            if(!s->round){
                unsigned different=0;for(unsigned n=0;n<8;n++)different|=s->a[n]^0xa6;
                s->valid=!different;s->done=1;pwch_wipe(s->schedule,sizeof(s->schedule));pwch_wipe(s->a,sizeof(s->a));pwch_wipe(block,sizeof(block));
                if(!s->valid)pwch_wipe(s->plain,sizeof(s->plain));return s->valid?2:-1;
            }s->round--;s->index=s->blocks;
        }
    }pwch_wipe(block,sizeof(block));return 1;
}
#endif

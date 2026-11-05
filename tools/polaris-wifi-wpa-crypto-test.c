#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-wpa-crypto.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static uint8_t key[128],input[4096],expected[512],output[512];
static struct pwch_pmk pmk;
static struct pwch_unwrap unwrap;
static unsigned number(FILE*f)
{uint8_t p[4];CHECK(fread(p,1,4,f)==4);return p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24);}
static int zero(const void*p,unsigned n)
{const uint8_t*q=p;unsigned v=0;for(unsigned i=0;i<n;i++)v|=q[i];return !v;}
int main(int argc,char**argv)
{
    CHECK(argc==2);FILE*f=fopen(argv[1],"rb");CHECK(f);uint8_t magic[8];CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWCRYP1",8));
    unsigned records=number(f);CHECK(records>20&&records<256);
    for(unsigned record=0;record<records;record++){
        unsigned type=number(f),kb=number(f),bytes=number(f),out=number(f);
        CHECK(kb<=sizeof(key)&&bytes<=sizeof(input)&&out<=sizeof(expected));
        CHECK(fread(key,1,kb,f)==kb&&fread(input,1,bytes,f)==bytes&&fread(expected,1,out,f)==out);memset(output,0,sizeof(output));
        if(type==1){
            CHECK(!kb&&out==20);struct pwch_sha1 sha;pwch_sha_init(&sha);
            for(unsigned n=0;n<bytes;){unsigned step=1+(n%67);if(step>bytes-n)step=bytes-n;pwch_sha_add(&sha,input+n,step);n+=step;}
            pwch_sha_final(&sha,output);CHECK(zero(&sha,sizeof(sha)));
        }else if(type==2){
            CHECK(out==20);struct pwch_hmac h;pwch_hmac_init(&h,key,kb);
            unsigned split=bytes/3;const uint8_t*parts[]={input,input+split,input+2*split};unsigned lengths[]={split,split,bytes-2*split};
            CHECK(pwch_hmac_parts(&h,parts,lengths,3,output));pwch_wipe(&h,sizeof(h));CHECK(zero(&h,sizeof(h)));
        }else if(type==3){
            CHECK(out==32);for(unsigned variant=0;variant<3;variant++){
                memset(&pmk,0,sizeof(pmk));CHECK(pwch_pmk_open(&pmk,key,kb,input,bytes));
                CHECK(!pwch_pmk_step(&pmk,0)&&!pwch_pmk_step(&pmk,33)&&pmk.round==0);
                unsigned calls=0,budget=variant==0?1:variant==1?7:32;int result;
                do{result=pwch_pmk_step(&pmk,budget);CHECK(result==1||result==2);calls++;}while(result==1&&calls<8193);
                CHECK(result==2&&calls==(8192+budget-1)/budget&&!memcmp(pmk.pmk,expected,32));
                CHECK(zero(&pmk.hmac,sizeof(pmk.hmac))&&zero(pmk.u,20)&&zero(pmk.sum,20));
                pwch_copy(output,pmk.pmk,32);pwch_wipe(&pmk,sizeof(pmk));CHECK(zero(&pmk,sizeof(pmk)));
            }
        }else if(type==4){
            CHECK(kb==16&&bytes==16&&out==16);uint8_t schedule[176];pwch_aes_key(key,schedule);pwch_copy(output,input,16);pwch_aes_decrypt(schedule,output);pwch_wipe(schedule,176);
        }else if(type==5){
            CHECK(kb==16&&out==bytes-8);
            for(unsigned variant=0;variant<2;variant++){
                memset(&unwrap,0,sizeof(unwrap));CHECK(pwch_unwrap_open(&unwrap,key,input,bytes));
                CHECK(!pwch_unwrap_step(&unwrap,0)&&!pwch_unwrap_step(&unwrap,5));
                int result;unsigned calls=0,budget=variant?4:1;
                do{result=pwch_unwrap_step(&unwrap,budget);CHECK(result==1||result==2);calls++;}while(result==1&&calls<385);
                CHECK(result==2&&calls==(6*(bytes/8-1)+budget-1)/budget&&!memcmp(unwrap.plain,expected,out));
                CHECK(zero(unwrap.schedule,176)&&zero(unwrap.a,8));pwch_copy(output,unwrap.plain,out);pwch_wipe(&unwrap,sizeof(unwrap));
            }
            for(unsigned fault=0;fault<3;fault++){
                unsigned at=fault==0?0:fault==1?bytes/2:bytes-1;input[at]^=1;memset(&unwrap,0,sizeof(unwrap));
                CHECK(pwch_unwrap_open(&unwrap,key,input,bytes));int result=1;
                for(unsigned n=0;n<384&&result==1;n++)result=pwch_unwrap_step(&unwrap,4);
                CHECK(result==-1&&!unwrap.valid&&zero(unwrap.plain,512)&&zero(unwrap.schedule,176)&&zero(unwrap.a,8));input[at]^=1;
            }
        }else CHECK(0);
        CHECK(!memcmp(output,expected,out));
    }
    CHECK(fgetc(f)==EOF&&!fclose(f));
    for(unsigned n=0;n<256;n++){CHECK(pwch_invsub(pwch_sub((uint8_t)n))==n);if(n)CHECK(pwch_mul((uint8_t)n,pwch_inverse((uint8_t)n))==1);}
    memset(&pmk,0,sizeof(pmk));CHECK(!pwch_pmk_open(&pmk,(const uint8_t*)"short",5,(const uint8_t*)"ssid",4));
    memset(&unwrap,0,sizeof(unwrap));for(unsigned n=0;n<24;n++)CHECK(!pwch_unwrap_open(&unwrap,key,input,n));
    CHECK(!pwch_unwrap_open(&unwrap,key,input,521));
    printf("PASS %u WPA2 crypto checks, %u independent vectors; SOFTWARE only\n",checks,records);return 0;
}

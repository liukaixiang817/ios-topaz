#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-nonce-pool.h"
static struct pwnp_state pool;
static unsigned checks;
static uint8_t raw[PWNP_BYTES],saved[PWNP_BYTES],output[32];
#define CHECK(x) do{assert(x);checks++;}while(0)
int main(int argc,char**argv)
{
    CHECK(argc==2);FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(raw,1,sizeof(raw),f)==sizeof(raw)&&!fclose(f));
    memcpy(saved,raw,sizeof(raw));CHECK(pwnp_open(&pool,raw,sizeof(raw),19)&&!pwnp_open(&pool,raw,sizeof(raw),19));
    CHECK(!pwnp_take(&pool,20,output)&&!pool.used);
    for(unsigned n=0;n<PWNP_COUNT;n++){
        CHECK(pwnp_take(&pool,19,output)&&pool.used==n+1&&!memcmp(output,raw+80+32*n,32)&&!pwnp_nonzero(pool.nonce[n],32));
    }
    CHECK(!pwnp_take(&pool,19,output));pwnp_stop(&pool);CHECK(pool.closed&&!pwnp_nonzero((uint8_t*)pool.nonce,sizeof(pool.nonce)));
    for(unsigned fault=0;fault<8;fault++){
        memset(&pool,0,sizeof(pool));memcpy(raw,saved,sizeof(raw));
        if(fault==0)raw[0]^=1;if(fault==1)raw[8]^=1;if(fault==2)raw[12]^=1;if(fault==3)raw[16]^=1;
        if(fault==4)raw[72]=1;if(fault==5)memset(raw+24,0,16);if(fault==6)memset(raw+80,0,32);if(fault==7)memcpy(raw+80,raw+112,32);
        CHECK(!pwnp_open(&pool,raw,sizeof(raw),19)&&!pool.opened);
    }
    printf("PASS %u nonce pool shape/one-use/exhaustion checks; SOFTWARE only, digest is the native parent's responsibility\n",checks);return 0;
}

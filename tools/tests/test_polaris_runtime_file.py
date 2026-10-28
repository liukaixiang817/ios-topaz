"""Offline bounded-root adapter tests, not native UFS/HFS persistence evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RuntimeFile(unittest.TestCase):
    def test_partial_io_fragmentation_failures_and_nonterminal_sync(self):
        source = r'''
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "runtime-owner.h"
#include "runtime-quiesce.h"
#include "runtime-file.h"
static unsigned char disk[64*4096],expected[sizeof(disk)],bounce[8192],buffer[10*4096];
static struct polaris_owner_work owner;
static unsigned calls,reads,writes,fail_call;
static uint32_t random_state=0x76543210;
static uint32_t random32(void){random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state;}
static uint64_t reference(unsigned byte){unsigned block=byte/4096,skip=byte%4096;return (uint64_t)(block<3?8+block:block<7?20+block-3:40+block-7)*4096+skip;}
static void reset(void){
 memset(&owner,0,sizeof(owner));owner.metadata_verified=owner.admitted=true;
 owner.partition_start=4;owner.partition_blocks=60;owner.filesystem_blocks=56;
 owner.file_blocks=10;owner.map_count=3;
 owner.map[0]=(struct polaris_owner_extent){0,8,3};
 owner.map[1]=(struct polaris_owner_extent){3,20,4};
 owner.map[2]=(struct polaris_owner_extent){7,40,3};
 for(unsigned i=0;i<sizeof(disk);i++)disk[i]=(unsigned char)(i*31+i/4096);
 memcpy(expected,disk,sizeof(disk));calls=reads=writes=fail_call=0;
}
static int transfer(void *context,uint64_t lba,uint32_t blocks,void *data,bool write){
 assert(context==&owner&&data==bounce&&blocks&&blocks<=2&&lba+blocks<=64);
 uint8_t cdb[10]={write?0x2a:0x28,0,(uint8_t)(lba>>24),(uint8_t)(lba>>16),(uint8_t)(lba>>8),(uint8_t)lba,0,0,(uint8_t)blocks,0};
 assert(polaris_owned_data_cdb(&owner,cdb,10,blocks*4096,write,0));
 calls++;if(calls==fail_call)return EIO;
 if(write){writes++;memcpy(disk+lba*4096,data,blocks*4096);}
 else{reads++;memcpy(data,disk+lba*4096,blocks*4096);}
 return 0;
}
static struct polaris_file_result io(uint64_t at,unsigned bytes,bool read,bool halt){
 return polaris_file_io(&owner,at,bytes,buffer,bounce,sizeof(bounce),read,halt,transfer,&owner);
}
int main(void){
 /* Independent byte-address reference, fragmented files and a deliberately
  * small bounce buffer exercise partial and multi-command transfers. */
 for(unsigned test=0;test<2000;test++){
  reset();unsigned at=random32()%sizeof(buffer),count=random32()%(sizeof(buffer)-at+1);
  for(unsigned i=0;i<count;i++)buffer[i]=(unsigned char)random32();
  for(unsigned i=0;i<count;i++)expected[reference(at+i)]=buffer[i];
  struct polaris_file_result result=io(at,count,false,false);
  assert(!result.status&&!result.io_error&&result.transferred==count);
  assert(!memcmp(disk,expected,sizeof(disk))); /* ALL non-owned/untouched bytes too. */
  memset(buffer,0xcc,sizeof(buffer));result=io(at,count,true,false);
  assert(!result.status&&result.transferred==count);
  for(unsigned i=0;i<count;i++)assert(buffer[i]==expected[reference(at+i)]);
  assert(!memcmp(disk,expected,sizeof(disk)));
 }
 reset();struct polaris_file_result result=io(0,4096,false,false);
 assert(!result.status&&writes==1&&reads==0); /* Full-block overwrite needs no read. */
 reset();result=io(4095,2,false,false);assert(!result.status&&reads==1&&writes==1);
 reset();result=io(3*4096-1,2,false,false);assert(!result.status&&reads==2&&writes==2);
 reset();fail_call=1;result=io(7,23,false,false);
 assert(result.status==POLARIS_FILE_IO_ERROR&&result.io_error==EIO&&!result.transferred&&!writes&&!memcmp(disk,expected,sizeof(disk)));
 reset();fail_call=2;result=io(7,23,false,false);
 assert(result.status==POLARIS_FILE_IO_ERROR&&!result.transferred&&!writes&&!memcmp(disk,expected,sizeof(disk)));
 reset();fail_call=2;result=io(0,4*4096,false,false);
 assert(result.status==POLARIS_FILE_IO_ERROR&&result.transferred==8192&&writes==1);
 for(unsigned i=0;i<8192;i++)expected[reference(i)]=buffer[i];
 assert(!memcmp(disk,expected,sizeof(disk)));
 reset();result=io(0,4096,false,true);assert(result.status==POLARIS_FILE_STOPPED&&!calls);
 for(unsigned test=0;test<8;test++){
  reset();uint64_t at=0;unsigned count=1;
  if(test==0)at=UINT64_MAX;
  if(test==1)at=10*4096;
  if(test==2)owner.admitted=false;
  if(test==3)owner.metadata_verified=false;
  if(test==4)owner.map[0].physical=owner.partition_start+owner.filesystem_blocks;
  if(test==5)owner.map[0].physical=UINT64_MAX;
  if(test==6)owner.file_blocks=UINT64_MAX;
  if(test==7)owner.error=1;
  result=io(at,count,false,false);assert(result.status==POLARIS_FILE_INVALID&&!calls&&!writes);
 }
 reset();result=io(10*4096,0,false,false);assert(!result.status&&!result.transferred&&!calls);
 /* Mounted HFS cache flushes update durability epochs but cannot authorize
  * reset. A later write becomes dirty again; final sealed sync is mandatory. */
 struct polaris_q q={0};struct polaris_file_sync sync={0};assert(polaris_q_init(&q,123,true));
 for(unsigned epoch=1;epoch<=20;epoch++){
  assert(polaris_q_begin(&q,4096,true)&&polaris_q_complete(&q,true,true,4096));
  assert(q.write_epoch==epoch&&q.flushed_epoch==epoch-1);
  assert(polaris_file_sync_begin(&q,&sync));
  assert(!polaris_q_begin(&q,4096,true)&&!polaris_q_begin(&q,4096,false));
  assert(!polaris_file_sync_begin(&q,&sync));
  assert(polaris_file_sync_complete(&q,&sync,true,true));
  assert(q.flushed_epoch==epoch&&q.phase==POLARIS_Q_RUNNING&&!q.inflight);
  struct polaris_shutdown_status status=polaris_q_status(&q);
  assert(!status.capabilities&&!polaris_q_reset_ready(&status,123,1,2));
 }
 assert(polaris_q_request(&q,123,1,2));
 assert(polaris_file_sync_begin(&q,&sync)&&polaris_file_sync_complete(&q,&sync,true,true));
 assert(q.phase==POLARIS_Q_REQUESTED&&!polaris_q_status(&q).capabilities);
 assert(!polaris_q_seal(&q,1,0)&&!polaris_q_seal(&q,0,1));
 assert(polaris_q_seal(&q,0,0)&&!polaris_file_sync_begin(&q,&sync));
 assert(polaris_q_flush_begin(&q)&&polaris_q_flush_complete(&q,true,true));
 struct polaris_shutdown_status status=polaris_q_status(&q);assert(polaris_q_reset_ready(&status,123,1,2));
 for(unsigned test=0;test<7;test++){
  memset(&q,0,sizeof(q));memset(&sync,0,sizeof(sync));assert(polaris_q_init(&q,456,true));
  assert(polaris_q_begin(&q,4096,true)&&polaris_q_complete(&q,true,true,4096));
  assert(polaris_file_sync_begin(&q,&sync));
  if(test==2)sync.cookie++;
  if(test==3)q.write_epoch++;
  if(test==4)q.phase=POLARIS_Q_REQUESTED;
  if(test==5)q.pending_bytes=4096;
  if(test==6)q.pending_write=true;
  assert(!polaris_file_sync_complete(&q,&sync,test!=0,test!=1));
  assert(q.phase==POLARIS_Q_FAILED&&q.error&&!polaris_q_status(&q).capabilities);
  assert(!polaris_file_sync_begin(&q,&sync)&&!polaris_q_seal(&q,0,0)&&!polaris_q_flush_begin(&q));
  if(test==0)assert(q.inflight&&sync.active); /* Unknown DMA stays owned. */
  if(test==1)assert(!q.inflight&&!sync.active); /* Completed device error. */
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'test.c').write_text(source)
            subprocess.run(['cc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I' + str(ROOT / 'shim/polaris'),
                            str(folder / 'test.c'), '-o', str(folder / 'test')], check=True)
            subprocess.run([str(folder / 'test')], check=True, timeout=30)


if __name__ == '__main__': unittest.main()

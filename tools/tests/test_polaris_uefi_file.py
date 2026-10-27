"""Disk loading must identify one GPT volume, bound reads, and close handles."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class EfiDiskReader(unittest.TestCase):
    def test_native_refusals_cleanup_and_partial_reads(self):
        root=Path(__file__).resolve().parents[2]
        code=r'''
#include "uefi-file.h"
#include <assert.h>
#include <string.h>
static uint8_t guid[16]={1,2,3},path[46],data[200001],dest[200000];
static uint64_t pos,length,count,maxread;
static unsigned roots,files,opens,reads,freed;
static int open_error,read_error,close_error,free_error;
static struct polaris_efi_file root,file;
static efi_handle handles[2]={(void*)1,(void*)2};
static efi_status close_(struct polaris_efi_file *f){
 if(f==&root)roots++;else {assert(f==&file);files++;}return close_error?EFI_ERROR|7:0;
}
static efi_status read_(struct polaris_efi_file *f,uint64_t *n,void *b){
 assert(f==&file&&*n<=65536);reads++;if(read_error&&reads==2)return EFI_ERROR|7;
 if(*n>maxread)*n=maxread;if(*n>length-pos)*n=length-pos;
 memcpy(b,data+pos,*n);pos+=*n;return 0;
}
static efi_status open_(struct polaris_efi_file *f,struct polaris_efi_file **out,const uint16_t *name,uint64_t mode,uint64_t attr){
 assert(f==&root&&mode==1&&attr==0&&name[0]=='\\');opens++;
 if(open_error)return EFI_ERROR|14;*out=&file;return 0;
}
static efi_status volume(struct polaris_efi_fs *fs,struct polaris_efi_file **out){(void)fs;*out=&root;return 0;}
static struct polaris_efi_fs fs={0x10000,volume};
static efi_status locate(uint32_t type,const efi_guid *g,void *key,uint64_t *n,efi_handle **out){
 assert(type==2&&g->a==0x964e5b22&&!key);*out=handles;*n=count;return 0;
}
static efi_status protocol(efi_handle h,const efi_guid *g,void **out){
 assert(h==(void*)1||h==(void*)2);*out=g->a==0x09576e91?(void*)path:(void*)&fs;return 0;
}
static efi_status free_(void *p){assert(p==handles);freed++;return free_error?EFI_ERROR|7:0;}
static struct efi_boot bs={.locate_buffer=locate,.handle_protocol=protocol,.free_pool=free_};
static struct polaris_efi_disk_result result;
static void reset(void){
 memset(path,0,sizeof(path));path[0]=4;path[1]=1;path[2]=42;path[40]=path[41]=2;
 uint64_t start=2048,blocks=258048;memcpy(path+8,&start,8);memcpy(path+16,&blocks,8);memcpy(path+24,guid,16);
 path[42]=0x7f;path[43]=0xff;path[44]=4;
 root=(struct polaris_efi_file){.open=open_,.close=close_};file=(struct polaris_efi_file){.close=close_,.read=read_};
 pos=roots=files=opens=reads=freed=open_error=read_error=close_error=free_error=0;
 length=sizeof(dest);count=1;maxread=7919;
 for(unsigned i=0;i<sizeof(data);i++)data[i]=(uint8_t)i;
}
static int run(void){static const uint16_t name[]={'\\','P',0};
 return polaris_efi_read_disk(&bs,guid,2048,258048,name,dest,sizeof(dest),&result);}
int main(void){
 reset();assert(run());assert(pos==sizeof(dest)&&reads>4&&freed==1&&roots==1&&files==1);
 assert(result.matches==1&&result.closed==2&&!memcmp(data,dest,sizeof(dest)));
 uint8_t appended[512];static const uint16_t app[]={'\\','E','F','I','\\','P','.','e','f','i',0};
 unsigned n=polaris_efi_file_path(&result,app,appended,sizeof(appended));
 assert(n==42+4+sizeof(app)+4&&!memcmp(appended,path,42));
 assert(appended[42]==4&&appended[43]==4&&appended[n-4]==0x7f);
 assert(!polaris_efi_file_path(&result,app,appended,12));
 result.matches=2;assert(!polaris_efi_file_path(&result,app,appended,sizeof(appended)));
 reset();path[24]^=1;assert(!run()&&!opens&&freed==1);
 reset();path[8]^=1;assert(!run()&&!opens);
 reset();path[16]^=1;assert(!run()&&!opens);
 reset();path[40]=1;assert(!run()&&!opens);
 reset();path[44]=0;assert(!run()&&!opens);
 reset();path[2]=3;assert(!run()&&!opens);
 reset();path[43]=1;assert(!run()&&!opens);
 reset();count=2;assert(!run()&&result.matches==2&&!opens&&freed==1);
 reset();free_error=1;assert(!run()&&!opens&&freed==1);
 reset();open_error=1;assert(!run()&&roots==1&&!files);
 reset();read_error=1;assert(!run()&&roots==1&&files==1);
 reset();close_error=1;assert(!run()&&roots==1&&files==1);
 reset();length--;assert(!run()&&roots==1&&files==1);
 reset();length++;assert(!run()&&roots==1&&files==1);
 reset();count=257;assert(!run()&&!opens&&freed==1);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'file.c';exe=Path(d)/'file';c.write_text(code)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),str(c),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()

/* Read one fixed payload from one uniquely identified GPT filesystem.
 * UEFI2.10 SimpleFileSystem/FileProtocol and HardDrive device-path ABI.
 * No Create, Write, Delete, SetInfo, block I/O or SetVariable interface. */
#ifndef POLARIS_UEFI_FILE_H
#define POLARIS_UEFI_FILE_H
#include "uefi.h"
struct polaris_efi_file {
    uint64_t revision;
    efi_status (*open)(struct polaris_efi_file *,struct polaris_efi_file **,const uint16_t *,uint64_t,uint64_t);
    efi_status (*close)(struct polaris_efi_file *);void *remove;
    efi_status (*read)(struct polaris_efi_file *,uint64_t *,void *);
};
struct polaris_efi_fs {uint64_t revision;efi_status (*open)(struct polaris_efi_fs *,struct polaris_efi_file **);};
struct polaris_efi_disk_result {
    efi_status status;uint64_t filesystems,matches,bytes,reads,closed;
    uint64_t path_bytes;uint8_t path[4096];
};
_Static_assert(offsetof(struct polaris_efi_file,read)==32,"EFI_FILE.Read");
static uint64_t polaris_efi_file_u64(const uint8_t *b)
{uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)b[i]<<(8*i);return v;}
/* One complete device path, one GPT HD node, exact partition identity. The
 * firmware owns this protocol buffer; traversal is bounded to4096bytes. */
static unsigned polaris_efi_disk_path(const uint8_t *p,const uint8_t guid[16],uint64_t start,uint64_t blocks)
{
    if(!p||!guid||!blocks)return 0;
    unsigned at=0,found=0;
    while(at<=4092){
        unsigned n=p[at+2]|(unsigned)p[at+3]<<8;
        if(n<4||n>4096-at)return 0;
        if(p[at]==0x7f)return p[at+1]==0xff&&n==4&&found==1?at+4:0;
        if(p[at]==4&&p[at+1]==1){
            if(n!=42||++found!=1||p[at+40]!=2||p[at+41]!=2||
               polaris_efi_file_u64(p+at+8)!=start||polaris_efi_file_u64(p+at+16)!=blocks)return 0;
            for(unsigned i=0;i<16;i++)if(p[at+24+i]!=guid[i])return 0;
        }
        at+=n;
    }return 0;
}
static int polaris_efi_read_disk(struct efi_boot *bs,const uint8_t guid[16],uint64_t start,uint64_t blocks,
    const uint16_t *name,uint8_t *dest,uint64_t bytes,struct polaris_efi_disk_result *r)
{
    static const efi_guid fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
    static const efi_guid dp_guid={0x9576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
    if(!r)return 0;
    *r=(struct polaris_efi_disk_result){.status=EFI_ERROR|2};
    if(!bs||!bs->locate_buffer||!bs->handle_protocol||!bs->free_pool||!dest||!bytes||!name)return 0;
    efi_handle *handles=0,chosen=0;uint64_t count=0;
    r->status=bs->locate_buffer(2,&fs_guid,0,&count,&handles);
    if(r->status||!handles||!count||count>256){if(handles)bs->free_pool(handles);return 0;}
    r->filesystems=count;
    for(uint64_t i=0;i<count;i++){
        uint8_t *path=0;
        if(bs->handle_protocol(handles[i],&dp_guid,(void**)&path)||!path)continue;
        unsigned n=polaris_efi_disk_path(path,guid,start,blocks);if(!n)continue;
        r->matches++;chosen=handles[i];r->path_bytes=n;
        for(unsigned j=0;j<n;j++)r->path[j]=path[j];
    }
    r->status=bs->free_pool(handles);if(r->status)return 0;
    if(r->matches!=1){r->status=EFI_ERROR|14;return 0;}
    struct polaris_efi_fs *fs=0;struct polaris_efi_file *root=0,*file=0;
    r->status=bs->handle_protocol(chosen,&fs_guid,(void**)&fs);
    if(r->status||!fs||!fs->open)return 0;
    r->status=fs->open(fs,&root);
    if(r->status||!root||!root->close)return 0;
    if(!root->open){root->close(root);r->status=EFI_ERROR|3;return 0;}
    r->status=root->open(root,&file,name,1,0); /* EFI_FILE_MODE_READ only. */
    efi_status closed=root->close(root);r->closed=1;
    if(!r->status&&closed)r->status=closed;
    if(r->status||!file||!file->close||!file->read){
        if(file&&file->close){file->close(file);r->closed++;}
        if(!r->status)r->status=EFI_ERROR|3;return 0;
    }
    while(r->bytes<bytes){
        uint64_t size=bytes-r->bytes;if(size>65536)size=65536;uint64_t wanted=size;
        r->status=file->read(file,&size,dest+r->bytes);r->reads++;
        if(r->status||!size||size>wanted){if(!r->status)r->status=EFI_ERROR|7;break;}
        r->bytes+=size;
    }
    if(!r->status){
        uint8_t byte;uint64_t extra=1;r->status=file->read(file,&extra,&byte);r->reads++;
        if(!r->status&&extra)r->status=EFI_ERROR|4;
    }
    closed=file->close(file);r->closed++;if(!r->status)r->status=closed;
    return !r->status&&r->bytes==bytes&&r->closed==2;
}
#endif

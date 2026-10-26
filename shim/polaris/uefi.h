/* Small AArch64 UEFI ABI subset. Layout informed by HackiOS xnuloader/efi.h
 * d82c64a3 (MIT, userland/gpu/LICENSE.hackios) and UEFI2.10. No write APIs. */
#ifndef POLARIS_UEFI_H
#define POLARIS_UEFI_H
#include <stddef.h>
#include <stdint.h>
typedef uint64_t efi_status;
typedef void *efi_handle;
typedef struct {uint32_t a;uint16_t b,c;uint8_t d[8];} efi_guid;
typedef struct {uint64_t signature;uint32_t revision,size,crc,reserved;} efi_header;
#define EFI_ERROR UINT64_C(0x8000000000000000)
#define EFI_TOO_SMALL (EFI_ERROR|5)
struct efi_output {void *reset;efi_status (*string)(struct efi_output *,const uint16_t *);};
struct efi_memory {uint32_t type,pad;uint64_t physical,virtual_address,pages,attributes;};
struct efi_boot {
    efi_header hdr;
    uint64_t (*raise_tpl)(uint64_t);
    void (*restore_tpl)(uint64_t);
    efi_status (*allocate_pages)(uint32_t,uint32_t,uint64_t,uint64_t *);
    efi_status (*free_pages)(uint64_t,uint64_t);
    efi_status (*get_map)(uint64_t *,void *,uint64_t *,uint64_t *,uint32_t *);
    efi_status (*allocate_pool)(uint32_t,uint64_t,void **);
    efi_status (*free_pool)(void *);
    efi_status (*create_event)(uint32_t,uint64_t,void *,void *,void **);
    void *set_timer,*wait_for_event;
    efi_status (*signal_event)(void *);
    efi_status (*close_event)(void *);
    void *check_event;
    efi_status (*install_protocol)(efi_handle *,const efi_guid *,uint32_t,void *);
    void *reinstall_protocol,*uninstall_protocol;
    efi_status (*handle_protocol)(efi_handle,const efi_guid *,void **);
    void *reserved,*register_notify,*locate_handle,*locate_path,*install_table;
    efi_status (*load_image)(uint8_t,efi_handle,void *,const void *,uint64_t,efi_handle *);
    efi_status (*start_image)(efi_handle,uint64_t *,uint16_t **);
    void *exit_image,*unload_image,*exit_boot_services,*next_count;
    efi_status (*stall)(uint64_t);
    efi_status (*watchdog)(uint64_t,uint64_t,uint64_t,const uint16_t *);
    void *connect,*disconnect;
    void *open_protocol,*close_protocol,*open_information,*protocols,*locate_buffer;
    efi_status (*locate_protocol)(const efi_guid *,void *,void **);
    void *install_multiple,*uninstall_multiple,*crc32,*copy_mem,*set_mem;
    efi_status (*create_event_ex)(uint32_t,uint64_t,void (*)(void *,void *),void *,const efi_guid *,void **);
};
struct efi_runtime {
    efi_header hdr;void *time[6];
    efi_status (*get_variable)(const uint16_t *,const efi_guid *,uint32_t *,uint64_t *,void *);
    void *get_next_variable,*set_variable,*get_next_high_count;
    void (*reset_system)(uint32_t,efi_status,uint64_t,const void *);
};
struct efi_system {
    efi_header hdr;uint16_t *vendor;uint32_t revision,pad;
    efi_handle in_handle;void *in;
    efi_handle out_handle;struct efi_output *out;
    efi_handle error_handle;struct efi_output *error;
    struct efi_runtime *runtime;struct efi_boot *boot;
    uint64_t table_count;void *tables;
};
struct efi_loaded {
    uint32_t revision,pad;efi_handle parent;struct efi_system *system;
    efi_handle device;void *file_path,*reserved;uint32_t options_bytes,pad2;
    void *options,*base;uint64_t bytes;uint32_t code_type,data_type;void *unload;
};
_Static_assert(sizeof(efi_header)==24,"UEFI header");
_Static_assert(sizeof(struct efi_memory)==40,"UEFI memory descriptor prefix");
_Static_assert(offsetof(struct efi_boot,get_map)==56,"GetMemoryMap");
_Static_assert(offsetof(struct efi_boot,handle_protocol)==152,"HandleProtocol");
_Static_assert(offsetof(struct efi_boot,stall)==248,"Stall");
_Static_assert(offsetof(struct efi_boot,watchdog)==256,"SetWatchdogTimer");
_Static_assert(offsetof(struct efi_boot,load_image)==200,"LoadImage");
_Static_assert(offsetof(struct efi_boot,create_event_ex)==368,"CreateEventEx");
_Static_assert(offsetof(struct efi_boot,locate_protocol)==320,"LocateProtocol");
_Static_assert(offsetof(struct efi_system,boot)==96,"BootServices");
_Static_assert(offsetof(struct efi_runtime,get_variable)==72,"GetVariable");
_Static_assert(offsetof(struct efi_runtime,reset_system)==104,"ResetSystem");
_Static_assert(offsetof(struct efi_loaded,base)==64,"ImageBase");
#endif

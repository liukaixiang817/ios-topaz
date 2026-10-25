/* Included once after the verified RAM-COW diagnostic state. Saved snapshots
 * only; no new hardware access, allocation, persistent logging or waits. */
#ifndef POLARIS_GPU_DIAGNOSTICS_H
#define POLARIS_GPU_DIAGNOSTICS_H
static bool
polaris_diag_report(void)
{
    if (!polaris_diag_enabled()) { return false; }
    extern void polaris_touch_report(void);
    polaris_touch_report();
    /* Full hardware snapshots are immutable after publication. Repainting
     * every unchanged row costs a screen scroll per line on CPU1, and also
     * evicts the first useful bootstrap messages from the RAM log. */
    extern void polaris_usb_report(void);
    extern uint32_t polaris_usb_status(char *,uint32_t);
    static bool usb_reported;
    static char usb_previous[160];char usb_current[160]={0};
    polaris_usb_status(usb_current,sizeof(usb_current));
    if(!usb_reported || strcmp(usb_previous,usb_current)) {
        polaris_usb_report();strlcpy(usb_previous,usb_current,sizeof(usb_previous));usb_reported=true;
    }
    extern void polaris_a630_report(void);
    extern uint32_t polaris_a630_status(void);
    extern uint32_t polaris_a630_details(char *,uint32_t);
    extern uint32_t polaris_gpu_overlay_line(char *,uint32_t);
    extern uint32_t polaris_gpu_client_line(char *,uint32_t);
    static uint32_t gpu_previous=UINT32_MAX;
    uint32_t gpu_current=polaris_a630_status();
    if(gpu_previous!=gpu_current){polaris_a630_report();gpu_previous=gpu_current;}
    else if(!gpu_current){char pending[80];if(polaris_a630_details(pending,sizeof(pending)))printf("D GPU PROGRESS: %s\n",pending);}
    char progress[80];
    if(polaris_gpu_overlay_line(progress,sizeof(progress)))printf("D GL BOOT: %s\n",progress);
    if(polaris_gpu_client_line(progress,sizeof(progress)))printf("D GL APP: %s\n",progress);
    char line[POLARIS_DIAG_BYTES];
    printf("\nPOLARIS DIAG: first failures, RAM only\n");
    static uint32_t emitted;
    for (unsigned i = 0; i < POLARIS_DIAG_SLOTS; i++) {
        if(emitted&(1u<<i))continue;
        lck_spin_lock(&polaris_diag_lock);
        memcpy(line, polaris_diag_lines[i], sizeof(line));
        lck_spin_unlock(&polaris_diag_lock);
        if (line[0]) { printf("%s\n", line);emitted|=1u<<i; }
    }
    /* A diagnostic must not wait behind a busy/stalled storage request. */
    if (lck_mtx_try_lock(&sweet_ufs_lock)) {
        unsigned used = polaris_root_cow.used, limit = polaris_root_cow.limit;
        unsigned reserved = (unsigned)(polaris_root_arena.size >> 20);
        uint64_t dirty = polaris_root_cow.dirty_blocks, written = polaris_root_cow.written_blocks;
        uint64_t failures = polaris_cow_failures;
        uint64_t base_calls = polaris_base_calls, ram_reads = polaris_ram_reads;
        uint64_t ram_merges = polaris_ram_merges, full_writes = polaris_full_writes;
        bool active = polaris_ram_cow_enabled, failed = polaris_io_failed;
        lck_mtx_unlock(&sweet_ufs_lock);
        printf("D COW: active=%u groups=%u/%u UFS-error=%u\n", active, used, limit, failed);
        printf("D RAM: reserved=%uMiB dirty=%lluKiB written=%lluKiB refused=%llu\n",
            reserved, dirty * 4, written * 4, failures);
        printf("D IO: base_calls=%llu ram_reads=%llu ram_merges=%llu full_writes=%llu\n",
            base_calls, ram_reads, ram_merges, full_writes);
    } else {
        printf("D COW: storage busy; reporting without waiting\n");
    }
    return true;
}

#endif

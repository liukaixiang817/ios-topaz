/* Resident A630 backend; caller holds the exclusive PolarisGPU service lock.
 * No function is safe for an interrupt/display callback. A false completion
 * permanently quarantines all DMA-owned objects until reboot.
 */
#ifndef POLARIS_GPU_H
#define POLARIS_GPU_H
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
bool polaris_gpu_ready(void);
bool polaris_gpu_boot_pending(void);
bool polaris_gpu_timestamp(uint64_t *value);
bool polaris_gpu_caller_allowed(void);
uint32_t polaris_gpu_caller_kind(void);
void polaris_gpu_loader_policy(int error);
bool polaris_gpu_quiescent(void);
bool polaris_gpu_map(uint64_t address, uint64_t physical, bool read_only, bool cached);
bool polaris_gpu_commit(void);
bool polaris_gpu_unmap(uint64_t address, uint64_t size);
bool polaris_gpu_submit(const uint64_t *addresses, const uint32_t *words, uint32_t count, uint32_t *fence);
void polaris_gpu_cache(void *address, uint64_t size);
void polaris_gpu_quarantine(void);
uint32_t polaris_gpu_client_line(char *out,uint32_t capacity);
uint32_t polaris_gpu_fault_line(unsigned line,char *out,uint32_t capacity);
uint32_t polaris_gpu_overlay_line(char *out,uint32_t capacity);
void polaris_gpu_overlay_exec(int error);
void PolarisGPUStart(void);
#ifdef __cplusplus
}
#endif
#endif

/* Exercise the actual staging parent with an independent uploaded RAM source. */
#include <stdint.h>
static uint8_t*payload_storage;
#define PMMN_TEST_PAYLOAD_BASE ((uintptr_t)payload_storage)
#define PMMN_TEST_PAYLOAD_BYTES 0x3f000
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE 1
#define EFI_XNU_MSS_FIRMWARE_OFFSET 4096
#define EFI_XNU_MSS_PAYLOAD_FW_BYTES 0x3e000
#if defined(PMS_PAYLOAD_SHARE_TEST)
#define PMSB_TEST_ENTRY payload_suite
#include "polaris-mss-mba-share-test.c"
#else
#define PMSI_TEST_ENTRY payload_suite
#include "polaris-mss-stage-test.c"
#endif
int main(int argc,char**argv)
{
    assert(!posix_memalign((void**)&payload_storage,4096,0x40000));
    int result=payload_suite(argc,argv);free(payload_storage);return result;
}

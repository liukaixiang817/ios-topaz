/* One exact default zone, prepared by verified PID1 before Apple launchd.
 * This changes only symlinks in volatile RAM COW, never UTC or TZif bytes. */
#ifndef POLARIS_TIMEZONE_H
#define POLARIS_TIMEZONE_H
#include <stdint.h>
struct polaris_timezone_report {
    uint32_t version,stage,error,validated,prepared,zoneinfo_active;
    uint32_t original_saved,localtime_active,restored,cleanup_failures,must_hold;
    int32_t january_offset,july_offset;
};
enum { PTZ_OK=0,PTZ_REFUSED=1,PTZ_SOURCE=2,PTZ_PREPARE=3,
       PTZ_ROLLED_BACK=4,PTZ_ROLLBACK_FAILED=5 };
int polaris_timezone_install(struct polaris_timezone_report *);
#ifdef POLARIS_TIMEZONE_FIXTURE
/* Host-only actual transaction under a private fixture root. Fault injection
 * and this path argument are absent from the iOS executable. */
int polaris_timezone_fixture(const char *,int,struct polaris_timezone_report *);
#endif
#endif

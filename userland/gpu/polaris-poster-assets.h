/* Exact20F66 official default7400 static wallpaper assets in verified volatile root, before launchd.
 * The caller must remain in PID1 until result0 or a complete rollback. A
 * must_hold result MUST stop launchd activation; never expose a partial set.
 * Private Apple-derived bytes are supplied only by the separately frozen
 * prepared-static-states-0002 header, never by a generic file/path/table API. */
#ifndef POLARIS_POSTER_ASSETS_H
#define POLARIS_POSTER_ASSETS_H
#include <stdint.h>
#define POLARIS_POSTER_ASSET_HEADER_SHA256 "2377b197c84246719fd7828a0e47cca918bed63b712be3813baaeef940b859c7"
struct polaris_poster_assets_report {
    uint32_t version,stage,error,validated,created_png,prepared_caml;
    uint32_t activated_caml,restored_caml,cleanup_failures,must_hold;
    uint64_t embedded_bytes,bundle_bytes;
};
enum { PPA_OK=0,PPA_REFUSED=1,PPA_SOURCE=2,PPA_PREPARE=3,
       PPA_ACTIVATE_ROLLED_BACK=4,PPA_ROLLBACK_FAILED=5 };
int polaris_poster_assets_install(struct polaris_poster_assets_report *);
#ifdef POLARIS_POSTER_ASSET_FIXTURE
/* Host-only: fixed asset suffixes under an absolute private/tmp fixture.
 * This entry point and fault controls do not exist in the runtime build. */
int polaris_poster_assets_fixture(const char *,int write_limit,int activation_failure,
    struct polaris_poster_assets_report *);
/* The exact read-only0444 SystemVersion gate only; fixture root never written. */
int polaris_poster_assets_version_fixture(const char *,struct polaris_poster_assets_report *);
#endif
#endif

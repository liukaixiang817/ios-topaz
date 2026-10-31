/* Only the tested backboardd child may opt into the default-OFF Mesa trial.
 * This changes its process environment, never any GPU or launchd state. */
#ifndef POLARIS_DRM_RETAINED_ENVIRONMENT_H
#define POLARIS_DRM_RETAINED_ENVIRONMENT_H
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#define PDRME_INTENT "POLARIS_DRM_RETAIN_CACHE"
#define PDRME_PORT "POLARIS_GPU_CONNECTION"
typedef char *(*pdrme_get_fn)(const char *);
typedef int (*pdrme_set_fn)(const char *,const char *,int);
typedef int (*pdrme_unset_fn)(const char *);
static inline int pdrme_clear(pdrme_get_fn get,pdrme_unset_fn unset)
{
    if(!get||!unset)return -1;
    int failed=unset(PDRME_INTENT)!=0;
    failed|=unset(PDRME_PORT)!=0;
    if(get(PDRME_INTENT)||get(PDRME_PORT))failed=1;
    return failed?-1:0;
}
static inline bool pdrme_space(char c)
{return c==' '||c=='\t'||c=='\n'||c=='\r';}
/* Exact one canonical token only. Duplicates, a missing terminator or any
 * other polarisgl value leave the optimization OFF; rendering is unchanged. */
static inline bool pdrme_gl_intent(const char *args,size_t capacity)
{
    if(!args||!capacity)return false;
    size_t length=0;while(length<capacity&&args[length])length++;
    if(length==capacity)return false;
    unsigned seen=0;bool enabled=false;
    for(size_t at=0;at<length;) {
        while(at<length&&pdrme_space(args[at]))at++;
        size_t start=at;while(at<length&&!pdrme_space(args[at]))at++;
        size_t bytes=at-start;
        if(bytes>=10&&!memcmp(args+start,"polarisgl=",10)) {
            if(seen++)return false;
            enabled=bytes==11&&args[start+10]=='1';
        }
    }
    return seen==1&&enabled;
}
static inline int pdrme_launch(const char *args,size_t capacity,bool accepted,
    pdrme_get_fn get,pdrme_set_fn set,pdrme_unset_fn unset)
{
    if(pdrme_clear(get,unset)||!set)return -1;
    if(!accepted||!pdrme_gl_intent(args,capacity))return 0;
    if(set(PDRME_INTENT,"1",1)) {
        (void)pdrme_clear(get,unset);return -1;
    }
    const char *value=get(PDRME_INTENT);
    if(!value||value[0]!='1'||value[1]||get(PDRME_PORT)) {
        (void)pdrme_clear(get,unset);return -1;
    }
    return 1;
}
#endif

/* Read the iOS16.5 capture stack's published capabilities, never capture.
 * This is a standalone diagnostic, not a camera driver or a camera surrogate.
 * No session, input, output, permission request, device lock, device-node open,
 * register access, power sequence, frame producer or software fallback exists.
 * Published formats do not establish that the sensor/ISP can supply a frame.
 */
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PCAM_BUDGET_NS UINT64_C(5000000000)
#define PCAM_HARD_NS UINT64_C(6000000000)
static uint64_t began;
static uint64_t monotonic_ns(void)
{
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
       (uint64_t)t.tv_sec>UINT64_MAX/UINT64_C(1000000000))return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static int in_budget(void)
{uint64_t n=monotonic_ns();return n&&n>=began&&n-began<PCAM_BUDGET_NS;}
static void *watchdog(void *unused)
{
    (void)unused;
    for(;;){
        uint64_t n=monotonic_ns();
        if(!n||n<began||n-began>=PCAM_HARD_NS){
            const char message[]="{\"schema\":\"polaris.camera.capabilities.v1\",\"error\":\"hard_timeout\",\"physical_capture_verified\":false}\n";
            (void)write(STDOUT_FILENO,message,sizeof(message)-1);_exit(124);
        }
        struct timespec pause={0,20000000};(void)nanosleep(&pause,NULL);
    }
}
static int print_result(NSDictionary *result,int status)
{
    NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
    if(!data||data.length>16384)return 70;
    const uint8_t *p=data.bytes;size_t at=0;
    while(at<data.length&&in_budget()){
        ssize_t n=write(STDOUT_FILENO,p+at,data.length-at);
        if(n>0)at+=(size_t)n;
        else if(n<0&&errno==EINTR)continue;
        else return 74;
    }
    if(at!=data.length)return 124;
    (void)write(STDOUT_FILENO,"\n",1);return status;
}
static int original_version(void)
{
    static const uint8_t expected[32]={0x46,0x45,0x7f,0x81,0xa0,0x4a,0x81,0xf4,
        0x62,0xbf,0xa0,0xab,0x24,0x69,0x3e,0xff,0x21,0x40,0xce,0x81,0xa2,0x54,0xe6,0x43,
        0x54,0xe4,0x3b,0xd0,0xb9,0x96,0xdd,0x22};
    int fd=open("/System/Library/CoreServices/SystemVersion.plist",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 0;
    struct stat a,b;uint8_t bytes[570],digest[32],extra;size_t at=0;int ok=0;
    if(fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_mode!=(S_IFREG|0444)||a.st_uid||a.st_gid||a.st_size!=sizeof(bytes))goto done;
    while(at<sizeof(bytes)&&in_budget()){
        ssize_t n=pread(fd,bytes+at,sizeof(bytes)-at,(off_t)at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto done;at+=(size_t)n;
    }
    if(at!=sizeof(bytes)||pread(fd,&extra,1,sizeof(bytes))||!CC_SHA256(bytes,sizeof(bytes),digest)||memcmp(digest,expected,32))goto done;
    if(fstat(fd,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_mode!=b.st_mode||
       a.st_uid!=b.st_uid||a.st_gid!=b.st_gid||a.st_size!=b.st_size||
       a.st_mtimespec.tv_sec!=b.st_mtimespec.tv_sec||a.st_mtimespec.tv_nsec!=b.st_mtimespec.tv_nsec)goto done;
    ok=1;
done:
    close(fd);return ok;
}
static BOOL char_node(const char *path)
{struct stat s;return lstat(path,&s)==0&&S_ISCHR(s.st_mode);}

int main(int argc,const char *argv[])
{
    (void)argv;
    int flags=fcntl(STDOUT_FILENO,F_GETFL);
    if(flags<0||fcntl(STDOUT_FILENO,F_SETFL,flags|O_NONBLOCK))return 74;
    began=monotonic_ns();if(!began)return 70;
    pthread_t thread;if(pthread_create(&thread,NULL,watchdog,NULL))return 70;
    (void)pthread_detach(thread);
    @autoreleasepool {
        NSMutableDictionary *result=[@{ @"schema":@"polaris.camera.capabilities.v1",
            @"capture_session_created":@NO,@"permission_requested":@NO,
            @"device_node_opened":@NO,@"direct_hardware_access_issued":@NO,
            @"capture_stack_side_effects_verified":@NO,
            @"physical_capture_verified":@NO,@"unique_identifiers_emitted":@NO } mutableCopy];
        if(argc!=1){result[@"error"]=@"no_arguments_allowed";return print_result(result,64);}
        if(!TARGET_OS_IPHONE||!original_version()){
            result[@"error"]=@"exact_original_20F66_required";return print_result(result,78);
        }
        result[@"native_polaris_char_node_present"]=@(char_node("/dev/polaris-camera"));
        result[@"foreign_redwood_char_node_present"]=@(char_node("/dev/redwood-camera"));
        @try {
#if TARGET_OS_IPHONE
            /* A single discovery call. No retry, synthetic device or fallback. */
            AVCaptureDeviceDiscoverySession *discovery=[AVCaptureDeviceDiscoverySession
                discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInWideAngleCamera,
                    AVCaptureDeviceTypeBuiltInTelephotoCamera,AVCaptureDeviceTypeBuiltInUltraWideCamera,
                    AVCaptureDeviceTypeBuiltInTrueDepthCamera]
                mediaType:AVMediaTypeVideo position:AVCaptureDevicePositionUnspecified];
            if(!in_budget()){result[@"error"]=@"query_timeout";return print_result(result,124);}
            NSArray<AVCaptureDevice *> *devices=discovery.devices;
            if(!devices||devices.count>8){result[@"error"]=@"missing_or_unbounded_devices";return print_result(result,65);}
            NSMutableArray *records=[NSMutableArray array];
            for(AVCaptureDevice *device in devices){
                if(!in_budget()){result[@"error"]=@"query_timeout";return print_result(result,124);}
                NSString *type=device.deviceType;
                if(![type isKindOfClass:NSString.class]||[type length]>160){result[@"error"]=@"invalid_device_type";return print_result(result,65);}
                NSArray<AVCaptureDeviceFormat *> *formats=device.formats;
                /* Count only. No exposure/focus/format setter or stream. */
                [records addObject:@{ @"type":type,@"position":@(device.position),
                    @"published_format_count":@(formats.count),@"capture_verified":@NO }];
            }
            result[@"devices"]=records;result[@"published_device_count"]=@(records.count);
            result[@"observation"]=@"published software capabilities only; no sensor identity or frame proof";
            return print_result(result,0);
#else
            result[@"error"]=@"iOS_only";return print_result(result,78);
#endif
        } @catch(NSException *exception){
            (void)exception;result[@"error"]=@"capture_stack_exception";return print_result(result,70);
        }
    }
}

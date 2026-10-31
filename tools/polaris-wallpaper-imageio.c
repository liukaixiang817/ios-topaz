/* Host-only lossless wallpaper conversion / round-trip evidence using Apple
 * ImageIO + CoreGraphics. Contains no Apple assets and no device interface. */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void fail(const char *why) { fprintf(stderr, "%s\n", why); exit(1); }
static CFURLRef file_url(const char *path)
{
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) fail("Cannot create filesystem URL");
    return url;
}
static void write_new(const char *path, const void *data, size_t n)
{
    FILE *f = fopen(path, "wbx");
    if (!f) fail("Cannot exclusively create evidence file");
    if (fwrite(data, 1, n, f) != n || fclose(f)) fail("Cannot finish evidence file");
}
static CGImageRef decode(const char *path, CGImageSourceRef *source_out)
{
    CFURLRef url = file_url(path);
    const void *keys[] = {kCGImageSourceShouldCache, kCGImageSourceShouldCacheImmediately,
        kCGImageSourceShouldAllowFloat};
    const void *values[] = {kCFBooleanTrue, kCFBooleanTrue, kCFBooleanFalse};
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CGImageSourceRef source = CGImageSourceCreateWithURL(url, options);
    CFRelease(url);
    if (!source || CGImageSourceGetCount(source) != 1) fail("Expected one ImageIO primary image");
    CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, options);
    CFRelease(options);
    if (!image) fail("ImageIO could not decode primary image");
    CFDataRef decoded = CGDataProviderCopyData(CGImageGetDataProvider(image));
    if (!decoded || CFDataGetLength(decoded) <= 0) fail("ImageIO pixel-provider decode unavailable; refusing a blank replacement");
    CFRelease(decoded);
    *source_out = source;
    return image;
}
struct pixels { uint8_t *bytes; size_t width, height, n; unsigned amin, amax; uint64_t alpha_count; };
static struct pixels rgba(CGImageRef image)
{
    struct pixels p = {0};
    p.width = CGImageGetWidth(image); p.height = CGImageGetHeight(image);
    if (!p.width || !p.height || p.width > 16384 || p.height > 16384 ||
        p.height > SIZE_MAX / p.width / 4) fail("Unsupported image dimensions");
    p.n = p.width * p.height * 4; p.bytes = calloc(1, p.n);
    if (!p.bytes) fail("Cannot allocate canonical RGBA8");
    CGColorSpaceRef color = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef ctx = CGBitmapContextCreate(p.bytes, p.width, p.height, 8, p.width * 4,
        color, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(color);
    if (!ctx) fail("Cannot create canonical sRGB RGBA8 context");
    CGContextSetBlendMode(ctx, kCGBlendModeCopy);
    CGContextSetInterpolationQuality(ctx, kCGInterpolationNone);
    CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)p.width, (CGFloat)p.height), image);
    CGContextFlush(ctx); CGContextRelease(ctx);
    p.amin = 255;
    for (size_t i = 3; i < p.n; i += 4) {
        unsigned a = p.bytes[i];
        if (a < p.amin) p.amin = a;
        if (a > p.amax) p.amax = a;
        if (a != 255) p.alpha_count++;
    }
    return p;
}
static void metadata(CGImageSourceRef source, const char *path)
{
    CFDictionaryRef properties = CGImageSourceCopyPropertiesAtIndex(source, 0, NULL);
    if (!properties) fail("No primary image metadata");
    CFErrorRef error = NULL;
    CFDataRef data = CFPropertyListCreateData(NULL, properties, kCFPropertyListXMLFormat_v1_0, 0, &error);
    if (!data || error) fail("Cannot serialize ImageIO metadata");
    write_new(path, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data));
    CFRelease(data); CFRelease(properties);
}
int main(int argc, char **argv)
{
    if (argc != 7 || strcmp(argv[1], "convert")) {
        fprintf(stderr, "usage: wallpaper-imageio convert INPUT OUTPUT.png SOURCE.rgba PNG.rgba METADATA.plist\n");
        return 2;
    }
    struct stat st;
    if (!stat(argv[3], &st) || errno != ENOENT) fail("PNG output must be a new file");
    CGImageSourceRef source;
    CGImageRef image = decode(argv[2], &source);
    metadata(source, argv[6]);
    struct pixels original = rgba(image);
    CFURLRef url = file_url(argv[3]);
    CGImageDestinationRef dest = CGImageDestinationCreateWithURL(url, CFSTR("public.png"), 1, NULL);
    CFRelease(url);
    if (!dest) fail("Cannot create PNG destination");
    /* Preserve decoded CGImage color space / alpha and original metadata.
     * PNG is lossless; there is no resizing or alpha removal path. */
    CGImageDestinationAddImage(dest, image, NULL);
    if (!CGImageDestinationFinalize(dest)) fail("Cannot encode original decoded CGImage as PNG");
    CFRelease(dest);
    CGImageSourceRef png_source;
    CGImageRef png = decode(argv[3], &png_source);
    struct pixels check = rgba(png);
    bool same = original.width == check.width && original.height == check.height &&
        original.n == check.n && !memcmp(original.bytes, check.bytes, original.n);
    write_new(argv[4], original.bytes, original.n);
    write_new(argv[5], check.bytes, check.n);
    printf("{\"width\":%zu,\"height\":%zu,\"rgba8_bytes\":%zu,"
        "\"source_bpc\":%zu,\"source_bpp\":%zu,\"source_alpha_info\":%u,"
        "\"png_bpc\":%zu,\"png_bpp\":%zu,\"png_alpha_info\":%u,"
        "\"alpha_min\":%u,\"alpha_max\":%u,\"nonopaque_pixels\":%" PRIu64 ","
        "\"png_alpha_min\":%u,\"png_alpha_max\":%u,\"png_nonopaque_pixels\":%" PRIu64 ","
        "\"normalization\":\"CoreGraphics sRGB RGBA8 premultiplied-last byte-order32Big; no interpolation; copy blend\","
        "\"whole_rgba8_equal\":%s}\n",
        original.width, original.height, original.n,
        CGImageGetBitsPerComponent(image), CGImageGetBitsPerPixel(image), (unsigned)CGImageGetAlphaInfo(image),
        CGImageGetBitsPerComponent(png), CGImageGetBitsPerPixel(png), (unsigned)CGImageGetAlphaInfo(png),
        original.amin, original.amax, original.alpha_count, check.amin, check.amax, check.alpha_count,
        same ? "true" : "false");
    free(original.bytes); free(check.bytes);
    CGImageRelease(image); CFRelease(source); CGImageRelease(png); CFRelease(png_source);
    return same ? 0 : 1;
}

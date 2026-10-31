/* Exact media target identity, shared by pre-exec and runtime admission. */
#ifndef POLARIS_MEDIA_ADMISSION_H
#define POLARIS_MEDIA_ADMISSION_H
/* Borrowed target vnode: exact media dyld identity, never a GPU role.
 * Also used before exec, when current_proc still names xpcproxy/launchd. */
bool polaris_media_image_allowed(vnode_t image)
{
    if(!polaris_gpu_overlay_ready() ||
       !__atomic_load_n(&pgpu_poster_preview,__ATOMIC_RELAXED) ||
       !polaris_ram_overlay_allowed())return false;
    if(!image)return false;
    struct vnode_attr attr={0};VATTR_INIT(&attr);
    VATTR_WANTED(&attr,va_uid);VATTR_WANTED(&attr,va_gid);
    VATTR_WANTED(&attr,va_mode);VATTR_WANTED(&attr,va_data_size);
    bool ok=vnode_isreg(image) && (vfs_flags(vnode_mount(image))&MNT_ROOTFS) &&
        !vnode_getattr(image,&attr,vfs_context_kernel()) &&
        VATTR_IS_SUPPORTED(&attr,va_uid) && VATTR_IS_SUPPORTED(&attr,va_gid) &&
        VATTR_IS_SUPPORTED(&attr,va_mode) && VATTR_IS_SUPPORTED(&attr,va_data_size) &&
        attr.va_uid==0 && attr.va_gid==0 && (attr.va_mode&07777)==0755 &&
        attr.va_data_size==188112;
    vnode_t expected=NULLVP;
    if(ok)ok=!vnode_lookup("/usr/sbin/mediaserverd",
        VNODE_LOOKUP_NOFOLLOW|VNODE_LOOKUP_NOCROSSMOUNT,&expected,vfs_context_kernel());
    ok=ok && expected==image;
    int read_error=0,resid=0;bool hashed=false;
    if(ok) {
        /* Bind the genuine0:0/0755 metadata and all188112 original bytes.
         * Never chmod or replace the Apple executable. */
        static const uint8_t hash[32]={
            0x35,0xd7,0x6b,0xbe,0x90,0xe8,0x4c,0x6d,0x45,0xb6,0x63,0x62,0x1c,0x52,0x3d,0xd6,
            0x41,0x9a,0x7f,0x24,0x81,0x4c,0x2b,0x53,0x7e,0x69,0xaf,0xe1,0x38,0x11,0x8e,0x20};
        void *data=kalloc_data(188112,Z_WAITOK);
        if(!data)ok=false;
        else {
            vfs_context_t ctx=vfs_context_kernel();
            read_error=vn_rdwr(UIO_READ,image,(caddr_t)data,188112,0,UIO_SYSSPACE,
                0,vfs_context_ucred(ctx),&resid,vfs_context_proc(ctx));
            hashed=!read_error && !resid && pgpu_digest(data,188112,hash);
            ok=hashed && polaris_ram_overlay_allowed();kfree_data(data,188112);
        }
    }
    static uint32_t reports;
    if(__atomic_fetch_add(&reports,1,__ATOMIC_RELAXED)<8)
        printf("POLARIS MEDIA ID: uid%u gid%u mode%o bytes%llu match%d hash%d read%d resid%d\n",
            (unsigned)attr.va_uid,(unsigned)attr.va_gid,(unsigned)attr.va_mode,
            (unsigned long long)attr.va_data_size,ok,hashed,read_error,resid);
    if(expected)vnode_put(expected);return ok;
}
bool polaris_media_compat_allowed(void)
{
    char name[32]={0};proc_name(proc_pid(current_proc()),name,sizeof(name));
    if(strcmp(name,"mediaserverd"))return false;
    vnode_t image=proc_getexecutablevnode(current_proc());
    if(!image)return false;
    bool ok=polaris_media_image_allowed(image);vnode_put(image);return ok;
}
#endif

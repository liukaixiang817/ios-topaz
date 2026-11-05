#!/usr/bin/env python3
"""Execute the actual patched shutdown functions with software platform leaves."""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path


def function(text, name):
    match = re.search(r'^(?:static )?(?:void|bool|int) '+re.escape(name)+r'\([^\n]*\)\n\{', text, re.M)
    if not match:
        raise ValueError('actual function definition missing: '+name)
    start = match.start()
    first = text.index('{', start)
    depth = 1
    end = first+1
    while depth:
        depth += (text[end] == '{')-(text[end] == '}')
        end += 1
    return text[start:end]+'\n'


PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "runtime-quiesce.h"
static bool ps_enabled=true,ps_bsd_ready=true,ps_owned;
static struct polaris_shutdown_slot polaris_uefi_shutdown;
static unsigned cache_calls,clock_seals,wifi_seals,reboots;
static int seal_error=EBUSY;
static void pi_cache(uintptr_t at,bool clean){(void)at;(void)clean;cache_calls++;}
static uint64_t mach_absolute_time(void){return 101;}
static int polaris_ufs_owned_status(struct polaris_shutdown_status*s){(void)s;return EIO;}
static void polaris_clock_seal(void){clock_seals++;}
static int polaris_wifi_interface_seal(void){wifi_seals++;return seal_error;}
static int reboot_kernel(int howto,void*p){assert(!howto&&!p&&!seal_error);reboots++;return EIO;}
'''
MAIN = r'''
int main(int argc,char**argv){
    assert(argc==2);unsigned mode=(unsigned)atoi(argv[1]);
    polaris_uefi_shutdown.kernel.phase=POLARIS_Q_RUNNING;
    polaris_uefi_shutdown.kernel.cookie=101;
    polaris_uefi_shutdown.firmware.cookie=101;
    polaris_uefi_shutdown.firmware.sequence=1;
    polaris_uefi_shutdown.firmware.mode=2;
    if(mode==3)polaris_uefi_shutdown.firmware.cookie=99;
    if(mode==4)ps_bsd_ready=false;
    if(mode==5)polaris_uefi_shutdown.kernel.phase=POLARIS_Q_FAILED;
    if(mode>=3){assert(!ps_poll());ps_execute();assert(!wifi_seals&&!clock_seals&&!reboots);
        if(mode==3)assert(polaris_uefi_shutdown.kernel.phase==POLARIS_Q_FAILED&&polaris_uefi_shutdown.kernel.error==EINVAL);
        return 0;}
    assert(ps_poll()&&polaris_uefi_shutdown_pending());
    if(mode==2)seal_error=ENXIO;
    ps_execute();assert(wifi_seals==1&&clock_seals==1&&!reboots);
    if(mode==2){assert(polaris_uefi_shutdown.kernel.phase==POLARIS_Q_FAILED&&polaris_uefi_shutdown.kernel.error==ENXIO);assert(!ps_poll());return 0;}
    assert(polaris_uefi_shutdown_pending()&&ps_poll());
    if(mode==0){seal_error=0;ps_execute();assert(reboots==1&&wifi_seals==2&&clock_seals==2);
        assert(polaris_uefi_shutdown.kernel.phase==POLARIS_Q_FAILED&&polaris_uefi_shutdown.kernel.error==EIO);}
    else{
        for(unsigned n=1;n<500;n++){assert(ps_poll());ps_execute();assert(polaris_uefi_shutdown_pending());}
        assert(!reboots&&wifi_seals==500);assert(ps_poll());ps_execute();
        assert(!reboots&&wifi_seals==501&&polaris_uefi_shutdown.kernel.phase==POLARIS_Q_FAILED&&polaris_uefi_shutdown.kernel.error==ETIMEDOUT);
    }
    assert(!ps_poll());return 0;
}
'''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    text = args.source.read_text()
    selected = ''.join(function(text, name) for name in
                       ['ps_publish', 'polaris_uefi_shutdown_pending', 'ps_poll', 'ps_execute'])
    assert 'phase==POLARIS_Q_REQUESTED' in selected and 'polaris_wifi_interface_seal()' in selected
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='polaris-wifi-drain-') as directory:
        source, binary = Path(directory)/'test.c', Path(directory)/'test'
        source.write_text(PREFIX+selected+MAIN)
        subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                        '-I'+str(root/'shim/polaris'),str(source),'-o',str(binary)],check=True)
        for mode in range(6):
            subprocess.run([str(binary),str(mode)],check=True)
    print('PASS 6 actual shutdown hook scenarios; SOFTWARE seal/clock/reboot leaves')

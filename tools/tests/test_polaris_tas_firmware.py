"""Non-executing TAS catalog: malformed counts/strings/references and bounds."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "polaris-tas-firmware.h"
static struct polaris_tas_catalog result,before;
static struct polaris_tas_workspace workspace;
static unsigned char fixture[16384],changed[16384];
static size_t at,driver_at,family_at,block_count_at,command_at,config_program_at;
static size_t config_pll_at,config_devices_at,calibration_ref_at,string_at;
static void number(unsigned n,unsigned v)
{for(unsigned i=0;i<n;i++)fixture[at++]=(unsigned char)(v>>(8*(n-1-i)));}
static void named(void)
{fixture[at]='n';at+=64;fixture[at++]='d';fixture[at++]=0;}
static void block(unsigned type)
{number(4,type);number(1,1);number(1,0xab);number(1,1);number(1,0xcd);
 command_at=at;number(4,1);number(4,0x00000102);}
static void data(void)
{named();block_count_at=at;number(2,1);block(4);}
static void make_fixture(void)
{
 memset(fixture,0,sizeof(fixture));at=0;
 memcpy(fixture,"5552",4);at=4;number(4,0);number(4,0x12345678);
 number(4,0x69100);number(4,0x1010000);driver_at=at;number(4,0x401);
 number(4,42);named();family_at=at;number(4,0);number(4,4);
 number(2,1);named();block(0);
 number(2,1);named();number(1,0);number(2,0x1234);data();
 number(2,1);named();config_devices_at=at;number(2,3);
 config_program_at=at;number(1,0);config_pll_at=at;number(1,0);
 number(4,48000);number(1,0);number(4,1536000);data();
 number(2,1);named();number(1,0);calibration_ref_at=at;number(1,0);data();
 string_at=92; /* Fixed28-byte header plus64-byte name. */
 unsigned n=(unsigned)at;
 for(unsigned i=0;i<4;i++)fixture[4+i]=(unsigned char)(n>>(8*(3-i)));
}
static bool parse(const unsigned char *p,size_t n)
{
 memset(&result,0xa5,sizeof(result));before=result;
 bool ok=polaris_tas_firmware_catalog(p,n,&result,&workspace);
 if(!ok)assert(memcmp(&result,&before,sizeof(result))==0);
 else {
  assert(result.bytes==n&&result.entry_count<=PTF_ENTRY_LIMIT&&result.block_count<=PTF_BLOCK_LIMIT);
  for(unsigned i=0;i<result.block_count;i++) {
   const struct polaris_tas_block *b=&result.blocks[i];
   assert(b->data.offset<=n&&b->data.bytes<=n-b->data.offset);
   assert(b->data.bytes==(uint64_t)b->commands*4);
  }
 }
 return ok;
}
static void reject_byte(size_t offset,unsigned value)
{memcpy(changed,fixture,at);changed[offset]=(unsigned char)value;assert(!parse(changed,at));}
int main(int argc,char **argv)
{
 assert(argc==2);make_fixture();
 if(!strcmp(argv[1],"positive")) {
  assert(parse(fixture,at));assert(result.plls==1&&result.programs==1);
  assert(result.configurations==1&&result.calibrations==1&&result.block_count==4);
  assert(result.checksum==0x12345678&&result.entries[2].rate==48000);
  assert(result.entries[2].devices==3&&result.entries[1].boost==0x1234);
  assert(result.blocks[0].p_checksum==0xab&&result.blocks[0].y_checksum==0xcd);
  assert(!memcmp(fixture+result.blocks[0].data.offset,"\0\0\1\2",4));
 } else if(!strcmp(argv[1],"truncation")) {
  for(size_t cut=0;cut<at;cut++)assert(!parse(fixture,cut));
 } else if(!strcmp(argv[1],"scope")) {
  reject_byte(0,'x');reject_byte(driver_at+3,2);reject_byte(family_at+3,1);
  reject_byte(family_at+7,5);reject_byte(7,0);
  memcpy(changed,fixture,at);memset(changed+string_at,'a',at-string_at);assert(!parse(changed,at));
 } else if(!strcmp(argv[1],"counts")) {
  reject_byte(block_count_at,255);reject_byte(command_at,255);
  reject_byte(command_at-4,2);reject_byte(command_at-2,2);
  reject_byte(family_at+8,2);
 } else if(!strcmp(argv[1],"references")) {
  reject_byte(config_program_at,1);reject_byte(config_pll_at,1);
  reject_byte(config_devices_at+1,0);reject_byte(config_devices_at+1,4);
  reject_byte(calibration_ref_at,1);
 } else if(!strcmp(argv[1],"alias")) {
  memset(&result,0xa5,sizeof(result));before=result;
  assert(!polaris_tas_firmware_catalog(fixture,at,&workspace.candidate,&workspace));
  assert(!polaris_tas_firmware_catalog(&result,sizeof(result),&result,&workspace));
  assert(!polaris_tas_firmware_catalog(fixture,at,&result,(struct polaris_tas_workspace *)&result));
  assert(!polaris_tas_firmware_catalog(NULL,at,&result,&workspace));
  assert(!polaris_tas_firmware_catalog(fixture,PTF_FILE_LIMIT+1,&result,&workspace));
  assert(!memcmp(&result,&before,sizeof(result)));
 } else if(!strcmp(argv[1],"trailing")) {
  memcpy(changed,fixture,at);changed[at]=0;unsigned n=(unsigned)at+1;
  for(unsigned i=0;i<4;i++)changed[4+i]=(unsigned char)(n>>(8*(3-i)));
  assert(!parse(changed,n));
 } else if(!strcmp(argv[1],"description")) {
  for(unsigned length=PTF_DESCRIPTION_LIMIT;length<=PTF_DESCRIPTION_LIMIT+1;length++) {
   memcpy(changed,fixture,string_at);memset(changed+string_at,'a',length);
   changed[string_at+length]=0;
   memcpy(changed+string_at+length+1,fixture+string_at+2,at-string_at-2);
   unsigned n=(unsigned)at+length-1;
   for(unsigned i=0;i<4;i++)changed[4+i]=(unsigned char)(n>>(8*(3-i)));
   assert(parse(changed,n)==(length==PTF_DESCRIPTION_LIMIT));
  }
 } else if(!strcmp(argv[1],"mutation")) {
  uint32_t seed=0x40102559;
  for(unsigned i=0;i<10000;i++) {
   memcpy(changed,fixture,at);
   for(unsigned j=0;j<1+i%7;j++) {
    seed=seed*1664525u+1013904223u;size_t offset=seed%at;
    seed=seed*1664525u+1013904223u;changed[offset]^=(unsigned char)(1u<<(seed%8));
   }
   (void)parse(changed,at);
  }
 } else return 2;
 puts("PASS");return 0;
}
'''


class TasCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="polaris-tas-catalog-")
        base = Path(cls.tmp.name)
        c = base / "check.c"
        c.write_text(HARNESS)
        cls.exe = base / "check"
        subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", "-O1", "-g", "-fsanitize=address,undefined",
                        "-fno-omit-frame-pointer", "-I", str(ROOT / "tools"), str(c),
                        "-o", str(cls.exe)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check_case(self, name):
        p = subprocess.run([str(self.exe), name], check=True, capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "PASS")

    def test_complete_catalog_and_retained_checksums(self): self.check_case("positive")
    def test_every_truncation_preserves_output(self): self.check_case("truncation")
    def test_identity_version_and_missing_string_end(self): self.check_case("scope")
    def test_count_overflow_and_checksum_flag_encoding(self): self.check_case("counts")
    def test_bad_program_pll_configuration_and_device_references(self): self.check_case("references")
    def test_alias_null_and_oversized_inputs(self): self.check_case("alias")
    def test_complete_consumption(self): self.check_case("trailing")
    def test_description_limit_and_terminator(self): self.check_case("description")
    def test_ten_thousand_mutations(self): self.check_case("mutation")


if __name__ == "__main__": unittest.main()

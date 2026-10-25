"""Own A630 GMEM contract and first-fault regression; no hardware substitute."""
from pathlib import Path
import unittest
from .test_polaris_a630_submit import run
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]


class GMEMTests(unittest.TestCase):
    def test_actual_parameter_reply_matches_native_UCHE_window(self):
        text = (ROOT / 'tools/PolarisGPU.cpp').read_text()
        start = text.index('switch(r.param.param)')
        switch = function(text, 'switch(r.param.param)')
        self.assertGreater(start, 0)
        run(r'''
#include <stdint.h>
#include "polaris-a630-core-profile.h"
#include "polaris-gpu-abi.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
static bool polaris_gpu_timestamp(uint64_t *p){*p=123;return true;}
static bool query(unsigned param,uint64_t *value){
 struct {struct msm_param param;}r={.param={.pipe=0x10,.param=param}};
''' + switch + r'''
 *value=r.param.value;return true;
done:return false;}
int main(void){uint64_t base=0,size=0;uint32_t lo=0,hi=0;
 assert(query(6,&base)&&query(2,&size));
 for(unsigned n=0;n<sizeof(a630_core_profile)/sizeof(a630_core_profile[0]);n++){
  if(a630_core_profile[n].word==0xe0b)lo=a630_core_profile[n].value;
  if(a630_core_profile[n].word==0xe0d)hi=a630_core_profile[n].value;
 }
 assert(lo==0x100000&&hi==0x1fffff&&base==lo&&size==hi-lo+1);
 /* The prior zero parameter sends GMEM descriptors outside the programmed
  * UCHE window. It must fail this same contract, not be mapped as memory. */
 assert(!(0>=lo&&0<=hi));
 for(unsigned offset=0;offset<size;offset+=4096)assert(base+offset>=lo&&base+offset<=hi);
 assert(!query(0x1234,&base));return 0;}
''')

    def test_actual_quiescence_preserves_each_failure_without_recovery(self):
        text = (ROOT / 'tools/polaris-a630-runtime.h').read_text()
        actual = function(text, 'bool polaris_gpu_quiescent(')
        run(r'''
#include "polaris-a630-core.h"
#include <assert.h>
static unsigned a630_client_io,mode,dead,reads;
static struct {struct a630_core_snapshot live;}a630_client_submit;
static struct {uint64_t physical;}a630_core_tables={0x1a578c000ull};
static bool a630_client_begin(void){return !dead;}
static bool a630_core_owned(void*p){assert(p==&a630_client_io);return true;}
static bool a630_core_read(void*p,uint32_t reg,uint32_t*v){
 assert(p==&a630_client_io);reads++;
 switch(reg){case 0x806:case 0x210:case 0x201:*v=0;break;
 case 0x823:*v=mode==6?0x80:0;break;case 0x808:*v=mode==1?1:3;break;
 case 0x821:case 0x824:*v=0;break;default:assert(0);}return true;}
static bool a630_smmu_read(void*p,uint32_t reg,uint32_t*v){
 assert(p==&a630_client_io);reads++;if(mode==5&&reg==0x8058)return false;
 if(reg==0x8058)*v=mode==2?0x80000402:0;
 else {assert(reg==0x8000);*v=mode==3?0:0xc01127;}return true;}
static bool a630_smmu_read64(void*p,uint32_t reg,uint64_t*v){
 assert(p==&a630_client_io&&reg==0x8020);reads++;
 *v=a630_core_tables.physical+(mode==4?(1ull<<32):0);return true;}
static bool a630_core_write(void*p,uint32_t r,uint32_t v){(void)p;(void)r;(void)v;assert(0);return false;}
static bool a630_gmu_sync(void*p){(void)p;assert(0);return false;}
static void a630_delay_us(void*p,uint32_t n){(void)p;(void)n;assert(0);}
static void polaris_gpu_quarantine(void){dead++;}
''' + actual + r'''
int main(void){
 for(mode=0;mode<7;mode++){
  dead=reads=0;a630_client_submit.live=(struct a630_core_snapshot){0};
  assert(polaris_gpu_quiescent()==(mode==0));assert(dead==(mode!=0));
  struct a630_core_snapshot *s=&a630_client_submit.live;
  if(mode==1)assert(s->error==A630_CORE_DATA&&s->offset==0x808&&s->actual==1);
  if(mode==2)assert(s->error==A630_CORE_FAULT&&s->offset==0x8058&&s->actual==0x80000402);
  if(mode==3)assert(s->error==A630_CORE_DATA&&s->offset==0x8000);
  if(mode==4)assert(s->error==A630_CORE_DATA&&s->offset==0x8020);
  if(mode==5)assert(s->error==A630_CORE_IO&&s->offset==0x8058);
  if(mode==6)assert(s->error==A630_CORE_FAULT&&s->offset==0x823);
  if(mode){unsigned before=reads;assert(!polaris_gpu_quiescent()&&reads==before&&dead==1);}
 }
 return 0;}
''')

    def test_actual_gmem_fetch_checks_every_pixel_and_keeps_T6_after_pass(self):
        text = (ROOT / 'userland/gpu/polaris-gl-test.c').read_text()
        actual = function(text, 'static unsigned gmem_fetch_contract(')
        self.assertLess(text.index('setenv("FD_MESA_DEBUG","gmem",1)'),
                        text.index('OSMesaCreateContextAttribs(attrs,NULL)'))
        self.assertLess(text.index('gmem_fetch_contract(v,s)'), text.index('report(6,0)'))
        self.assertIn('gmem.value!=0x100000', text)
        run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned GLuint,GLenum;typedef int GLint;typedef void*IOSurfaceRef;
#define GL_NUM_EXTENSIONS 1
#define GL_EXTENSIONS 2
#define GL_FRAGMENT_SHADER 3
#define GL_LINK_STATUS 4
#define GL_TRIANGLES 5
#define kIOSurfaceLockReadOnly 6
static unsigned mode,draws,locks,unlocks,checked;
static uint8_t pixels[4096*4];
static void glGetIntegerv(GLenum n,GLint*p){assert(n==1);*p=mode==1?0:1;}
static const unsigned char*glGetStringi(GLenum n,GLuint i){assert(n==2&&!i);return (void*)"GL_EXT_shader_framebuffer_fetch";}
static void test_step(unsigned n){assert(n>=43&&n<=48);}
static GLuint shader(GLenum n,const char*t){assert(n==3&&strstr(t,"inout vec4 c")&&strstr(t,"vec3(1.0)-c.rgb"));return mode==2?0:2;}
static GLuint glCreateProgram(void){return 3;}
static void glAttachShader(GLuint p,GLuint s){assert(p==3&&(s==1||s==2));}
static void glLinkProgram(GLuint p){assert(p==3);}
static void glGetProgramiv(GLuint p,GLenum n,GLint*v){assert(p==3&&n==4);*v=mode!=3;}
static void glUseProgram(GLuint p){assert(p==3);}
static void glDrawArrays(GLenum n,GLint f,GLint c){assert(n==5&&!f&&c==3);draws++;
 const int first[4]={191,128,64,255};
 for(unsigned i=0;i<4096;i++)for(unsigned k=0;k<4;k++)pixels[i*4+k]=((draws&1)&&k!=3)?255-first[k]:first[k];
 if(mode==6)pixels[4095*4]=0;}
static void glFinish(void){}
static GLenum glGetError(void){return mode==4?1:0;}
static int IOSurfaceLock(IOSurfaceRef s,int o,void*p){assert(s==(void*)1&&o==6&&!p);locks++;return mode==5?1:0;}
static void*IOSurfaceGetBaseAddress(IOSurfaceRef s){assert(s==(void*)1);checked++;return mode==7?NULL:pixels;}
static int IOSurfaceUnlock(IOSurfaceRef s,int o,void*p){assert(s==(void*)1&&o==6&&!p);unlocks++;return 0;}
static void glDeleteProgram(GLuint p){assert(p==3);}
static void glDeleteShader(GLuint s){assert(s==2);}
''' + actual + r'''
int main(void){
 const unsigned result[]={0,41,42,43,44,45,46,46};
 for(mode=0;mode<8;mode++){
  draws=locks=unlocks=checked=0;assert(gmem_fetch_contract(1,(void*)1)==result[mode]);
  if(!mode)assert(draws==4&&locks==4&&unlocks==4&&checked==4);
  if(mode==6||mode==7)assert(locks==1&&unlocks==1);
 }
 return 0;}
''')

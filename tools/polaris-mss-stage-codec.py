#!/usr/bin/env python3
"""Independent MSS_STAGE_RAW_V1 decoder; local staging never proves modem boot."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('mss_memory_codec',Path(__file__).with_name('polaris-mss-memory-codec.py'))
memory=importlib.util.module_from_spec(spec);spec.loader.exec_module(memory)
early=memory.early;Layout=early.Layout;fields=early.fields
ASSET=Layout(fields(4,'offset bytes')+[('sha256',1,32)])
CACHE=Layout(fields(8,'address ctr_before ctr_after el sctlr')+
             fields(4,'operation line_bytes lines_issued lines_returned attempted barrier_issued barrier_returned complete error reserved'))
PAGE=Layout([('source',early.TRANSLATION,1),('target',early.TRANSLATION,1),('cache',CACHE,1),('after',early.ARCH,1)]+
            fields(4,'bytes words_issued words_returned complete'))
NATIVE=Layout(fields(8,'memory retained blob blob_bytes assets asset_count')+
              [('memory_digest',1,32),('retained_digest',1,32),('asset',ASSET,2),('entry',early.ARCH,1),('final',early.ARCH,1),
               ('core',early.CORE,2),('source_AT',early.TRANSLATION,128),('source_hash',1,64),('copied_hash',1,64),('page',PAGE,259)]+
              fields(4,'attempted unknown error')+[('source_pages',4,2)]+fields(4,'pages assets_complete complete'))
LAYOUTS=dict(pmsf_asset=ASSET,pwmk_record=CACHE,pmsi_page=PAGE,pmsi_result=NATIVE)


def translation(a,page):
    return (a['page']==page and a['read_par']==a['write_par']==(0xff00000000000b80|page) and
            a['saved']==a['restored'] and all(a[k]==1 for k in ('read_issued','read_returned','write_issued','write_returned')))


def cache(c,page):
    size=4<<((c['ctr_before']>>16)&15)
    return (16<=size<=4096 and c['address']==page and c['ctr_before']==c['ctr_after'] and
            c['el']==4 and c['sctlr']&5==5 and c['operation']==1 and c['line_bytes']==size and
            c['lines_issued']==c['lines_returned']==4096//size and
            all(c[k]==1 for k in ('attempted','barrier_issued','barrier_returned','complete')) and not c['error'] and not c['reserved'])


def decode(raw,mraw,eraw,hraw,firmware=None):
    if len(raw)!=NATIVE.size:raise ValueError(f'MSS_STAGE_RAW_V1 needs exactly {NATIVE.size} bytes')
    r=NATIVE.decode(raw);m=memory.decode(mraw,eraw,hraw);h=early.HOLD.decode(hraw);e=early.NATIVE.decode(eraw);issues=[]
    def require(ok,label):
        if not ok:issues.append(label)
    require(m['local_completion_consistent'],'allocation/retained completion');m=m['record']
    require(r['memory_digest']==hashlib.sha256(mraw).hexdigest() and r['retained_digest']==hashlib.sha256(hraw).hexdigest(),'allocation/retained digests')
    require(tuple(r[k] for k in ('attempted','unknown','error','pages','assets_complete','complete'))==(1,0,0,259,2,1),'staging completion')
    require(r['source_pages']==[59,3],'source page counts')
    require(r['blob']%4096==0 and 0<r['blob_bytes']<=0x4000000 and 2<=r['asset_count']<=32,'source blob geometry')
    ib=e['image']['base'];ie=ib+e['image']['bytes']
    require(ib<=r['assets']<ie and r['assets']+40*r['asset_count']<=ie,'resident source descriptors')
    transport=firmware.get('payload_transport') if firmware else None
    if transport:
        offset=transport['offset']
        require(transport['mode']=='payload-tail' and offset>0 and offset%4096==0 and
                r['blob']==h['payload']+offset and offset+r['blob_bytes']==h['input']['logical_bytes'] and
                transport['payload_bytes']==h['input']['logical_bytes'] and
                early.owned(early.descriptors(h['map']),r['blob'],r['blob_bytes'],2),'retained payload source')
    else:
        require(ib<=r['blob']<ie and r['blob']+r['blob_bytes']<=ie,'resident source image')
    require(memory.stable(h['final'],r['entry']) and memory.stable(r['entry'],r['final'],3840000),'stage CPU/time')
    if firmware:
        require(r['blob_bytes']==firmware['bytes'] and r['asset_count']==len(firmware['assets']),'generated bundle geometry')
    previous=r['entry']['cpu']['ticks']
    for kind,a in enumerate(r['asset']):
        expected=(238304,8412)[kind];q=m['memory']['claim'][kind+1]
        require(a['bytes']==expected and a['offset']%4096==0 and a['offset']+a['bytes']<=r['blob_bytes'],f'asset {kind} geometry')
        require(r['source_hash'][64*kind:64*(kind+1)]==r['copied_hash'][64*kind:64*(kind+1)]==a['sha256'],f'asset {kind} hashes')
        if firmware:require(all(a[k]==firmware['assets'][kind][k] for k in ('offset','bytes','sha256')),f'asset {kind} generated identity')
        for n in range(64):
            at=r['source_AT'][64*kind+n]
            require(translation(at,r['blob']+a['offset']+4096*n) if n<(expected+4095)//4096 else at==early.TRANSLATION.decode(bytes(early.TRANSLATION.size)),f'asset {kind} source AT {n}')
        for n in range((256,3)[kind]):
            p=r['page'][(256 if kind else 0)+n];page=q['requested']+4096*n
            size=min(4096,max(0,expected-4096*n))
            require(translation(p['target'],page),f'asset {kind} target AT {n}')
            require(translation(p['source'],r['blob']+a['offset']+4096*n) if size else p['source']==early.TRANSLATION.decode(bytes(early.TRANSLATION.size)),f'asset {kind} copy source AT {n}')
            require(tuple(p[k] for k in ('bytes','words_issued','words_returned','complete'))==(size,512,512,1),f'asset {kind} write {n}')
            require(cache(p['cache'],page),f'asset {kind} cache {n}')
            require(memory.stable(r['entry'],p['after'],3840000) and p['after']['cpu']['ticks']>=previous,f'asset {kind} CPU/time {n}')
            previous=p['after']['cpu']['ticks']
    require(r['final']['cpu']['ticks']>=previous,'final ordering')
    require(memory.disjoint(r['blob']+r['asset'][0]['offset'],r['asset'][0]['bytes'],r['blob']+r['asset'][1]['offset'],r['asset'][1]['bytes']),'source asset overlap')
    for n,s in enumerate(r['core']):
        require((s['pages'],s['hash_count'],s['hash_failed'],s['complete'],s['TPL'],s['smm'])==(57,5,0,1,4,0),f'Core {n} completion')
        require(s['hashes']==e['call'][4]['source'][1]['hashes'],f'Core {n} hashes')
        require(all(a['page']==e['core']+4096*k and a['raw']==(0xff00000000000b80|a['page']) and
                    a['issued']==a['returned']==1 for k,a in enumerate(s['AT'])),f'Core {n} AT')
    return dict(format='MSS_STAGE_RAW_V1',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                local_completion_consistent=not issues,issues=issues,physical_wifi_proven=False,
                source_mode='payload-tail' if transport else 'embedded',
                secure_ownership_proven=False,remote_started=False,record=r)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('raw',type=Path)
    p.add_argument('--memory',type=Path,required=True);p.add_argument('--early',type=Path,required=True)
    p.add_argument('--retained',type=Path,required=True);p.add_argument('--firmware-manifest',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=decode(a.raw.read_bytes(),a.memory.read_bytes(),a.early.read_bytes(),a.retained.read_bytes(),
                  json.loads(a.firmware_manifest.read_text()) if a.firmware_manifest else None)
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='record'}))


if __name__=='__main__':main()

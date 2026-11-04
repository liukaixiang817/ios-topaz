#!/usr/bin/env python3
"""Independent descriptor-free MSS_MBA_SHARE_RAW_V1 decoder.

The raw prefix contains expected descriptor bytes and returned events, never
the actual page that might still be inaccessible during an uncertain SMC.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec=importlib.util.spec_from_file_location('stage_codec',Path(__file__).with_name('polaris-mss-stage-codec.py'))
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
early=stage.early;Layout=early.Layout;fields=early.fields
TRANSITION=Layout(fields(8,'target_daif target_group daif_before group_before daif_read group_read')+
                  fields(4,'returned precondition_error daif_written daif_observed group_written group_observed'))
PEER=Layout(fields(8,'target raw')+fields(4,'issued returned'))
DEST=Layout(fields(4,'vmid permissions'))
SPEC=Layout(fields(8,'descriptor_pa region_pa region_bytes')+fields(4,'sources destinations')+
            [('source',4,3),('destination',DEST,3)])
REGS=Layout([('x',8,7)])
COMMAND=Layout([('page',8,1)]+fields(4,'sequence operation')+[('registers',REGS,1)])
EVENT=Layout([('command',COMMAND,1)]+fields(8,'before after')+fields(4,'issued returned return_raw reserved')+
             [('response',REGS,1),('cache',stage.CACHE,1)])
TRANSACTION=Layout(fields(8,'page opening last')+fields(4,'started unknown error pending step events rounds complete')+
                   [('spec',SPEC,1),('initial',REGS,1),('next',REGS,1),('expected',1,4096),('event',EVENT,6)])
PREFIX=Layout(fields(8,'stage base bytes')+[('stage_digest',1,32),('entry',early.ARCH,1),('masked',early.ARCH,1),
                ('assigned',early.ARCH,1),('restored',early.ARCH,1),('fp',early.FP,1),('mask',TRANSITION,1),('restore',TRANSITION,1),
                ('source',early.CORE,2),('descriptor_AT',early.TRANSLATION,1),('peer',PEER,14),('transaction',TRANSACTION,1),
                ('response',REGS,6),('cache',stage.CACHE,6),('step',early.ARCH,6)]+
              fields(4,'attempted unknown error mask_issued cpu_held assignment_issued assignment_returned_zero restore_issued complete reserved'),alignment=4096)
LAYOUTS=dict(pwrpc_transition=TRANSITION,pmsb_peer=PEER,pwma_destination=DEST,pwma_spec=SPEC,pwma_registers=REGS,
             pwmt_command=COMMAND,pwmt_event=EVENT,pwmt_transaction=TRANSACTION,pmsb_result=PREFIX)


def cpu(a,b,masked):
    return (stage.memory.admitted(a) and a['cpu']['sctlr']&5==5 and a['cpacr']==b['cpacr'] and
            all(a['cpu'][k]==b['cpu'][k] for k in a['cpu'] if k not in ('ticks','daif','group1')) and
            b['cpu']['daif']==(0xc0 if masked else 0) and b['cpu']['group1']==(0 if masked else 1) and
            0<=b['cpu']['ticks']-a['cpu']['ticks']<=3840000)


def transition(t,restore):
    return (tuple(t[k] for k in ('target_daif','target_group','daif_before','group_before','daif_read','group_read'))==
            ((0,1,0xc0,0,0,1) if restore else (0xc0,0,0,1,0xc0,0)) and
            t['precondition_error']==0 and all(t[k]==1 for k in ('returned','daif_written','daif_observed','group_written','group_observed')))


def decode(raw,sraw,mraw,eraw,hraw,firmware=None):
    if len(raw)!=PREFIX.size:raise ValueError(f'MSS_MBA_SHARE_RAW_V1 prefix needs exactly {PREFIX.size} bytes')
    r=PREFIX.decode(raw);s=stage.decode(sraw,mraw,eraw,hraw,firmware);e=early.NATIVE.decode(eraw);m=stage.memory.NATIVE.decode(mraw);issues=[]
    def require(ok,label):
        if not ok:issues.append(label)
    require(s['local_completion_consistent'],'actual staging completion');s=s['record']
    require(r['stage_digest']==hashlib.sha256(sraw).hexdigest(),'stage binding')
    require(tuple(r[k] for k in ('attempted','unknown','error','mask_issued','cpu_held','assignment_issued',
                                'assignment_returned_zero','restore_issued','complete','reserved'))==(1,0,0,1,0,1,1,1,1,0),'native completion')
    require(r['base']==m['memory']['claim'][1]['requested'] and r['bytes']==0x100000,'actual staged MBA extent')
    require(stage.memory.stable(s['final'],r['entry']) and cpu(r['entry'],r['masked'],True) and
            cpu(r['entry'],r['assigned'],True) and cpu(r['entry'],r['restored'],False),'CPU/time envelope')
    require(transition(r['mask'],False) and transition(r['restore'],True),'CPU mask/restore')
    require(r['fp']['saved']==r['fp']['restored']==1 and r['fp']['cpacr_before']==r['entry']['cpacr'],'FP restore')
    for n,p in enumerate(r['peer']):
        require((p['target'],p['raw'],p['issued'],p['returned'])==(0x100*(n%7+1),1,1,1),f'peer {n}')
    t=r['transaction'];q=t['spec'];page=t['page']
    require(page and page%4096==0 and stage.translation(r['descriptor_AT'],page),'descriptor translation')
    require(tuple(t[k] for k in ('started','unknown','error','pending','step','complete'))==(1,0,0,0,4,1) and
            1<=t['rounds']<=4 and t['events']==t['rounds']+2,'transaction completion')
    require(q==dict(descriptor_pa=page,region_pa=r['base'],region_bytes=0x100000,sources=1,destinations=1,
                    source=[3,0,0],destination=[dict(vmid=15,permissions=6),dict(vmid=0,permissions=0),dict(vmid=0,permissions=0)]),'exact MP_ASSIGN spec')
    expected=bytearray(4096);struct.pack_into('<I',expected,0,3);struct.pack_into('<QQ',expected,64,r['base'],0x100000)
    struct.pack_into('<II',expected,128,15,6);struct.pack_into('<QQQ',expected,256,4,page+128,24)
    require(t['expected']==expected.hex(),'encoded descriptor expectation')
    initial=dict(x=[0x42000c16,0x1117,page+64,16,page,page+256,0]);require(t['initial']==initial,'initial secure registers')
    previous=t['opening'];next_regs=initial;rounds=0
    require(r['masked']['cpu']['ticks']<=t['opening']<=t['last']<=r['assigned']['cpu']['ticks'] and
            t['last']-t['opening']<=1920000,'secure operation timing')
    for n,event in enumerate(t['event']):
        if n>=min(t['events'],6):
            require(event==EVENT.decode(bytes(EVENT.size)) and r['response'][n]==REGS.decode(bytes(REGS.size)) and
                    r['cache'][n]==stage.CACHE.decode(bytes(stage.CACHE.size)) and r['step'][n]==early.ARCH.decode(bytes(early.ARCH.size)),f'unused event {n}')
            continue
        op=1 if n==0 else 3 if n==t['events']-1 else 2;c=event['command']
        require((c['page'],c['sequence'],c['operation'])==(page,n+1,op),f'event {n} command')
        require(tuple(event[k] for k in ('issued','returned','return_raw','reserved'))==(1,1,1,0) and
                previous<=event['before']<=event['after']<=t['last'] and cpu(r['entry'],r['step'][n],True) and
                event['after']==r['step'][n]['cpu']['ticks'],f'event {n} completion/time')
        previous=event['after']
        if op==2:
            require(c['registers']==next_regs and event['response']==r['response'][n],f'event {n} same-request continuation')
            response=event['response']['x'];rounds+=1
            if n==t['events']-2:require(response[0]==response[1]==0,f'event {n} returned zero')
            else:require(response[0]==1,f'event {n} interrupted');next_regs=event['response']
            require(event['cache']==stage.CACHE.decode(bytes(stage.CACHE.size)) and r['cache'][n]==event['cache'],f'event {n} no cache callback')
        else:
            cache=event['cache'];require(cache==r['cache'][n] and cache['operation']==(1 if op==1 else 2) and
                stage.cache(dict(cache,operation=1),page),f'event {n} descriptor cache')
            require(c['registers']==REGS.decode(bytes(REGS.size)) and event['response']==REGS.decode(bytes(REGS.size)) and
                    r['response'][n]==event['response'],f'event {n} no secure callback')
    require(rounds==t['rounds'] and t['next']==next_regs,'secure round/continuation count')
    for n,c in enumerate(r['source']):
        require((c['pages'],c['hash_count'],c['hash_failed'],c['complete'],c['TPL'],c['smm'])==(57,5,0,1,4,0),f'Core {n} completion')
        require(c['hashes']==e['call'][4]['source'][1]['hashes'],f'Core {n} hashes')
        require(all(a['page']==e['core']+4096*k and a['raw']==(0xff00000000000b80|a['page']) and
                    a['issued']==a['returned']==1 for k,a in enumerate(c['AT'])),f'Core {n} AT')
    return dict(format='MSS_MBA_SHARE_RAW_V1',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                local_completion_consistent=not issues,issues=issues,descriptor_page_exported=False,
                physical_wifi_proven=False,DMA_retirement_proven=False,remote_started=False,record=r)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('raw',type=Path)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--firmware-manifest',type=Path);a=p.parse_args()
    result=decode(a.raw.read_bytes(),*[Path(str(a.raw)+suffix).read_bytes() for suffix in ('.stage','.memory','.early','.retained')],
                  firmware=json.loads(a.firmware_manifest.read_text()) if a.firmware_manifest else None)
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='record'}))


if __name__=='__main__':main()

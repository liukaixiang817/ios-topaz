"""Strict runtime RAM-history pages / WLR3 receipt decoder.

No USB/device command, reset authority, PMIC or persistence API. Structural
correspondence is not optical evidence or physical-image admission.
"""
import struct
import zlib

HEADER=80
RECORD=struct.Struct('<QQBBBBQ')
LIMIT=8192


def page(data):
    if type(data) is not bytes or not 112<=len(data)<=980:
        raise ValueError('runtime page length/type')
    if data[:8]!=b'WLRPAGE3' or zlib.crc32(data[:-4])!=struct.unpack_from('<I',data,len(data)-4)[0]:
        raise ValueError('runtime page magic/CRC')
    cookie,snapshot,total,offset=struct.unpack_from('<QIII',data,8)
    count,size=struct.unpack_from('<HH',data,28)
    if not cookie or not snapshot or not 1<=total<=LIMIT or offset%32 or offset>=total or \
       count!=min(32,total-offset) or size!=28 or len(data)!=HEADER+count*28+4:
        raise ValueError('runtime page geometry')
    if any(data[77:80]) or data[72] not in (0,128) or data[73] not in (0,2) or data[74]&~31:
        raise ValueError('runtime page reserved/context')
    error,firmware_error,runtime_error,issued,completed=struct.unpack_from('<IIIII',data,36)
    request,ack=struct.unpack_from('<QQ',data,56)
    if completed>issued or ack>request:
        raise ValueError('runtime page command counters')
    raw=data[HEADER:-4]
    records=[dict(zip(('began_us','ended_us','fault','rt','valid','expected','sequence'),row))
             for row in RECORD.iter_unpack(raw)]
    for r in records:
        if r['valid'] not in (0,1,3) or r['expected'] not in (0,2,128,130) or r['sequence']>request or \
           (not r['valid'] and (r['fault'] or r['rt'])) or (r['valid']==1 and r['rt']):
            raise ValueError('runtime raw-record encoding')
    return dict(cookie=cookie,snapshot=snapshot,total=total,offset=offset,count=count,
        prefix_crc=struct.unpack_from('<I',data,32)[0],error=error,firmware_error=firmware_error,
        runtime_error=runtime_error,issued=issued,completed=completed,request=request,ack=ack,
        module=data[72],irq=data[73],flags=data[74],fault_or=data[75],rt_or=data[76],
        records=records,raw=raw,identity=data[:24]+data[30:80])


def journal(pages):
    if type(pages) is not list or not 1<=len(pages)<=256:
        raise ValueError('bounded runtime page list required')
    decoded=[page(p) for p in pages]
    first=decoded[0];count=0;records=[];raw=[]
    for p in decoded:
        if p['identity']!=first['identity'] or p['offset']!=count:
            raise ValueError('foreign snapshot, missing/reordered/duplicate page')
        count+=p['count'];records+=p['records'];raw.append(p['raw'])
    if count!=first['total'] or zlib.crc32(b''.join(raw))!=first['prefix_crc']:
        raise ValueError('incomplete history/prefix CRC')
    fault_or=rt_or=0;previous=sequence=0;observations_valid=True
    for r in records:
        if r['valid']&1:fault_or|=r['fault']
        if r['valid']&2:rt_or|=r['rt']
        if r['sequence']<sequence:raise ValueError('raw sequence regressed')
        sequence=r['sequence']
        valid=(r['valid']==3 and r['began_us']>0 and r['began_us']>=previous and
               r['ended_us']>r['began_us'] and r['ended_us']-r['began_us']<=200000 and
               not ((r['fault']|r['rt'])&~1))
        observations_valid=observations_valid and valid
        previous=r['ended_us']
    if fault_or!=first['fault_or'] or rt_or!=first['rt_or']:
        raise ValueError('cumulative raw status omitted/replaced')
    # Each full hardware verification contributes two observations under one
    # expected module/IRQ state and request. Per-record validity alone cannot
    # prove a complete pair, especially after a missing/relabelled record.
    pairs_valid=len(records)%2==0
    for at in range(0,len(records)-1,2):
        a,b=records[at:at+2]
        pairs_valid=pairs_valid and a['expected']==b['expected'] and \
            a['sequence']==b['sequence'] and b['ended_us']>=a['began_us'] and \
            b['ended_us']-a['began_us']<=200000
    observations_valid=observations_valid and pairs_valid
    failed=bool(first['error'] or first['firmware_error'] or first['runtime_error'])
    if not failed and not observations_valid:
        raise ValueError('invalid observation in purported success')
    return {k:v for k,v in first.items() if k not in ('records','raw','identity')} | dict(
        records=records,observations_valid=observations_valid,failed=failed,
        analysis_passed=True,physical_admission=False,optical_off_proven=False)


def receipt(data,j,*,cookie,native_cookie,native_sequence,mode):
    if type(data) is not bytes or len(data)!=60 or data[:4]!=b'WLR3':
        raise ValueError('runtime receipt framing')
    if struct.unpack_from('<I',data,56)[0]!=1 or \
       zlib.crc32(data[:52]+data[56:])!=struct.unpack_from('<I',data,52)[0]:
        raise ValueError('runtime receipt version/CRC')
    actual_cookie,actual_native=struct.unpack_from('<QQ',data,4)
    actual_mode,seq,count,first,last,history_crc=struct.unpack_from('<IIIIII',data,20)
    request=struct.unpack_from('<Q',data,44)[0]
    if not cookie or not native_cookie or not native_sequence or mode not in (1,2) or \
       actual_cookie!=cookie or actual_native!=native_cookie or actual_mode!=mode or \
       seq!=native_sequence or j['cookie']!=cookie or count!=j['total'] or count!=last or \
       first+2!=last or first<4 or history_crc!=j['prefix_crc'] or request!=j['request']:
        raise ValueError('foreign session/native drain/history receipt')
    if j['failed'] or not j['observations_valid'] or j['flags']!=27 or j['module']!=128 or j['irq']!=2 or \
       j['issued']!=j['completed'] or j['issued']!=j['request']*2 or j['request']!=j['ack']:
        raise ValueError('runtime did not restore/seal')
    for r in j['records'][-4:]:
        if r['expected']!=130 or r['valid']!=3 or r['sequence']!=request or ((r['fault']|r['rt'])&~1):
            raise ValueError('terminal readbacks missing/not restored')
    return dict(cookie=cookie,native_cookie=native_cookie,native_sequence=native_sequence,mode=mode,
        records=count,first=first,last=last,history_crc=history_crc,request=request,
        restoration_consistent=True,physical_admission=False,optical_off_proven=False,
        firmware_age_guard_source_required=True)


def zero_write_receipt(data,*,cookie=None):
    """WLZ4 is pre-CPU/pre-WRITE refusal recovery, never native restoration."""
    if type(data) is not bytes or len(data)!=40 or data[:4]!=b'WLZ4' or \
       zlib.crc32(data[:36])!=struct.unpack_from('<I',data,36)[0]:
        raise ValueError('native zero-write receipt framing/CRC')
    mode=struct.unpack_from('<I',data,4)[0]
    session,observed=struct.unpack_from('<QQ',data,8)
    error,runtime_error,flags=struct.unpack_from('<III',data,24)
    if mode!=2 or not session or not observed or flags or (cookie is not None and cookie!=session):
        raise ValueError('native zero-write receipt scope/session')
    return dict(cookie=session,observed_us=observed,error=error,runtime_error=runtime_error,
                mode=mode,CPU_ON_issued=False,AP_stage=0,issued=0,completed=0,uncertain=False,
                native_drain_proven=False,WLED_restoration_proven=False)


def _extend_actual(j,fields,records):
    """Append actual raw fields only; no synthesized clock/status observation."""
    before=b''.join(RECORD.pack(*(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected','sequence')))
                    for r in j['records'])
    if len(j['records'])!=j['total'] or zlib.crc32(before)!=j['prefix_crc']:
        raise ValueError('changed captured prefix')
    all_records=j['records']+records
    raw=b''.join(RECORD.pack(*(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected','sequence')))
                 for r in all_records)
    if len(all_records)!=fields['total'] or fields['total']>LIMIT or zlib.crc32(raw)!=fields['prefix_crc']:
        raise ValueError('terminal full raw-history CRC/count')
    previous=sequence=fault=rt=0
    for i,r in enumerate(all_records):
        if (r['valid']!=3 or r['expected'] not in (0,2,128,130) or
            (r['fault']|r['rt'])&~1 or r['began_us']<=0 or r['began_us']<previous or
            not r['began_us']<r['ended_us']<=r['began_us']+200000 or
            not sequence<=r['sequence']<=fields['request']):
            raise ValueError('terminal invalid/serious/partial raw observation')
        if i&1:
            a=all_records[i-1]
            if (a['sequence']!=r['sequence'] or a['expected']!=r['expected'] or
                r['ended_us']-a['began_us']>200000):raise ValueError('terminal incomplete raw pair')
        previous=r['ended_us'];sequence=r['sequence'];fault|=r['fault'];rt|=r['rt']
    if len(all_records)%2 or (fault,rt)!=(fields['fault_or'],fields['rt_or']):
        raise ValueError('terminal lifetime status omitted')
    return dict(fields,records=all_records,observations_valid=True,failed=False,analysis_passed=True,
                physical_admission=False,optical_off_proven=False)


def exit_footer(data,prefix,*,native_cookie,native_sequence,recover=False):
    if (type(data) is not bytes or len(data) not in (100,212) or data[:8]!=b'WLEXIT05' or
        zlib.crc32(data[:-4])!=struct.unpack_from('<I',data,len(data)-4)[0]):
        raise ValueError('atomic exit footer framing/CRC')
    cookie,snapshot,total,offset=struct.unpack_from('<QIII',data,8)
    count,size=struct.unpack_from('<HH',data,28)
    nc,ns,mode=struct.unpack_from('<QII',data,80)
    if (type(recover) is not bool or not cookie or cookie!=prefix['cookie'] or not snapshot or
        snapshot<=prefix['snapshot'] or count!=(0 if recover else 4) or size!=28 or
        offset!=prefix['total'] or total!=offset+count or len(data)!=100+count*28 or
        not native_cookie or not native_sequence or (nc,ns,mode)!=(native_cookie,native_sequence,2)):
        raise ValueError('foreign/stale prefix or native drain token')
    if (prefix['failed'] or not prefix['observations_valid'] or prefix['flags']!=(27 if recover else 11) or
        any(data[36:48]) or any(data[77:80]) or data[72:75]!=bytes([128,2,27])):
        raise ValueError('native WLED not restored/drained')
    issued,completed=struct.unpack_from('<II',data,48);request,ack=struct.unpack_from('<QQ',data,56)
    if (issued!=completed or issued!=request*2 or request!=ack or
        any(prefix[k]!=v for k,v in zip(('issued','completed','request','ack'),(issued,completed,request,ack)))):
        raise ValueError('terminal command history changed')
    fields={k:v for k,v in prefix.items() if k!='records'}
    fields.update(snapshot=snapshot,total=total,offset=0,count=min(32,total),
                  prefix_crc=struct.unpack_from('<I',data,32)[0],flags=27,fault_or=data[75],rt_or=data[76])
    records=[dict(zip(('began_us','ended_us','fault','rt','valid','expected','sequence'),r))
             for r in RECORD.iter_unpack(data[96:-4])]
    for r in records:
        if r['expected']!=130 or r['sequence']!=request:raise ValueError('terminal saved-state readbacks absent')
    return _extend_actual(prefix,fields,records)


def exit_receipt(data,sealed):
    if type(data) is not bytes or len(data)!=60 or data[:4]!=b'WLR5':
        raise ValueError('atomic exit final receipt framing')
    cookie,count,crc=struct.unpack_from('<QII',data,4)
    if cookie!=sealed['cookie'] or count!=sealed['total']+2:
        raise ValueError('atomic exit foreign or replayed receipt')
    records=[]
    for at in (20,40):
        began,ended,fault,rt,valid,expected=struct.unpack_from('<QQBBBB',data,at)
        if expected!=130:raise ValueError('fresh pair did not restore original WLED state')
        records.append(dict(began_us=began,ended_us=ended,fault=fault,rt=rt,valid=valid,
                            expected=expected,sequence=sealed['request']))
    fields={k:v for k,v in sealed.items() if k!='records'}
    fields.update(total=count,prefix_crc=crc,fault_or=sealed['fault_or']|records[0]['fault']|records[1]['fault'],
                  rt_or=sealed['rt_or']|records[0]['rt']|records[1]['rt'])
    return _extend_actual(sealed,fields,records)

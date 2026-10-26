"""Parse a bounded, read-only snapshot of the original EFI boot variables."""
import hashlib
import struct
import uuid


def load_option(data):
    if not isinstance(data,(bytes,bytearray)) or not 8<=len(data)<=4096:raise ValueError('invalid EFI load option size')
    data=bytes(data)
    attributes,path_bytes=struct.unpack_from('<IH',data)
    end=6
    while end+2<=len(data) and data[end:end+2]!=b'\0\0':end+=2
    if end+2>len(data):raise ValueError('unterminated load-option description')
    description=data[6:end].decode('utf-16-le');start=end+2;stop=start+path_bytes
    if not path_bytes or stop>len(data):raise ValueError('load-option path outside variable')
    nodes=[];at=start;finished=False
    while at<stop:
        if at+4>stop or len(nodes)>=256:raise ValueError('invalid device path')
        kind,subtype,size=struct.unpack_from('<BBH',data,at)
        if size<4 or size>stop-at:raise ValueError('invalid device-path node length')
        body=data[at:at+size];node=dict(type=kind,subtype=subtype,bytes=size,offset=at-start)
        if (kind,subtype)==(4,1) and size==42:
            partition,first,blocks=struct.unpack_from('<IQQ',body,4)
            node.update(partition=partition,first_LBA=first,blocks=blocks,MBR_type=body[40],signature_type=body[41])
            if body[40:42]==b'\x02\x02':node['GPT_partition_GUID']=str(uuid.UUID(bytes_le=body[24:40]))
        elif (kind,subtype)==(4,4):
            if size<6 or (size-4)%2 or body[-2:]!=b'\0\0':raise ValueError('invalid EFI file path')
            path=body[4:-2].decode('utf-16-le')
            if '\0' in path:raise ValueError('embedded NUL in EFI file path')
            node['file_path']=path
        if kind==0x7f:
            if size!=4 or subtype not in (1,0xff):raise ValueError('invalid device-path end')
            if subtype==0xff:
                if at+size!=stop:raise ValueError('data after device-path end')
                finished=True
        nodes.append(node);at+=size
    if not finished:raise ValueError('device path has no final end node')
    return dict(description=description,attributes=attributes,path_bytes=path_bytes,
                path_offset=start,nodes=nodes,optional_data_bytes=len(data)-stop)


def parse_snapshot(raw):
    if not isinstance(raw,(bytes,bytearray)) or not 32<=len(raw)<=65536 or raw[:8]!=b'PEFIBV01':raise ValueError('invalid boot-variable snapshot')
    raw=bytes(raw)
    version,count,size,complete=struct.unpack_from('<IIQQ',raw,8)
    if version!=1 or not 1<=count<=67 or size!=len(raw) or complete not in (0,1):raise ValueError('invalid snapshot header')
    at=32;rows=[];seen=set();order=None
    for _ in range(count):
        if at+32>len(raw):raise ValueError('truncated variable header')
        ident,attrs,status,length,needed=struct.unpack_from('<IIQQQ',raw,at);at+=32
        if ident>0x10002 or ident in seen or length>4096 or length>len(raw)-at:raise ValueError('invalid variable record')
        if status and length:raise ValueError('failed variable read contains data')
        if not status and length!=needed:raise ValueError('variable size mismatch')
        if complete and status not in (0,0x800000000000000e):raise ValueError('complete snapshot contains read failure')
        seen.add(ident);data=raw[at:at+length];name={0x10000:'BootOrder',0x10001:'BootCurrent',0x10002:'BootNext'}.get(ident,f'Boot{ident:04X}')
        row=dict(id=ident,name=name,attributes=attrs,status=f'0x{status:016x}',bytes=length,reported_bytes=needed,
                 data_offset=at,sha256=hashlib.sha256(data).hexdigest())
        if not status:
            if ident==0x10000:
                if not length or length>128 or length%2:raise ValueError('invalid BootOrder')
                order=list(struct.unpack('<'+'H'*(length//2),data));row['order']=order
            elif ident in (0x10001,0x10002):
                if length!=2:raise ValueError('invalid boot selection variable')
                row['option']=struct.unpack('<H',data)[0]
            else:
                try:row['load_option']=load_option(data)
                except (ValueError,UnicodeError) as error:row['load_option_error']=str(error)
        padded=(length+7)&~7
        if at+padded>len(raw) or any(raw[at+length:at+padded]):raise ValueError('invalid variable padding')
        at+=padded;rows.append(row)
    if at!=len(raw):raise ValueError('trailing snapshot data')
    if complete and (order is None or not {0x10000,0x10001,0x10002}.issubset(seen) or not set(order).issubset(seen)):
        raise ValueError('missing referenced boot variables')
    return dict(complete=bool(complete),version=version,records=rows,bytes=len(raw),
                snapshot_sha256=hashlib.sha256(raw).hexdigest(),read_only=True,UEFI_variable_writes=False)

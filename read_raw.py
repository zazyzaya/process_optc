from collections import defaultdict
import gzip
import glob
import json
from math import ceil
from multiprocessing import Manager, Pool, Lock
import os
import random 

from dateutil import parser
from joblib import Parallel, delayed
import pickle
from tqdm import tqdm

RAW_OPTC = '/mnt/raid1_ssd_4tb/datasets/OpTC/ecar/'
TRAIN = 'benign_gz/'
TEST = 'eval_gz/'
SPLIT = 'flow_split/'

# From checking the first/last line of each file
FIRST_TS = 1568676405.62800
LAST_TS  = 1569436694.309
F_DELTA = 100 # Num snapshots per file
SNAPSHOT_SIZE = 60*60 # seconds
MAX_BUFFER = 2**16 # Max lines workers store before flushing out

get_ts = lambda x : parser.parse(x).timestamp()
get_snapshot = lambda x : (x - FIRST_TS) // SNAPSHOT_SIZE
def host_to_idx(x):
    # Workstation
    if len(x) > 5:
        return int(x[9:13])
    # Domain controller
    else:
        return 1000 + int(x[2:])

def label_line(src,dst,ts):
    return 0 # TODO


def ignore(ip):
    if ip is None: 
        return True 
    
    if (
        ip.startswith('ff') or # Multicast
        ip.endswith('255') or  # Broadcast
        ip.endswith('1')       # Gateway
    ):
        return True

    if ':' in ip:
        return False

    # A hostname slipped in
    if ip.startswith('S') or ip.startswith('DC'):
        return False

    # Check for multicast (224.0.0.0 - 239.255.255.255)
    first_octet = int(ip.split('.')[0])
    if first_octet >= 224 and first_octet <= 239:
        return True

    return False


def default_map():
    # Hosts in the 142.20 network are named based on their IPs
    # 142.20.56.2 == Host 1
    # 142.20.56.254 == Host 253 (.255 is skipped as it's broadcast addr, so Host 254 DNE)
    # 142.20.57.0 == Host 255
    # 142.20.57.254 == Host 509
    # 142.20.58.0 == Host 511, etc.
    ip_map = defaultdict(set)
    upper = '142.20'

    for i in range(976):
        host = f'SysClient{i:04d}.systemia.com'
        lower = (i+1) % 256

        if lower == 255:
            continue # Skip broadcast addr

        mid = 56 + ((i+1)//256)
        ip = f'{upper}.{mid}.{lower}'

        ip_map[ip].add(host)

    #ip_map['142.20.61.130'].add('DC1')

    # The 10.50 subnet also seems to be ordered in a similar way 
    # 10.50.0.102 == Host 2 
    # 10.50.0.244 == Host 144 (highest in the 10.50.0 observed)
    # 10.50.1.2 = Host 152 (lowest in 10.50.1 range observed)
    # 10.50.1.250 == Host 400 
    # 10.50.2.2 == 402
    # 10.50.2.225 = 625
    # 10.50.3.2 = 652
    # Seems like pattern is 0 - 250, then increase 3rd octet 
    upper = '10.50'
    for i in range(976): 
        host = f'SysClient{i:04d}.systemia.com'
        lower = (100 + i) % 250 
        mid = (100 + i) // 250
        ip = f'{upper}.{mid}.{lower}'

        ip_map[ip].add(host)

    # 10.20 has similar pattern 
    # 10.20.3.179 = Host 1 
    # 10.20.3.254 = Host 74
    # Pattern doesn't work here... 
    # 10.20.4.29 = Host 101 (skip .255 and .0?)
    # 10.20.4.254 = Host 318
    # 10.20.5.2 = Host 320 (.1 would be 319?)
    # 10.20.5.254 = 562
    # 10.20.6.2 = Host 564 (.1 would be 563?)
    # 10.20.6.254 = Host 806
    # 10.20.7.2 = 808
    # Pattern breaks here too? 
    # 10.20.7.175 = 975

    return ip_map

def build_map(in_f, i, tot):
    ip_map = defaultdict(set)
    f = gzip.open(in_f)

    line = f.readline()
    prog = tqdm(desc='%d/%d' % (i+1, tot))

    cnt = 0
    while line: # and cnt < 100000:
        datum = json.loads(line)

        if datum['object'] == 'FLOW':
            props = datum['properties']
            src_ip = props.get('src_ip')
            dst_ip = props.get('dst_ip')
            ip = dst_ip if props['direction'] == 'inbound' else src_ip

            if not ignore(ip): # and ip.startswith('142')
                host = datum['hostname']
                ip_map[ip].add(host)
                
            cnt += 1

        line = f.readline()
        prog.update()

    prog.close()
    return ip_map

def build_maps(out_f='flow_split/nmap.pkl'):
    files = glob.glob(RAW_OPTC+'/**/**/*.gz')
    print(len(files))

    maps = Parallel(n_jobs=128, prefer='processes')(
        delayed(build_map)(f,i,len(files)) for i,f in enumerate(files)
    )

    node_map = default_map()
    for m in maps: 
        for k,v in m.items():
            node_map[k] = node_map[k].union(v)

    with open('uncompressed.pkl', 'wb+') as f:
        pickle.dump(node_map, f)

    out_map = dict()
    for k,v in node_map.items(): 
        if len(v) == 1: 
            out_map[k] = v.pop()

    with open(out_f, 'wb+') as f:
        pickle.dump(out_map, f)


def split_all(nmap_f, fold=TRAIN):
    files = glob.glob(RAW_OPTC+fold+'**/*.gz')
    
    # So processes aren't all touching the same files at the same time 
    random.shuffle(files)
    
    print(len(files))
    print(files[0])

    # Split into smaller files
    with open(nmap_f, 'rb') as f:
        node_map = pickle.load(f)

    # Fill in hosts we can infer from IP addr
    dm = default_map()
    for k,v in dm.items(): 
        if k not in node_map: 
            node_map[k] = v.pop()

    with Manager() as manager:
        p = Pool(processes=64)
        lock = manager.Lock()

        #f = '/mnt/raid1_ssd_4tb/datasets/OpTC/ecar/eval_gz/23Sep19/AIA-201-225.ecar-last.json.gz'
        #copy_one(f, node_map, lock, 1, len(files))

        # Start all jobs
        tasks = [
            p.apply_async(copy_one, (f, node_map, lock, i, len(files)))
            for i,f in enumerate(files)
        ]
        print("Queued %d jobs" % len(tasks))

        for i,t in enumerate(tasks):
            t.wait()
            print("Finished (%d/%d)" % (i+1, len(tasks)))

        p.close()
        p.join()


def copy_one_nethawk(in_f, node_map, lock, i, tot):
    '''
    Build NetHawk-style graph of
        Flow: usr -[port]-> host
        File: usr -[extension]-> host
        Proc: usr -[filename]-> host
    '''
    in_f = gzip.open(in_f)

    line = in_f.readline()
    prog = tqdm(desc='%d/%d' % (i+1, tot))

    buffer = {
        'FLOW': None,
        'FILE': None,
        'PROCESS': None
    }
    io_buffer = defaultdict(str)
    buffer_contents = 0
    while line:
        datum = json.loads(line)

        if datum['object'] == 'FLOW':
            props = datum['properties']
            host = datum['hostname']
            usr = datum['principal'].split('\\')[-1].lower()

            # Edge features
            size = props.get('size', 0)
            img = props.get('image_path', '').split("\\")[-1]
            st = props.get('start_time', -1)
            en = props.get('end_time', -1)
            src_port = props.get('src_port','')
            dst_port = props.get('dest_port','')
            direction = props.get('direction')

            # Only log if we can attribute src and dst hosts
            if usr.lower() not in ['system','network service','local service','']:
                ts = get_ts(datum['timestamp'])
                if direction == 'inbound':
                    port = src_port
                else:
                    port = dst_port

                snapshot = get_snapshot(ts)

                # Avoid repeats from repeated requests
                if (usr,host,img) == buffer['FLOW']:
                    line = in_f.readline()
                    prog.update()
                    continue
                else:
                    buffer['FLOW'] = (usr,host,img)

                io_buffer[snapshot] += f'{ts},FLOW,{datum["action"]},{usr},{host},{img},{size},{port}\n'
                buffer_contents += 1

        elif datum['object'] == 'FILE':
            props = datum['properties']
            host = datum['hostname']
            usr = datum['principal'].split('\\')[-1].lower()

            if usr.lower() not in ['system','network service','local service','']:
                ts = get_ts(datum['timestamp'])
                snapshot = get_snapshot(ts)

                ftype = props.get('file_path')
                img = props.get('image_path')

                # Avoid repeats from repeated requests
                if (usr,host,img) == buffer['FILE']:
                    line = in_f.readline()
                    prog.update()
                    continue
                else:
                    buffer['FILE'] = (usr,host,img)

                if ftype and img:
                    ftype = ftype.split('.')[-1].lower()
                    img = img.split('\\')[-1].lower()
                    io_buffer[snapshot] += f'{ts},FILE,{datum["action"]},{usr},{host},{img},{ftype}\n'
                    buffer_contents += 1

        elif datum['object'] == 'PROCESS':
            props = datum['properties']
            host = datum['hostname']
            usr = datum['principal'].split('\\')[-1].lower()

            if usr.lower() not in ['system','network service','local service','']:
                ts = get_ts(datum['timestamp'])
                snapshot = get_snapshot(ts)

                img = props.get('image_path')
                # Avoid repeats from repeated requests
                if (usr,host,img) == buffer['PROCESS']:
                    line = in_f.readline()
                    prog.update()
                    continue
                else:
                    buffer['PROCESS'] = (usr,host,img)

                if img:
                    img = img.split('\\')[-1].lower()
                    io_buffer[snapshot] += f'{ts},PROCESS,{datum["action"]},{usr},{host},{img}\n'
                    buffer_contents += 1


        # Try to minimize syncrhonization
        prog.update()
        if buffer_contents > MAX_BUFFER:
            for f_num,out_str in io_buffer.items():
                fname = SPLIT+str(int(f_num)) + '.csv'

                with lock:
                    out_f = open(fname, 'a+')
                    out_f.write(out_str)
                    out_f.close()

            # Empty buffer
            io_buffer = defaultdict(str)
            buffer_contents = 0

        line = in_f.readline()
        prog.update()

    # Write before returning regardless of buffer len
    for f_num,out_str in io_buffer.items():
        fname = SPLIT+str(int(f_num)) + '.csv'

        with lock:
            out_f = open(fname, 'a+')
            out_f.write(out_str)
            out_f.close()

    prog.close()

def copy_one(in_f, node_map, lock, i, tot):
    in_f = gzip.open(in_f)

    line = in_f.readline()
    prog = tqdm(desc='%d/%d' % (i+1, tot))

    buffer = None
    io_buffer = defaultdict(str)
    buffer_contents = 0
    
    # Only care about internal traffic 
    ignore = [443, 80]
    while line:
        datum = json.loads(line)

        if datum['object'] == 'FLOW' and datum['action'] == 'START':
            props = datum['properties']

            # Edge features
            src_port = int(props.get('src_port',9999))
            dst_port = int(props.get('dest_port',9999))
            is_tcp = props.get('l4protocol') == '6'

            if (not is_tcp) or (src_port > 1024 and dst_port > 1024) or (src_port in ignore or dst_port in ignore): 
                line = in_f.readline()
                prog.update()
                continue 

            src_ip = props['src_ip']
            dst_ip = props['dest_ip']
            host = datum['hostname']

            usr = datum['principal'].split('\\')[-1]

            def check_hostname(ip): 
                host = node_map.get(ip)
                if host is None: 
                    return ip 
                
                return host 

            if props['direction'] == 'inbound':
                src = check_hostname(src_ip)
                dst = host
            elif props['direction'] == 'outbound':
                src = host
                dst = check_hostname(dst_ip)

            # Only log if we can attribute src and dst hosts
            if src and dst: 
                ts = get_ts(datum['timestamp'])

                #src = host_to_idx(src)
                #dst = host_to_idx(dst)
                snapshot = get_snapshot(ts)

                io_buffer[snapshot] += f'{ts},{src},{src_port},{dst},{dst_port},{usr}\n'
                buffer_contents += 1

                # Try to minimize syncrhonization
                if buffer_contents > MAX_BUFFER:
                    for f_num,out_str in io_buffer.items():
                        fname = SPLIT+str(int(f_num)) + '.csv'

                        with lock:
                            out_f = open(fname, 'a+')
                            out_f.write(out_str)
                            out_f.close()

                    # Empty buffer
                    io_buffer = defaultdict(str)
                    buffer_contents = 0

        line = in_f.readline()
        prog.update()

    # Write before returning regardless of buffer len
    for f_num,out_str in io_buffer.items():
        fname = SPLIT+str(int(f_num)) + '.csv'

        with lock:
            out_f = open(fname, 'a+')
            out_f.write(out_str)
            out_f.close()

    prog.close()

def compress(): 
    def compress_one(fid): 
        try: 
            in_f = open(f'flow_split/{fid}.csv', 'r') 
        except FileNotFoundError: 
            return 
        
        line = in_f.readline()

        uq = set()
        while line: 
            _,src,sp,dst,dp,_ = line.split(',')
            if int(sp) > int(dp): 
                uq.add((src,dp,dst))
            else: 
                uq.add((dst,sp,src))

            line = in_f.readline() 

        in_f.close()

        out_f = open(f'flow_split_uq/{fid}.csv', 'w+')
        for (src,port,dst) in uq: 
            out_f.write(f'{src},{port},{dst}\n')
        out_f.close()

    Parallel(n_jobs=64, prefer='processes')(
        delayed(compress_one)(i) for i in tqdm(range(158))
    )

if __name__ == '__main__':
    #build_maps()
    #build_maps(fold=TEST)
    #split_all('flow_split/nmap.pkl')
    compress()

    '''
    # Testing
    with open('flow_split/nmap.pkl', 'rb') as f:
        node_map = pickle.load(f)

    copy_one(
        '/home/ead/datasets/OpTC/ecar/benign_gz/17-18Sep19/AIA-51-75.ecar-last.json.gz',
        node_map, Lock(), 0,1
    )
    '''
#!/usr/bin/env python3
"""Finite private byte transport. stdout is exclusively framed opaque bytes."""
import argparse
import errno
import os
import selectors
import socket
import struct
import subprocess
import sys
import time

HEADER=struct.Struct('!BII')
OPEN,DATA,CLOSE=1,2,3
PAYLOAD=65536
STREAMS=16
QUEUED=1024*1024


def append_bounded(queue,data,current_total):
    if current_total+len(data)>QUEUED:raise ValueError('queued byte capacity')
    queue.extend(data)


def close_write(sock):
    try:sock.shutdown(socket.SHUT_WR)
    except OSError as error:
        if error.errno!=errno.ENOTCONN:raise


def relay(mode,read_fd,write_fd,listen_port,target_port,lifetime):
    """CLOSE is a write-half EOF; retire only when both halves have drained."""
    streams={};incoming=bytearray();outgoing=bytearray();next_id=1
    listener=None;end=time.monotonic()+lifetime
    os.set_blocking(read_fd,False);os.set_blocking(write_fd,False)
    def queued():return len(incoming)+len(outgoing)+sum(len(s['queue']) for s in streams.values())
    def frame(kind,ident,body=b''):
        append_bounded(outgoing,HEADER.pack(kind,ident,len(body))+body,queued())
    def add(ident,sock):
        if ident==0 or ident in streams or len(streams)>=STREAMS:
            sock.close();raise ValueError('stream capacity or identity')
        sock.setblocking(False)
        streams[ident]={'socket':sock,'queue':bytearray(),'read_eof':False,
                        'peer_eof':False,'write_eof':False}
    try:
        if mode=='remote':
            listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',listen_port));listener.listen(STREAMS);listener.setblocking(False)
        while time.monotonic()<end:
            if len(incoming)+len(outgoing)+sum(len(s['queue']) for s in streams.values())>QUEUED:
                raise ValueError('queued byte capacity')
            for ident,s in list(streams.items()):
                if s['peer_eof'] and not s['queue'] and not s['write_eof']:
                    close_write(s['socket']);s['write_eof']=True
                if s['read_eof'] and s['write_eof']:
                    s['socket'].close();del streams[ident]
            with selectors.DefaultSelector() as poll:
                poll.register(read_fd,selectors.EVENT_READ,('input',None))
                if outgoing:poll.register(write_fd,selectors.EVENT_WRITE,('output',None))
                if listener:poll.register(listener,selectors.EVENT_READ,('accept',None))
                for ident,s in streams.items():
                    events=(0 if s['read_eof'] else selectors.EVENT_READ)
                    if s['queue']:events|=selectors.EVENT_WRITE
                    if events:poll.register(s['socket'],events,('socket',ident))
                ready=poll.select(max(0,min(.1,end-time.monotonic())))
            for key,events in ready:
                kind,ident=key.data
                if kind=='accept':
                    sock,_=listener.accept();add(next_id,sock);frame(OPEN,next_id);next_id+=1
                elif kind=='output':
                    del outgoing[:os.write(write_fd,outgoing)]
                elif kind=='input':
                    data=os.read(read_fd,PAYLOAD)
                    if not data:raise ValueError('transport disconnected or truncated')
                    append_bounded(incoming,data,queued())
                    while len(incoming)>=HEADER.size:
                        kind2,stream,length=HEADER.unpack_from(incoming)
                        if kind2 not in (OPEN,DATA,CLOSE) or length>PAYLOAD or stream==0:
                            raise ValueError('invalid frame')
                        if kind2!=DATA and length:raise ValueError('invalid control payload')
                        if kind2==DATA and not length:raise ValueError('empty data')
                        if len(incoming)<HEADER.size+length:break
                        body=incoming[HEADER.size:HEADER.size+length];del incoming[:HEADER.size+length]
                        if kind2==OPEN:
                            if mode!='local':raise ValueError('unexpected open')
                            if stream in streams or len(streams)>=STREAMS:raise ValueError('stream capacity or identity')
                            add(stream,socket.create_connection(('127.0.0.1',target_port),timeout=2))
                        else:
                            if stream not in streams:raise ValueError('unknown stream')
                            s=streams[stream]
                            if s['peer_eof']:raise ValueError('data after close')
                            if kind2==DATA:s['queue'].extend(body)
                            else:s['peer_eof']=True
                else:
                    s=streams[ident]
                    if events&selectors.EVENT_WRITE:
                        del s['queue'][:s['socket'].send(s['queue'])]
                    if events&selectors.EVENT_READ:
                        data=s['socket'].recv(PAYLOAD)
                        if data:frame(DATA,ident,data)
                        else:s['read_eof']=True;frame(CLOSE,ident)
    finally:
        if listener:listener.close()
        for s in streams.values():s['socket'].close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('local','remote'),required=True)
    p.add_argument('--target-host',choices=('127.0.0.1',),default='127.0.0.1')
    p.add_argument('--target-port',type=int)
    p.add_argument('--listen-host',choices=('127.0.0.1',),default='127.0.0.1')
    p.add_argument('--listen-port',type=int,default=18443)
    p.add_argument('--lifetime-seconds',type=int,required=True)
    p.add_argument('--ssh-config');p.add_argument('--ssh-host')
    args=p.parse_args()
    if not 0<args.lifetime_seconds<=3600:p.error('lifetime must be 1..3600 seconds')
    child=None
    try:
        if args.mode=='local':
            if not args.ssh_config or not args.ssh_host or not args.target_port:p.error('local target and private SSH configuration required')
            if os.stat(args.ssh_config).st_mode&0o077:p.error('SSH configuration must be private')
            child=subprocess.Popen(['ssh','-T','-F',args.ssh_config,args.ssh_host,
                'python3','/tmp/fs3-ssh-relay.py','--mode','remote','--listen-host','127.0.0.1',
                '--listen-port',str(args.listen_port),'--lifetime-seconds',str(args.lifetime_seconds)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            relay('local',child.stdout.fileno(),child.stdin.fileno(),args.listen_port,args.target_port,args.lifetime_seconds)
        else:relay('remote',0,1,args.listen_port,0,args.lifetime_seconds)
        return 0
    except (OSError,ValueError) as error:
        print('relay stopped: '+type(error).__name__+': '+str(error),file=sys.stderr);return 1
    finally:
        if child:
            if child.poll() is None:child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
            child.stdin.close();child.stdout.close()

if __name__=='__main__':sys.exit(main())

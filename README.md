# IDA Debug Bridge

IDA Debugger Module to Synchronize Memory and Registers with third-party Backends (GDB, Tenet, etc.)

## Screenshot

<img width="960" src="https://user-images.githubusercontent.com/21212051/139926345-f979a0d9-a7ac-4ed7-a8ac-1a152a215b21.png">

## Installation

This plugin currently only supports debugging sessions for PE and ELF programs on x86 or AMD64 architecture.

Since this is only a project for Proof of Concept, only the source code of the plugin is provided.

In order to build this plugin, you need to copy the content of this project and the source code of `jsoncpp` to the `dbg` folder of the IDA SDK. Edit the rules of the `makefile`. Then follow the instructions of `install_make.txt` in IDA SDK to make.

After the compilation is complete, you need to copy the generated plugin to IDA's `plugins` directory.

## Usage

You need to insert the following code in Tenet to synchronize memory and registers with IDA database via TCP connection on port 5000.

Then follow the steps below.

1. Start the IDA process
2. Select IDA Debug Bridge debugger
3. Start a debugging session
4. Load Tenet trace file

Now, you can explore the Time Travel Debugging experience seamlessly integrated with IDA.

Insert the following code to `__init__()` inside `context.py`.

```python
def server_loop(self,t):
    print(self,t)
    import json, socket
    host = '127.0.0.1'
    port = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    
    if self.arch.POINTER_SIZE == 8:
        REGISTERS = ["RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP","R8","R9","R10","R11","R12","R13","R14","R15"]
    else:
        REGISTERS = ["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP"]
        
    while(True):
        client_socket, addr = s.accept()
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data: break
            print('TENET RECV: ',data)
            req = json.loads(data)
            if (req['func'] == 'dbg_read_memory'):
                print(req['func'],req['ea'],req['len'])
                mem = self.reader.get_memory(req['ea'],req['len'])
                output = []
                for i in range(req['len']):
                    if mem.mask[i] == 0xFF:
                        output.append("%02X" % mem.data[i])
                    else:
                        output.append("00")
                        
                ret = ''.join(output)
                print('TENET SEND: ',ret)
                client_socket.send(json.dumps({'ret': ret}).encode('utf-8'))
            
            if (req['func'] == 'dbg_read_registers'):
                print(req['func'])
                reg = self.reader.get_registers()
                ret = []
                for i in REGISTERS:
                    ret.append(reg[i])
                    
                print('TENET SEND: ',ret)
                client_socket.send(json.dumps({'ret': ret}).encode('utf-8'))
                
        client_socket.close()

import _thread
_thread.start_new_thread(self.server_loop,(self,))
```

Insert the following code to `seek()` inside `reader.py`.

```python
import ida_dbg
ida_dbg.continue_process()
```

## Troubleshoot

It is recommended to modify `get_instruction_addresses()` inside `ida_api.py` to workaround the buggy IDA SDK.

```python
if (self.is_64bit()):
    if seg.sclass - 1 != ida_segment.SEG_CODE:
        continue
else:
    if seg.sclass != ida_segment.SEG_CODE:
        continue
```

## Protocol

### Synchronize Registers

Forwarded from IDA's `dbg_read_registers()` API.

```json
{"func":"dbg_read_registers"}
```

### Synchronize Memory

Forwarded from IDA's `dbg_read_memory()` API. The parameters include the address and length of the memory area.

```json
{"ea":140724733087136,"func":"dbg_read_memory","len":8}
```

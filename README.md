# IDA Debug Bridge

IDA Debugger Module working with third-party Backends (GDB, Tenet, etc.) via TCP

## Screenshot

<img width="960" src="https://user-images.githubusercontent.com/21212051/139926345-f979a0d9-a7ac-4ed7-a8ac-1a152a215b21.png">

## Installation

Since this is only a project for Proof of Concept, only the original code of the plug-in is provided.

In order to build this plugin, you need to copy the content of this project and the source code of `jsoncpp` to the `dbg` folder of the IDA SDK. Edit the rules of the `makefile`. Then follow the instructions of `install_make.txt` in IDA SDK to make.

After the compilation is complete, you need to copy the generated plugin to IDA's `plugins` directory.

## Usage

You need to insert the following code in Tenet to synchronize memory and registers with IDA database via TCP connection on port 5000.

Then follow the steps below.

1. Start the IDA process
2. Select IDA Debug Bridge debugger
3. Start a debugging session
4. Load Tenet trace file

Next, you can explore the Time Travel Debugging experience seamlessly integrated with IDA.

```python
def server_loop(self,t):
    print(self,t)
    import json, socket
    host = '127.0.0.1'
    port = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    REGISTERS = ["RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP","R8","R9","R10","R11","R12","R13","R14","R15"]
    while(True):
        client_socket, addr = s.accept()
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data: break
            print('TENET RECV: ' + data)
            req = json.loads(data)
            if (req['func'] == 'dbg_read_memory'): # get_memory
                print(req['func'],req['ea'],req['len'])
                mem = self.reader.get_memory(req['ea'],req['len'])
                output = []
                for i in range(req['len']):
                    if mem.mask[i] == 0xFF:
                        output.append("%02X" % mem.data[i])
                    else:
                        output.append("00")
                
                ret = ''.join(output)
                print(ret)
                client_socket.send(json.dumps({'ret': ret}).encode('utf-8'))
            
            if (req['func'] == 'dbg_read_registers'): # get_registers
                print(req['func'])
                reg = self.reader.get_registers()
                ret = []
                for i in REGISTERS:
                    ret.append(reg[i])
                ret.extend([0]*7)
                print(ret)
                client_socket.send(json.dumps({'ret': ret}).encode('utf-8'))
                
        client_socket.close()

import _thread
_thread.start_new_thread(self.server_loop,(self,))
```


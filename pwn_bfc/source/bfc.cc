#include <iostream>
#include <vector>
#include <sys/mman.h>
#include <stack>
#include <cstring>
#include <unistd.h>
using namespace std; 
/*
if_oob:
	//push rdi
	// DateMaxLen
	mov rax, qword ptr [rdi+0x8] 
	// DataOffset
	mov rbx, qword ptr [rdi+0x10]
	inc rbx
	cmp rax, rbx
	jg rett
	// rdi: rdi: mmapAddr
	push rdi
	// MallocAddr
	mov rax, qword ptr [rdi+0x20]
	// DateMaxLen
	mov rdi, qword ptr [rdi+0x8]
	shl rdi, 1
	//malloc
	call rax
	mov rdi, qword ptr [rsp]

	//mov rsi, rax
	// new dataAdr
	push rax

	mov rdx, qword ptr [rdi+0x8]
	mov rax, [rdi+0x30]
	mov rsi, [rdi]
	mov rdi, qword ptr [rsp] 
	// memcpy
	call rax
	mov rdi, qword ptr [rsp+0x8]

	mov rax, qword ptr [rdi+0x28]
	mov rdi, [rdi]
	// free
	call rax
	pop rsi
	pop rdi
	// update BaseDataAddr && DateMaxLen
	mov qword ptr [rdi], rsi
	mov rax, qword ptr [rdi+0x8]
	shl rax, 1
	mov qword ptr [rdi+0x8], rax
rett:
	ret

_incptr:
	call if_oob
	add qword ptr [rdi+0x10], 1
	ret

_decptr:
	call if_oob
	sub qword ptr [rdi+0x10], 1
	ret

_incvalue:
	mov rax, qword ptr [rdi]
	mov rbx, qword ptr [rdi+0x10]
	add byte ptr [rax+rbx], 1
	ret

_decvalue:
	mov rax, qword ptr [rdi]
	mov rbx, qword ptr [rdi+0x10]
	sub byte ptr [rax+rbx], 1
	ret

_read:
	push rdi
	mov rax, qword ptr [rdi]
	mov rbx, qword ptr [rdi+0x10]
	add rax, rbx
	mov rsi, rax
	xor rax, rax
	xor rdi, rdi
	xor rdx, rdx
	inc rdx
	syscall
	pop rdi
	ret

_write:
	push rdi
	mov rax, qword ptr [rdi]
	mov rbx, qword ptr [rdi+0x10]
	add rax, rbx
	mov rsi, rax
	xor rax, rax
	inc rax
	mov rdi, rax
	mov rdx, rax
	syscall
	pop rdi
	ret
_jz: 
	mov rax, qword ptr [rdi]
	mov rbx, qword ptr [rdi+0x10]
	mov cl, byte ptr [rax+rbx] 
	xor cl, cl
	ret
*/

enum INSTR{INC_RSI = 0, DEC_RSI, ADD_ONE, SUB_ONE, READ, WRITE, JZ, JMP};

string asmptr[] = {{"\x48\x8B\x47\x08\x48\x8B\x5F\x10\x48\xFF\xC3\x48\x39\xD8\x7F\x42\x57\x48\x8B\x47\x20\x48\x8B\x7F\x08\x48\xD1\xE7\xFF\xD0\x48\x8B\x3C\x24\x50\x48\x8B\x57\x08\x48\x8B\x47\x30\x48\x8B\x37\x48\x8B\x3C\x24\xFF\xD0\x48\x8B\x7C\x24\x08\x48\x8B\x47\x28\x48\x8B\x3F\xFF\xD0\x5E\x5F\x48\x89\x37\x48\x8B\x47\x08\x48\xD1\xE0\x48\x89\x47\x08\xC3"},
{"\xE8\xA8\xFF\xFF\xFF\x48\x83\x47\x10\x01\xC3"},
{"\xE8\x9D\xFF\xFF\xFF\x48\x83\x6F\x10\x01\xC3"},
{"\x48\x8B\x07\x48\x8B\x5F\x10\x80\x04\x18\x01\xC3"},
{"\x48\x8B\x07\x48\x8B\x5F\x10\x80\x2C\x18\x01\xC3"},
{"\x57\x48\x8B\x07\x48\x8B\x5F\x10\x48\x01\xD8\x48\x89\xC6\x48\x31\xC0\x48\x31\xFF\x48\x31\xD2\x48\xFF\xC2\x0F\x05\x5F\xC3"},
{"\x57\x48\x8B\x07\x48\x8B\x5F\x10\x48\x01\xD8\x48\x89\xC6\x48\x31\xC0\x48\xFF\xC0\x48\x89\xC7\x48\x89\xC2\x0F\x05\x5F\xC3"},
{"\x48\x8B\x07\x48\x8B\x5F\x10\x8A\x0C\x18\x20\xC9\xC3"},
{"\x8A\x47\x38\x20\xC0\x74\x13\x80\x6F\x38\x01\x57\x48\x8B\x47\x20\x48\x31\xFF\x48\x83\xC7\x01\xFF\xD0\x5F\xC3"}};

int SizeOfCode;
char *ptr;

unsigned int CurRip=0;
unsigned int CodeLen;
char *CodeAddr;

stack<unsigned int>stk;

struct MetaData{
	char *BaseDataAddr;
	long long DataMaxLen;
	long long DataOffset;
    
	char *CodeAddr;

    void* (*MallocAddr)(long unsigned int);
    void (*FreeAddr)(void*);
    void* (*MemcpyAddr)(void*, const void*, long unsigned int);
    long long MallCount;

};

#define IF_OOB_LEN 0x53
#define INC_PTR_LEN 0xb
#define DEC_PTR_LEN 0xb
#define INC_VALUE_LEN 0xc
#define DEC_VALUE_LEN 0xc
#define MY_READ_LEN 0x1e
#define MY_WRITE_LEN 0x1e
#define JUMP_ZERO_LEN 0xd
#define MALLOC0x10_LEN 0x1b

#define IF_OOB 0x0
#define INC_PTR (IF_OOB+IF_OOB_LEN)
#define DEC_PTR (INC_PTR+INC_PTR_LEN)
#define INC_VALUE (DEC_PTR+DEC_PTR_LEN)
#define DEC_VALUE (INC_VALUE+INC_VALUE_LEN)
#define MY_READ (DEC_VALUE+DEC_VALUE_LEN)
#define MY_WRITE (MY_READ+MY_READ_LEN)
#define JUMP_ZERO (MY_WRITE+MY_WRITE_LEN)
#define MALLOC0x10 (JUMP_ZERO+JUMP_ZERO_LEN)
#define CODE_START_ADDR (MALLOC0x10+MALLOC0x10_LEN)


struct MetaData meta_data;

void init() {
    // 远程docker环境一致
    setbuf(stdout, new char[0x400]);
    setbuf(stdin, new char[0x1000]);
    
    //setbuf(stderr, NULL);
    CodeAddr = (char*)mmap(NULL, 0x2000, PROT_EXEC|PROT_READ|PROT_WRITE, 34, -1, 0);
    //printf("mmap addr:0x%x\n",CodeAddr);
    if(!CodeAddr) 
        _exit(-1);
    meta_data.BaseDataAddr = new char[0x10];
    meta_data.DataMaxLen = 0x10;
    meta_data.DataOffset = 0;
    meta_data.MallCount = 2;

    meta_data.CodeAddr = CodeAddr;
    meta_data.MallocAddr = &malloc;
    meta_data.FreeAddr = &free;
    meta_data.MemcpyAddr = &memcpy;
    //CodeLen += sizeof(struct MetaData);
    for (int i=0; i < 9; i++) {
        memcpy(CodeAddr+CodeLen, asmptr[i].c_str(), asmptr[i].length());
        CodeLen += asmptr[i].length();
    }

}

void fini() {
    CodeAddr[CodeLen++] = '\xC3';
    mprotect(CodeAddr, 0x2000, PROT_EXEC);
}


void incptr() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = INC_PTR - (CodeLen + 4);
    CodeLen += 4;
}

void decptr() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = DEC_PTR - (CodeLen + 4);
    CodeLen += 4;
}

void incvalue() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = INC_VALUE - (CodeLen + 4);
    CodeLen += 4;
}

void decvalue() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = DEC_VALUE - (CodeLen + 4);
    CodeLen += 4;
}

void syswrite() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = MY_WRITE - (CodeLen + 4);
    CodeLen += 4;
}

void sysread() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = MY_READ - (CodeLen + 4);
    CodeLen += 4;
}

void jz() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = JUMP_ZERO - (CodeLen + 4);
    CodeLen += 4;
    CodeAddr[CodeLen++] = '\x0F';
    CodeAddr[CodeLen++] = '\x84';
    CodeLen += 4;

    unsigned int addr = CodeLen-11;

    stk.push(addr);
}

void jmp() {
    if(stk.empty()) {
        cout<<"syntax error!"<<endl;
        _exit(-1);
    }
    CodeAddr[CodeLen++] = '\xE9';

    unsigned int addr = stk.top();
    stk.pop();
    // redirection
    int lowAddr, highAddr;
    lowAddr = (CodeLen+4) - (addr+11);
    highAddr = (addr - (CodeLen+4));
    *(unsigned int *)(CodeAddr + CodeLen) = highAddr;
    CodeLen += 4;
    *(unsigned int *)(CodeAddr + addr + 1 + 4 + 2) = lowAddr;
}

void malloc0x10() {
    CodeAddr[CodeLen++] = '\xE8';
    *(unsigned int *)(CodeAddr + CodeLen) = MALLOC0x10- (CodeLen + 4);
    CodeLen += 4;
}


int main() {
    init();
    std::cout << "size of code:";
    cin>>SizeOfCode;
    cout<<"code:";
    for(int i=0; i<SizeOfCode; i++) {
        char a;
        std::cin >> a;
        switch (a) {
            case '>': //指针向右移动一格
                incptr();
                break;
            case '<': //指针向左移动一格
                decptr();
                break;
            case '+'://使指针当前格的字节数值加1
                incvalue();
                break;
            case '-'://使指针当前格的字节数值减1
                decvalue();
                break;
            case '.'://把当前格数值按 ASCII 表输出到终端
                syswrite();
                break;
            case ','://接受一个字节的输入，将其值存储在数据指针的字节中。
                sysread();
                break;
            case '['://当指针当前值为 0 时，程序跳转至与之对应的 ] 之后；否则程序正常执行
                jz();
                break;
            case ']'://程序跳转回与之对应的 [ 处
                jmp();
                break;
            case '?':
                malloc0x10();
                break;
            case '\n':
            case ' ':
            case '\t':
            ;break;
            default:
            cout<<"syntax error!"<<endl;
            _exit(-1);
            break;
        }
        if(CodeLen >= (0x2000-0x20))
            break;
    }
    fini();
    //"\xcc";
    /*
        bind CodeAddr to rdi using gcc inline asm
    */
    asm volatile ("movq %0, %%rdi;\n"
        :
        : "r"(&meta_data));
    
    ((void (*)(void))(CodeAddr + CODE_START_ADDR))();
    //func();
    _exit(0);


}
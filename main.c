#include <stdio.h>
#include <string.h>
#include <windows.h>

void print_error(){
    printf("[-] Error has occured - LastError: %lu\n", GetLastError());
}

void debug_dump(void* addr, size_t size){
    for(size_t i = 0; i < size; i++){
        if(i % 8 == 0)
            printf("\n");
        printf("0x%02X ", *((unsigned char*)addr + i));
    }
    printf("\n");
}

void* get_remote_func_addr(const char* module, const char* proc){
    HMODULE remote_module = GetModuleHandleA(module);
    if(NULL == remote_module){
        printf("Module %s not found, trying to load it manually\n", module);
        remote_module = LoadLibraryA(module);
        if(NULL == remote_module){
            printf("Cannot load %s\n", module);
            print_error();
            return NULL;
        }
    }
    void* func_addr = GetProcAddress(remote_module, proc);
    if(NULL == func_addr){
        printf("Cannot obtain %s addr\n", proc);
        print_error();
        return NULL;
    }
    return func_addr;
}

//////////////////////////////////////////////////

unsigned int* retain_orig(void* addr, size_t size){
    unsigned int* temp = calloc(1, size);
    if(NULL == temp){
        printf("Cannot allocate buffer with size %zu bytes\n", size);
        return NULL;
    }
    memcpy(temp, addr, size);
    return temp;
}

unsigned char* generate_patch(void* hook_addr, size_t* size){
    // 0:  48 b8 66 55 44 33 22    movabs rax,0x112233445566
    // 7:  11 00 00
    // a:  50                      push   rax
    // b:  c3                      ret
    unsigned char temp[] = {
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, //movabs rax,0x00000000000
        0x50,                                                                                         //push rax
        0xc3                                                                                          //ret
    };

    size_t temp_size = sizeof(temp) / sizeof(temp[0]);
    *size = temp_size;
    unsigned char* jump_buffer = calloc(1, temp_size);
    memcpy(jump_buffer, temp, temp_size);
    
    jump_buffer[2] = (((long long)hook_addr) >> 0   ) & 0xff;
    jump_buffer[3] = (((long long)hook_addr) >> 8   ) & 0xff;
    jump_buffer[4] = (((long long)hook_addr) >> 16  ) & 0xff;
    jump_buffer[5] = (((long long)hook_addr) >> 24  ) & 0xff;
    jump_buffer[6] = (((long long)hook_addr) >> 32  ) & 0xff;
    jump_buffer[7] = (((long long)hook_addr) >> 40  ) & 0xff;
    jump_buffer[8] = (((long long)hook_addr) >> 48  ) & 0xff;
    jump_buffer[9] = (((long long)hook_addr) >> 56  ) & 0xff;

    return jump_buffer;
}

void install_hook(void* orig_addr, void* hook_addr){
    size_t patch_size = 0;
    unsigned char* patch = generate_patch(hook_addr, &patch_size);
    debug_dump(patch, patch_size);

    unsigned long old_protect;
    if(VirtualProtectEx(GetCurrentProcess(), orig_addr, patch_size, PAGE_EXECUTE_READWRITE, &old_protect) == 0){
        print_error();
        exit(EXIT_FAILURE);
    }
    memcpy(orig_addr, patch, patch_size);
}

void remove_hook(){
    // todo
    // old_protect is needed
}

//////////////////////////////////////////////////


int messagebox_hook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType){

    /* 
        4) OUR HOOK FUNCTION SHOULD LOOK LIKE THIS

    patched_func:
	... => hook logic 
	55           push   rbp			                    => this is from the original function
	48 89 e5     mov    rbp,rsp		                    => this is from the original function
	48 83 ec 10  sub    rsp,0x10		                => this is from the original function
	             jmp original_func + temp_buffer_size	=> jump back to the original
    */

    printf("[*] From hook => MessageBoxA was called!\n");
    printf("hwnd: %u\nlptext: %s\nlpcaption: %s\nutype: %u", hWnd, lpText, lpCaption, uType);
    // __asm__{
    //     //after func logic
    // }
    return 0; // replace with original messagebox + offset
}

int main(void){
    void* messagebox_orig = get_remote_func_addr("user32.dll", "MessageBoxA");
    if(NULL == messagebox_orig)
        exit(EXIT_FAILURE);

    // __asm__{
    //     movabs rax, 0x1122334455667788
    //     push rax
    //     ret
    // }


    printf("hi %llX\n", messagebox_orig);
    printf("messagebox_hook: %llX\n", messagebox_hook);

    puts("MessageBoxA before hook:");
    debug_dump(messagebox_orig, 100);

    MessageBoxA(0, "Test", "Test", MB_OK);
    
    install_hook(messagebox_orig, messagebox_hook);

    puts("MessageBoxA after hook:");
    debug_dump(messagebox_orig, 100);

    MessageBoxA(0, "Test", "Test", MB_OK);

    return 0;
}
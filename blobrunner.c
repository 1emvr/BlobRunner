#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string>

#ifdef _WIN64
#include <WinBase.h>
#endif

typedef std::string STRING;

const char* _version = "0.0.5";
const char* _banner = " __________.__        ___.  __________\n"
" \\______   \\  |   ____\\_ |__\\______   \\__ __  ____   ____   ___________     \n"
"  |    |  _/  |  /  _ \\| __ \\|       _/  |  \\/    \\ /    \\_/ __ \\_  __ \\  \n"
"  |    |   \\  |_(  <_> ) \\_\\ \\    |   \\  |  /   |  \\   |  \\  ___/|  | \\/ \n"
"  |______  /____/\\____/|___  /____|_  /____/|___|  /___|  /\\___  >__|          \n"
"         \\/                \\/       \\/           \\/     \\/     \\/    \n\n"
"                                                                     %s    \n\n";

// jmp opcode used to hook module export. overwrites 0x0 with allocated buffer address.
BYTE opcode[] = { 0xe8,0x00,0x00,0x00,0x00 };

// assembly loader used to bootstrap shellcode. overwrites "call xxxxx" at a pre-calculated offset.
BYTE loader[] = {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
};

struct PROC_FILE {
	LPVOID buffer;
	DWORD size;
};

void banner() {
	system("cls");
	printf(_banner, _version);
	return;
}

VOID destroy_file(PROC_FILE* proc_file) {

	if (proc_file->buffer) {
		VirtualFree(proc_file->buffer, proc_file->size, MEM_RELEASE);
	}
	if (proc_file) {
		free(proc_file);
	}
}

PROC_FILE* process_file(char* filename, bool jit, int offset, bool debug) {

	FILE* handle;
	PCHAR buffer;
	PROC_FILE *proc_file = (PROC_FILE*) malloc(sizeof(PROC_FILE));

	handle = fopen(filename, "rb");

	if (!handle) {
		printf(" [!] Error: Unable to open %s\n", filename);
		return nullptr;
	}

	printf(" [*] Reading file %s...\n", filename);

	fseek(handle, 0, SEEK_END);
	proc_file->size = ftell(handle); //Get Length

	printf(" [*] File Size: 0x%04x\n", proc_file->size);

	fseek(handle, 0, SEEK_SET); //Reset
	proc_file->size += 1;

	buffer = (char*) malloc(proc_file->size); //Create Buffer
	fread(buffer, proc_file->size, 1, handle);
	fclose(handle);

	printf(" [*] Allocating Memory...");
	proc_file->buffer = VirtualAlloc(NULL, proc_file->size, 0x3000, 0x40);

	printf(".Allocated!\n");
	printf(" [*]   |-Base: 0x%08x\n", (int)(size_t)proc_file->buffer);
	printf(" [*] Copying input data...\n");

	CopyMemory(proc_file->buffer, buffer, proc_file->size);
	return proc_file;
}

UINT_PTR find_region(HANDLE process, UINT_PTR cexport, SIZE_T size) {

	UINT_PTR address = 0;
	UINT_PTR retval = 0;

	printf(" [*] Searching for available VM space of 0x%08x bytes\n", size);

	for (address = (cexport & 0xFFFFFFFFFFF70000) - 0x70000000;
		 address < cexport + 0x70000000;
		 address += 0x10000) {

		if (!(retval = (UINT_PTR) VirtualAlloc((LPVOID) address, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			continue;
		}
	}

	printf(" [*] Found new address for hook at: 0x%08x\n", address);
	return retval;
}

BOOL threadless(PROC_FILE *shellcode, BOOL nopause) {
	
	LPVOID exp_addr  = 0;
	LPVOID cexp_addr = 0;

	UINT_PTR rva   = 0;
	UINT_PTR hook  = 0;
	UINT_PTR chook = 0;

	SIZE_T read   = 0;
	SIZE_T write  = 0;
	DWORD protect = 0;

	HANDLE process = GetCurrentProcess();
	BOOL success  = false;

	CHAR org_bytes[5] = { };
	CONST CHAR msg[] = " [*] Navigate to the Thread Entry and set a breakpoint. Then press any key to resume the thread.\n";

	if (nopause == false) {
		printf("%s", msg);
		getchar();
	}

	printf(" [*] Setting up export for hooking\n");
	printf(" [*] Total size: 0x%08x\n", shellcode->size + sizeof(loader));

	if (!(exp_addr = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "OpenFile"))) {
		printf(" [!] Error: Failed to get address for target export\n");
		goto defer;
	}

	if (!(hook = find_region(process, (UINT_PTR) exp_addr, shellcode->size + sizeof(loader)))) {
		printf(" [!] Error: Failed to find sufficient virtual memory\n");
		goto defer;
	}

	chook = hook;
	rva = (UINT_PTR) hook - ((UINT_PTR) exp_addr + 5);

	CopyMemory(&cexp_addr, &exp_addr, sizeof(void*));
	CopyMemory((PBYTE)loader + 0x12, &cexp_addr, sizeof(void*));
	CopyMemory((PBYTE)opcode + 0x1, &rva, 4);

	printf(" [*] Saving original export bytes at: 0x%08x\n", cexp_addr);
	if (!ReadProcessMemory(process, cexp_addr, (LPVOID) org_bytes, 5, &read) || read != 5) {
		printf(" [!] Error: Failed to read dll memory\n");
		goto defer;
	}

	printf(" [*] Changing protections on export at: 0x%08x\n", cexp_addr);
	if (!VirtualProtect(cexp_addr, 8, PAGE_EXECUTE_READWRITE, &protect)) {
		printf(" [!] Error: Failed to modify protections on dll export\n");
		goto defer;
	}

	printf(" [*] Writing hook address to export at: 0x%08x\n", cexp_addr);
	if (!WriteProcessMemory(process, (void*) exp_addr, opcode, 5, &write) || write != 5) {
		printf(" [!] Error: Failed to patch code to dll export at: 0x%08x\n", exp_addr);
		goto defer;
	}
	
	printf(" [*] Writing loader code to process hook at: 0x%08x\n", hook);
	if (!WriteProcessMemory(process, (LPVOID) hook, loader, sizeof(loader), &write) || write != sizeof(loader)) {
		printf(" [!] Error: Failed to write loader to hook region at: 0x%08x\n", hook);
		goto defer;
	}

	printf(" [*] Writing shellcode to hook address at: 0x%08x\n", hook + sizeof(loader));
	if (!WriteProcessMemory(process, (PBYTE)hook + sizeof(loader), shellcode->buffer, shellcode->size, &write) || write != shellcode->size) {
		printf(" [!] Error: Failed append shellcode to hook address at: 0x%08x\n", hook + sizeof(loader));
		goto defer;
	} 

	printf(" [*] Making shellcode section executable at: 0x%08x\n", hook);
	if (!VirtualProtect((LPVOID) hook, shellcode->size + sizeof(loader), PAGE_EXECUTE_READ, &protect)) {
		printf(" [!] Error: Failed to change protections on shellcode\n");
		goto defer;
	}

	success = true;

 defer:
	if (process) {
		CloseHandle(process);
	}

	if (success) {
		HFILE handle    = { };
		LPOFSTRUCT lpof = { };

		printf(" [*] Making call to OpenFile()\n");
		handle = OpenFile("doesnotexist.txt", lpof, 0x0);

		// TODO: restore original export bytes
	}

	return success;
}

void thread(LPVOID base, int offset, bool nopause, bool jit, bool debug)
{
	LPVOID shell_entry;

#ifdef _WIN64
	DWORD   thread_id;
	HANDLE  thread_handle;
	const char msg[] = " [*] Navigate to the Thread Entry and set a breakpoint. Then press any key to resume the thread.\n";
#else
	const char msg[] = " [*] Navigate to the EP and set a breakpoint. Then press any key to jump to the shellcode.\n";
#endif

	shell_entry = (LPVOID)((UINT_PTR)base + offset);

#ifdef _WIN64

	printf(" [*] Creating Suspended Thread...\n");
	thread_handle = CreateThread(
		NULL,          // Attributes
		0,             // Stack size (Default)
	    (PTHREAD_START_ROUTINE) shell_entry, // Thread EP
		NULL,          // Arguments
		0x4,           // Create Suspended
		&thread_id);   // Thread identifier

	if (thread_handle == NULL) {
		printf(" [!] Error Creating thread...");
		return;
	}
	printf(" [*] Created Thread: [%d]\n", thread_id);
	printf(" [*] Thread Entry: 0x%016x\n", (int)(size_t)shell_entry);

#endif

	if (nopause == false) {
		printf("%s", msg);
		getchar();
	}
	else
	{
		if (jit == true) {
			// Force an exception by making the first byte not executable.
			// This will cause
			DWORD oldp;

			printf(" [*] Removing EXECUTE access to trigger exception...\n");

			VirtualProtect(shell_entry, 1 , PAGE_READWRITE, &oldp);
		}
	}

#ifdef _WIN64
	printf(" [*] Resuming Thread..\n");
	ResumeThread(thread_handle);
#else
	printf(" [*] Entry: 0x%08x\n", (int)(size_t)shell_entry);
	printf(" [*] Jumping to shellcode\n");
	__asm jmp shell_entry;
#endif
}

void print_help() {
	printf(" [!] Error: No file!\n\n");
	printf("     Required args: <inputfile>\n\n");
	printf("     Optional Args:\n");
	printf("         --offset <offset> The offset to jump into.\n");
	printf("         --nopause         Don't pause before jumping to shellcode. Danger!!! \n");
	printf("         --threadless      Execute shellcode using EAT hooking.\n");
	printf("         --jit             Forces an exception by removing the EXECUTE permission from the alloacted memory.\n");
	printf("         --debug           Verbose logging.\n");
	printf("         --version         Print version and exit.\n\n");
}

STRING GetLastErrorAsString() {

    DWORD error_id = GetLastError();
    if(error_id == 0) {
        return std::string(); //No error message has been recorded
    }
    
    LPSTR messageBuffer = nullptr;

    SIZE_T size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, error_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    
    STRING message(messageBuffer, size);
    LocalFree(messageBuffer);
            
    return message;
}

#define THREADLESS 1
#define THREAD 0

int main(int argc, char* argv[]) {

	INT method = THREAD;
	INT offset = 0;

	BOOL jit = false;
	BOOL debug = false;
	BOOL nopause = false;
	CHAR* nptr;

	banner();

	if (argc < 2) {
		print_help();
		return 1;
	}

	printf(" [*] Using file: %s \n", argv[1]);

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--offset") == 0) {
			printf(" [*] Parsing offset...\n");
			i = i + 1;
			if (strncmp(argv[i], "0x", 2) == 0) {
				offset = strtol(argv[i], &nptr, 16);
			}
			else {
				offset = strtol(argv[i], &nptr, 10);
			}
		}
		else if (strcmp(argv[i], "--nopause") == 0) {
			nopause = true;
		}
		else if (strcmp(argv[i], "--jit") == 0) {
			jit = true;
			nopause = true;
		}
		else if (strcmp(argv[i], "--debug") == 0) {
			debug = true;
		}
		else if (strcmp(argv[i], "--version") == 0) {
			printf("Version: %s", _version);
		}
		else if (strcmp(argv[i], "--threadless") == 0) {
			method = THREADLESS;
		}
		else {
			printf("[!] Warning: Unknown arg: %s\n", argv[i]);
		}
	}

	PROC_FILE *shellcode;
	switch (method) {
			case THREADLESS: {
				printf(" [*] Executing using ThreadlessInjection method.\n");

				if (!(shellcode = process_file(argv[1], 0, 0, 0))) {
					printf(" [!] Exiting...");
					return 1;
				}

				if (!threadless(shellcode, nopause)) { 
					printf(" [!] Error: %s\n", GetLastErrorAsString().c_str());
					return 1;
				}

				destroy_file(shellcode);
			}

			case THREAD: {
				printf(" [*] Executing using a new thread.\n");

				shellcode = process_file(argv[1], jit, offset, debug);
				if (shellcode == NULL) {
					printf(" [!] Exiting...");
					return -1;
				}

				printf(" [*] Using offset: 0x%08x\n", offset);

				thread(shellcode->buffer, offset, nopause, jit, debug);
				destroy_file(shellcode);
			}
		}

	
	printf("Pausing - Press any key to quit.\n");
	getchar();

	return 0;
}

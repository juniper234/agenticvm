/* Console launcher: fixed sibling Python/script, argv forwarding, no shell. */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>

static wchar_t command[32768];
static wchar_t root[32768],python[32768],script[32768];
static STARTUPINFOW startup;
static PROCESS_INFORMATION process;
static size_t used;
static BOOL WINAPI control(DWORD signal) {
    /* Python receives Ctrl+C itself and requests bounded child cleanup. */
    return signal==CTRL_C_EVENT || signal==CTRL_BREAK_EVENT;
}
static void put(wchar_t c) {
    if (used >= 32766) ExitProcess(2);
    command[used++]=c; command[used]=0;
}
static void quote(const wchar_t *arg) {
    put(L'"');
    size_t slashes=0;
    for (; *arg; arg++) {
        if (*arg==L'\\') { slashes++; continue; }
        if (*arg==L'"') { for(size_t i=0;i<slashes*2+1;i++) put(L'\\'); }
        else { for(size_t i=0;i<slashes;i++) put(L'\\'); }
        put(*arg); slashes=0;
    }
    for(size_t i=0;i<slashes*2;i++) put(L'\\');
    put(L'"'); put(L' ');
}
static void join(wchar_t *target,const wchar_t *prefix,const wchar_t *suffix) {
    size_t i=0; while(*prefix) target[i++]=*prefix++;
    while(*suffix) target[i++]=*suffix++;
    target[i]=0;
}
static void message(const char *value,DWORD length) {
    DWORD written; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),value,length,&written,NULL);
}
void mainCRTStartup(void) {
    SetConsoleCtrlHandler(control,TRUE);
    int argc=0;
    wchar_t **argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv) ExitProcess(2);
    DWORD size=GetModuleFileNameW(NULL,root,32768);
    if(!size || size>=32000) ExitProcess(2);
    while(size && root[size]!=L'\\') size--;
    if(!size) ExitProcess(2); root[size]=0;
    join(python,root,L"\\tools\\python\\python.exe");
#ifdef AGENTICVM_LIVE
    join(script,root,L"\\scripts\\run-live-agents.py");
#elif defined(AGENTICVM_TRANSFER)
    join(script,root,L"\\scripts\\run-encrypted-transfer.py");
#elif defined(AGENTICVM_REPLICATOR)
    join(script,root,L"\\scripts\\run-agent-replicator.py");
#else
    join(script,root,L"\\scripts\\run-agent-chain.py");
#endif
    quote(python); quote(L"-I"); quote(L"-B"); quote(script);
    for(int i=1;i<argc;i++) quote(argv[i]);
    startup.cb=sizeof(startup);
    if(!CreateProcessW(python,command,NULL,NULL,TRUE,0,NULL,root,&startup,&process)) {
        const char text[]="Cannot start bundled Python. Keep the whole application folder together.\r\n";
        message(text,sizeof(text)-1); ExitProcess(2);
    }
    WaitForSingleObject(process.hProcess,INFINITE);
    DWORD code=1; GetExitCodeProcess(process.hProcess,&code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    DWORD mode=0;
    if(argc==1 && GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&mode)) {
        const char text[]="\r\nPress Enter to close.\r\n";
        message(text,sizeof(text)-1);
        char input[8]; DWORD count; ReadFile(GetStdHandle(STD_INPUT_HANDLE),input,sizeof(input),&count,NULL);
    }
    LocalFree(argv);
    ExitProcess(code);
}

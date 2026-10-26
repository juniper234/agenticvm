/* One file: pinned ZIP overlay + native Windows console bootstrap.
 * No shell file association, system Python, elevation or feature changes.
 * The generated header contains an EncodedCommand for the fixed extraction
 * program. User paths enter through an environment variable, never code text.
 */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include "sprout-bootstrap.h"
static wchar_t self[32768],powershell[32768],command[32768];
static STARTUPINFOW startup;
static PROCESS_INFORMATION process;
static BOOL WINAPI control(DWORD signal) {
    return signal==CTRL_C_EVENT || signal==CTRL_BREAK_EVENT;
}
static void error(void) {
    const char message[]="Sprout could not start its bundled installer.\r\n";
    DWORD count; WriteFile(GetStdHandle(STD_ERROR_HANDLE),message,sizeof(message)-1,&count,NULL);
    ExitProcess(1);
}
void mainCRTStartup(void) {
    SetConsoleCtrlHandler(control,TRUE);
    DWORD size=GetModuleFileNameW(NULL,self,32768);
    if(!size || size>=32768 || !SetEnvironmentVariableW(L"AGARDEN_INSTALLER_SELF",self)) error();
    size=GetSystemDirectoryW(powershell,32000);
    const wchar_t suffix[]=L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    for(size_t i=0;i<sizeof(suffix)/sizeof(wchar_t);i++) powershell[size+i]=suffix[i];
    size_t used=0;
    command[used++]=L'"';
    for(size_t i=0;powershell[i];i++) command[used++]=powershell[i];
    command[used++]=L'"'; command[used++]=L' ';
    const wchar_t arguments[]=L"-NoLogo -NoProfile -NonInteractive -EncodedCommand " SPROUT_COMMAND;
    for(size_t i=0;i<sizeof(arguments)/sizeof(wchar_t);i++) command[used++]=arguments[i];
    if(used>=32768) error();
    startup.cb=sizeof(startup);
    if(!CreateProcessW(powershell,command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&process)) error();
    WaitForSingleObject(process.hProcess,INFINITE);
    DWORD code=1; GetExitCodeProcess(process.hProcess,&code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    ExitProcess(code);
}

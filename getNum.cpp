#include <Windows.h>
#include <stdio.h>
DWORD_PTR getFunctionSyscall(char* library){
    PDWORD funcAddr = 0;
    HANDLE libraryBase = LoadLibraryA(library);

    if(libraryBase){
        char* nani = (char*)malloc(65536);
        if(nani){
            memset(nani,0,65536);
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) libraryBase;
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) (dosHeader->e_lfanew + (DWORD_PTR) libraryBase);

            DWORD_PTR exportDirectoryRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR) libraryBase + exportDirectoryRVA);

            PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + exportDirectory->AddressOfFunctions);
            PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + exportDirectory->AddressOfNames);
            PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + exportDirectory->AddressOfNameOrdinals);
            for(int i = 0;i<exportDirectory->NumberOfFunctions;i++){
                DWORD functionNameRVA = addressOfNamesRVA[i];
                DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
                char* functionName = (char*) functionNameVA;
                DWORD_PTR functionAddressRVA = 0;
                if(functionName[0] == 'N' && functionName[1] == 't'){
                    functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
                    DWORD_PTR functionAddress = ((DWORD_PTR)libraryBase + functionAddressRVA);
                    int syscall = ((int*)functionAddress)[1];
                    nani[0] = '{';
                    nani[1] = '\n';
                    sprintf(nani + strlen(nani),"\t\"0x%x\" : \"%s\",\n",syscall,functionName);
                   
                }
                 
            }
            nani[strlen(nani)-2] = '\n';
            nani[strlen(nani)-1] = '}';
            FILE* file = fopen("syscalls.json","w");
            fwrite(nani,1,strlen(nani),file);
            fclose(file);
        }
       
        
    }
    return NULL;
}

int main(){
    getFunctionSyscall("ntdll");
}
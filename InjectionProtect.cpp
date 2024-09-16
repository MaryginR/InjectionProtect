#include "InjectionProtect.h"

bool checkAllMemoryProtection() {
    HANDLE hProcess = GetCurrentProcess();
    if (hProcess == NULL) {
        throw "Failed to get current process handle.";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;

    // Перебираем все участки памяти
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        // Проверяем, что память используется (MEM_COMMIT)
        if (mbi.State == MEM_COMMIT) {
            // Проверяем, что память не имеет прав на запись
            if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                CloseHandle(hProcess);
                return false; // Обнаружена память с правами на запись и исполнение
            }
        }

        // Переходим к следующему участку памяти
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return true;  // Все проверенные участки памяти имеют корректную защиту
}

bool CheckIAT()
{
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule)
    {
        throw "Error: Unable to get module handle.";
        return;
    }

    // Получаем информацию о заголовке PE-файла
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

    // Получаем таблицу импорта
    DWORD importDirectoryRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirectoryRVA == 0)
    {
        throw "Error: No import table found.";
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + importDirectoryRVA);

    while (pImportDesc->Name != 0)
    {
        LPCSTR pDllName = (LPCSTR)((DWORD_PTR)hModule + pImportDesc->Name);
        HMODULE hImportedModule = LoadLibraryA(pDllName);

        if (hImportedModule)
        {
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);

            while (pOriginalThunk->u1.Function)
            {
                FARPROC pRealAddr = nullptr;
                PIMAGE_IMPORT_BY_NAME pImportByName = nullptr;

                if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    // Импорт по порядковому номеру
                    pRealAddr = GetProcAddress(hImportedModule, (LPCSTR)(pOriginalThunk->u1.Ordinal & 0xFFFF));
                }
                else
                {
                    // Импорт по имени
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)hModule + pOriginalThunk->u1.AddressOfData);
                    pRealAddr = GetProcAddress(hImportedModule, (LPCSTR)pImportByName->Name);
                }

                // Проверяем, совпадает ли адрес в IAT с реальным адресом функции
                if (pRealAddr && pRealAddr != (FARPROC)pFirstThunk->u1.Function)
                {
                    
                    return false; //Обнаружена инъекция кода в IAT
                }

                pOriginalThunk++;
                pFirstThunk++;
            }

            FreeLibrary(hImportedModule);
        }

        pImportDesc++;
    }

    return true; // Инъекций не обнаружено
}

int main()
{
    CheckIAT();
    checkAllMemoryProtection();

    return 0;
}

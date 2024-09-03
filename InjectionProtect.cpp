#include "InjectionProtect.h"

void CheckIAT()
{
    // Получаем дескриптор текущего модуля
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule)
    {
        std::cerr << "Error: Unable to get module handle." << std::endl;
        return;
    }

    // Получаем информацию о заголовке PE-файла
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

    // Получаем таблицу импорта
    DWORD importDirectoryRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirectoryRVA == 0)
    {
        std::cerr << "Error: No import table found." << std::endl;
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + importDirectoryRVA);

    while (pImportDesc->Name != 0)
    {
        // Получаем имя DLL
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
                    
                    std::cout << "Warning: Possible IAT hook detected";
                }

                pOriginalThunk++;
                pFirstThunk++;
            }

            FreeLibrary(hImportedModule);
        }

        pImportDesc++;
    }
}

int main()
{
    CheckIAT();

    return 0;
}

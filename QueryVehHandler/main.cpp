// veh_list.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<map>
#include"FindPattern.hpp"
#include"EasyPdb.h"
#include"defs.h"


#define     FONT_COLOR_NONE				"\033[0m"
#define     FONT_COLOR_RED					"\033[31;1m"
#define     FONT_COLOR_GREEN				"\033[32;1m"
#define		FONT_COLOR_BROWN			"\033[33;1m"
#define		FONT_COLOR_BLUE					"\033[34;1m"
#define		FONT_COLOR_PINK					"\033[35;1m"
#define		FONT_COLOR_CYAN				"\033[36;1m"
#define		FONT_COLOR_GRAY				"\033[37;1m"

#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#define UFIELD_OFFSET(type, field)    ((DWORD)(LONG_PTR)&(((type *)0)->field))
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))


#ifdef _WIN64
#define NTDLLPATH "\\system32\\ntdll.dll"
ULONG64  RtlDecodePointer(ULONG64 key)
{
	unsigned int ret; 
	unsigned int ProcessInformation;

	typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	fnNtQueryInformationProcess lpNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	ret = lpNtQueryInformationProcess((HANDLE)-1, 36, &ProcessInformation, 4, 0);
	if (ret >= 0)
	{
		return  __ROR8__(key, 0x40 - (ProcessInformation & 0x3F)) ^ ProcessInformation;
	}
	return 0;
}
#else
#define NTDLLPATH "\\SysWOW64\\ntdll.dll"
int  RtlDecodePointer(int key)
{
	unsigned int ret; // edx
	unsigned int ProcessInformation; 

	typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	fnNtQueryInformationProcess lpNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	ret = lpNtQueryInformationProcess((HANDLE) - 1, 36, &ProcessInformation, 4, 0);
	if (ret >= 0)
	{
		return ProcessInformation ^ __ROR4__(key, 32 - (ProcessInformation & 0x1F));
	}
	return 0;
}
#endif

typedef struct _RTL_VECTORED_HANDLER_LIST
{
	SRWLOCK ExceptionLock;
	LIST_ENTRY ExceptionList;
	SRWLOCK ContinueLock;
	LIST_ENTRY ContinueList;
} RTL_VECTORED_HANDLER_LIST, * PRTL_VECTORED_HANDLER_LIST;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY
{
	LIST_ENTRY List;
	PULONG_PTR Flag;
	ULONG RefCount;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} RTL_VECTORED_EXCEPTION_ENTRY, * PRTL_VECTORED_EXCEPTION_ENTRY;


LONG myException1(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	return EXCEPTION_CONTINUE_SEARCH;
}

LONG myException2(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	printf("[+]Download pdb.....\n");
	std::string ntpath = std::string(std::getenv("systemroot"))+ NTDLLPATH;
	std::string pdbPath = EzPdbDownload(ntpath);
	if (pdbPath.empty())
	{
		std::cout << "[-]download pdb failed " << GetLastError() << std::endl;;
		return 1;
	}

	EZPDB pdb;
	if (!EzPdbLoad(pdbPath, &pdb))
	{
		std::cout << "[-]load pdb failed " << GetLastError() << std::endl;
		return 1;
	}
	printf("-----------------------------------------------------------\n");
	ULONG rva = EzPdbGetRva(&pdb, "LdrpVectorHandlerList");
	printf("[+]rva LdrpVectorHandlerList = %x\n", rva);
	EzPdbUnload(&pdb);

	//添加VEH
	int i = 0;
	std::map<ULONG64,BOOL> mapException{};
	mapException[(ULONG64)myException1] = TRUE;
	mapException[(ULONG64)myException2] = TRUE;
	printf("[+]Add Vector Handler\n");
	for (auto item : mapException)
	{
		AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)item.first);
		printf("[*]myTestException_%d = %p\n", ++i, item.first);
	}


	printf("[+]Enter to Query");
	getchar();
	printf("-----------------------------------------------------------\n");
	auto QueryList = [=](RTL_VECTORED_HANDLER_LIST* LdrpVectorHandlerList,BOOL exception) {
		
		PLIST_ENTRY startLink{};
		PLIST_ENTRY currentLink{};
		ULONG64 decode_vehHandler{};

		if (exception)
		{
			startLink = (PLIST_ENTRY)PTR_ADD_OFFSET((LPVOID)LdrpVectorHandlerList, UFIELD_OFFSET(RTL_VECTORED_HANDLER_LIST, ExceptionList));;
			currentLink = LdrpVectorHandlerList->ExceptionList.Flink;
		}
		else {
			startLink = (PLIST_ENTRY)PTR_ADD_OFFSET((LPVOID)LdrpVectorHandlerList, UFIELD_OFFSET(RTL_VECTORED_HANDLER_LIST, ContinueList));;
			currentLink = LdrpVectorHandlerList->ContinueList.Flink;
		}
		int i = 0;
		while (currentLink != startLink && i <= 40)
		{
			PRTL_VECTORED_EXCEPTION_ENTRY addressOfEntry = CONTAINING_RECORD(currentLink, RTL_VECTORED_EXCEPTION_ENTRY, List);
#ifdef _WIN64
			decode_vehHandler = RtlDecodePointer((ULONG64)addressOfEntry->VectoredHandler);
#else
			decode_vehHandler = RtlDecodePointer((int)addressOfEntry->VectoredHandler);
#endif
			//检查白名单
			if (mapException.count(decode_vehHandler) == 0)
				printf(FONT_COLOR_RED);
			else
				printf(FONT_COLOR_GREEN);
			printf("[%04d]origin=%p\tdecrypt=%p\n", i + 1, addressOfEntry->VectoredHandler, decode_vehHandler);
			printf(FONT_COLOR_NONE);
			currentLink = addressOfEntry->List.Flink;

			i++;
		}
	};
	RTL_VECTORED_HANDLER_LIST* LdrpVectorHandlerList = reinterpret_cast<RTL_VECTORED_HANDLER_LIST*>((ULONG64)GetModuleHandleA("ntdll.dll") + rva);
	printf("[+]ExceptionList\n");
	QueryList(LdrpVectorHandlerList,TRUE);
	printf("[+]ContinueList\n");
	QueryList(LdrpVectorHandlerList, FALSE);

	printf("\n");
	system("pause");
}

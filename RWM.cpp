#pragma once


#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include "RWM.h"


#pragma region ////////////////////////FUNCTIONS////////////////////////
DWORD RWM::DetourFunction(void* src, void* hkFunct, DWORD len)
{
	if (len < 5 || len > 250)
		 return 0xDEADBEEF;
	DWORD dwOldProt;
	byte* funct = new byte[len + 5];

	memcpy(&funct[0], src, len);
	*(byte*)(&funct[len]) = 0xE9;
	*(DWORD*)(&funct[len] + 1) = (DWORD)src - (DWORD)&funct[len];
	VirtualProtect((LPVOID)src, len + 5, PAGE_EXECUTE, &dwOldProt);

	VirtualProtect((LPVOID)src, len, PAGE_EXECUTE_READWRITE, &dwOldProt);
	memset((BYTE*)src, 0x90, len);

	*(BYTE*)src = 0xE9;//asm jump
	DWORD addr = (DWORD)hkFunct - (DWORD)src - 5;
	*(DWORD*)((DWORD)src + 1) = addr;

	VirtualProtect((LPVOID)src, len, dwOldProt, &dwOldProt);

	return (DWORD)&funct[0];
}
int RWM::GetRandom(int min, int max)
{
	return (rand() % (max - min) + min);
}
void RWM::MsgBoxA(DWORD addy)
{
	char szBuffer[1024];
	sprintf_s(szBuffer, "%02x", addy);
	MessageBoxA(NULL, (LPCSTR)szBuffer, NULL, MB_OK);
}
MODULEINFO RWM::GetModuleInfo(char *szModule)
{
	MODULEINFO modinfo = {0};
	HMODULE hModule = GetModuleHandle((LPCSTR)szModule);
	if(hModule == 0) 
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}
DWORD RWM::GetDMA(DWORD Base, DWORD offsets[], int level)
{
	DWORD Ptr = *(DWORD*)(Base);
	if(Ptr == 0) return NULL;

	for(int i = 0; i < level; i++)
	{
		if(i == level - 1)
		{
			Ptr = (DWORD)(Ptr+offsets[i]);
			if(Ptr == 0) return NULL;
			return Ptr;
		}
		else
		{
			Ptr = *(DWORD*)(Ptr+offsets[i]);
			if(Ptr == 0) return NULL;
		}
	}
	return Ptr;
}
DWORD RWM::FindPattern(char *module, char *pattern, char *mask)
{
	MODULEINFO mInfo = GetModuleInfo(module);
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size =  (DWORD)mInfo.SizeOfImage;

	DWORD patternLength = (DWORD)strlen(mask);

	for(DWORD i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for(DWORD j = 0; j < patternLength; j++)
		{
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
		}
		if(found) 
		{
			return base + i;
		}
	}

	return NULL;
} 
#pragma endregion

#pragma region /////////////////////////WRITING/////////////////////////
bool RWM::Write::Byte(DWORD address, byte value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(byte*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 1, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Word(DWORD address, WORD value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(WORD*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 2, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Dword(DWORD address, DWORD value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 4, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(DWORD*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 4, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Qword(DWORD address, __int64 value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 8, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(__int64*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 8, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Float(DWORD address, float value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 4, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(float*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 4, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Double(DWORD address, double value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 8, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(double*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 8, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Char(DWORD address, char value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, strlen(&value), PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(char*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, strlen(&value), dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Bool(DWORD address, bool value)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!(*(bool*)address = value)) return false;
	if(!VirtualProtect((LPVOID)address, 1, dwOldProt, &dwOldProt)) return false;
	return true;
}
bool RWM::Write::Bytes(uintptr_t address, char* value, int ammount)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, ammount, PAGE_EXECUTE_READWRITE, &dwOldProt)) return false;
	if(!memcpy((LPVOID)address, value, ammount)) return false;
	if(!VirtualProtect((LPVOID)address, ammount, dwOldProt, &dwOldProt)) return false;
	return true;
}
#pragma endregion

#pragma region /////////////////////////READING/////////////////////////
byte RWM::Read::Byte(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt)) return NULL;
	byte ret = *(byte*)address;
	if(!VirtualProtect((LPVOID)address, 1, dwOldProt, &dwOldProt)) return NULL;
	return ret;
}
WORD RWM::Read::Word(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &dwOldProt)) return 0xDEAD;
	WORD ret = *(WORD*)address;
	if(!VirtualProtect((LPVOID)address, 2, dwOldProt, &dwOldProt)) return 0xDEAD;
	return ret;
}
DWORD RWM::Read::Dword(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProt)) return 0xDEAD1;
	DWORD ret = *(DWORD*)address;
	if(!VirtualProtect((LPVOID)address, sizeof(DWORD), dwOldProt, &dwOldProt)) return 0xDEAD2;
	return ret;
}
__int64 RWM::Read::Qword(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 8, PAGE_EXECUTE_READWRITE, &dwOldProt)) return 0xDEADDEADDEADDEAD;
	__int64 ret = *(__int64*)address;
	if(!VirtualProtect((LPVOID)address, 8, dwOldProt, &dwOldProt)) return 0xDEADDEADDEADDEAD;
	return ret;
}
float RWM::Read::Float(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 4, PAGE_EXECUTE_READWRITE, &dwOldProt)) return 0xDEADDEAD;
	float ret = *(float*)address;
	if(!VirtualProtect((LPVOID)address, 4, dwOldProt, &dwOldProt)) return 0xDEADDEAD;
	return ret;
}
double RWM::Read::Double(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 8, PAGE_EXECUTE_READWRITE, &dwOldProt)) return 0xDEADDEAD;
	double ret = *(double*)address;
	if(!VirtualProtect((LPVOID)address, 8, dwOldProt, &dwOldProt)) return 0xDEADDEAD;
	return ret;
}
char* RWM::Read::Char(DWORD address, int ammount)
{
	unsigned long dwOldProt;
	char *ret;
	if(!VirtualProtect((LPVOID)address, ammount, PAGE_EXECUTE_READWRITE, &dwOldProt)) return "<ERROR 0xDEAD>";
	if(!memcpy(ret, (LPVOID)address, ammount)) return "<ERROR 0xDEAD>";
	if(!VirtualProtect((LPVOID)address, ammount, dwOldProt, &dwOldProt)) return "<ERROR 0xDEAD>";
	return ret;
}
bool RWM::Read::Bool(DWORD address)
{
	unsigned long dwOldProt;
	if(!VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt)) return NULL;
	bool ret = *(bool*)address;
	if(!VirtualProtect((LPVOID)address, 1, dwOldProt, &dwOldProt)) return NULL;
	return ret;
}
std::string RWM::Read::String(DWORD address)
{
	if (address < 0x400000)
		return "";
	return std::string((const char*)address); 
}  
#pragma endregion
#pragma warning(disable: 4996)

#include "RWM.cpp"
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <fstream>
#include <string>
#include <iostream>



#define X3_NOT_INITIALIZED 80000000;
#define SendChatMessage 0x00B389F0


typedef int(__stdcall* tX3Dispatch)(void*, uint32_t);
tX3Dispatch oX3Dispatch = nullptr;


RWM::Write write;

FILE * f;
bool handled = false;
bool open = true;
bool paused = false;
std::ofstream outfile;

#pragma region ------------------------------- Func Protos -------------------------------------
typedef void(__thiscall* tPrintChatMessage)(DWORD*, LPCSTR, LPCSTR, BYTE, bool, bool, BYTE);
typedef short(__cdecl* tSendChatMessage)(BYTE, LPCSTR, LPCSTR);
tPrintChatMessage oPrintChatMessage = reinterpret_cast<tPrintChatMessage>(0x00581AC0);
tSendChatMessage oSendChatMessage = nullptr;
short __cdecl hkSendChatMessage(BYTE bType, LPCSTR lpName, LPCSTR lpText);

typedef int(WINAPI * tSend)(SOCKET, LPCSTR, size_t, int);
typedef int(WINAPI * tRecv)(SOCKET, char*, size_t, int);
tSend oSend = nullptr;
tRecv oRecv = nullptr;
int WINAPI hkSend(SOCKET s, const char* data_out, size_t len, int flags);
int WINAPI hkRecv(SOCKET s, char* data_out, size_t len, int flags);



typedef char(__fastcall * tCrypt)(DWORD*, DWORD, LPCSTR, void *, size_t);
tCrypt oChooseEncryption48 = nullptr;
tCrypt oEncrypt16 = nullptr;
char __fastcall hkChooseEncryption48(DWORD * _thisptr, DWORD edx, LPCSTR src, void* dst, size_t size);
char __fastcall hkEncrypt16(DWORD* _thisptr, DWORD edx, LPCSTR src, void* dst, size_t size);


bool fileExists(const char* filename);
#pragma endregion

#pragma region -------------------------------- HKSend/Recv ------------------------------------
int WINAPI hkSend(SOCKET sock, LPCSTR buff, size_t len, int flags)
{
	void** ret = NULL;
	__asm { mov ret, ebp};

	if (!handled)
	{
		byte* buffer = new byte[4096];
		memcpy(&buffer[0], buff, len);

		if (open & !paused)
		{
			std::cout << "UNHANDLED PACKET (logged by send)" << std::endl;
			std::cout << "Return address: " << (void*)ret[1] << std::endl;
			std::cout << "Size:" << len << std::endl;
			std::cout << "Data: ";
		}
		outfile << "UNHANDLED PACKET (logged by send)" << std::endl;
		outfile << "Return address: " << (void*)ret[1] << std::endl;
		outfile << "Size:" << len;

		time_t rawtime;
		struct tm * timeinfo;
		char tbuff[80];

		time(&rawtime);
		timeinfo = localtime(&rawtime);

		strftime(tbuff, sizeof(tbuff), "%d-%m-%Y %I:%M:%S", timeinfo);

		outfile << std::endl << "Time: " << tbuff;
		outfile << std::endl << "Data: ";
		for (int i = 0; i < len; i++)
		{
			char temp[256];
			sprintf_s(temp, "%02x", buffer[i]);
			if (open & !paused)
				std::cout << temp << " ";
			outfile << temp << " ";
		}
		if (open & !paused)
			std::cout << std::endl << "ASCII: ";
		outfile << std::endl << "ASCII: ";
		for (int i = 0; i < len; i++)
		{
			if (isprint(buff[i]) || buff[i] == 0x0A)
			{
				if (open & !paused)
					std::cout << buff[i];
				outfile << buff[i];
			}
		}
		if (open & !paused)
			std::cout << std::endl << "------------------------------------------------------" << std::endl;

		outfile << std::endl << "------------------------------------------------------" << std::endl;
		delete[] buffer;
	}
	handled = false;
	return oSend(sock, buff, len, flags);
}


int WINAPI hkRecv(SOCKET s, char* data_out, size_t len, int flags)
{
	int _origreturn = oRecv(s, data_out, len, flags);
	
	if (_origreturn == SOCKET_ERROR)
		return SOCKET_ERROR;

	void** retaddr = NULL;
	__asm { mov retaddr, ebp};

	byte* buffer = new byte[len];
	memcpy(&buffer[0], data_out, _origreturn);

	if (open & !paused)
	{
		std::cout << "RECEIVED PACKET (logged by recv)" << std::endl;
		std::cout << "Return address: " << (void*)retaddr[1] << std::endl;
		std::cout << "Size:" << _origreturn << std::endl;
		std::cout << "Data: ";
	}
	outfile << "RECEIVED PACKET (logged by recv)" << std::endl;
	outfile << "Return address: " << (void*)retaddr[1] << std::endl;
	outfile << "Size:" << _origreturn;

	time_t rawtime;
	struct tm * timeinfo;
	char tbuff[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(tbuff, sizeof(tbuff), "%d-%m-%Y %I:%M:%S", timeinfo);

	outfile << std::endl << "Time: " << tbuff;
	outfile << std::endl << "Data: ";
	for (int i = 0; i < _origreturn; i++)
	{
		char temp[256];
		sprintf_s(temp, "%02x", buffer[i]);
		if (open & !paused)
			std::cout << temp << " ";
		outfile << temp << " ";
	}
	if (open & !paused)
		std::cout << std::endl << "ASCII: " << data_out;
	outfile << std::endl << "ASCII: " << data_out;
	if (open & !paused)
		std::cout << std::endl << "------------------------------------------------------" << std::endl;

	outfile << std::endl << "------------------------------------------------------" << std::endl;
	delete[] buffer;
	return _origreturn;
}

#pragma endregion

#pragma region -------------------------------- HK Crypto --------------------------------------
char __fastcall hkChooseEncryption48(DWORD * _thisptr, DWORD edx, LPCSTR src, void* dst, size_t size)
{
	byte * buff = new byte[4096];
	memcpy(&buff[0], src, size);
	if (open & !paused)
	{
		std::cout << "Size:" << size << std::endl;
		std::cout << "Data: ";
	}
	outfile << "Size:" << size << std::endl;

	time_t rawtime;
	struct tm * timeinfo;
	char tbuff[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(tbuff, sizeof(tbuff), "%d-%m-%Y %I:%M:%S", timeinfo);

	outfile << std::endl << "Time: " << tbuff;
	outfile << std::endl << "Data: ";
	for (int i = 0; i < size; i++)
	{
		char temp[256];
		sprintf_s(temp, "%02x", buff[i]);
		if (open & !paused)
			std::cout << temp << " ";
		outfile << temp << " ";
	}
	std::cout << std::endl << "ASCII: ";
	outfile << std::endl << "ASCII: ";
	for (int i = 0; i < size; i++)
	{
		if (isprint(src[i]) || src[i] == 0x0A)
		{
			if (open & !paused)
				std::cout << src[i];
			outfile << src[i];
		}
	}
	if (open & !paused)
		std::cout << std::endl << "------------------------------------------------------" << std::endl;
	outfile << std::endl << "------------------------------------------------------" << std::endl;

	delete[] buff;
	handled = true;
	return oChooseEncryption48(_thisptr, edx, src, dst, size);
}

char __fastcall hkEncrypt16(DWORD* _thisptr, DWORD edx, LPCSTR src, void* dst, size_t size)
{
	byte * buff = new byte[4096];
	memcpy(&buff[0], src, size);
	if (open & !paused)
	{
		std::cout << "Size:" << size << std::endl;
		std::cout << "Data: ";
	}
	outfile << "Size:" << size;

	time_t rawtime;
	struct tm * timeinfo;
	char tbuff[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(tbuff, sizeof(tbuff), "%d-%m-%Y %I:%M:%S", timeinfo);

	outfile << std::endl << "Time: " << tbuff;
	outfile << std::endl << "Data: ";
	for (int i = 0; i < size; i++)
	{
		char temp[256];
		sprintf_s(temp, "%02x", buff[i]);
		if (open & !paused)
			std::cout << temp << " ";
		outfile << temp << " ";
	}
	std::cout << std::endl << "ASCII: ";
	outfile << std::endl << "ASCII: ";
	for (int i = 0; i < size; i++)
	{
		if (isprint(src[i]) || src[i] == 0x0A)
		{
			if (open & !paused)
				std::cout << src[i];
			outfile << src[i];
		}
	}
	if (open & !paused)
		std::cout << std::endl << "------------------------------------------------------" << std::endl;
	outfile << std::endl << "------------------------------------------------------" << std::endl;

	delete[] buff;
	handled = true;
	return oEncrypt16(_thisptr, edx, src, dst, size);
}
#pragma endregion

#pragma region ----------------------------- CChat/ Commands -----------------------------------
short __cdecl hkSendChatMessage(BYTE bType, LPCSTR lpName, LPCSTR lpText)
{
	if (strcmp(lpText, "/wpe open") == 0)
	{
		if (!open)
		{
			open = true;
			AllocConsole();
			freopen_s(&f, "CONOUT$", "w", stdout);
			std::cout << "                              REAL PACKET LOGGER" << std::endl << std::endl;

			oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE opened.", lpName, 10, true, false, 1);
		}
		else
			oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE is already open.", lpName, 10, true, false, 1);
		return 0;
	}
	else if (strcmp(lpText, "/wpe close") == 0)
	{
		if (open)
		{
			open = false;
			paused = true;
			oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE closed.", lpName, 10, true, false, 1);
		}
		else
			oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE is already closed.", lpName, 10, true, false, 1);

		return 0;
	}
	else if (strcmp(lpText, "/wpe start") == 0)
	{
		if (open)
			paused = false;

		oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE started.", lpName, 10, true, false, 1);
		return 0;
	}
	else if (strcmp(lpText, "/wpe stop") == 0)
	{
		if (open)
			paused = true;

		oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE paused", lpName, 10, true, false, 1);
		return 0;
	}
	else if (strcmp(lpText, "/wpe cls") == 0)
	{
		if (open)
		{
			AllocConsole();
			std::cout << "                              REAL PACKET LOGGER" << std::endl << std::endl;
		}

		oPrintChatMessage((DWORD*)*(DWORD*)(0x011B95A8 + 0x108), "WPE's screen cleared.", lpName, 10, true, false, 1);
		return 0;
	}


	return oSendChatMessage(bType, lpName, lpText);
}
#pragma endregion


bool fileExists(const char* fileName)
{
	std::ifstream test(fileName);
	bool retaddr = (test) ? true : false;
	test.close();
	return retaddr;
}


unsigned __stdcall Main()
{
	MessageBeep(1000);
	int i = 0;
	while (fileExists(std::string("log" + std::to_string(i) + ".tho").c_str()))
		i++;
	outfile.open("log" + std::to_string(i) + ".tho", std::fstream::out);
	if (open)
	{
		AllocConsole();
		freopen_s(&f, "CONOUT$", "w", stdout);
		std::cout << "                              REAL PACKET LOGGER" << std::endl << std::endl;
	}


	write.Bytes(0x00F0DFB8, "\x90\x90", 2);


	HMODULE hmd = GetModuleHandle("Ws2_32.dll");

	void* addr = (void*)GetProcAddress(hmd, "send");
	oSend = reinterpret_cast<tSend>(RWM::DetourFunction((void*)addr, hkSend, 5));

	addr = (void*)GetProcAddress(hmd, "recv");
	oRecv = reinterpret_cast<tRecv>(RWM::DetourFunction((void*)addr, hkRecv, 5));

	oChooseEncryption48 = reinterpret_cast<tCrypt>(RWM::DetourFunction((void*)(0x00E07610), hkChooseEncryption48, 7));
	oEncrypt16 = reinterpret_cast<tCrypt>(RWM::DetourFunction((void*)(0x00E07650), hkEncrypt16, 5));
	
	
	oSendChatMessage = reinterpret_cast<tSendChatMessage>(RWM::DetourFunction((void*)SendChatMessage, hkSendChatMessage, 5));
	

	return 0;
}


__declspec(dllexport) int32_t __stdcall x3_1(void* func, uint32_t type)
{
	if (oX3Dispatch)
		return oX3Dispatch(func, type);

	std::string Path;
	Path.resize(MAX_PATH);

	if (!GetModuleFileNameA(NULL, const_cast<LPSTR>(Path.data()), MAX_PATH))
	{
		MessageBoxA(NULL, "GetModuleFileNameA failed!", "Error", 0);
		return X3_NOT_INITIALIZED;
	}

	HMODULE hX3;
	if (!(hX3 = LoadLibraryW(L"XIGNCODE\\x3.dummy")))
	{
		MessageBoxA(NULL, "LoadLibraryW failed!", "Error", 0);
		return X3_NOT_INITIALIZED;
	}

	if (!(oX3Dispatch = reinterpret_cast<tX3Dispatch>(GetProcAddress(hX3, reinterpret_cast<LPCSTR>(1)))))
	{
		MessageBoxA(NULL, "GetProcAddress failed!", "Error", 0);
		return X3_NOT_INITIALIZED;
	}

	Main();


	return oX3Dispatch(func, type);
}
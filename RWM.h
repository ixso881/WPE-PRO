
class RWM 
{
public:
	struct Write 
	{
		static bool Byte(DWORD address, byte value);
		static bool Word(DWORD address, WORD value);
		static bool Dword(DWORD address, DWORD value);
		static bool Qword(DWORD address, __int64 value);
		static bool Float(DWORD address, float value);
		static bool Double(DWORD address, double value);
		static bool Char(DWORD address, char value);
		static bool Bool(DWORD address, bool value);
		static bool Bytes(uintptr_t address, char* value, int ammount);
	};
	struct Read 
	{
		static byte Byte(DWORD address);
		static WORD Word(DWORD address);
		static DWORD Dword(DWORD address);
		static __int64 Qword(DWORD address);
		static float Float(DWORD address);
		static double Double(DWORD address);
		static char* Char(DWORD address, int ammount);
		static bool Bool(DWORD address);
		static std::string String(DWORD address);
	};
	static DWORD GetDMA(DWORD Base, DWORD offsets[], int level);
	static DWORD FindPattern(char *module, char *pattern, char *mask); // example FindPattern("Process.exe", "\xE9\x01\x54\x21\xDF", "x????");
	static MODULEINFO GetModuleInfo(char *szModule);
	static void MsgBoxA(DWORD addy);
	static int GetRandom(int min, int max);
	static DWORD DetourFunction(void* src, void* hkFunct, DWORD len);
};

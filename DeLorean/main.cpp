#if defined(UNICODE)
	#error "Please disable the UNICODE character set from the project settings"
#endif

#include <windows.h>

bool __stdcall DllMain(HINSTANCE instance, unsigned long int reason, void *reserved)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{
			MessageBox(NULL, "Hey!", "Placeholder", MB_OK | MB_ICONWARNING);
			return true;
		}

		default:
			return true;
	}
}

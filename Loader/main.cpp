#if defined(UNICODE)
	#error "Please disable the UNICODE character set from the project settings"
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <string>
#include <stdexcept>
#include <algorithm>

int main(int argc, char *argv[]);
void Usage(const char *executable_path);
bool GetProgramFolder(std::string & path);
bool GetParentFolderFromPath(const std::string & path, std::string & folder);
bool GetModulePath(std::string & path);
bool GetModuleBaseAddress(unsigned long process_id, const std::string & module_name, unsigned char **base_address);
bool GetExportedSymbolRVA(const std::string & module_name, const std::string symbol_name, unsigned long int & symbol_rva);
bool GetRemoteProcAddress(unsigned long process_id, const std::string & module_name, const std::string & symbol_name, unsigned char **symbol_address);
bool CreateRemoteString(const std::string & content, HANDLE process, unsigned char **remote_buffer);
bool InjectModule(PROCESS_INFORMATION process_info, bool resume_process);

int main(int argc, char *argv[])
{
	PROCESS_INFORMATION process_info = { 0 };

	// cleanup routine
	auto L_ReleaseProcessHandles = [&process_info]() -> void
	{
		if (process_info.hProcess != NULL)
			CloseHandle(process_info.hProcess);

		if (process_info.hThread != NULL)
			CloseHandle(process_info.hThread);
	};

	try
	{
		//
		// unknown argument(s)
		//

		if (argc <= 1)
		{
			Usage(argv[0]);
			return 1;
		}

		//
		// attach to a running process
		//

		else if (strcmp(argv[1], "-a") == 0)
		{
			if (argc != 3)
			{
				std::cout << "Invalid parameter: missing process id" << std::endl;
				Usage(argv[0]);
				return 1;
			}

			std::cout << "Attaching to process \"" << argv[2] << "\"...";
			process_info.dwProcessId = atoi(argv[2]);

			process_info.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_info.dwProcessId);
			if (process_info.hProcess == NULL)
				throw std::runtime_error("Failed to attach to the specified process");
		}

		//
		// create a new process
		//

		else if (strcmp(argv[1], "-s") == 0)
		{
			if (argc < 3)
			{
				std::cout << "Invalid parameter: you have to specify the executable path" << std::endl;
				Usage(argv[0]);
				return 1;
			}

			// get the working directory
			STARTUPINFO startup_info;
			startup_info.cb = sizeof(STARTUPINFO);
			GetStartupInfo(&startup_info);

			std::string working_directory;
			if (!GetParentFolderFromPath(argv[2], working_directory))
				throw std::runtime_error("Invalid parameter: the executable path is invalid");

			// build the command line
			std::string command_line = std::string("\"") + argv[2] + "\"";

			if (argc > 3)
			{
				for (int i = 3; i < argc; i++)
				{
					command_line += " ";
					command_line += argv[i];
				}
			}

			std::cout << "Command line: " << command_line << std::endl;
			std::cout << "Working directory: " << working_directory << std::endl;

			std::cout << "Creating the process..." << std::endl;
			if (CreateProcess(NULL, &command_line[0], NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, working_directory.data(), &startup_info, &process_info) == 0)
				throw std::runtime_error("Failed to create the process");

			// wait for the system breakpoint
			while (true)
			{
				DEBUG_EVENT debug_event;
				if (WaitForDebugEvent(&debug_event, INFINITE) == 0)
					throw std::runtime_error("Failed to debug the process");

				if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
					break;

				if (ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE) == 0)
					throw std::runtime_error("Failed to resume the process");
			}
		}

		// inject the module
		if (!InjectModule(process_info, process_info.hThread != NULL))
			throw std::runtime_error("Failed to inject the module inside the process");

		L_ReleaseProcessHandles();
		return 0;
	}

	catch (std::runtime_error & exception)
	{
		std::cout << "An error has occurred:" << std::endl << exception.what() << std::endl;

		L_ReleaseProcessHandles();
		return 1;
	}
}

void Usage(const char *executable_path)
{
	const char *executable_name = strrchr(executable_path, '\\');
	if (executable_name == NULL)
		executable_name = executable_path;
	else
		executable_name++;

	std::cout << "DeLorean Loader" << std::endl;
	std::cout << "Website: http://alessandrogar.io" << std::endl << std::endl;
	std::cout << "Usage:" << std::endl;
	std::cout << "\tStart a new process" << std::endl;
	std::cout << "\t" << executable_name << " -r <executable_path> [arguments]" << std::endl << std::endl;
	std::cout << "\tAttach to an existing process" << std::endl;
	std::cout << "\t" << executable_name << " -a <process_id>" << std::endl;
}

bool GetProgramFolder(std::string & path)
{
	// get the folder where the user has saved the executable
	HANDLE process = (HANDLE) GetCurrentProcess();
	if (process == NULL)
		return false;

	unsigned long int buffer_size = MAX_PATH + 1;

	path.resize(buffer_size);
	if (path.size() != buffer_size)
		return false;

	if (QueryFullProcessImageName(process, 0, &path[0], &buffer_size) == 0)
	{
		int error_code = GetLastError();
		return false;
	}

	std::string parent_folder;
	if (!GetParentFolderFromPath(path, parent_folder))
		return false;

	path = parent_folder;
	return true;
}

bool GetParentFolderFromPath(const std::string & path, std::string & folder)
{
	// get the parent folder for the given path
	folder = std::string(path);
	if (folder[folder.size() - 1] == '\\')
		folder.resize(folder.size() - 1);

	std::string::size_type delimiter_index = folder.rfind("\\");
	if (delimiter_index == std::string::npos || delimiter_index < 2)
		return false;

	if (folder[delimiter_index - 1] == ':')
		return true;

	folder.resize(delimiter_index);
	return true;
}

bool GetModulePath(std::string & path)
{
	// get the path for the delorean library
	if (!GetProgramFolder(path))
		return false;

	path += std::string("\\DeLorean.dll");
	return true;
}

bool GetModuleBaseAddress(unsigned long process_id, const std::string & module_name, unsigned char **base_address)
{
	// enumerate the modules inside the given process, and get the base address for the specified image
	HANDLE process_snapshot;

	for (int i = 0; i < 10; i++)
	{
		process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
		if (process_snapshot != NULL)
			break;

		if (GetLastError() != ERROR_BAD_LENGTH)
			return false;

		Sleep(100);
	}

	MODULEENTRY32 current_module = { 0 };
	bool found = false;

	while (true)
	{
		if (current_module.dwSize == 0)
		{
			current_module.dwSize = sizeof (MODULEENTRY32);

			if (!Module32First(process_snapshot, &current_module))
				break;
		}
		else
		{
			if (!Module32Next(process_snapshot, &current_module))
			{
				CloseHandle(process_snapshot);
				break;
			}
		}

		auto L_SearchPredicate = [](char left, char right)
		{
			return (toupper(left) == toupper(right));
		};

		std::string current_module_path = current_module.szExePath;
		if (std::search(current_module_path.begin(), current_module_path.end(), module_name.begin(), module_name.end(), L_SearchPredicate) == current_module_path.end())
			continue;

		*base_address = static_cast<unsigned char *>(current_module.modBaseAddr);
		found = true;

		break;
	}

	CloseHandle(process_snapshot);
	return found;
}

bool GetExportedSymbolRVA(const std::string & module_name, const std::string symbol_name, unsigned long int & symbol_rva)
{
	// use the windows loader to extract the rva for the specified symbol; keep in mind that this
	// only works for
	// 1. modules inside our PATH
	// 2. images that can be loaded inside our address space (i.e.: you can't mix x64 and x86)
	HMODULE module = LoadLibrary(module_name.data());
	if (module == NULL)
		return false;

	unsigned char *symbol_address = (unsigned char *) GetProcAddress(module, symbol_name.data());
	if (symbol_address == NULL)
		return false;

	symbol_rva = (unsigned long int) (symbol_address - (unsigned char *) module);
	FreeLibrary(module);

	return true;
}

bool GetRemoteProcAddress(unsigned long process_id, const std::string & module_name, const std::string & symbol_name, unsigned char **symbol_address)
{
	// get the virtual address for the specified symbol
	unsigned long int symbol_rva;
	if (!GetExportedSymbolRVA(module_name.data(), symbol_name.data(), symbol_rva))
		return false;

	unsigned char *module_base_address;
	if (!GetModuleBaseAddress(process_id, module_name.data(), &module_base_address))
		return false;
	
	*symbol_address = module_base_address + symbol_rva;
	return true;
}

bool CreateRemoteString(const std::string & content, HANDLE process, unsigned char **remote_buffer)
{
	// allocate a buffer inside the specified process, and fill it with the given data
	unsigned char *allocated_buffer = (unsigned char *) VirtualAllocEx(process, NULL, content.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocated_buffer == NULL)
		return false;

	SIZE_T written_bytes;
	if (WriteProcessMemory(process, allocated_buffer, content.data(), content.size() + 1, &written_bytes) == 0)
	{
		VirtualFreeEx(process, (LPVOID) allocated_buffer, 0, MEM_RELEASE);
		return false;
	}

	*remote_buffer = allocated_buffer;
	return true;
}

bool InjectModule(PROCESS_INFORMATION process_info, bool resume_process)
{
	// get the address of LoadLibraryA
	unsigned char *loadlibrarya_address;
	if (!GetRemoteProcAddress(process_info.dwProcessId, "Kernel32.dll", "LoadLibraryA", &loadlibrarya_address))
		return false;

	// get the module path
	std::string module_path;
	if (!GetModulePath(module_path))
		return false;

	// write the library path inside the process
	unsigned char *remote_buffer;
	if (!CreateRemoteString(module_path, process_info.hProcess, &remote_buffer))
		return false;

	//
	// inject the module
	//

	HANDLE remote_thread = NULL;

	auto L_CleanUp = [&process_info, &remote_buffer, &remote_thread]() -> void
	{
		VirtualFreeEx(process_info.hProcess, remote_buffer, 0, MEM_RELEASE);

		if (remote_thread != NULL)
			CloseHandle(remote_thread);
	};	

	try
	{
		remote_thread = CreateRemoteThread(process_info.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) loadlibrarya_address, remote_buffer, 0, NULL);
		if (remote_thread == NULL)
			throw 1;
		
		if (resume_process)
		{
			if (DebugSetProcessKillOnExit(false) == 0)
				throw 1;

			if (DebugActiveProcessStop(process_info.dwProcessId) == 0)
				throw 1;
		}

		// wait for the thread to terminate
		if (WaitForSingleObject(remote_thread, INFINITE) != WAIT_OBJECT_0)
			throw 1;

		unsigned long int thread_status;
		if (GetExitCodeThread(remote_thread, &thread_status) == 0)
			throw 1;

		if (thread_status == 0)
			throw 1;

		L_CleanUp();
		return true;
	}

	catch (...)
	{
		L_CleanUp();
		return false;
	}
}

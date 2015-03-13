#include <windows.h>
#include "hook.h"

//
// HookException class
//

HookException::HookException(ExceptionCode exception_code, bool critical_error) : exception_code(exception_code), critical_error(critical_error), std::runtime_error(exceptionCodeToString(exception_code))
{
}

HookException::~HookException()
{
}

const char *HookException::what() const
{
	return exceptionCodeToString(exception_code);
}

HookException::ExceptionCode HookException::getExceptionCode() const
{
	return exception_code;
}

bool HookException::isCriticalError() const
{
	return critical_error;
}

const char *HookException::exceptionCodeToString(ExceptionCode exception_code)
{
	switch (exception_code)
	{
		case ExceptionCode::NotConfigured:
			return "NotConfigured";

		case ExceptionCode::NotEnabled:
			return "NotEnabled";

		case ExceptionCode::BridgeNotGenerated:
			return "BridgeNotGenerated";

		case ExceptionCode::HookIsAlreadyEnabled:
			return "HookIsAlreadyEnabled";

		case ExceptionCode::HookIsAlreadyDisabled:
			return "HookIsAlreadyDisabled";

		case ExceptionCode::DisassemblerInitializationError:
			return "DisassemblerInitializationError";

		case ExceptionCode::FailedToDisassemble:
			return "FailedToDisassemble";

		case ExceptionCode::TargetMemoryProtectionError:
			return "TargetMemoryProtectionError";

		case ExceptionCode::BridgeMemoryProtectionError:
			return "BridgeMemoryProtectionError";

		case ExceptionCode::UnknownError:
		default:
			return "UnknownError";
	}
}

//
// Hook class
//

Hook::Hook(void *target, void *filter) : target(target), filter(filter)
{
	enabled = false;

#if defined(_M_IX86)
	cs_mode disasm_mode = CS_MODE_32;

#elif defined(_M_AMD64)
	cs_mode disasm_mode = CS_MODE_64;

#else
	#error Unsupported architecture
#endif

	if (cs_open(CS_ARCH_X86, disasm_mode, &disassembler) != CS_ERR_OK)
		throw HookException(HookException::ExceptionCode::DisassemblerInitializationError, true);
}

Hook::~Hook()
{
	if (enabled)
		disable();

	cs_close(&disassembler);
}

void Hook::configure(void *target, const void *filter)
{
	if (enabled)
		throw HookException(HookException::ExceptionCode::HookIsAlreadyEnabled, false);

	this->target = target;
	this->filter = filter;
}

bool Hook::isEnabled() const
{
	return enabled;
}

void Hook::enable()
{
	if (enabled)
		throw HookException(HookException::ExceptionCode::HookIsAlreadyEnabled, false);

	if (target == nullptr || filter == nullptr)
		throw HookException(HookException::ExceptionCode::NotConfigured, false);

	// generate the hook
	std::vector<unsigned char> hook;
	generateHook(hook, target, filter);

	// determine the bridge length
	unsigned int bridge_size = 0;
	unsigned char *current_opcode = static_cast<unsigned char *>(target);

	while (bridge_size < hook.size())
	{
		cs_insn *instruction;
		size_t instruction_count = cs_disasm(disassembler, current_opcode, 15, reinterpret_cast<uint64_t>(current_opcode), 1, &instruction);
		if (instruction_count <= 0)
			throw HookException(HookException::ExceptionCode::FailedToDisassemble, false);

		bridge_size += instruction->size;
		current_opcode += instruction->size;

		cs_free(instruction, 1);
	}

	// make a backup of the function prologue
	original_function_prologue.resize(bridge_size);
	for (unsigned int i = 0; i < bridge_size; i++)
		original_function_prologue.data()[i] = static_cast<unsigned char *>(target)[i];

	// make sure we can write to the destination memory
	unsigned long int original_memory_protection;
	if (VirtualProtect(target, bridge_size, PAGE_EXECUTE_READWRITE, (PDWORD) &original_memory_protection) == 0)
		throw HookException(HookException::ExceptionCode::TargetMemoryProtectionError, false);

	// write the hook
	for (std::vector<unsigned char>::size_type i = 0; i < hook.size(); i++)
		static_cast<unsigned char *>(target)[i] = hook.data()[i];

	enabled = true;

	// restore the previous memory protection
	if (VirtualProtect(target, bridge_size, original_memory_protection, (PDWORD) &original_memory_protection) == 0)
		throw HookException(HookException::ExceptionCode::TargetMemoryProtectionError, true);

	FlushInstructionCache(GetCurrentProcess(), target, bridge_size);

	// allocate the bridge buffer
	bridge.resize(bridge_size + hook.size());

	// generate the bridge jump
	generateHook(hook, bridge.data() + bridge_size, static_cast<unsigned char *>(target) + bridge_size);

	// generate the bridge
	unsigned char *bridge_ptr = bridge.data();
	for (unsigned int i = 0; i < bridge_size; i++)
	{
		*bridge_ptr = original_function_prologue.data()[i];
		bridge_ptr++;
	}

	for (std::vector<unsigned char>::size_type i = 0; i < hook.size(); i++)
	{
		*bridge_ptr = hook.data()[i];
		bridge_ptr++;
	}

	// make sure the bridge can be executed
	if (VirtualProtect(bridge.data(), bridge.size(), PAGE_EXECUTE_READWRITE, (PDWORD) &original_memory_protection) == 0)
	{
		bridge.clear();
		throw HookException(HookException::ExceptionCode::BridgeMemoryProtectionError, true);
	}

	FlushInstructionCache(GetCurrentProcess(), bridge.data(), bridge.size());
}

void Hook::disable()
{
	if (!enabled)
		throw HookException(HookException::ExceptionCode::HookIsAlreadyDisabled, false);

	unsigned long int original_memory_protection;
	if (VirtualProtect(target, original_function_prologue.size(), PAGE_EXECUTE_READWRITE, (PDWORD) &original_memory_protection) == 0)
		throw HookException(HookException::ExceptionCode::TargetMemoryProtectionError, false);

	unsigned char *destination = static_cast<unsigned char *>(target);
	for (std::vector<unsigned char>::size_type i = 0; i < original_function_prologue.size(); i++)
		destination[i] = original_function_prologue.data()[i];

	enabled = false;

	if (VirtualProtect(target, original_function_prologue.size(), original_memory_protection, (PDWORD) &original_memory_protection) == 0)
		throw HookException(HookException::ExceptionCode::TargetMemoryProtectionError, false);

	bridge.clear();
	original_function_prologue.clear();
}

const void *Hook::getBridge() const
{
	if (!enabled)
		throw HookException(HookException::ExceptionCode::NotEnabled, false);

	if (bridge.size() == 0)
		throw HookException(HookException::ExceptionCode::BridgeNotGenerated, true);

	return bridge.data();
}

void Hook::generateHook(std::vector<unsigned char> & hook, const void *position, const void *destination)
{
	const unsigned char *opcode_position = reinterpret_cast<const unsigned char *>(position);
	const unsigned char *jump_destination = reinterpret_cast<const unsigned char *>(destination);

#if defined(_M_IX86)
	hook.resize(5);

	hook.data()[0] = 0xE9;
	reinterpret_cast<unsigned long int *>(hook.data() + 1)[0] = jump_destination - opcode_position - 5;

#else
	// todo: add the x64 code
	#error Unsupported architecture
#endif
}

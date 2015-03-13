#ifndef HOOK_H
#define HOOK_H

#include <stdexcept>
#include <vector>

#include <capstone.h>

class HookException final : public std::runtime_error
{
public:
	enum class ExceptionCode
	{
		NotConfigured,
		NotEnabled,
		BridgeNotGenerated,
		HookIsAlreadyEnabled,
		HookIsAlreadyDisabled,
		DisassemblerInitializationError,
		FailedToDisassemble,
		TargetMemoryProtectionError,
		BridgeMemoryProtectionError,
		UnknownError
	};

private:
	ExceptionCode exception_code;
	bool critical_error;

public:
	HookException(ExceptionCode exception_code, bool critical_error);
	virtual ~HookException();

	virtual const char *what() const;
	ExceptionCode getExceptionCode() const;
	bool isCriticalError() const;

	static const char *exceptionCodeToString(ExceptionCode exception_code);
};

class Hook final
{
private:
	bool enabled;
	csh disassembler;

	std::vector<unsigned char> original_function_prologue;
	std::vector<unsigned char> bridge;

	void *target;
	const void *filter;

public:
	Hook(void *target = nullptr, void *filter = nullptr);
	~Hook();

	void configure(void *target, const void *filter);

	bool isEnabled() const;
	void enable();
	void disable();

	const void *getBridge() const;

private:
	static void generateHook(std::vector<unsigned char> & hook, const void *position, const void *destination);
};

#endif // HOOK_H

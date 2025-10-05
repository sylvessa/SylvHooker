# SylvHooker

the goal of this is to make a tiny portable function hooker that works on as many windows version as possible whilst remaining purely independent, not relying on any other libraries, and does everything basically as raw as it can.

tested from as far back as NT 4.0 (1996) and as new as Windows 11 (2021).

in theory should work as far back as NT 3.1

Contributions are welcome.

## features

- create inline trampolines for functions and function pointers
- automatic prologue length calculation
- x86 app support, x64 app support too but x64 hasnt been tested
- ability to disable hooks
- minimal dependency surface

## examples

### hooking a function pointer

```cpp
#include <windows.h>
#include <iostream>
#include "SylvHooker.h"

// original function
int add(int a, int b) { return a + b; }

// detour function
int add_detour(int a, int b) { return a + b + 100; }

int main()
{
	void* funcPtr = (void*)add;
	void* detPtr = (void*)add_detour;

	SylvHooker::CreateHook((void*&)funcPtr, detPtr);
	SylvHooker::CommitHooks();

	int result = ((int(*)(int,int))funcPtr)(2,3); // calls detour -> returns 105
	std::cout << "Result: " << result << std::endl;

	SylvHooker::Uninitialize();
	return 0;
}
```

### hooking a winapi func

```cpp
#include <windows.h>
#include <iostream>
#include "SylvHooker.h"

namespace WinAPI {
	inline HMODULE hUser32 = GetModuleHandleA("user32.dll");
	inline decltype(&MessageBoxA) oMessageBoxA = reinterpret_cast<decltype(&MessageBoxA)>(GetProcAddress(hUser32, "MessageBoxA"));
}

int WINAPI MessageBoxA_hook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	std::cout << "MESSAGEBOX GOT: " << lpText << " | " << lpCaption << std::endl;
	return WinAPI::oMessageBoxA(hWnd, lpText, lpCaption, uType);
}

int main()
{
	SylvHooker::CreateHook((void*&)WinAPI::oMessageBoxA, (void*)MessageBoxA_hook);
	SylvHooker::CommitHooks();

	MessageBoxA(NULL, "Hello", "World", MB_OK);

	SylvHooker::Uninitialize();
	return 0;
}
```

## API

- `bool SylvHooker::CreateHook(void*& target, void* detour, size_t overwriteLen = 0)` (overwriteLen is optional, use it if length calculation fails, but it shouldnt)
- `bool SylvHooker::CommitHooks()`
- `bool SylvHooker::EnableHook(void* target)`
- `bool SylvHooker::DisableHook(void* target)`
- `bool SylvHooker::RemoveHook(void* target)`
- `bool SylvHooker::Uninitialize()`
- `SylvHooker::debug` / `SylvHooker::debug2` for logging. `debug` = minimal logging, `debug2` = extensive logging

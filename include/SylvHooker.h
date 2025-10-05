#pragma once
#include <vector>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include "windows.h"

using std::memcpy;

struct HookEntry
{
	void* target = nullptr;
	void* detour = nullptr;
	void* trampoline = nullptr;
	std::vector<uint8_t> origBytes;
	size_t overwriteLen = 0;
	bool enabled = false;
};

class SylvHooker
{
public:
	// Minimal logging
	static bool debug;

	// Extensive logging
	static bool debug2;

	// Removes all hooks and cleans up
	static bool Uninitialize();

	// Creates a hook for the given target -> detour. 
	// overwriteLen is optional, use if length calc fails
	static bool CreateHook(void*& target, void* detour, size_t overwriteLen = 0);

	// Commits all created hooks (actually writes the jmp)
	static bool CommitHooks();

	// Enables a previously created hook
	static bool EnableHook(void* target);

	// Disabled a previous enabled hook
	static bool DisableHook(void* target);

	// Removes a previously created hook
	static bool RemoveHook(void* target);

	// Internal, but you can use if you want
	static std::string FormatString(const char* format, ...);
private:
	static std::unordered_map<void*, HookEntry> g_hooks;
};
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
	static bool debug;
	static bool debug2;

	static bool Uninitialize();
	static bool CreateHook(void*& target, void* detour, size_t overwriteLen = 0);
	static bool CommitHooks();
	static bool EnableHook(void* target);
	static bool DisableHook(void* target);
	static bool RemoveHook(void* target);

private:
	static std::unordered_map<void*, HookEntry> g_hooks;
};
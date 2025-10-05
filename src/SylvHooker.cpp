#include "SylvHooker.h"

bool SylvHooker::debug = false;
bool SylvHooker::debug2 = false; // truly extensive logging

std::unordered_map<void*, HookEntry> SylvHooker::g_hooks;

std::string FormatString(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	return std::string(buffer);
}

static bool WriteMemory(void* addr, const void* data, size_t len)
{
	if (SylvHooker::debug2) 
		std::cout << FormatString("WriteMemory called: addr=%p, len=%zu, data=%p", addr, len, data) << std::endl; 

	DWORD old;
	if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) {
		if (SylvHooker::debug2) 
			std::cerr << "WriteMemory: VirtualProtect failed!" << std::endl;
		return false;
	}

	std::memcpy(addr, data, len);
	DWORD tmp;
	VirtualProtect(addr, len, old, &tmp);
	FlushInstructionCache(GetCurrentProcess(), addr, len);

	if (SylvHooker::debug2) 
	{
		std::cout << FormatString("WriteMemory: wrote %zu bytes to %p", len, addr) << std::endl;

		std::string bytes;
		for (size_t i = 0; i < len; ++i)
			bytes += FormatString("%02X ", ((uint8_t*)addr)[i]);
		std::cout << FormatString("Memory at %p: %s", addr, bytes.c_str()) << std::endl;
	}
	return true;
}


static void* AllocTrampoline(size_t size)
{
	void* p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (SylvHooker::debug)
		std::cout << FormatString("Allocated trampoline at %p (%zu bytes)", p, size) << std::endl;

	return p;
}

static bool MakeRelJump(void* src, void* dst)
{
	if (SylvHooker::debug2) 
		std::cout << FormatString("MakeRelJump: src=%p, dst=%p", src, dst) << std::endl;

	if (sizeof(void*) == 4)
	{
		uint8_t buf[5];
		int32_t rel = (int32_t)((uint8_t*)dst - ((uint8_t*)src + 5));
		buf[0] = 0xE9;
		std::memcpy(buf + 1, &rel, 4);
		if (SylvHooker::debug2) 
			std::cout << FormatString("MakeRelJump (32-bit): rel=%x", rel) << std::endl;
		return WriteMemory(src, buf, 5);
	}
	else
	{
		uint8_t buf[14];
		buf[0] = 0x48;
		buf[1] = 0xB8;
		std::memcpy(buf + 2, &dst, 8);
		buf[10] = 0xFF;
		buf[11] = 0xE0;
		buf[12] = 0x90;
		buf[13] = 0x90;
		if (SylvHooker::debug2) 
		{
			std::string hex;
			for (int i = 0; i < 14; ++i)
				hex += FormatString("%02X ", buf[i]);
			std::cout << FormatString("MakeRelJump (64-bit): buf=%s", hex.c_str()) << std::endl;
		}
		return WriteMemory(src, buf, 14);
	}
}

static bool WriteRelJumpToBuffer(uint8_t* dstBuf, void* fromAddr, void* toAddr)
{
	if (SylvHooker::debug2) 
		std::cout << FormatString("WriteRelJumpToBuffer: dstBuf=%p, fromAddr=%p, toAddr=%p", dstBuf, fromAddr, toAddr) << std::endl;

	if (sizeof(void*) == 4)
	{
		dstBuf[0] = 0xE9;
		int32_t rel = (int32_t)((uint8_t*)toAddr - ((uint8_t*)fromAddr + 5));
		std::memcpy(dstBuf + 1, &rel, 4);
		if (SylvHooker::debug2) 
			std::cout << FormatString("WriteRelJumpToBuffer (32-bit): rel=%x", rel) << std::endl;
		return true;
	}
	else
	{
		dstBuf[0] = 0x48;
		dstBuf[1] = 0xB8;
		std::memcpy(dstBuf + 2, &toAddr, 8);
		dstBuf[10] = 0xFF;
		dstBuf[11] = 0xE0;
		dstBuf[12] = 0x90;
		dstBuf[13] = 0x90;
		if (SylvHooker::debug2) 
		{
			std::string hex;
			for (int i = 0; i < 14; ++i)
				hex += FormatString("%02X ", dstBuf[i]);
			std::cout << FormatString("WriteRelJumpToBuffer (64-bit): buf=%s", hex.c_str()) << std::endl;
		}
		return true;
	}
}

size_t CalculateInstructionLength(void* func, size_t minBytes)
{
	if (SylvHooker::debug2) 
		std::cout << FormatString("CalculateInstructionLength: func=%p, minBytes=%zu", func, minBytes) << std::endl;

	uint8_t* ptr = (uint8_t*)func;
	size_t len = 0;
	int inst_num = 0;

	while (len < minBytes)
	{
		if (SylvHooker::debug2)
			std::cout << FormatString("begin instruction %d at offset %zu (abs ptr %p)", inst_num, len, ptr + len) << std::endl;

		if (IsBadReadPtr(ptr + len, 1)) {
			std::cerr << "CANT READ" << std::endl;
			break;
		}

		const uint8_t* code = ptr + len;
		const uint8_t* start = code;
		size_t ins_len = 0;

		// get dat prefix
		bool prefix = true;
		bool operandSize = false, addressSize = false, rexW = false;
		int prefixes = 0;
		while (prefix && prefixes < 15) {
			uint8_t b = *code;
			if (SylvHooker::debug2)
				std::cout << FormatString("prefix loop: b=%02X, code=%p, prefixes=%d", b, code, prefixes) << std::endl;

			switch (b) {
			case 0xF0: case 0xF2: case 0xF3: // LOCK and REP/REPE/REPNE
			case 0x2E: case 0x36: case 0x3E: case 0x26: // SEG
			case 0x64: case 0x65:
				++code; ++prefixes; continue;
			case 0x66: operandSize = true; ++code; ++prefixes; continue;
			case 0x67: addressSize = true; ++code; ++prefixes; continue;
			default:
				if (sizeof(void*) == 8 && (b & 0xF0) == 0x40) {
					rexW = b & 8; ++code; ++prefixes;
					if (SylvHooker::debug2)
						std::cout << FormatString("REX prefix 0x%02X detected (rexW=%d)", b, !!rexW) << std::endl;
					continue;
				}
				prefix = false;
				break;
			}
		}

		// pls work
		uint8_t opcode1 = *code++;
		uint8_t opcode2 = 0;
		bool two_byte = false;
		if (opcode1 == 0x0F) {
			two_byte = true;
			opcode2 = *code++;
		}

		std::string info = FormatString("opcode: %02X%s%s", opcode1, two_byte ? " " : "", two_byte ? FormatString("%02X", opcode2).c_str() : "");

		if (SylvHooker::debug)
			std::cout << FormatString("decoding: %s at %p", info.c_str(), start) << std::endl;

		// decode shitt
		bool hasModRM = false, hasImm = false, hasDisp = false;
		int immSize = 0, dispSize = 0;

		if (!two_byte) {
			if ((opcode1 & 0xF7) == 0xC7) { hasModRM = true; immSize = operandSize ? 2 : 4; }
			else if (opcode1 == 0x68) { immSize = operandSize ? 2 : 4; }
			else if ((opcode1 & 0xF0) == 0x70) { immSize = 1; }
			else if ((opcode1 & 0xF8) == 0xB8) { immSize = operandSize ? 2 : 4; }
			else if ((opcode1 & 0xFE) == 0x04) { immSize = 1; }
			else if ((opcode1 & 0xFC) == 0x80) { hasModRM = true; immSize = 1; }
			else if (opcode1 == 0xEB) { immSize = 1; }
			else if (opcode1 == 0xE9) { immSize = operandSize ? 2 : 4; }
			else if (opcode1 == 0xE8) { immSize = operandSize ? 2 : 4; }
			else if ((opcode1 & 0xF8) == 0x50) { /* push/pop/incs: no modrm, no imm */ }
			else if ((opcode1 & 0xC0) == 0x00 || (opcode1 & 0xC0) == 0x40 || (opcode1 & 0xC0) == 0x80) { hasModRM = true; }
			else if ((opcode1 & 0xF0) == 0x90) { /* NOPs, XCHG, etc */ }
			else { if (opcode1 != 0x90 && opcode1 != 0xCC) hasModRM = true; }
		}
		else {
			if (opcode2 >= 0x80 && opcode2 <= 0x8F) { immSize = operandSize ? 2 : 4; }
			else { hasModRM = true; }
		}

		// moddRM/SIB/disp decode
		uint8_t modrm = 0, sib = 0;
		uint8_t mod = 0, rm = 0;
		if (hasModRM) {
			modrm = *code++;
			mod = (modrm & 0xC0) >> 6;
			rm = (modrm & 0x07);
			if (SylvHooker::debug2)
				std::cout << FormatString("modrm: %02X (mod=%d rm=%d)", modrm, mod, rm) << std::endl;

			// SIB
			if ((sizeof(void*) == 4 || sizeof(void*) == 8) && mod != 3 && rm == 4) {
				sib = *code++;
				uint8_t base = sib & 0x07;
				if (SylvHooker::debug2)
					std::cout << FormatString("SIB: %02X (base=%d)", sib, base) << std::endl;
				if (mod == 0 && base == 5) {
					dispSize = 4;
					if (SylvHooker::debug2)
						std::cout << "SIB special: mod==0 && base==5, dispSize=4" << std::endl;
				}
			}
			// displacement from modrm
			if (mod == 1) {
				dispSize = 1;
				if (SylvHooker::debug2) std::cout << "modrm mod==1, dispSize=1" << std::endl;
			}
			else if (mod == 2) {
				dispSize = 4;
				if (SylvHooker::debug2) std::cout << "modrm mod==2, dispSize=4" << std::endl;
			}
			else if (mod == 0 && rm == 5) {
				dispSize = 4;
				if (SylvHooker::debug2) std::cout << "modrm mod==0 && rm==5, dispSize=4" << std::endl;
			}
		}

		code += dispSize;
		code += immSize;

		ins_len = code - start;

		if (ins_len == 0) {
			std::cerr << FormatString("ZERO LENGTH AT %ps", start) << std::endl;
			ins_len = 1;
		}

		if (SylvHooker::debug2) {
			std::cout << FormatString("decoded %zu bytes at %p: %s%s%s%s", ins_len, start, info.c_str(),
				hasModRM ? " [modrm]" : "",
				dispSize ? FormatString(" [disp=%d]", dispSize).c_str() : "",
				immSize ? FormatString(" [imm=%d]", immSize).c_str() : "") << std::endl;
			std::string memBytes;
			for (size_t i = 0; i < ins_len; ++i)
				memBytes += FormatString("%02X ", *(start + i));
			std::cout << FormatString("Bytes: %s", memBytes.c_str()) << std::endl;
		}

		len += ins_len ? ins_len : 1;
		++inst_num;
	}

	if (SylvHooker::debug)
		std::cout << FormatString("Total instruction length calculated: %zu for 0x%p", len, func) << std::endl;

	return len;
}

bool SylvHooker::CreateHook(void*& target, void* detour, size_t overwriteLen)
{
	if (SylvHooker::debug2)
		std::cout << FormatString("CreateHook: target=%p detour=%p", target, detour) << std::endl;

	if (!target || !detour) {
		if (SylvHooker::debug2)
			std::cerr << "CreateHook failed: target or detour is nullptr" << std::endl;
		return false;
	}

	if (g_hooks.find(target) != g_hooks.end()) {
		if (SylvHooker::debug2)
			std::cerr << "CreateHook: already hooked!" << std::endl;
		return false;
	}

	if (SylvHooker::debug2) std::cout << "target not already hooked" << std::endl;

	size_t minJumpLen = (sizeof(void*) == 4) ? 5 : 14;

	std::cout << FormatString("minjumplen %d", minJumpLen) << std::endl;

	if (overwriteLen == 0) overwriteLen = CalculateInstructionLength(target, minJumpLen);

	HookEntry e{};
	e.target = target;
	e.detour = detour;
	e.overwriteLen = overwriteLen;
	e.enabled = false;
	e.origBytes.resize(overwriteLen);
	std::memcpy(e.origBytes.data(), target, overwriteLen);

	if (SylvHooker::debug2) {
		std::string origBytes;
		for (size_t i = 0; i < overwriteLen; ++i)
			origBytes += FormatString("%02X ", e.origBytes[i]);
		std::cout << FormatString("Original bytes: %s", origBytes.c_str()) << std::endl;
	}

	size_t trampSize = overwriteLen + minJumpLen + 16;
	void* tramp = AllocTrampoline(trampSize);
	if (!tramp) {
		if (SylvHooker::debug2)
			std::cerr << "CreateHook: AllocTrampoline failed!" << std::endl;
		return false;
	}

	uint8_t* p = (uint8_t*)tramp;
	std::memcpy(p, e.origBytes.data(), overwriteLen);

	uint8_t* jmpBack = p + overwriteLen;
	void* returnAddr = (uint8_t*)target + overwriteLen;
	WriteRelJumpToBuffer(jmpBack, jmpBack, returnAddr);

	if (SylvHooker::debug2)
		std::cout << FormatString("Trampoline setup: tramp=%p jmpBack=%p returnAddr=%p", tramp, jmpBack, returnAddr) << std::endl;

	e.trampoline = tramp;

	target = e.trampoline;

	g_hooks.emplace(e.target, std::move(e));

	if (debug)
		std::cout << FormatString("Registered hook: %p -> %p, trampoline at %p (len %zu)", e.target, detour, tramp, overwriteLen) << std::endl;

	if (SylvHooker::debug2) 
		std::cout << "CreateHook: hook emplaced successfully" << std::endl;

	return true;
}

bool SylvHooker::CommitHooks()
{
	if (SylvHooker::debug2)
		std::cout << "CommitHooks called." << std::endl;

	
	for (auto& kv : g_hooks)
	{
		if (SylvHooker::debug2)
			std::cout << FormatString("CommitHooks: Processing hook for target=%p detour=%p enabled=%d", kv.second.target, kv.second.detour, kv.second.enabled) << std::endl;

		if (!kv.second.enabled)
		{
			if (MakeRelJump(kv.second.target, kv.second.detour))
			{
				kv.second.enabled = true;
				if (debug)
					std::cout << FormatString("Hook committed: %p -> %p", kv.second.target, kv.second.detour) << std::endl;
				if (SylvHooker::debug2)
					std::cout << "CommitHooks: MakeRelJump succeeded." << std::endl;
			}
			else if (debug)
			{
				std::cerr << FormatString("Failed to commit hook: %p", kv.second.target) << std::endl;
				if (SylvHooker::debug2)
					std::cerr << "CommitHooks: MakeRelJump failed." << std::endl;
			}
		}
	}
	if (SylvHooker::debug2)
		std::cout << "CommitHooks finished." << std::endl;
	return true;
}

bool SylvHooker::EnableHook(void* target)
{
	if (SylvHooker::debug2)
		std::cout << FormatString("EnableHook called: target=%p", target) << std::endl;

	auto it = g_hooks.find(target);
	if (it == g_hooks.end() || it->second.enabled) {
		if (SylvHooker::debug2)
			std::cerr << "EnableHook: Already enabled or not found." << std::endl;
		return false;
	}

	bool ok = MakeRelJump(it->second.target, it->second.detour);
	if (!ok) {
		if (SylvHooker::debug2)
			std::cerr << "EnableHook: MakeRelJump failed!" << std::endl;
		return false;
	}

	it->second.enabled = true;
	if (debug)
		std::cout << FormatString("Hook enabled on %p", it->second.target) << std::endl;

	if (SylvHooker::debug2)
		std::cout << "EnableHook: succeeded." << std::endl;

	return true;
}

bool SylvHooker::DisableHook(void* target)
{
	if (SylvHooker::debug2)
		std::cout << FormatString("DisableHook called: target=%p", target) << std::endl;

	
	auto it = g_hooks.find(target);
	if (it == g_hooks.end() || !it->second.enabled) {
		if (SylvHooker::debug2)
			std::cerr << "DisableHook: Already disabled or not found." << std::endl;
		return false;
	}

	bool ok = WriteMemory(it->second.target, it->second.origBytes.data(), it->second.overwriteLen);
	if (!ok) {
		if (SylvHooker::debug2)
			std::cerr << "DisableHook: WriteMemory failed!" << std::endl;
		return false;
	}

	it->second.enabled = false;
	if (debug)
		std::cerr << FormatString("Hook disabled on %p", it->second.target) << std::endl;

	if (SylvHooker::debug2)
		std::cout << "DisableHook: succeeded." << std::endl;

	return true;
}

bool SylvHooker::RemoveHook(void* target)
{
	if (SylvHooker::debug2)
		std::cout << FormatString("RemoveHook called: target=%p", target) << std::endl;

	
	auto it = g_hooks.find(target);
	if (it == g_hooks.end()) {
		if (SylvHooker::debug2)
			std::cerr << "RemoveHook: Not found." << std::endl;
		return false;
	}

	if (it->second.enabled)
		DisableHook(target);

	if (it->second.trampoline)
		VirtualFree(it->second.trampoline, 0, MEM_RELEASE);

	if (debug)
		std::cerr << FormatString("Hook removed on %p", it->second.target) << std::endl;

	g_hooks.erase(it);

	if (SylvHooker::debug2)
		std::cout << "RemoveHook: erased from map." << std::endl;

	return true;
}

bool SylvHooker::Uninitialize()
{
	if (SylvHooker::debug2)
		std::cout << "Uninitialize called." << std::endl;

	
	for (auto& kv : g_hooks)
	{
		if (SylvHooker::debug2)
			std::cout << FormatString("Uninitialize: cleaning hook target=%p", kv.second.target) << std::endl;

		if (kv.second.enabled)
			WriteMemory(kv.second.target, kv.second.origBytes.data(), kv.second.overwriteLen);
		if (kv.second.trampoline)
			VirtualFree(kv.second.trampoline, 0, MEM_RELEASE);
	}
	g_hooks.clear();

	if (debug)
		std::cerr << "SylvHooker uninitialized" << std::endl;
	if (SylvHooker::debug2)
		std::cout << "Uninitialize finished." << std::endl;

	return true;
}
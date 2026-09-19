#include "pch.h"
#include "LargePakPatch.h"
#include "Patchfinder.h"

namespace
{
    uint64_t ResolveRelativeCall(uint64_t instruction)
    {
        const auto displacement = *reinterpret_cast<int32_t*>(instruction + 1);
        return instruction + 5 + displacement;
    }

    bool PatchBytes(uint64_t address, const uint8_t* bytes, size_t size)
    {
        if (!address)
            return false;

        DWORD oldProtection;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtection))
            return false;

        memcpy(reinterpret_cast<void*>(address), bytes, size);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
        VirtualProtect(reinterpret_cast<void*>(address), size, oldProtection, &oldProtection);
        return true;
    }

    bool ReturnImmediately(uint64_t address)
    {
        constexpr uint8_t bytes[] = { 0xC3 };
        return PatchBytes(address, bytes, sizeof(bytes));
    }

    bool ReturnZero(uint64_t address)
    {
        constexpr uint8_t bytes[] = { 0x31, 0xC0, 0xC3 };
        return PatchBytes(address, bytes, sizeof(bytes));
    }

    uint64_t FindRequestExit()
    {
        const auto stringReference = Tellurium::Patchfinder::FindStringRef(L"Memory pools allocations failed, exiting...\n");
        if (!stringReference)
            return 0;

        int callCount = 0;
        for (int offset = 0; offset < 2048; ++offset)
        {
            const auto instruction = stringReference + offset;
            if (*reinterpret_cast<uint8_t*>(instruction) == 0xE8)
            {
                if (++callCount == 2)
                    return ResolveRelativeCall(instruction);
            }
        }

        return 0;
    }

    uint64_t FindUnsafeEnvironment()
    {
        const auto stringReference = Tellurium::Patchfinder::FindStringRef(L"UnsafeEnvironment_Title");
        if (!stringReference)
            return 0;

        for (int offset = 0; offset < 2048; ++offset)
        {
            const auto address = stringReference - offset;
            if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(address, 0, false) ||
                Tellurium::Patchfinder::CheckBytes<0x40, 0x55>(address, 0, false))
                return address;
        }

        return 0;
    }
}

bool Tellurium::LargePakPatch::Init()
{
    const auto requestExit = FindRequestExit();
    const auto unsafeEnvironment = FindUnsafeEnvironment();

    constexpr static auto unsafeEnvironmentAltPattern = Tellurium::Patchfinder::Pattern<
        "E8 ? ? ? ? 48 8B 4D ? 48 85 C9 74 ? E8 ? ? ? ? 48 8B 4D ? 48 85 C9 74 ? E8 ? ? ? ? 4C 8B 7C 24 ? 4C 8B B4 24">();
    const auto unsafeEnvironmentAltCall = unsafeEnvironmentAltPattern.Scan();
    const auto unsafeEnvironmentAlt = unsafeEnvironmentAltCall
        ? ResolveRelativeCall(unsafeEnvironmentAltCall)
        : 0;

    const bool requestExitPatched = ReturnImmediately(requestExit);
    const bool unsafeEnvironmentPatched = unsafeEnvironment
        ? ReturnZero(unsafeEnvironment)
        : ReturnImmediately(unsafeEnvironmentAlt);

    return requestExitPatched && unsafeEnvironmentPatched;
}

bool Tellurium::LargePakPatch::InitOnce()
{
    static volatile LONG initialized = 0;
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0)
        return Init();

    return true;
}
#include "MemoryTrapManager.h"
#include "Zydis/Zydis.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define LOG(Level, Fmt, ...) \
    { \
        char LogMessageBuffer[256]; \
        sprintf_s(LogMessageBuffer, Fmt, __VA_ARGS__); \
        this->LogInternal(Level, LogMessageBuffer); \
    }

#define LOG_DEBUG(Fmt, ...) LOG(EMTMLoggingLevel::LOG_DEBUG, Fmt, __VA_ARGS__)

FMemoryTrapManager::FMemoryTrapManager() {
    //Default bind logging callback to print to the console
    this->LogCallback = [](EMTMLoggingLevel Level, const char* Message){
        if (Level != EMTMLoggingLevel::LOG_DEBUG || MEMORY_TRAP_MANAGER_DEBUG) {
            printf_s("MemoryTrapManager: %s: %s\n", LoggingLevelToString(Level), Message);
        }
    };

    //Initialize Zydis Decoder instance
    LOG_DEBUG("Initializing Zydis instruction decoder");
    ZydisDecoder = std::shared_ptr<ZydisDecoder_>(new ZydisDecoder_{});
    ZydisDecoderInit(ZydisDecoder.get(), ZYDIS_MACHINE_MODE_LONG_64, ZydisStackWidth::ZYDIS_STACK_WIDTH_64);

    //Obtain memory page size from the system info
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    this->MemoryPageSize = SystemInfo.dwPageSize;
    LOG_DEBUG("System Memory Page Size: 0x%x", (int32_t) MemoryPageSize);

    //Register the vectored exception handler
    AddVectoredExceptionHandler(TRUE, &FMemoryTrapManager::StaticHandleVectoredException);
    LOG_DEBUG("Registered vector exception handler");
}

void FMemoryTrapManager::TrapMemoryAccess(void *MemoryAddressRaw, int32_t Flags, const FMemoryTrapNotify &Notify) {
    std::scoped_lock LockScope(TrapTableMutex);
    auto MemoryAddress = (uint64_t) MemoryAddressRaw;

    //Create the guarded page first, or use the existing one
    uint64_t MemoryPageStartAddress = MemoryAddress & ~(MemoryPageSize - 1);
    LOG_DEBUG("Setting trap for %p at Memory Page %p", MemoryAddressRaw, MemoryPageStartAddress);

    const std::shared_ptr<FTrappedMemoryPageInfo> PageInfo = InternalSetupGuardPage(MemoryPageStartAddress);

    //Create trap info for the new trap
    std::shared_ptr<FMemoryTrapInfo> MemoryTrapInfo = std::make_shared<FMemoryTrapInfo>();
    MemoryTrapInfo->TrappedMemoryAddress = MemoryAddress;
    MemoryTrapInfo->Flags = Flags;
    MemoryTrapInfo->Notify = Notify;

    //Register the trap
    PageInfo->SetTraps.push_back(MemoryTrapInfo);
    LOG_DEBUG("Set Trap for Accessing %p on memory page %p", MemoryAddress, MemoryPageStartAddress);
}

void FMemoryTrapManager::ProcessPendingEvents() {
    std::scoped_lock LockScope(TrapTableMutex);

    for (const FQueuedTrapEvent& TrapEvent : this->QueuedTrapEvents) {
        TrapEvent.TrapInfo->Notify(TrapEvent.Event);
    }
    this->QueuedTrapEvents.clear();
}

void FMemoryTrapManager::SetLogCallback(const FMemoryTrapManagerLogCallback& Callback) {
    this->LogCallback = Callback;
    LOG_DEBUG("")
}

FMemoryTrapManager& FMemoryTrapManager::Get() {
    static FMemoryTrapManager Singleton{};
    return Singleton;
}

const char* FMemoryTrapManager::LoggingLevelToString(EMTMLoggingLevel Level) {
    switch (Level) {
        case EMTMLoggingLevel::LOG_ERROR: return "ERROR";
        case EMTMLoggingLevel::LOG_WARNING: return "WARNING";
        case EMTMLoggingLevel::LOG_DISPLAY: return "LOG";
        case EMTMLoggingLevel::LOG_DEBUG: return "DEBUG";
        default: return "UNKNOWN";
    }
}

void FMemoryTrapManager::LogInternal(EMTMLoggingLevel Level, const char* Message) {
    this->LogCallback(Level, Message);
}

/** Computes length of the instruction, in bytes */
int32_t FMemoryTrapManager::ComputeInstructionLengthBytes(uint64_t InstructionDataPointer) {
    ZydisDecodedInstruction Instruction;
    ZydisDecoderDecodeBuffer(ZydisDecoder.get(), (void *) InstructionDataPointer, 255, &Instruction);
    return Instruction.length;
}

/** Setups the guard page at the provided memory address, or returns the existing one. DOES NOT SYNCHRONIZE! */
std::shared_ptr<FTrappedMemoryPageInfo> FMemoryTrapManager::InternalSetupGuardPage(uint64_t MemoryPageStartAddress) {
    const auto ExistingPageInfo = this->TrappedMemoryPages.find(MemoryPageStartAddress);

    //If the page is already set up, return the existing trapped page entry
    if (ExistingPageInfo != this->TrappedMemoryPages.end()) {
        return ExistingPageInfo->second;
    }

    //Otherwise, query the page attributes and verify that it can be hooked
    MEMORY_BASIC_INFORMATION PageInfo;
    if (VirtualQuery((void *) MemoryPageStartAddress, &PageInfo, sizeof(PageInfo)) == 0L) {
        throw std::invalid_argument(
                std::format("VirtualQuery failed for provided memory address: 0x{:X}", MemoryPageStartAddress));
    }
    if (PageInfo.State != MEM_COMMIT) {
        throw std::invalid_argument(std::format("Page at memory address 0x{:X} is not committed, cannot trap access",
                                                MemoryPageStartAddress));
    }
    if ((PageInfo.Protect & PAGE_GUARD) != 0) {
        throw std::invalid_argument(
                std::format("Page at memory address 0x{:X} is already marked as guarded", MemoryPageStartAddress));
    }

    //Record basic page information
    DWORD NewProtectionFlags = PageInfo.Protect | PAGE_GUARD;
    DWORD InitialProtectionFlags = PageInfo.Protect;

    //Add PAGE_GUARD to the page protection flags
    DWORD OldPageProtectionFlags;
    if (!VirtualProtect((void *) MemoryPageStartAddress, MemoryPageSize, NewProtectionFlags, &OldPageProtectionFlags)) {
        throw std::invalid_argument(
                std::format("VirtualProtect failed for memory address 0x{:X}", MemoryPageStartAddress));
    }

    //Create the page entry, insert it into the map and return its entry
    std::shared_ptr<FTrappedMemoryPageInfo> MemoryPageInfo = std::make_shared<FTrappedMemoryPageInfo>();
    MemoryPageInfo->PageBaseAddress = MemoryPageStartAddress;
    MemoryPageInfo->InitialPageProtectionFlags = InitialProtectionFlags;
    MemoryPageInfo->ModifiedPageProtectionFlags = NewProtectionFlags;

    LOG_DEBUG("Set protection to PAGE_GUARD for memory page at %p", MemoryPageStartAddress);
    this->TrappedMemoryPages.insert({MemoryPageStartAddress, MemoryPageInfo});
    return MemoryPageInfo;
}

/** Handles vectored exceptions */
LONG FMemoryTrapManager::StaticHandleVectoredException(PEXCEPTION_POINTERS ExceptionInfo) {
    //Handle guard page violation exception ourselves
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        return FMemoryTrapManager::Get().InternalHandleGuardPageViolation(ExceptionInfo);
    }

    //Handle breakpoint exception ourselves, it might be one of our debug breaks
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        return FMemoryTrapManager::Get().InternalHandleBreakpoint(ExceptionInfo);
    }

    //Pass the exception to other handlers
    return EXCEPTION_CONTINUE_SEARCH;
}

/** Handles memory trap exception */
LONG FMemoryTrapManager::InternalHandleGuardPageViolation(PEXCEPTION_POINTERS ExceptionInfo) {
    //Skip exceptions that are either not guard page violations or do not have valid number of parameters
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION ||
        ExceptionInfo->ExceptionRecord->NumberParameters != 2) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    auto InstructionAddress = (uint64_t) ExceptionInfo->ExceptionRecord->ExceptionAddress;
    uint64_t AccessedMemoryAddress = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    EMemoryTrapEvent EventType = ExceptionInfo->ExceptionRecord->ExceptionInformation[0] ? EMemoryTrapEvent::EVENT_MEMORY_WRITE : EMemoryTrapEvent::EVENT_MEMORY_READ;

    uint64_t MemoryPageStartAddress = AccessedMemoryAddress & ~(MemoryPageSize - 1);

    std::scoped_lock LockScope(TrapTableMutex);
    const auto MemoryPageIterator = this->TrappedMemoryPages.find(MemoryPageStartAddress);

    //We do not care about that particular memory page, so just pass execution to the next handler
    if (MemoryPageIterator == this->TrappedMemoryPages.end()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    LOG_DEBUG("Guard page access to the trapped page at %p from Instruction %p for address %p",
                        MemoryPageStartAddress, InstructionAddress, AccessedMemoryAddress);

    //This is the memory page that we have trapped access to, retrieve the info and queue the events
    std::shared_ptr<FTrappedMemoryPageInfo> PageInfo = MemoryPageIterator->second;

    FMemoryTrapEvent MemoryTrapEventImmediate{AccessedMemoryAddress, EventType, InstructionAddress, ExceptionInfo->ContextRecord};
    FMemoryTrapEvent MemoryTrapEvent{AccessedMemoryAddress, EventType, InstructionAddress, nullptr};

    //Queue trap events on all traps that match the accessed memory address
    std::set<std::shared_ptr<FMemoryTrapInfo>> MemoryTrapsToRemove;

    for (const std::shared_ptr<FMemoryTrapInfo> &TrapInfo: PageInfo->SetTraps) {
        if (TrapInfo->TrappedMemoryAddress == AccessedMemoryAddress && (
                (TrapInfo->Flags & TRAP_READ) != 0 && (EventType == EMemoryTrapEvent::EVENT_MEMORY_READ) ||
                (TrapInfo->Flags & TRAP_WRITE) != 0 && (EventType == EMemoryTrapEvent::EVENT_MEMORY_WRITE))) {
            
            //If notify was requested to be triggered immediately, trigger it right now, otherwise queue it up for later
            if ((TrapInfo->Flags & TRAP_FIRE_IMMEDIATE) != 0) {
                LOG_DEBUG("Immediately firing memory trap event for memory trap at %p Event %x", TrapInfo->TrappedMemoryAddress, EventType);
                TrapInfo->Notify(MemoryTrapEventImmediate);
            } else {
                LOG_DEBUG("Queueing memory trap event for memory trap at %p Event %x", TrapInfo->TrappedMemoryAddress, EventType);
                FQueuedTrapEvent QueuedTrapEvent{TrapInfo, MemoryTrapEvent};
                this->QueuedTrapEvents.push_back(QueuedTrapEvent);
            }

            //If memory trap was registered as a one-time-only one, we need to clean it up
            if ((TrapInfo->Flags & EMemoryAccessTrapFlags::TRAP_SINGLE_USE) != 0) {
                MemoryTrapsToRemove.insert(TrapInfo);
                LOG_DEBUG("Removing one time memory trap at %p", TrapInfo->TrappedMemoryAddress);
            }
        }
    }

    //Remove single-use traps we have collected from last call
    PageInfo->SetTraps.remove_if([&](const std::shared_ptr<FMemoryTrapInfo> &Element) {
        return MemoryTrapsToRemove.contains(Element);
    });

    //If we are left with no traps remaining on the page, remove the page entry and continue the execution normally
    if (PageInfo->SetTraps.empty()) {
        LOG_DEBUG("Clearing protected memory page at %p", PageInfo->PageBaseAddress);
        this->TrappedMemoryPages.erase(PageInfo->PageBaseAddress);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    //At this point we still have traps remaining on the page, but the PAGE_GUARD flag has been reset
    //We cannot add it back right now because we want the next instruction to read the data normally from the page
    //That's why we compute it's size and replace the next instruction with debugger break
    //We will handle that debugger break to reset the PAGE_GUARD flag and bring back the original instruction byte

    const int32_t NextInstructionLength = ComputeInstructionLengthBytes(InstructionAddress);
    const uint64_t BreakpointInstructionAddress = InstructionAddress + NextInstructionLength;

    uint8_t BreakpointInstructionId = 0xCC;
    DWORD NewProtectionFlags = PAGE_EXECUTE_READWRITE;
    const int32_t BreakpointInstructionLength = 1;

    //Change page flags to the new ones, so we can modify the instruction data
    DWORD OriginalProtectionFlags;
    VirtualProtect((void *) BreakpointInstructionAddress, BreakpointInstructionLength, NewProtectionFlags,
                   &OriginalProtectionFlags);
    LOG_DEBUG(
            "Changed protection to PAGE_EXECUTE_READWRITE for instruction at %p. Current Instruction: %p, Current Inst Length: %d",
            BreakpointInstructionAddress, InstructionAddress, NextInstructionLength);

    auto *InstructionBytePtr = (uint8_t *) BreakpointInstructionAddress;
    uint8_t OriginalInstructionByte = *InstructionBytePtr;

    //Change the instruction byte to the breakpoint and then flush instruction cache
    *InstructionBytePtr = BreakpointInstructionId;
    FlushInstructionCache(GetCurrentProcess(), InstructionBytePtr, BreakpointInstructionLength);
    LOG_DEBUG("Changed instruction byte at %p from 0x%x to 0x%x and flushed cache", InstructionBytePtr,
                        OriginalInstructionByte, BreakpointInstructionId);

    //Create the entry in the breakpoint table, so we can catch the breakpoint later
    std::shared_ptr<FTemporaryDebugBreakInfo> DebugBreakInfo = std::make_shared<FTemporaryDebugBreakInfo>();
    DebugBreakInfo->InstructionAddress = BreakpointInstructionAddress;
    DebugBreakInfo->OriginalPageProtection = OriginalProtectionFlags;
    DebugBreakInfo->OriginalInstructionByte = OriginalInstructionByte;
    DebugBreakInfo->TrappedMemoryPageAddress = MemoryPageStartAddress;

    this->InsertedDebugBreakInstructions.insert({BreakpointInstructionAddress, DebugBreakInfo});
    LOG_DEBUG("Inserted debug break instruction at %p with memory page at %p", BreakpointInstructionAddress,
                        PageInfo->PageBaseAddress);

    //Continue execution normally without the PAGE_GUARD flag
    return EXCEPTION_CONTINUE_EXECUTION;
}

/** Handle breakpoint exception */
LONG FMemoryTrapManager::InternalHandleBreakpoint(PEXCEPTION_POINTERS ExceptionInfo) {
    //Skip exceptions that are either not breakpoints
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    std::scoped_lock LockScope(TrapTableMutex);
    auto InstructionAddress = (uint64_t) ExceptionInfo->ExceptionRecord->ExceptionAddress;
    const auto BreakpointIterator = this->InsertedDebugBreakInstructions.find(InstructionAddress);

    //If this breakpoint is not caused by ass, pass execution to the next handler
    if (BreakpointIterator == this->InsertedDebugBreakInstructions.end()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    LOG_DEBUG("Encountered breakpoint at expected address %p", InstructionAddress);

    const int32_t BreakpointInstructionLength = 1;
    std::shared_ptr<FTemporaryDebugBreakInfo> DebugBreakInfo = BreakpointIterator->second;
    auto *InstructionBytePtr = (uint8_t *) InstructionAddress;

    //Change the instruction byte back to the original instruction and flush instruction cache
    uint8_t CurrentInstructionByte = *InstructionBytePtr;
    *InstructionBytePtr = DebugBreakInfo->OriginalInstructionByte;
    FlushInstructionCache(GetCurrentProcess(), InstructionBytePtr, BreakpointInstructionLength);
    LOG_DEBUG("Replaced breakpoint byte from 0x%x to original 0x%x at %p and flushed cache",
                        CurrentInstructionByte, DebugBreakInfo->OriginalInstructionByte, InstructionBytePtr);

    //Change the code page protection flags back to their original values
    DWORD ChangedPageProtectionFlags;
    VirtualProtect(InstructionBytePtr, BreakpointInstructionLength, DebugBreakInfo->OriginalPageProtection,
                   &ChangedPageProtectionFlags);
    LOG_DEBUG("Reset protection flags from 0x%x to original 0x%x for breakpoint at %p",
                        ChangedPageProtectionFlags, DebugBreakInfo->OriginalPageProtection, InstructionBytePtr);

    //Remove the breakpoint track from the map
    this->InsertedDebugBreakInstructions.erase(DebugBreakInfo->InstructionAddress);

    const auto MemoryPageInfoIterator = this->TrappedMemoryPages.find(DebugBreakInfo->TrappedMemoryPageAddress);
    LOG_DEBUG("Attempting to bring back guard page with attached address %p for breakpoint at %p",
                        DebugBreakInfo->TrappedMemoryPageAddress, InstructionBytePtr);

    //Bring back the PAGE_GUARD flag on the page that breakpoint has been associated with
    if (MemoryPageInfoIterator != this->TrappedMemoryPages.end()) {
        const std::shared_ptr<FTrappedMemoryPageInfo> PageInfo = MemoryPageInfoIterator->second;

        DWORD OldProtectionFlags;
        VirtualProtect((void *) PageInfo->PageBaseAddress, MemoryPageSize, PageInfo->ModifiedPageProtectionFlags,
                       &OldProtectionFlags);
        LOG_DEBUG("Brought back PAGE_GUARD flag on the page %p handled by the breakpoint at %p",
                            DebugBreakInfo->TrappedMemoryPageAddress, InstructionBytePtr);
    }

    //Continue the execution of the next instruction normally
    return EXCEPTION_CONTINUE_EXECUTION;
}


#pragma once
#include <map>
#include <functional>
#include <mutex>
#include <set>

#ifdef MTM_SHARED
#ifdef BUILDING_MTM
#define MTM_API __declspec(dllexport)
#else
#define MTM_API __declspec(dllimport)
#endif
#else
#define MTM_API
#endif

#ifndef MEMORY_TRAP_MANAGER_DEBUG
#define MEMORY_TRAP_MANAGER_DEBUG 1
#endif

//Internal predeclarations
struct ZydisDecoder_;
struct _EXCEPTION_POINTERS;
struct _CONTEXT;
typedef long WIN32_LONG;
typedef unsigned long WIN32_DWORD;

/** Describes possible flags that can be passed to TrapMemoryAccess */
enum EMemoryAccessTrapFlags : int32_t {

    /** Memory reads will be trapped and reported */
    TRAP_READ = 0x1,

    /** Memory writes will be trapped and reported */
    TRAP_WRITE = 0x2,

    /** Memory writes and reads will be trapped and reported */
    TRAP_READWRITE = 0x3,

    /** Trap will be automatically removed after triggering once */
    TRAP_SINGLE_USE = 0x4,

    /**
     * Trap will fire immediately and will not be queued
     * WARNING! Such traps will be triggered right inside of the vectored exception handler
     * Proceed with caution. While this allows accessing registers and stack at the time of the memory access,
     * a lot of APIs are dangerous to call inside of the exception handler
     */
    TRAP_FIRE_IMMEDIATE = 0x8
};

/** Describes possible types of the trapped event */
enum class EMemoryTrapEvent {
    EVENT_MEMORY_READ = 0x1,
    EVENT_MEMORY_WRITE = 0x2
};

/** Describes a single trapped memory access event */
struct FMemoryTrapEvent {
    /** Memory address that has been accessed */
    uint64_t AccessedMemoryAddress;

    /** Type of the access that has occurred */
    EMemoryTrapEvent Event;

    /** Address of the instruction that has caused the access */
    uint64_t TrappedInstructionAddress;

    /**
     * Machine-specific context associated with this trap, contains captured values of registers and additional information
     * Changes to the context will be reflected on the code executing after the notify is finished
     * Only available when TRAP_FIRE_IMMEDIATE is set, otherwise NULL
     * */
    _CONTEXT* TrapContext;
};

/** A callback function called when trap is triggered */
using FMemoryTrapNotify = std::function<void(FMemoryTrapEvent)>;

/** Information about a registration of a single memory trap */
struct FMemoryTrapInfo {
    uint64_t TrappedMemoryAddress;
    int32_t Flags;
    FMemoryTrapNotify Notify;
};

/** A trapped memory access event that has been queued */
struct FQueuedTrapEvent {
    std::shared_ptr<FMemoryTrapInfo> TrapInfo;
    FMemoryTrapEvent Event;
};

/** Describes a guarded trapped memory page */
struct FTrappedMemoryPageInfo {
    uint64_t PageBaseAddress;
    std::list<std::shared_ptr<FMemoryTrapInfo>> SetTraps;
    WIN32_DWORD InitialPageProtectionFlags;
    WIN32_DWORD ModifiedPageProtectionFlags;
};

/** Describes a location where debugger break interrupt has been inserted */
struct FTemporaryDebugBreakInfo {
    uint64_t InstructionAddress;
    WIN32_DWORD OriginalPageProtection;
    uint8_t OriginalInstructionByte;
    uint64_t TrappedMemoryPageAddress;
};

/** Possible logging levels for the trap manager */
enum class EMTMLoggingLevel {
    LOG_ERROR,
    LOG_WARNING,
    LOG_DISPLAY,
    LOG_DEBUG
};

/** A callback function fired when trap manager invokes logging */
using FMemoryTrapManagerLogCallback = std::function<void(EMTMLoggingLevel Level, const char* Message)>;

/** Allows trapping memory access at provided locations */
class MTM_API FMemoryTrapManager {
    FMemoryTrapManagerLogCallback LogCallback;
    std::shared_ptr<ZydisDecoder_> ZydisDecoder;
    uint64_t MemoryPageSize;
    std::mutex TrapTableMutex;
    std::vector<FQueuedTrapEvent> QueuedTrapEvents;

    std::map<uint64_t, std::shared_ptr<FTrappedMemoryPageInfo>> TrappedMemoryPages;
    std::map<uint64_t, std::shared_ptr<FTemporaryDebugBreakInfo>> InsertedDebugBreakInstructions;

    /** Constructs and initializes trap manager */
    FMemoryTrapManager();
public:
    //Delete copy, assignment or move constructors
    FMemoryTrapManager(const FMemoryTrapManager&) = delete;
    FMemoryTrapManager(FMemoryTrapManager&&) = delete;
    void operator=(const FMemoryTrapManager&) = delete;

    /** Registers a new memory trap at the specified address */
    void TrapMemoryAccess(void* MemoryAddressRaw, int32_t Flags, const FMemoryTrapNotify& Notify);

    /** Dispatches queued memory trap events on the calling thread */
    void ProcessPendingEvents();

    /** Sets the callback that will be used by the memory trap manager for logging */
    void SetLogCallback(const FMemoryTrapManagerLogCallback& Callback);

    /** Retrieves and potentially initializes the global memory trap table singleton */
    static FMemoryTrapManager& Get();

    /** Converts logging level to the string */
    static const char* LoggingLevelToString(EMTMLoggingLevel Level);
private:
    /** Logs the message to the attached logging callback */
    void LogInternal(EMTMLoggingLevel Level, const char* Message);

    /** Computes length of the instruction, in bytes */
    int32_t ComputeInstructionLengthBytes(uint64_t InstructionDataPointer);

    /** Setups the guard page at the provided memory address, or returns the existing one. DOES NOT SYNCHRONIZE! */
    std::shared_ptr<FTrappedMemoryPageInfo> InternalSetupGuardPage(uint64_t MemoryPageStartAddress);

    /** Handles vectored exceptions */
    static WIN32_LONG StaticHandleVectoredException(_EXCEPTION_POINTERS* ExceptionInfo);

    /** Handles memory trap exception */
    WIN32_LONG InternalHandleGuardPageViolation(_EXCEPTION_POINTERS* ExceptionInfo);

    /** Handle breakpoint exception */
    WIN32_LONG InternalHandleBreakpoint(_EXCEPTION_POINTERS* ExceptionInfo);
};

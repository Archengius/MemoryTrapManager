#include <iostream>
#include "MemoryTrapManager.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

//Needed here to ensure that we do not accidentally PAGE_GUARD our own strings because
//they will be placed closely to the global static variables in the test executable
//This ensures that we will have enough blank space between our resources and the test variables we attempt to capture,
//so that LOGGING our own strings will not cause our own interrupt handler to trigger
static uint64_t EmptyPlaceholderMultiPageVariable[1024];

//Example buffer that is 4 pages in size
static int64_t ExampleVariable;
static int64_t TestVariable;
static int64_t UnusedVariable;

void FunctionWithTestVariable(int64_t TestVariableVal, int64_t ExampleValue) {
    std::cout << "TestVariable: " << TestVariableVal << " ExampleValue: " << ExampleValue << std::endl;
}

int main() {
    EmptyPlaceholderMultiPageVariable[125] = 130;
    std::cout << "Placeholder variable: " << EmptyPlaceholderMultiPageVariable[125] << std::endl;

    FMemoryTrapManager::Get().TrapMemoryAccess(&ExampleVariable, TRAP_READWRITE, [](const FMemoryTrapEvent &Event) {
        std::cout << "Notify Called! Accessed From 0x" << (void *) Event.TrappedInstructionAddress << " With Event " << (int32_t) Event.Event << std::endl;
    });
    FMemoryTrapManager::Get().TrapMemoryAccess(&TestVariable, TRAP_READ | TRAP_FIRE_IMMEDIATE,[](const FMemoryTrapEvent &Event) {
        std::cout << "Immediate notify called. Current RDX value: " << Event.TrapContext->Rdx << ". Changing value to 100" << std::endl;
        Event.TrapContext->Rdx = 100;
    });

    UnusedVariable = 1;
    std::cout << "Trapped successfully" << std::endl;
    ExampleVariable = 1;

    UnusedVariable = 2;
    std::cout << "Changed value successfully first time" << std::endl;
    ExampleVariable = 2;
    std::cout << "Changed value second time" << std::endl;

    UnusedVariable = 3;
    std::cout << "Changed variable value. New Value: " << ExampleVariable << std::endl;

    FunctionWithTestVariable(TestVariable, UnusedVariable);

    FMemoryTrapManager::Get().ProcessPendingEvents();
    return 0;
}

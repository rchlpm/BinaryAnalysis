#TODO attempts to iterate each function and extract signature bytes
#@rachel meredith 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import Function
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.mem import Memory
from ghidra.program.flatapi import FlatProgramAPI


# Get the current program
current_program = state.getCurrentProgram()

# Get the function manager for the current program
function_manager = current_program.getFunctionManager()

# Get an iterator over all functions in the program
function_iterator = function_manager.getFunctions(True)

# Initialize the FlatProgramAPI
api = FlatProgramAPI(current_program)

# Iterate over all functions in the program
while function_iterator.hasNext():
    current_function = function_iterator.next()
    print("Processing function: " + current_function.getName())

    # Extract the function signature bytes
    signature = current_function.getSignature()

    # Get the memory block that contains the function signature
    # https://github.com/NationalSecurityAgency/ghidra/issues/1969
    # Get the address of the function

    # Get the function signature bytes
    function_address = current_function.getEntryPoint()

    memory = current_program.getMemory()
    signature_block = memory.getBlock(function_address)
    if signature_block is None:
        print("Cannot find memory block containing function signature")
        continue

    # Get the function signature bytes
    signature_length = 3
    function_signature = api.getBytes(current_function.entryPoint, signature_length)

    # Label the function with the appropriate type based on its signature
    if b"\x48\x8b\x0d" in function_signature:
        createLabel(current_function.entryPoint, "cryptographic_function", True, SourceType.ANALYSIS)
    elif b"\x48\x8b\x11" in function_signature:
        createLabel(current_function.entryPoint, "network_function", True, SourceType.ANALYSIS)

    # Get the instructions in the function body
    function_body = current_function.getBody()
    address_set = AddressSet(function_body.getMinAddress(), function_body.getMaxAddress())
    instructions = current_program.getListing().getInstructions(address_set, True)
    for instruction in instructions:
        # Extract relevant instructions for each function
        if instruction.getMnemonicString() == "PUSH":
            # Found a PUSH instruction
            # Extract the operand value and do something with it
            operand = instruction.getOpObjects(0)[0]
            print("Found PUSH instruction with operand: " + operand.toString())

        elif instruction.getMnemonicString() == "MOV":
            # Found a MOV instruction
            # Extract the source and destination operands and do something with them
            source_operand = instruction.getOpObjects(0)[0]
            dest_operand = instruction.getOpObjects(1)[0]
            print("Found MOV instruction with source operand: " + source_operand.toString() +
                  " and destination operand: " + dest_operand.toString())

print("Finished!")

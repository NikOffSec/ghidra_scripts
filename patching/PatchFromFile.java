//Patches bytes at an address from a binary file, padding the remainder with NOPs.
//@author NikOffSec
//@category Patching

import java.io.File;
import java.nio.file.Files;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.NumericUtilities;

public class PatchFromFile extends GhidraScript {

    @Override
    protected void run() throws Exception {
        File file = askFile("Select patch binary", "Select");
        Address start = askAddress("Patch start", "Start address:");
        int size = askInt("Patch size", "Size in bytes:");

        if (size <= 0) {
            throw new IllegalArgumentException("Patch size must be positive");
        }

        byte[] patch = Files.readAllBytes(file.toPath());

        Instruction first = getInstructionContaining(start);
        if (first != null && !first.getMinAddress().equals(start)) {
            throw new IllegalArgumentException(
                "Start address " + start + " is mid-instruction (instruction begins at " + first.getMinAddress() + ")");
        }
        if (first == null) {
            println("Warning: no instruction at " + start + "; region length cannot be verified against code");
        }

        int regionLen = alignToInstructions(start, size);
        if (regionLen != size) {
            println(String.format("Size %d ends mid-instruction; extending region to %d bytes", size, regionLen));
        }

        Address end = start.add(regionLen - 1);
        MemoryBlock block = getMemoryBlock(start);
        if (block == null || !block.contains(end) || !block.isInitialized()) {
            throw new IllegalArgumentException("Patch region must be within a single initialized memory block");
        }

        if (patch.length > regionLen) {
            throw new IllegalStateException(String.format(
                "Overpatching: patch is %d bytes but region is %d bytes. Need to create a hook manually.",
                patch.length, regionLen));
        }

        byte[] filled = new byte[regionLen];
        System.arraycopy(patch, 0, filled, 0, patch.length);

        int remaining = regionLen - patch.length;
        if (remaining > 0) {
            byte[] nop = getNop(start.add(patch.length));
            if (remaining % nop.length != 0) {
                throw new IllegalStateException(String.format(
                    "Remaining %d bytes is not a multiple of the NOP length (%d)", remaining, nop.length));
            }
            for (int i = patch.length; i < regionLen; i += nop.length) {
                System.arraycopy(nop, 0, filled, i, nop.length);
            }
        }

        clearListing(start, end);
        setBytes(start, filled);
        disassemble(start);

        println(String.format("Patched %s-%s: %d patch bytes, %d NOP bytes", start, end, patch.length, remaining));
    }

    private int alignToInstructions(Address start, int size) {
        Instruction last = getInstructionContaining(start.add(size - 1));
        if (last == null) {
            return size;
        }
        return (int) (last.getMaxAddress().subtract(start) + 1);
    }

    private byte[] getNop(Address addr) throws Exception {
        try {
            Assembler asm = Assemblers.getAssembler(currentProgram);
            byte[] nop = asm.assembleLine(addr, "NOP");
            if (nop != null && nop.length > 0) {
                return nop;
            }
        }
        catch (Exception e) {
            println("Could not assemble NOP: " + e.getMessage());
        }
        String hex = askString("NOP bytes", "Enter NOP instruction as hex (e.g. 90, 1f2003d5):");
        return NumericUtilities.convertStringToBytes(hex.replaceAll("\\s", ""));
    }
}

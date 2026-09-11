//Installs a code-cave trampoline hook for a patch too large to fit inline.
//@author NikOffSec
//@category Patching


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class HookOverpatch extends GhidraScript {

    @Override
    protected void run() throws Exception {
        File file = askFile("Select patch binary", "Select");
        Address start = askAddress("Patch start", "Start address:");
        int size = askInt("Patch size", "Intended replace size (bytes):");
        if (size <= 0) throw new IllegalArgumentException("Size must be positive");

        byte[] patch = Files.readAllBytes(file.toPath());
        Assembler asm = Assemblers.getAssembler(currentProgram);

        Instruction firstIns = getInstructionContaining(start);
        if (firstIns == null) throw new IllegalArgumentException("No instruction at " + start);
        if (!firstIns.getMinAddress().equals(start)) {
            throw new IllegalArgumentException("Start is mid-instruction; begins at " + firstIns.getMinAddress());
        }

        Address regionEnd = instrBoundaryAtLeast(start, size);
        int regionLen = (int) regionEnd.subtract(start);
        if (patch.length <= regionLen) {
            throw new IllegalStateException(String.format(
                "Patch (%d B) fits region (%d B). Use the inline patcher, not a hook.", patch.length, regionLen));
        }

        Address cave = askCave(patch.length + 32);

        byte[] jmp = assemble(asm, start, "JMP 0x" + Long.toHexString(cave.getOffset()));
        if (jmp == null) throw new IllegalStateException("Cannot assemble jump to cave (out of range?). Pick a closer cave.");

        Address clobberEnd = instrBoundaryAtLeast(start, Math.max(regionLen, jmp.length));
        int clobberLen = (int) clobberEnd.subtract(start);

        List<Instruction> tail = new ArrayList<>();
        for (Address a = regionEnd; a.compareTo(clobberEnd) < 0; ) {
            Instruction i = getInstructionAt(a);
            if (i == null) throw new IllegalStateException("Displaced bytes at " + a + " are not a clean instruction");
            tail.add(i);
            a = i.getMaxAddress().add(1);
        }

        byte[] tailBytes = relocateTail(asm, tail, cave.add(patch.length));
        Address backFrom = cave.add(patch.length + tailBytes.length);
        byte[] back = assemble(asm, backFrom, "JMP 0x" + Long.toHexString(clobberEnd.getOffset()));
        if (back == null) throw new IllegalStateException("Cannot assemble return jump (cave too far from code).");

        int caveNeed = patch.length + tailBytes.length + back.length;
        verifyCave(cave, caveNeed, start, clobberEnd);

        byte[] site = new byte[clobberLen];
        System.arraycopy(jmp, 0, site, 0, jmp.length);
        byte[] nop = assemble(asm, start.add(jmp.length), "NOP");
        if (nop == null) throw new IllegalStateException("Cannot assemble NOP for padding");
        for (int off = jmp.length; off < clobberLen; off += nop.length) {
            if (off + nop.length > clobberLen) throw new IllegalStateException("NOP fill does not align to clobber end");
            System.arraycopy(nop, 0, site, off, nop.length);
        }

        byte[] caveBytes = new byte[caveNeed];
        System.arraycopy(patch, 0, caveBytes, 0, patch.length);
        System.arraycopy(tailBytes, 0, caveBytes, patch.length, tailBytes.length);
        System.arraycopy(back, 0, caveBytes, patch.length + tailBytes.length, back.length);

        clearListing(start, clobberEnd.subtract(1));
        setBytes(start, site);
        disassemble(start);

        clearListing(cave, cave.add(caveNeed - 1));
        setBytes(cave, caveBytes);
        disassemble(cave);

        println("Hook installed.");
        println(String.format("  site   : %s .. %s  (jmp %dB + %dB nop)", start, clobberEnd, jmp.length, clobberLen - jmp.length));
        println(String.format("  cave   : %s  (%dB = %d patch + %d relocated + %d ret-jmp)",
            cave, caveNeed, patch.length, tailBytes.length, back.length));
        println("  resumes: " + clobberEnd);
    }

    private Address instrBoundaryAtLeast(Address start, int n) {
        Instruction i = getInstructionContaining(start.add(n - 1));
        return (i == null) ? start.add(n) : i.getMaxAddress().add(1);
    }

    private byte[] relocateTail(Assembler asm, List<Instruction> tail, Address dest) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Address cur = dest;
        for (Instruction i : tail) {
            byte[] orig = i.getBytes();
            byte[] re = assemble(asm, cur, i.toString());
            if (re == null || !Arrays.equals(re, orig)) {
                throw new IllegalStateException("Displaced instruction '" + i + "' at " + i.getAddress()
                    + " is position-dependent and cannot be safely relocated. Create the hook manually.");
            }
            out.write(orig);
            cur = cur.add(orig.length);
        }
        return out.toByteArray();
    }

    private Address askCave(int need) throws Exception {
        String s = askString("Code cave", "Cave address (blank = auto-scan for " + need + "B of padding):", "");
        if (s != null && !s.trim().isEmpty()) {
            return currentProgram.getAddressFactory().getAddress(s.trim());
        }
        Address found = findCave(need);
        if (found == null) {
            throw new IllegalStateException("No " + need + "B code cave found. Supply one or add a loadable section. "
                + "A Ghidra-created block will NOT be mapped in the real process.");
        }
        println("Auto-selected cave at " + found);
        return found;
    }

    private Address findCave(int need) throws Exception {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute() || b.getSize() < need) continue;
            byte[] buf = new byte[(int) Math.min(b.getSize(), Integer.MAX_VALUE)];
            b.getBytes(b.getStart(), buf);
            int run = 0;
            byte rb = 0;
            for (int i = 0; i < buf.length; i++) {
                byte v = buf[i];
                boolean pad = v == 0x00 || v == (byte) 0xCC || v == (byte) 0x90;
                if (pad && run > 0 && v == rb) run++;
                else if (pad) { run = 1; rb = v; }
                else run = 0;
                if (run >= need) return b.getStart().add((long) (i - need + 1));
            }
        }
        return null;
    }

    private void verifyCave(Address cave, int need, Address siteStart, Address siteEnd) throws Exception {
        MemoryBlock b = getMemoryBlock(cave);
        Address last = cave.add(need - 1);
        if (b == null || !b.isInitialized() || !b.isExecute() || !b.contains(last)) {
            throw new IllegalStateException("Cave must be " + need + "B inside one initialized executable block");
        }
        if (cave.compareTo(siteEnd) < 0 && siteStart.compareTo(last) <= 0) {
            throw new IllegalStateException("Cave overlaps the patch site");
        }
    }

    private byte[] assemble(Assembler asm, Address at, String line) {
        try {
            byte[] b = asm.assembleLine(at, line);
            return (b == null || b.length == 0) ? null : b;
        }
        catch (Exception e) {
            return null;
        }
    }
}

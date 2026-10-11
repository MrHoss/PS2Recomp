// Ensures every .ctors/.init_array pointer target has a Ghidra function.
// Fixes recompilation failures where initializer targets fall inside
// another function's body and Ghidra never created a standalone function.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class EnsureCtorFunctions extends GhidraScript {

    private static final String[] SECTION_NAMES = {".ctors", ".init_array", ".preinit_array"};

    @Override
    public void run() throws Exception {
        ByteOrder order = currentProgram.getLanguage().isBigEndian()
            ? ByteOrder.BIG_ENDIAN
            : ByteOrder.LITTLE_ENDIAN;

        int checked = 0;
        int created = 0;
        int missing = 0;

        for (String sectionName : SECTION_NAMES) {
            MemoryBlock block = currentProgram.getMemory().getBlock(sectionName);
            if (block == null || block.getSize() < 4) {
                println("EnsureCtor: section " + sectionName + " not present or empty, skipping");
                continue;
            }

            byte[] data = new byte[(int) block.getSize()];
            currentProgram.getMemory().getBytes(block.getStart(), data);
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(order);

            for (int offset = 0; offset + 4 <= data.length; offset += 4) {
                long target = buffer.getInt(offset) & 0xFFFFFFFFL;
                if (target == 0L || target == 0xFFFFFFFFL) {
                    continue;
                }
                checked++;

                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(target);
                if (addr == null) {
                    println("EnsureCtor: invalid target 0x" + Long.toHexString(target));
                    missing++;
                    continue;
                }

                Function existing = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (existing != null) {
                    continue;
                }

                if (currentProgram.getListing().getInstructionAt(addr) == null) {
                    boolean disassembled = disassemble(addr);
                    if (!disassembled) {
                        println("EnsureCtor: failed to disassemble at " + addr);
                        missing++;
                        continue;
                    }
                }

                Function createdFunction = createFunction(addr, null);
                if (createdFunction != null) {
                    created++;
                    println("EnsureCtor: created function " + createdFunction.getName() + " at " + addr);
                } else {
                    println("EnsureCtor: createFunction returned null at " + addr);
                    missing++;
                }
            }
        }

        println("EnsureCtor: checked " + checked + " initializer pointers, created " +
            created + " functions, " + missing + " unresolved");
    }
}

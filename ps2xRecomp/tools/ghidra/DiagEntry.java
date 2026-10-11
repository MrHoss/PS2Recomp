import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DiagEntry extends GhidraScript {
    @Override
    public void run() throws Exception {
        long lo = 0x2d9000L;
        long hi = 0x2db000L;
        FunctionManager fm = currentProgram.getFunctionManager();
        ghidra.program.model.address.AddressFactory af = currentProgram.getAddressFactory();
        ghidra.program.model.listing.Listing listing = currentProgram.getListing();
        long[] probe = {0x2d98d0L, 0x2d98d4L, 0x2d98d8L, 0x2d98dcL, 0x2d9a98L};
        for (long p : probe) {
            ghidra.program.model.address.Address a = af.getDefaultAddressSpace().getAddress(p);
            ghidra.program.model.listing.Instruction ins = listing.getInstructionAt(a);
            Function cf = fm.getFunctionContaining(a);
            println(String.format("PROBE 0x%x ins=%s text=%s flow=%s fall=%s func=%s",
                    p,
                    ins == null ? "no" : "yes",
                    ins == null ? "-" : ins.toString(),
                    ins == null ? "-" : ins.getFlowType().toString(),
                    ins == null ? "-" : String.valueOf(ins.getFallThrough()),
                    cf == null ? "none" : cf.getName()));
        }
        println("--- gap instructions 0x2d98d8..0x2d9a98 ---");
        long g = 0x2d98d8L;
        while (g < 0x2d9a98L) {
            ghidra.program.model.address.Address a = af.getDefaultAddressSpace().getAddress(g);
            ghidra.program.model.listing.Instruction ins = listing.getInstructionAt(a);
            Function cf = fm.getFunctionContaining(a);
            println(String.format("GAP 0x%x ins=%s text=%s func=%s", g,
                    ins == null ? "no" : "yes",
                    ins == null ? "-" : ins.toString(),
                    cf == null ? "none" : cf.getName()));
            g += 4;
        }

        for (Function f : fm.getFunctions(true)) {
            long s = f.getEntryPoint().getOffset();
            AddressSetView b = f.getBody();
            long e = b.getMaxAddress().getOffset();
            if (e >= lo && s <= hi) {
                println(String.format("%s start=0x%x end=0x%x ranges=%d numAddr=%d",
                        f.getName(), s, e, b.getNumAddressRanges(), b.getNumAddresses()));
                for (AddressRange r : b) {
                    println(String.format("    range 0x%x - 0x%x", r.getMinAddress().getOffset(), r.getMaxAddress().getOffset()));
                }
            }
        }
    }
}

package dbglink.ghidra;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Ghidra-side static bridge for DBGLink.
 *
 * <p>The native x64dbg plugin remains responsible for live debugging. This
 * plugin only exposes the allowlisted, bounded Ghidra Program API over a
 * loopback socket: static-analysis queries plus annotation mutations
 * (renames, comments, created functions), journaled for replay.</p>
 */
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "DBGLink",
    category = "DBGLink",
    shortDescription = "DBGLink static analysis bridge",
    description = "Provides bounded static-analysis evidence to the local DBGLink MCP server."
)
public class DbgLinkGhidraPlugin extends ProgramPlugin {

    private final AtomicReference<Program> activeProgram = new AtomicReference<>();
    private GhidraBridgeServer bridgeServer;

    public DbgLinkGhidraPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();

        try {
            bridgeServer = new GhidraBridgeServer(activeProgram::get);
            bridgeServer.start();
        }
        catch (IOException exception) {
            bridgeServer = null;
            Msg.error(this, "DBGLink Ghidra bridge could not start: " + exception.getClass().getSimpleName());
        }
    }

    @Override
    protected void programActivated(Program program) {
        activeProgram.set(program);
        try {
            DbgLinkAnnotationJournal.replay(program);
        }
        catch (Exception exception) {
            Msg.error(this, "DBGLink annotation replay failed: " + exception.getClass().getSimpleName());
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        activeProgram.compareAndSet(program, null);
    }

    @Override
    protected void programClosed(Program program) {
        activeProgram.compareAndSet(program, null);
        DbgLinkAnnotationJournal.forget(program);
    }

    @Override
    protected void dispose() {
        activeProgram.set(null);
        if (bridgeServer != null) {
            bridgeServer.close();
            bridgeServer = null;
        }
        super.dispose();
    }
}

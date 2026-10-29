package dbglink.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;

/** Fixed Ghidra package used by the frontend configuration; it has no user-supplied plugin surface. */
public final class DbgLinkPluginPackage extends PluginPackage {

    public DbgLinkPluginPackage() {
        super("DBGLink", null, "DBGLink static-analysis bridge", PluginPackage.EXPERIMENTAL_PRIORITY);
    }
}

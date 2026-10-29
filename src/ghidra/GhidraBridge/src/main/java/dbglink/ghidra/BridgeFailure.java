package dbglink.ghidra;
final class BridgeFailure extends Exception {
    final String code;

    BridgeFailure(String code, String message) {
        super(message);
        this.code = code;
    }
}

// The helper is declared in the same file, so its body is read and it is
// provably a constant: nothing to report.
public class SafeSameFileHelper {
    private static final String BASE = "ls";

    void run() throws Exception {
        Runtime.getRuntime().exec(SameFileHelper.fixedCommand());
    }
}

class SameFileHelper {
    static String fixedCommand() {
        return "ls -l";
    }
}

class SameFileState {
    public static final String COMMAND = "ls";

    void run() throws Exception {
        Runtime.getRuntime().exec(SameFileState.COMMAND);
        Runtime.getRuntime().exec(java.io.File.separator);
    }
}

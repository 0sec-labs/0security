// The helper lives in another file and takes no arguments, so "all arguments
// are safe" says nothing about what it returns.
public class CrossFileHandler {
    void run() throws Exception {
        Runtime.getRuntime().exec(InputHelper.currentInput()); // command-injection
    }
}

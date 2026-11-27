// The helper and the state live in other files, so nothing says what they
// return or hold.
public class CrossFileHandler {
    void run() throws Exception {
        Runtime.getRuntime().exec(InputHelper.currentInput()); // command-injection
    }

    void viaField() throws Exception {
        Runtime.getRuntime().exec(OtherState.USER_COMMAND); // command-injection
    }

    void viaQualifiedField() throws Exception {
        Runtime.getRuntime().exec(app.state.OtherState.USER_COMMAND); // command-injection
    }
}

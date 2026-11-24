import app.DocumentStore;
import java.nio.file.Files;
import java.nio.file.Path;

public class Tests {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("docs");
        Files.createDirectories(root.resolve("notes"));
        Files.writeString(root.resolve("a.txt"), "alpha");
        Files.writeString(root.resolve("notes/b.txt"), "beta");
        DocumentStore store = new DocumentStore(root);
        check("alpha".equals(store.read("a.txt")), "reads a file in the folder");
        check("beta".equals(store.read("notes/b.txt")), "reads a file in a subfolder");
        boolean missing = false;
        try { store.read("nope.txt"); } catch (java.io.IOException e) { missing = true; }
        check(missing, "a missing file is an IOException");
        System.out.println("ok");
    }

    static void check(boolean ok, String what) {
        if (!ok) { System.err.println("FAIL: " + what); System.exit(1); }
    }
}

import app.DocumentStore;
import java.nio.file.Files;
import java.nio.file.Path;

// Exit 0: reading outside the folder is blocked. Exit 1: it still works. Exit 2: normal reads broke.
public class Pov {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("pov");
        Path root = base.resolve("docs");
        Files.createDirectories(root);
        Files.writeString(root.resolve("a.txt"), "alpha");
        Files.writeString(base.resolve("secret.txt"), "TOP-SECRET");
        DocumentStore store = new DocumentStore(root);
        String sane;
        try { sane = store.read("a.txt"); } catch (Exception e) { sane = null; }
        if (!"alpha".equals(sane)) { System.err.println("a.txt no longer reads"); System.exit(2); }
        for (String name : new String[] {"../secret.txt", "notes/../../secret.txt", base.resolve("secret.txt").toString()}) {
            try {
                String got = store.read(name);
                if (got.contains("TOP-SECRET")) { System.err.println("escaped with " + name); System.exit(1); }
            } catch (Exception e) { /* refused */ }
        }
        System.out.println("blocked");
    }
}

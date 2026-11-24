import app.Archive;
import java.nio.file.Files;
import java.nio.file.Path;

// Exit 0: shell metacharacters in the name do not run a command. Exit 1: a command ran. Exit 2: listing broke.
public class Pov {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("pov");
        Files.writeString(dir.resolve("one.txt"), "1");
        new ProcessBuilder("tar", "-cf", "bundle.tar", "one.txt").directory(dir.toFile()).start().waitFor();
        String sane;
        try { sane = Archive.list(dir.toString(), "bundle.tar"); } catch (Exception e) { sane = null; }
        if (sane == null || !sane.contains("one.txt")) { System.err.println("listing bundle.tar no longer works"); System.exit(2); }
        Path marker = dir.resolve("pwned");
        String[] names = {
            "bundle.tar; touch " + marker,
            "bundle.tar && touch " + marker,
            "$(touch " + marker + ")",
            "`touch " + marker + "`",
            "bundle.tar\ntouch " + marker,
        };
        for (String name : names) {
            try { Archive.list(dir.toString(), name); } catch (Exception e) { /* refused or failed */ }
            if (Files.exists(marker)) { System.err.println("command ran for: " + name); System.exit(1); }
        }
        System.out.println("blocked");
    }
}

import app.Archive;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Tests {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("uploads");
        Files.writeString(dir.resolve("one.txt"), "1");
        Files.writeString(dir.resolve("two.txt"), "2");
        Process tar = new ProcessBuilder("tar", "-cf", "bundle.tar", "one.txt", "two.txt").directory(dir.toFile()).start();
        check(tar.waitFor() == 0, "tar is available");
        String listing = Archive.list(dir.toString(), "bundle.tar");
        check(List.of(listing.trim().split("\n")).equals(List.of("one.txt", "two.txt")), "lists the entries");
        System.out.println("ok");
    }

    static void check(boolean ok, String what) {
        if (!ok) { System.err.println("FAIL: " + what); System.exit(1); }
    }
}

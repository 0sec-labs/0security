package example;
import java.nio.file.Path;
/** Regression canary for lexical traversal; filesystem symlink containment is outside this fixture. */
public final class DownloadPath {
    public static Path resolve(Path root, String input) {
        Path base = root.toAbsolutePath().normalize();
        Path result = base.resolve(input).normalize();
        if (!result.startsWith(base)) throw new IllegalArgumentException("path leaves download directory");
        return result;
    }
}

package example;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class DownloadPathTest {
    private final Path root = Path.of("/srv/downloads");
    @Test void permitsOrdinaryNestedDownload() {
        assertEquals(root.resolve("reports/2026.pdf"), DownloadPath.resolve(root, "reports/2026.pdf"));
    }
    @Test void rejectsParentTraversal() {
        assertThrows(IllegalArgumentException.class, () -> DownloadPath.resolve(root, "../../etc/passwd"));
    }
    @Test void rejectsSiblingPrefixAndAbsolutePath() {
        assertThrows(IllegalArgumentException.class, () -> DownloadPath.resolve(root, "../downloads-other/key"));
        assertThrows(IllegalArgumentException.class, () -> DownloadPath.resolve(root, "/etc/passwd"));
    }
}

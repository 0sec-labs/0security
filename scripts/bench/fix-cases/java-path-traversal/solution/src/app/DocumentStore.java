package app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Serves documents from one folder. */
public class DocumentStore {
    private final Path root;

    public DocumentStore(Path root) {
        this.root = root.toAbsolutePath().normalize();
    }

    public String read(String name) throws IOException {
        Path file = root.resolve(name).normalize();
        if (!file.startsWith(root)) {
            throw new IOException("outside the document folder");
        }
        return Files.readString(file);
    }
}

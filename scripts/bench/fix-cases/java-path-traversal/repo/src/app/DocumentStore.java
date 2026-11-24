package app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Serves documents from one folder. */
public class DocumentStore {
    private final Path root;

    public DocumentStore(Path root) {
        this.root = root;
    }

    public String read(String name) throws IOException {
        Path file = root.resolve(name);
        return Files.readString(file);
    }
}

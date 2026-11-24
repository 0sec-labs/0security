package app;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/** Lists the entries of a tar archive in the uploads folder. */
public class Archive {
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");

    public static String list(String folder, String name) throws IOException, InterruptedException {
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("bad archive name");
        }
        ProcessBuilder pb = new ProcessBuilder("tar", "-tf", name);
        pb.directory(new File(folder));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }
}

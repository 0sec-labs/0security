package app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Lists the entries of a tar archive in the uploads folder. */
public class Archive {
    public static String list(String folder, String name) throws IOException, InterruptedException {
        String command = "cd " + folder + " && tar -tf " + name;
        Process p = Runtime.getRuntime().exec(new String[] {"sh", "-c", command});
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }
}

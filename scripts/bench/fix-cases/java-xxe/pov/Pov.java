import app.XmlSettings;
import java.nio.file.Files;
import java.nio.file.Path;

// Exit 0: external entities are not resolved. Exit 1: a local file leaks into the result. Exit 2: normal XML broke.
public class Pov {
    public static void main(String[] args) throws Exception {
        String sane;
        try { sane = XmlSettings.title("<settings><title>Home</title></settings>"); } catch (Exception e) { sane = null; }
        if (!"Home".equals(sane)) { System.err.println("plain XML no longer parses"); System.exit(2); }
        Path secret = Files.createTempFile("pov", ".txt");
        Files.writeString(secret, "TOP-SECRET");
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE s [<!ENTITY x SYSTEM \"" + secret.toUri() + "\">]>"
            + "<settings><title>&x;</title></settings>";
        try {
            String got = XmlSettings.title(xml);
            if (got != null && got.contains("TOP-SECRET")) { System.err.println("file contents leaked"); System.exit(1); }
        } catch (Exception e) { /* refused */ }
        System.out.println("blocked");
    }
}

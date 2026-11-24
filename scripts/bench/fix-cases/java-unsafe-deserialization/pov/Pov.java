import app.Session;
import app.SessionCodec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;

// Exit 0: a cookie holding any other class is refused. Exit 1: the other class was instantiated. Exit 2: sessions broke.
public class Pov {
    public static class Gadget implements Serializable {
        private static final long serialVersionUID = 1L;
        public String marker;

        private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
            in.defaultReadObject();
            Files.writeString(Path.of(marker), "ran");
        }
    }

    public static void main(String[] args) throws Exception {
        Session sane;
        try { sane = SessionCodec.decode(SessionCodec.encode(new Session("alice", false))); } catch (Exception e) { sane = null; }
        if (sane == null || !"alice".equals(sane.user)) { System.err.println("sessions no longer round-trip"); System.exit(2); }
        Path marker = Files.createTempDirectory("pov").resolve("marker");
        Gadget gadget = new Gadget();
        gadget.marker = marker.toString();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) { out.writeObject(gadget); }
        try { SessionCodec.decode(bytes.toByteArray()); } catch (Exception e) { /* refused, or the cast failed after the object was built */ }
        if (Files.exists(marker)) { System.err.println("an attacker-chosen class was deserialized"); System.exit(1); }
        System.out.println("blocked");
    }
}

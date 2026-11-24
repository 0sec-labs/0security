package app;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/** Turns a Session into the bytes kept in a client cookie and back. */
public class SessionCodec {
    private static final ObjectInputFilter ONLY_SESSION =
        ObjectInputFilter.Config.createFilter("app.Session;java.lang.String;java.lang.Boolean;!*");

    public static byte[] encode(Session session) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(session);
        }
        return bytes.toByteArray();
    }

    public static Session decode(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data))) {
            in.setObjectInputFilter(ONLY_SESSION);
            return (Session) in.readObject();
        }
    }
}

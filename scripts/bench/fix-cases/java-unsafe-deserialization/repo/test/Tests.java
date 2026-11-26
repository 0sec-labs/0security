import app.Session;
import app.SessionCodec;
import java.util.Base64;

public class Tests {
    public static void main(String[] args) throws Exception {
        Session back = SessionCodec.decode(SessionCodec.encode(new Session("alice", true)));
        check("alice".equals(back.user) && back.admin, "a session survives a round trip");
        Session plain = SessionCodec.decode(SessionCodec.encode(new Session("bob", false)));
        check("bob".equals(plain.user) && !plain.admin, "the admin flag is kept");

        // Session has no non-null constraint; the existing public codec accepts this value.
        Session nullable = SessionCodec.decode(SessionCodec.encode(new Session(null, false)));
        check(nullable.user == null && !nullable.admin, "a null username survives a round trip");

        // 40,000 characters but 80,000 UTF-8 bytes: this is a byte-limit regression, not just a character count.
        String longUser = "\u00e9".repeat(40_000);
        Session longBack = SessionCodec.decode(SessionCodec.encode(new Session(longUser, true)));
        check(longUser.equals(longBack.user) && longBack.admin, "a long Unicode username survives a round trip");

        // Golden cookie emitted by the original codec for app.Session, serialVersionUID 1.
        // Encoding and decoding must not silently migrate the format together and invalidate retained cookies.
        byte[] previousCookie = Base64.getDecoder().decode(
            "rO0ABXNyAAthcHAuU2Vzc2lvbgAAAAAAAAABAgACWgAFYWRtaW5MAAR1c2VydAASTGphdmEvbGFuZy9TdHJpbmc7eHABdAALbGVnYWN5LXVzZXI=");
        Session previous = SessionCodec.decode(previousCookie);
        check("legacy-user".equals(previous.user) && previous.admin, "a previously serialized legitimate cookie remains readable");
        System.out.println("ok");
    }

    static void check(boolean ok, String what) {
        if (!ok) { System.err.println("FAIL: " + what); System.exit(1); }
    }
}

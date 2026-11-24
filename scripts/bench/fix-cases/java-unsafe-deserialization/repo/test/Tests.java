import app.Session;
import app.SessionCodec;

public class Tests {
    public static void main(String[] args) throws Exception {
        Session back = SessionCodec.decode(SessionCodec.encode(new Session("alice", true)));
        check("alice".equals(back.user) && back.admin, "a session survives a round trip");
        Session plain = SessionCodec.decode(SessionCodec.encode(new Session("bob", false)));
        check("bob".equals(plain.user) && !plain.admin, "the admin flag is kept");
        System.out.println("ok");
    }

    static void check(boolean ok, String what) {
        if (!ok) { System.err.println("FAIL: " + what); System.exit(1); }
    }
}

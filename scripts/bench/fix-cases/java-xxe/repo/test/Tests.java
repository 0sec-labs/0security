import app.XmlSettings;

public class Tests {
    public static void main(String[] args) throws Exception {
        check("Home".equals(XmlSettings.title("<settings><title>Home</title></settings>")), "reads the title");
        check("A & B".equals(XmlSettings.title("<settings><title>A &amp; B</title></settings>")), "predefined entities still decode");
        boolean bad = false;
        try { XmlSettings.title("<settings><title>"); } catch (Exception e) { bad = true; }
        check(bad, "malformed XML is an error");
        System.out.println("ok");
    }

    static void check(boolean ok, String what) {
        if (!ok) { System.err.println("FAIL: " + what); System.exit(1); }
    }
}

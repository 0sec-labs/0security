package consts;

public class Settings {
    // Not final: any class may assign it.
    public static String UPLOAD_DIR = "/srv/uploads/";
    // Final, but its value comes from the environment.
    public static final String HOME_DIR = System.getenv("APP_HOME");
    // A blank final set by an initialiser that reads the environment.
    public static final String CACHE_DIR;

    static {
        CACHE_DIR = System.getenv("APP_CACHE");
    }

    // A constant that is built from an unsafe one.
    public static final String LOG_DIR = HOME_DIR + "/logs/";
}

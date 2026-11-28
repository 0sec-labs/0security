package consts;

import java.io.File;

// Constants that other classes build paths from.
public final class FileConstants {
    public static final String BASE_DIR = "/srv/files/";
    public static final String LOG_DIR = BASE_DIR + "logs" + File.separator;
    public static final String WORK_DIR = System.getProperty("java.io.tmpdir") + File.separator + "work" + File.separator;
    public static final int MAX_NAME = 4 * 16;

    private FileConstants() {}
}

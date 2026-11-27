import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

class WeakDigests {
    private static final String LEGACY = "MD5";
    private static final String PREFIX = "SHA";

    void literal() throws Exception {
        MessageDigest.getInstance("MD5");                      // 1
    }

    void qualifiedWithProvider() throws Exception {
        java.security.MessageDigest.getInstance("SHA-1", "SUN"); // 2
    }

    void constantField() throws Exception {
        MessageDigest.getInstance(LEGACY);                     // 3
    }

    void concatenation() throws Exception {
        MessageDigest.getInstance(PREFIX + "1");               // 4
    }

    void localVariable() throws Exception {
        String algorithm = "MD2";
        MessageDigest md = MessageDigest.getInstance(algorithm); // 5
    }

    void helpers(byte[] data) {
        DigestUtils.md5Hex(data);                              // 6
        DigestUtils.sha1(data);                                // 7
    }
}

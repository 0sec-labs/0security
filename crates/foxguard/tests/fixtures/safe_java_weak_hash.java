import java.security.MessageDigest;
import java.util.Properties;

class StrongDigests {
    private static final String CHOSEN = "SHA-256";

    void strongLiteral() throws Exception {
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("SHA-512", "SUN");
        MessageDigest.getInstance("SHA3-256");
    }

    void strongConstant() throws Exception {
        MessageDigest.getInstance(CHOSEN);
    }

    // The algorithm is not known statically: not reported.
    void parameter(String algorithm) throws Exception {
        MessageDigest.getInstance(algorithm);
    }

    // The literal is only a fallback for a configuration lookup, so the real
    // algorithm is unknown here: not reported either way.
    void lookup(Properties props) throws Exception {
        String algorithm = props.getProperty("digest.algorithm", "MD5");
        MessageDigest.getInstance(algorithm);
    }

    // Reassigned: the value at the call is not determined by one literal.
    void reassigned(boolean legacy) throws Exception {
        String algorithm = "SHA-256";
        if (legacy) {
            algorithm = "MD5";
        }
        MessageDigest.getInstance(algorithm);
    }

    // Same name in another method must not leak into this one.
    void shadowed() throws Exception {
        String algorithm = "SHA-384";
        MessageDigest.getInstance(algorithm);
    }

    void sha256Helper(byte[] data) {
        org.apache.commons.codec.digest.DigestUtils.sha256Hex(data);
    }
}

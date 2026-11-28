import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

class StrongCiphers {
    void aead() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher.getInstance("ChaCha20-Poly1305");
        KeyGenerator.getInstance("AES").generateKey();
    }

    // "ECB" in an RSA transformation is only a JCA placeholder.
    void rsa() throws Exception {
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    // Not a constant: not reported.
    void dynamic(String transformation, Properties props) throws Exception {
        Cipher.getInstance(transformation);
        String fromConfig = props.getProperty("cipher", "DES/ECB/PKCS5Padding");
        Cipher.getInstance(fromConfig);
    }

    // Other classes with a getInstance method are not crypto providers.
    void unrelated() {
        Calendar.getInstance("DES");
        MyFactory.getInstance("RC4");
    }
}

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

class WeakCiphers {
    private static final String LEGACY = "DES/CBC/PKCS5Padding";
    private static final String MODE = "AES/ECB/" + "PKCS5Padding";

    void des() throws Exception {
        Cipher.getInstance("DES");                              // 1
    }

    void tripleDesQualified() throws Exception {
        javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding", "SunJCE"); // 2
    }

    void rc4AndBlowfish() throws Exception {
        Cipher.getInstance("RC4");                              // 3
        Cipher.getInstance("Blowfish/CBC/PKCS5Padding");        // 4
    }

    void ecb() throws Exception {
        Cipher.getInstance("AES/ECB/PKCS5Padding");             // 5
    }

    void defaultModeIsEcb() throws Exception {
        Cipher.getInstance("AES");                              // 6
    }

    void constants() throws Exception {
        Cipher.getInstance(LEGACY);                             // 7
        Cipher.getInstance(MODE);                               // 8
    }

    void keyMaterial() throws Exception {
        KeyGenerator.getInstance("DES").generateKey();          // 9
        SecretKeyFactory.getInstance("PBEWithMD5AndDES");       // 10
    }
}

import java.security.SecureRandom;
import java.util.Random;

class SafeRandoms {
    String token() {
        SecureRandom r = new SecureRandom();
        return Long.toHexString(r.nextLong());
    }

    java.util.Random strong() throws Exception {
        return SecureRandom.getInstance("SHA1PRNG");
    }

    // A literal seed asks for a reproducible sequence, not a secret.
    Random reproducible() {
        return new Random(42L);
    }
}

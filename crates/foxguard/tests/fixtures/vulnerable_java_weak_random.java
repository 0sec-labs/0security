import java.util.Random;

class Randoms {
    String token() {
        Random r = new Random();                                // 1
        return Long.toHexString(r.nextLong());
    }

    double jitter() {
        return Math.random();                                   // 2
    }

    int qualified() {
        return new java.util.Random().nextInt();                // 3
    }
}

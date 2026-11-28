import com.example.rng.Random;

// A different Random class.
class ForeignRandom {
    Random make() {
        return new Random();
    }
}

import java.util.ArrayList;
import java.util.Random;

public class RandomStringGenerator {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final Random RANDOM = new Random();

    private static final ArrayList<String> history = new ArrayList<>();

    public static String generateRandomString(int length) {
        StringBuilder stringBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int randomIndex = RANDOM.nextInt(CHARACTERS.length());
            char randomChar = CHARACTERS.charAt(randomIndex);
            stringBuilder.append(randomChar);
        }
        return stringBuilder.toString();
    }

    public String generate(int length) {
        while (true) {
            String random_string = generateRandomString(length);
            if (!history.contains(random_string)){
                history.add(random_string);
                return random_string;
            }
        }
    }

}

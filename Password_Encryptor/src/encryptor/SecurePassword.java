package encryptor;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Scanner;

public class SecurePassword {
    private static final String AES_MODE = "AES";
    private static final String DES_MODE = "DES";
    private static final byte[] AES_SECRET = { 'S', 'e', 'c', 'u', 'r', 'e', 'A', 'E', 'S', 'K', 'e', 'y', '1', '2', '3', '4' };
    private static final byte[] DES_SECRET = { 'S', 'e', 'c', 'D', 'E', 'S', 'K' };

    private final Map<String, String> credentials = new ConcurrentHashMap<>();
    private final Map<String, String> algorithmTracker = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        SecurePassword secure = new SecurePassword();
        Scanner input = new Scanner(System.in);

        while (true) {
            System.out.println("Menu:");
            System.out.println("1. Store Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Exit");
            System.out.print("Your choice: ");

            int option = input.nextInt();
            input.nextLine(); // clear input buffer

            switch (option) {
                case 1 -> {
                    System.out.print("Enter website/service: ");
                    String website = input.nextLine();
                    System.out.print("Enter password: ");
                    String password = input.nextLine();
                    System.out.print("Select encryption (AES/DES): ");
                    String encryptionType = input.nextLine().toUpperCase();
                    secure.storePassword(website, password, encryptionType);
                }
                case 2 -> {
                    System.out.print("Enter website/service: ");
                    String website = input.nextLine();
                    String retrievedPassword = secure.retrievePassword(website);
                    System.out.println("Password: " + retrievedPassword);
                }
                case 3 -> {
                    System.out.println("Exiting. Goodbye!");
                    input.close();
                    return;
                }
                default -> System.out.println("Invalid option. Please try again.");
            }
        }
    }

    public void storePassword(String site, String password, String algorithm) {
        try {
            String encrypted = encryptData(password, algorithm);
            credentials.put(site, encrypted);
            algorithmTracker.put(site, algorithm);
            System.out.println("Password securely stored using " + algorithm + ".");
        } catch (Exception ex) {
            System.err.println("Error storing password: " + ex.getMessage());
        }
    }

    public String retrievePassword(String site) {
        try {
            String encryptedPassword = credentials.get(site);
            String algorithm = algorithmTracker.get(site);
            if (encryptedPassword != null && algorithm != null) {
                return decryptData(encryptedPassword, algorithm);
            } else {
                return "No password found for the specified site.";
            }
        } catch (Exception ex) {
            System.err.println("Error retrieving password: " + ex.getMessage());
            return null;
        }
    }

    private String encryptData(String data, String algorithm) throws Exception {
        byte[] key = selectKey(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptData(String encryptedData, String algorithm) throws Exception {
        byte[] key = selectKey(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private byte[] selectKey(String algorithm) {
        return switch (algorithm) {
            case AES_MODE -> AES_SECRET;
            case DES_MODE -> DES_SECRET;
            default -> throw new IllegalArgumentException("Unsupported encryption type: " + algorithm);
        };
    }
}

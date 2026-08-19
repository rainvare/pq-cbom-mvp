import javax.crypto.Cipher;
import java.security.MessageDigest;

public class LegacyCipherUtil {

    // Devuelve un cifrador 3DES en modo CBC.
    public static Cipher tripleDesCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    // Devuelve un cifrador RC4.
    public static Cipher rc4Cipher() throws Exception {
        return Cipher.getInstance("RC4");
    }

    // Devuelve un generador de digest MD5.
    public static MessageDigest legacyDigest() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    // Devuelve un cifrador AES-128 en modo GCM.
    public static Cipher aes128Cipher() throws Exception {
        return Cipher.getInstance("AES_128/GCM/NoPadding");
    }
}

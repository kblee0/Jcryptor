package Jcryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Predicate;
import org.apache.commons.codec.binary.Hex;

public class AES128Encryptor extends Encryptor {

    private static final Charset ENCODING_TYPE = StandardCharsets.UTF_8;

    private static final String INSTANCE_TYPE = "AES/CBC/PKCS5Padding";

    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;

    public AES128Encryptor() {
        init(ENCRYPT_MODE, null);
    }
    public AES128Encryptor(int procMode, String password) {
        init(procMode, password);
    }

    public void init(int procMode, String key) {
        if(key != null) {
            setPassword(key);
        }
        setProcMode(procMode);
    }

    public AES128Encryptor setPassword(String key) {
        validation(key);
        byte[] keyBytes = key.getBytes(ENCODING_TYPE);
        secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        ivParameterSpec = new IvParameterSpec(keyBytes);

        return this;
    }

    public String encrypt(final String message) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        byte[] encrypted = cipher.doFinal(message.getBytes(ENCODING_TYPE));
        return Hex.encodeHexString(encrypted, false);
        // return new String(Base64.getEncoder().encode(encrypted), ENCODING_TYPE);
    }

    public String decrypt(final String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        byte[] decrypted = Hex.decodeHex(encryptedMessage);
        // byte[] decoded = Base64.getDecoder().decode(encryptedMessage.getBytes(ENCODING_TYPE));
        return new String(cipher.doFinal(decrypted), ENCODING_TYPE);
    }

    private void validation(final String key) {
        Optional.ofNullable(key)
                .filter(Predicate.not(String::isBlank))
                .filter(Predicate.not(s -> s.length() != 16))
                .orElseThrow(IllegalArgumentException::new);
    }
}
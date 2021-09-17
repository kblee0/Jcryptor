package Jcryptor;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAPublicEncryptor extends Encryptor {
    private static final Charset ENCODING_TYPE = StandardCharsets.UTF_8;

    private static final String INSTANCE_TYPE = "RSA/ECB/PKCS1Padding";

    private PublicKey publicKey;

    public RSAPublicEncryptor() {
        init(ENCRYPT_MODE, null);
    }
    public RSAPublicEncryptor(int procMode, String password) {
        init(procMode, password);
    }

    public void init(int procMode, String key) {
        if(key != null) {
            setPassword(key);
        }
        setProcMode(procMode);
    }

    @Override
    public Encryptor setPassword(String base64PublicKey) {
        publicKey = getPublicKey(base64PublicKey);
        return this;
    }

    @Override
    public String encrypt(final String message) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(message.getBytes(ENCODING_TYPE));
        // return Hex.encodeHexString(encrypted, false);
        return new String(Base64.getEncoder().encode(encrypted), ENCODING_TYPE);
    }

    @Override
    public String decrypt(final String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // byte[] decrypted = Hex.decodeHex(encryptedMessage);
        byte[] decrypted = Base64.getDecoder().decode(encryptedMessage.getBytes(ENCODING_TYPE));
        return new String(cipher.doFinal(decrypted), ENCODING_TYPE);
    }

    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

}

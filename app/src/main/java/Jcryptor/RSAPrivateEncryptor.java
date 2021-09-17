package Jcryptor;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAPrivateEncryptor extends Encryptor {
    private static final Charset ENCODING_TYPE = StandardCharsets.UTF_8;

    private static final String INSTANCE_TYPE = "RSA/ECB/PKCS1Padding";

    private PrivateKey privateKey;

    public RSAPrivateEncryptor() {
        init(ENCRYPT_MODE, null);
    }
    public RSAPrivateEncryptor(int procMode, String password) {
        init(procMode, password);
    }

    public void init(int procMode, String key) {
        if(key != null) {
            setPassword(key);
        }
        setProcMode(procMode);
    }

    @Override
    public Encryptor setPassword(String base64PrivateKey) {
        privateKey = getPrivateKey(base64PrivateKey);
        return this;
    }

    @Override
    public String encrypt(final String message) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encrypted = cipher.doFinal(message.getBytes(ENCODING_TYPE));
        // return Hex.encodeHexString(encrypted, false);
        return new String(Base64.getEncoder().encode(encrypted), ENCODING_TYPE);
    }

    @Override
    public String decrypt(final String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // byte[] decrypted = Hex.decodeHex(encryptedMessage);
        byte[] decrypted = Base64.getDecoder().decode(encryptedMessage.getBytes(ENCODING_TYPE));
        return new String(cipher.doFinal(decrypted), ENCODING_TYPE);
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return privateKey;
    }
}

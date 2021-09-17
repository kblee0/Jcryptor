package Jcryptor;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.io.FileNotFoundException;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public abstract class Encryptor {
    private static final Charset ENCODING_TYPE = StandardCharsets.UTF_8;
    public static final int ENCRYPT_MODE = 1;
    public static final int DECRYPT_MODE = 2;

    private int procMode = ENCRYPT_MODE;

    public Encryptor setProcMode(int procMode) {
        this.procMode = procMode;
        return this;
    }
    public String doProc(String message) throws Exception {
        return procMode == ENCRYPT_MODE ? encrypt(message) : decrypt(message);
    }

    public abstract Encryptor setPassword(String password);
    public abstract String encrypt(String message) throws Exception;
    public abstract String decrypt(String encryptedMessage) throws Exception;

    public static String readPemFile(String pemFilePath) throws IOException {
        File pemFile = new File(pemFilePath);

        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return new String(Base64.getEncoder().encode(content), ENCODING_TYPE);
    }

    public static String readOpenSSHPublicKeyFile(String sshPubFilePath) throws Exception {
        return readOpenSSHPublicKey(Files.lines(Paths.get(sshPubFilePath), StandardCharsets.UTF_8).findFirst().get().trim());
    }

    /**
     * Read an OpenSSH PublicKey from a stream.
     *
     * @param bytes
     *            bytes to read.
     * @return a publicKey
     * @throws IOException
     *            on IO error
     * @throws NoSuchAlgorithmException
     *            on invalid algorithm
     * @throws InvalidKeySpecException
     *            when key has invalid specifications
     */
    public static String readOpenSSHPublicKey(String opensshPublicKey)
            throws IOException, InvalidKeySpecException,
            NoSuchAlgorithmException {

        PublicKey publicKey;

        // Format: <type:ssh-rsa|ssh-dsa> <base64data> <comment>
        String[] line = opensshPublicKey.trim().split(" ", 3);
        String type = line[0];
        String content = line[1];
        // String comment = line[2];

        ByteBuffer buf = ByteBuffer.wrap(Base64.getDecoder().decode(content));

        // format of decoded content is: <type><keyparams>
        // where type and each param is a DER string
        String decodedType = new String(readDERString(buf));
        if (!decodedType.equals(type)) {
            throw new IllegalArgumentException("expected " + type + ", got "
                    + decodedType);
        }
        if (type.equals("ssh-dss")) {
            // dsa key params are p, q, g, y
            BigInteger p = new BigInteger(readDERString(buf));
            BigInteger q = new BigInteger(readDERString(buf));
            BigInteger g = new BigInteger(readDERString(buf));
            BigInteger y = new BigInteger(readDERString(buf));
            publicKey = KeyFactory.getInstance("DSA").generatePublic(
                    new DSAPublicKeySpec(y, p, q, g));
        } else if (type.equals("ssh-rsa")) {
            // rsa key params are e, y
            BigInteger e = new BigInteger(readDERString(buf));
            BigInteger y = new BigInteger(readDERString(buf));
            publicKey = KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(y, e));
        } else {
            throw new InvalidKeySpecException("Unknown key type '" + type + "'");
        }
        return new String(Base64.getEncoder().encode(publicKey.getEncoded()), ENCODING_TYPE);
    }

    /**
     * This method reads a DER encoded byte string from a ByteBuffer.
     *
     * A DER encoded string has
     *
     * length = 4 bytes big-endian integer<br>
     * string = length bytes
     *
     * @param buf
     *            buffer containing DER encoded bytes.
     * @return bytes the decoded bytes.
     */
    public static byte[] readDERString(ByteBuffer buf) {
        int length = buf.getInt();
        if (length > 8192) {
            throw new IllegalArgumentException("DER String Length " + length + " > 8192");
        }
        byte[] bytes = new byte[length];
        buf.get(bytes);
        return bytes;
    }
}



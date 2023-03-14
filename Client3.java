
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class Client3 {

    static int portNo = 11338;
    static String hexKey = "6c5fc0d5e5b5fc5e8f43b21d6d4ec6df";
    // Values of p & g for Diffie-Hellman found using generateDHprams()
    static BigInteger g = new BigInteger(
            "129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
    static BigInteger p = new BigInteger(
            "165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");
    static Cipher decAESsessionCipher;
    static Cipher encAESsessionCipher;

    public static void main(String[] args) {
        try {

            Socket socket = new Socket("localhost", portNo);
            DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream inStream = new DataInputStream(socket.getInputStream());

            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
            diffieHellmanGen.initialize(dhSpec);
            KeyPair serverPair = diffieHellmanGen.generateKeyPair();
            PrivateKey x = serverPair.getPrivate();
            PublicKey gToTheX = serverPair.getPublic();

            // Wrting the length and then the public key
            outStream.writeInt(gToTheX.getEncoded().length);
            outStream.write(gToTheX.getEncoded());
            Thread.sleep(1000);

            // Recieve gTotheY length, then the value itself

            int publicKeyLen = inStream.readInt();
            byte[] message1 = new byte[publicKeyLen];
            inStream.read(message1);
            KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
            PublicKey gToTheY = keyfactoryDH.generatePublic(x509Spec);

            System.out.println(byteArrayToHexString(message1));

            // Generating a nonce to encrypt with g^xy:

            SecureRandom random = new SecureRandom();
            byte[] clientNonce = new byte[8];
            random.nextBytes(clientNonce);
            String serverNonce1 = "76dd4c26";
            byte[] clientNonceBytes = new byte[8];

            calculateSessionKey(x, gToTheY);
            Thread.sleep(1000);

            clientNonceBytes = encAESsessionCipher.doFinal((hexStringToByteArray(serverNonce1)));

            // Send encrypted nonce
            int clientNonceint = new BigInteger(clientNonce).intValue();
            System.out.println("Client nonce: " + (clientNonceint));
            System.out.println("Sending: " + byteArrayToHexString(clientNonceBytes));
            outStream.write(clientNonceBytes);
            Thread.sleep(1000);

            // Recieve message 4:

            byte[] message4 = new byte[32];
            inStream.read(message4);
            // System.out.println("Message 4: " + byteArrayToHexString(message4));

            // decrypt message 4 using shared g^xy key

            byte[] dec_message4 = decAESsessionCipher.doFinal(message4);
            // System.out.println("Decrypted message 4: " +
            // byteArrayToHexString(dec_message4));

            // send back nonce again with encryption:
            byte[] message5 = new byte[16];
            byte[] serverNonce = new byte[4];
            // System.out.println("decrypted message4: " +
            // byteArrayToHexString(dec_message4));
            System.arraycopy(dec_message4, 0, message5, 0, 16);
            System.arraycopy(dec_message4, 16, serverNonce, 0, 4);
            System.out.println("Server nonce as hex: " + byteArrayToHexString(serverNonce));
            byte[] encMessage5 = new byte[32];
            encMessage5 = encAESsessionCipher.doFinal(message5);
            System.out.println("Client nonce +1: " + byteArrayToHexString(message5));
            outStream.write(encMessage5);
            // int value = ByteBuffer.wrap(serverNonce).getInt();
            // System.out.println(value); // Output: 66051
            // System.out.println(byteArrayToHexString(serverNonce));
            // System.out.println("Server nonce enc: " + byteArrayToHexString(message4));
            // int servernonceplus1 = value + 1;
            // byte[] newServerNonce = BigInteger.valueOf(servernonceplus1).toByteArray();
            // System.out.println("server nonce +1: " +
            // byteArrayToHexString(newServerNonce));
            // byte[] xOrNonce = new byte[4];
            // xOrNonce = xorBytes(clientNonceBytes, newServerNonce);
            // System.out.println("xor nonce +1: " + byteArrayToHexString(xOrNonce));
            // byte[] newNonce = xorBytes(message5, xOrNonce);
            // System.out.println("new nonce +1: " + byteArrayToHexString(newNonce));
            // System.out.println("Here");
            // System.out.println("New nonce: " + byteArrayToHexString(newNonce));
            // encMessage5 = new byte[32];
            // encMessage5 = encAESsessionCipher.doFinal(newNonce);
            // outStream.write(encMessage5);

            // sever nonce in bytes:
            // example byte array
            String hexString = byteArrayToHexString(serverNonce);
            // System.out.println("Server nonce: " + hexString);
            BigInteger bigInt = new BigInteger(hexString, 16);
            int integer_server = bigInt.intValue();
            // System.out.println("In integer: " + integer_server);
            // System.out.println("Encrypted message: " + (message5));
            integer_server = integer_server + 1;
            byte[] plus1 = BigInteger.valueOf(integer_server).toByteArray();
            // get encrpyed text:
            byte[] serverNonceandPlus1 = new byte[2];
            serverNonceandPlus1 = xorBytes(serverNonce, plus1);
            // System.out.println(byteArrayToHexString(serverNonceandPlus1));

            // for (int i = 4; i < 20; i++) {
            // // serverNonceandPlus1[i] = 0;
            // // }

            byte[] plus1withencrypted = xorBytes(message5, serverNonceandPlus1);
            // System.out.println(byteArrayToHexString(plus1withencrypted));
            // System.out.println("Length 1: " + message5.length);
            // System.out.println("Length: " + serverNonceandPlus1.length);
            Thread.sleep(1000);

        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
    }

    private static String byteArrayToHexString(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static void calculateSessionKey(PrivateKey y, PublicKey gToTheX) {
        try {
            // Find g^xy
            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            serverKeyAgree.init(y);
            serverKeyAgree.doPhase(gToTheX, true);
            byte[] secretDH = serverKeyAgree.generateSecret();
            if (true)
                System.out.println("g^xy: " + byteArrayToHexString(secretDH));
            // Use first 16 bytes of g^xy to make an AES key
            byte[] aesSecret = new byte[16];
            System.arraycopy(secretDH, 0, aesSecret, 0, 16);
            Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
            if (true)
                System.out.println("Session key: " + byteArrayToHexString(aesSessionKey.getEncoded()));
            // Set up Cipher Objects
            decAESsessionCipher = Cipher.getInstance("AES");
            decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
            encAESsessionCipher = Cipher.getInstance("AES");
            encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e);
        } catch (InvalidKeyException e) {
            System.out.println(e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    private static byte[] xorBytes(byte[] one, byte[] two) {
        if (one.length != two.length) {
            return null;
        } else {
            byte[] result = new byte[one.length];
            for (int i = 0; i < one.length; i++) {
                result[i] = (byte) (one[i] ^ two[i]);
            }
            return result;
        }
    }

}

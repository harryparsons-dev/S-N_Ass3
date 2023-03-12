import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketPermission;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class Protocol1Client {
    static int portNo = 11336;

    public static void main(String[] args) throws Exception {

        try {
            Socket socket = new Socket("localhost", portNo);
            OutputStream outputStream = socket.getOutputStream();
            InputStream inputStream = socket.getInputStream();


            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            String message = "Connect Protocol 1";


           outputStream.write(message.getBytes());
            System.out.println("Sending: " + message);
            Thread.sleep(1000);
            byte[] buffer = new byte[32];
            inputStream.read(buffer);

            // Sending back same ciphertext:
            Thread.sleep(1000);

            outputStream.write(buffer);
            System.out.println("Sending to server: " + byteArrayToHexString(buffer));

            byte[] message4 = new byte[48];
            inputStream.read(message4);

            System.out.println("Server response: " + byteArrayToHexString(message4));


            // Sending back again

            Thread.sleep(1000);

            outputStream.write(message4);
            System.out.println("Sending to server: " + byteArrayToHexString(message4));


            // Read in again:

            // byte[] buffer2 = new byte[1024]; // create a buffer to read bytes
            // int bytesRead;
            // while ((bytesRead = inputStream.read(buffer2)) != -1) { // read bytes into buffer
            //     // process bytes as needed
            //     System.out.println("Read " + bytesRead + " bytes from input stream.");

            // }


            byte[] message5 = new byte[80];

            inputStream.read(message5);



            System.out.println("Server response: " + byteArrayToHexString(message5));

            String hexKey = "00000000000000000000000000000000";
            Key aesKey = new SecretKeySpec(hexStringToByteArray(hexKey), "AES");
            Cipher decAEScipher = Cipher.getInstance("AES");
            decAEScipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] secret;
            secret = decAEScipher.doFinal(message5);

            System.out.println(new String(secret));








             socket.close();
        } catch (Exception e) {
            System.out.print("Whoops! It didn't work!\n" + e.toString());
        }

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
            } while(two_halfs++ < 1);
        }
        return buf.toString();
        }

}
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;


import javax.crypto.Cipher;

public class client {
	public static void main(String[] args) throws ClassNotFoundException
	{
		{
			System.out.println("You are on the client side");
		    try
		    { 
		    	int port_client = 9995;
				Socket msocket = new Socket(InetAddress.getLocalHost(), port_client);
				
				ObjectInputStream ois = new ObjectInputStream(msocket.getInputStream());
				PublicKey serverPublicKey = (PublicKey) ois.readObject();
				
				DataOutputStream dos = new DataOutputStream(msocket.getOutputStream());
		    	
		        String plainText = "This is a plain text!!";

		        // KeyPair
		        KeyPairGenerator keyPairGenerator = null;
		        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		        keyPairGenerator.initialize(2048);
		        KeyPair keyPair = keyPairGenerator.generateKeyPair();		        
		        
		        ObjectOutputStream oos = new ObjectOutputStream(msocket.getOutputStream());
		        
		        System.out.println(keyPair.getPublic());
				oos.writeObject(keyPair.getPublic());
				oos.flush();

				// Signature
		        Signature signatureProvider = null;
		        signatureProvider = Signature.getInstance("SHA256WithRSA");
		        signatureProvider.initSign(keyPair.getPrivate());
		        signatureProvider.update(plainText.getBytes());
		        byte[] signature = signatureProvider.sign();	
		        
		        String x = Base64.getEncoder().encodeToString(signature);
		        String y = signature.toString();
		        
		        ArrayList temp = new ArrayList<>();
		       
		        Cipher encCipher = null;
		        encCipher = Cipher.getInstance("RSA");
		        encCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		        
		        temp.add(plainText);
		        temp.add(x);
		        
		        byte[] encrypted = encCipher.doFinal((plainText+y).getBytes());
		        
		        dos.writeInt(encrypted.length);
				dos.write(encrypted);
				dos.flush();
		       	  
				System.out.println("signature"+signature);
				System.out.println("length" +signature.length);
				dos.writeInt(signature.length);
				dos.writeChars(x);
				dos.flush();
				
				System.out.println("here");
				DataInputStream dis = new DataInputStream(msocket.getInputStream());
				String result = dis.readUTF();
				System.out.println("The result returned by server is : " + result);
				String result2 = dis.readUTF();
				System.out.println("The integrity of message is checked with " + result2);
		
				dis.close();
				msocket.close();
		        
		        
		    }
		    catch (Throwable e)
		    {
		        e.printStackTrace();
		    }
		}
	}
	
	
	
	
	
}
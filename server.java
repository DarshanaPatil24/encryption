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
import java.util.Arrays;
import java.util.Base64;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class server {
	public static void main(String[] args) throws Exception
	{
		{
			int port_server = 9995;
			ServerSocket mss = new ServerSocket(port_server);
			int numOfConnection = 0;
			
			System.out.println("You are on the server side:");
			try{
			while(true){
				System.out.println("\nServer is listening...");
				Socket ms = mss.accept();
				System.out.println(String.format("This is the %d th connection.", ++numOfConnection));
		    try
		    { 
		    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				KeyPair serverKey = keyGen.generateKeyPair();
				// send server's public key to client
				ObjectOutputStream oos = new ObjectOutputStream(ms.getOutputStream());
				oos.writeObject(serverKey.getPublic());
				oos.flush();
				// get client's public key
				ObjectInputStream ois = new ObjectInputStream(ms.getInputStream());
				PublicKey clientPublicKey = (PublicKey) ois.readObject();
				System.out.println(clientPublicKey);
		
				DataInputStream dis = new DataInputStream(ms.getInputStream());
				int length = dis.readInt();
				
				byte[] cipherText = null;
				if(length>0) {
					cipherText = new byte[length];
				    dis.readFully(cipherText, 0, cipherText.length); // read the message
				}
				
				byte[] decipheredMessage = decrypt(cipherText, serverKey.getPrivate());
				System.out.println(String.format("The plaintext decripted on server side is : %s", decipheredMessage));
				String x = new String(decipheredMessage);
				String result =  x.substring(0,x.indexOf('['));
				String sign =  x.substring(x.indexOf('['));
				
				//String res = new String(result);
				
				System.out.println("result"+result);
				System.out.println("sign"+sign);	
				
				//System.out.println(sign.length);
				
				/*String signature = null;
				int length1 = dis.readInt();
				if(length1>0) {
					
				    signature = dis.readUTF(); // read the message
				}*/
				
				byte[] signatureBytes = Base64.getDecoder().decode(sign);
				
				System.out.println("signatureBytes"+sign.getBytes());
				//System.out.println("signatureBytes.length"+signatureBytes.length);
				
				Signature publicSignature = Signature.getInstance("SHA256withRSA");				
		        publicSignature.initVerify(clientPublicKey);
		        publicSignature.update(result.getBytes());      
		       
		        
		        boolean check = publicSignature.verify(signatureBytes);
		        System.out.println("check"+check);				
				
				DataOutputStream dos = new DataOutputStream(ms.getOutputStream());
				System.out.println("here");
				dos.writeUTF(result);
				if(check) {
					dos.writeUTF("yes");
				}else{
					dos.writeUTF("no");
				}
				
				dos.flush();
				dos.close();
				oos.close();
		        
		       
		    }finally {
				ms.close();
			}
		}
			}
			finally {
				mss.close();
			}
		}
	}
	
	 public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws Exception {
	        Cipher decriptCipher = Cipher.getInstance("RSA");
	        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
	        byte[] x = decriptCipher.doFinal(encrypted);
	        return x;
	    }
	 
	
	
	}

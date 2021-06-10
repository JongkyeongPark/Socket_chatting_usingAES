package network;

import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client extends Thread {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		ServerSocket serverSocket = null;
		Socket socket = null;
		BufferedReader in = null;
		BufferedWriter out = null;
		Scanner sc = new Scanner(System.in);
		String serverPublic;
		
		try {
			try {
				serverSocket = new ServerSocket(9999);
				System.out.println("연결 대기중... ");
				
				socket = serverSocket.accept();
				System.out.println("연결 되었습니다. ");
			}catch(BindException e){
				socket = new Socket("localhost", 9999);
			}
			
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));//Client로부터 읽어올 준
			out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			
			serverPublic = in.readLine(); //서버로부터 받은 public key 
			System.out.println("> Received Public Key: "+serverPublic);
			System.out.println("Creating AES 256 Key...");
			String key = "11111222223333344444555556666612"; //AES 비밀키  
			//server로부터 받은 String 형식의 publicKey를 다시 PublicKey 형식으로 바꾼다.  
			KeyFactory factory = KeyFactory.getInstance("RSA"); // String을 다시 PublicKey형식으로 되돌린다. 
			X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(serverPublic));
			
			
			PublicKey publicKey;
			publicKey = factory.generatePublic(keySpecX509);
			//RSA 공개키를 이용해 AES 비밀키를 암호화한다. 
			Cipher aesEncrypt = Cipher.getInstance("RSA"); 
	        String aesEncStr;
			aesEncrypt.init(Cipher.ENCRYPT_MODE, publicKey); 
			byte[] byteAesKey = key.getBytes();
	        byte[] aesEncKeyByte = aesEncrypt.doFinal(byteAesKey); //String -> byte
	        
	        aesEncStr = Base64.getEncoder().encodeToString(aesEncKeyByte); //byte -> String
			
	        // print
	        System.out.println("AES 256 Key: "+key);
	        System.out.println("Encrypted AES Key: "+aesEncStr);
	        out.write(aesEncStr+"\n"); //Client측으로 PublicKey전
			out.flush(); //flush
	        
			//initial vector 생성 IV생성 및 RSA public key를 이용해 AES암호화. 후 서버 측으로 전송. 
			String IV = "7777788888999991";
			String IVEncStr;
			aesEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] byteIVEnc = aesEncrypt.doFinal(IV.getBytes());
			IVEncStr = Base64.getEncoder().encodeToString(byteIVEnc); //byte -> String
			out.write(IVEncStr + "\n");
			out.flush();
			
			byte[] byteIV = IV.getBytes();
			ServerReceiveThread receiveThread = new ServerReceiveThread(socket, byteAesKey, byteIV);
		    receiveThread.start();
		    ClientSendingThread sendingThread = new ClientSendingThread(socket, byteAesKey, byteIV);
		    sendingThread.start();
			
		    synchronized(receiveThread) {
		    	try{
                    System.out.println("receiveThread가 완료될때까지 기다립니다.");
                    receiveThread.wait();
                }catch(InterruptedException e){
                    e.printStackTrace();
                }
		    }
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				out.close();
				sc.close();
				in.close();
				//socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	
	
	static String byteToBase64 (byte[] input) {
		String base64String;
		base64String = Base64.getEncoder().encodeToString(input);
		
		return base64String;
		
	}
}



class ClientSendingThread extends Thread{
	private final Socket socket;
	private final byte[] byteAesKey;
	private final byte[] byteIV;
	Cipher cipher;
	BufferedWriter out = null;
	private Scanner sc = new Scanner(System.in);
	
	public ClientSendingThread(Socket socket, byte[] byteAesKey, byte[] byteIV) throws IOException {
		this.socket = socket;
		this.byteAesKey = byteAesKey;
		this.byteIV = byteIV;
		out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));//Client에게 보낼 스트림에대한 준비 
	}	
	@Override
	public void run() {
		System.out.println("클라센딩쓰레드 실행!!");
		try { 
			String writeString;
			byte[] encWriteString;
			while(true) {
				System.out.print("\n>");
				writeString = sc.nextLine(); // 서버측 채팅 입력.. 
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				SecretKeySpec aesKeySpec = new SecretKeySpec(byteAesKey, "AES");
				AlgorithmParameterSpec paramSpec = new IvParameterSpec(byteIV);
				cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, paramSpec);
				encWriteString = cipher.doFinal(writeString.getBytes("UTF-8"));
				out.write(Base64.getEncoder().encodeToString(encWriteString) + "\n");
				out.flush();//버퍼를 비움.
			}
		} catch(NoSuchElementException e){
			try {
				out.close();
				sc.close();
				socket.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}finally {
			try {
				out.close();
				sc.close();
//				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
}

class ClientReceiveThread extends Thread{
	private final Socket socket;
	private final byte[] byteAesKey;
	private final byte[] byteIV;
	Cipher cipher;
	BufferedReader in = null;
	BufferedWriter out = null;
	private Scanner sc = new Scanner(System.in);
	
	public ClientReceiveThread(Socket socket, byte[] byteAesKey, byte[] byteIV) throws IOException {
		this.socket = socket;
		this.byteAesKey = byteAesKey;
		this.byteIV = byteIV;
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));//Client로부터 읽어올 준
		out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
	}	
	@Override
	public void run() {
		System.out.println("클라리시브쓰레드 실행!!");
		try {
			String receivedString;
			String plainString;
			byte[] plainByte;
			
			while(true) {
				receivedString = in.readLine(); //Client로부터 한줄을 읽어온다. 	
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				SecretKeySpec aesKeySpec = new SecretKeySpec(byteAesKey, "AES");
				AlgorithmParameterSpec paramSpec = new IvParameterSpec(byteIV);
				cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, paramSpec);
				byte[] decByte = Base64.getDecoder().decode(receivedString);
				
				plainByte = cipher.doFinal(decByte);
				
				plainString = new String(plainByte, "UTF-8");
				
				System.out.println("\n>Received: "+"\""+plainString);
				System.out.println("Encrypted Message: "+receivedString);
				
				if(plainString.equalsIgnoreCase("exit")) {
					cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, paramSpec);
					byte[] encExit = cipher.doFinal(plainString.getBytes("UTF-8"));
					out.write(Base64.getEncoder().encodeToString(encExit) + "\n");
					out.flush();//버퍼를 비움.
					break;
				}
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}finally {
			try {
				System.out.println("Connection Closed");
				sc.close();
				in.close();
				//socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
}



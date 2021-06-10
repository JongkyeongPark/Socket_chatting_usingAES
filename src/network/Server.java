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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class Server {
	
	public static void main(String[] args) {
		
		ServerSocket server = null;
		Socket socket = null;
		BufferedReader in = null;
		BufferedWriter out = null;
		Scanner sc = new Scanner(System.in);
		
		KeyPair rsaPair = null;
		PublicKey publicKey;
		PrivateKey privateKey;
		String strPublic;
		String strPrivate;
		
		try {
			try {
				server = new ServerSocket(9999);
				System.out.println("연결 대기중... ");
				
				socket = server.accept();
				System.out.println("연결 되었습니다. ");
			}catch(BindException e){
				socket = new Socket("localhost", 9999);
			}
			
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));//Client로부터 읽어올 준
			out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));//Client에게 보낼 스트림에대한 준비 
			
			
			System.out.println("> Creating RSA Key Pair...");
			rsaPair = makeRSAKeyPair();
			publicKey = rsaPair.getPublic();
			privateKey = rsaPair.getPrivate();
			byte[] bytePublic = publicKey.getEncoded(); //byte로 변
			byte[] bytePrivate = privateKey.getEncoded(); //byte로 변
			strPublic = byteToBase64(bytePublic);
			strPrivate = byteToBase64(bytePrivate);
			System.out.println("Private Key : "+strPrivate);
			System.out.println("Public Key : "+strPublic);
			
			out.write(strPublic+"\n"); //Client측으로 PublicKey전
			out.flush(); //flush
			// client로부터 publickey로 암호화된 AES 32bit key를 받는다. 
			String aesEncKey;
			aesEncKey = in.readLine();
			byte[] byteAesKey = rsaDecrypt(aesEncKey, privateKey);
	        //print
	        System.out.println("Received AES Key: "+ aesEncKey);
	        System.out.println("Decrypted AES Key: "+ new String(byteAesKey, "utf-8"));
	        
	        String encIV;
			encIV = in.readLine();
			byte[] byteIV = rsaDecrypt(encIV, privateKey); //클라이언트로부터 받은 IV값. 
			
			ServerReceiveThread receiveThread = new ServerReceiveThread(socket, byteAesKey, byteIV);
		    receiveThread.start();
		    ServerSendingThread sendingThread = new ServerSendingThread(socket, byteAesKey, byteIV);
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
				//sc.close();
				in.close();
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
	
	static byte[] rsaDecrypt (String input, PrivateKey privateKey ) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			byte[] byteTemp = Base64.getDecoder().decode(input.getBytes());
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        byte[] aesDecKey = cipher.doFinal(byteTemp);
	        return aesDecKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static KeyPair makeRSAKeyPair(){
		KeyPairGenerator make = null;
		SecureRandom random = new SecureRandom();
		try {
			make = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		make.initialize(2048, random);
		KeyPair pair = make.genKeyPair();
		return pair;
		
	}
}


class ServerSendingThread extends Thread{
	private final Socket socket;
	private final byte[] byteAesKey;
	private final byte[] byteIV;
	Cipher cipher;
	BufferedWriter out = null;
	private Scanner sc = new Scanner(System.in);
	
	public ServerSendingThread(Socket socket, byte[] byteAesKey, byte[] byteIV) throws IOException {
		this.socket = socket;
		this.byteAesKey = byteAesKey;
		this.byteIV = byteIV;
		out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));//Client에게 보낼 스트림에대한 준비
	}	
	@Override
	public void run() {
		try {
			System.out.println("서버센딩쓰레드 실행!!");
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
				//socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
}

class ServerReceiveThread extends Thread{
	private final Socket socket;
	private final byte[] byteAesKey;
	private final byte[] byteIV;
	Cipher cipher;
	BufferedReader in = null;
	BufferedWriter out = null;
	private Scanner sc = new Scanner(System.in);
	
	public ServerReceiveThread(Socket socket, byte[] byteAesKey, byte[] byteIV) throws IOException {
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
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
}


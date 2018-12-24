package com.disusered;

import org.apache.cordova.LOG;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

class AES_Encryptor {
 private static final String TAG = "AES_Encryptor";
 private static final int BLOCK_SIZE = 16;
 // private static String CIPHER_TYPE = "AES/CBC/PKCS5PADDING"; // = AES128 // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
 // private static String CIPHER_TYPE = "AES/CBC/NOPADDING"; // = AES128 // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
    private static String CIPHER_TYPE = "AES/CTR/NOPADDING"; // = AES128 // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html

 public static void Encrypt(SecretKey secretKey, byte[] iv, File plainTextFile, File encryptedFile) throws Exception{
  Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
  cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
  // System.out.println("AES_CTR_PKCS5PADDING IV:"+cipher.getIV());
  // System.out.println("AES_CTR_PKCS5PADDING Algoritm:"+cipher.getAlgorithm());
  byte buf[] = new byte[4096];

  try (InputStream in = new FileInputStream(plainTextFile);
       OutputStream out = new FileOutputStream(encryptedFile);) {

   int readBytes = in.read(buf);
   while(readBytes > 0){

    // byte[] cipherBytes = cipher.update(buf, 0 , readBytes);
       byte[] cipherBytes = cipher.doFinal(buf, 0, readBytes);
       out.write(cipherBytes);
       readBytes = in.read(buf);
   }

  } catch( Exception e ) {
      LOG.w(TAG, e.getMessage());
  }

 }

 public static void Decrypt(SecretKey secretKey, byte[] iv, File cipherTextFile, File decryptedFile) throws Exception{
  Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
  cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

  if(!decryptedFile.exists()){
   decryptedFile.createNewFile(); //: Here, it may be fail if ...
  }

  byte buf[] = new byte[4096];
  try (InputStream in = new FileInputStream(cipherTextFile);
    OutputStream out = new FileOutputStream(decryptedFile);){
   int readBytes = in.read(buf);
   while(readBytes > 0){
    // byte[] decryptedBytes = cipher.update(buf, 0 , readBytes);
    byte[] decryptedBytes = cipher.doFinal(buf, 0 , readBytes);
    out.write(decryptedBytes);
    readBytes = in.read(buf);
   }
   cipher.doFinal();
  }

 }


 /*
 public static void main(String args[]) throws Exception {
  KeyGenerator keyGen = KeyGenerator.getInstance("AES");
  keyGen.init(256,new SecureRandom( ) );
  SecretKey secretKey = keyGen.generateKey();
  byte[] iv = new byte[128 / 8];
  SecureRandom prng = new SecureRandom();
  prng.nextBytes(iv);

  {
   String originalFile = "./domino.zip";
   String encryptedFile = "./domino.enc";
   String deryptedFile = "./decrypted.zip";

   // AES_CTR_PKCS5PADDING.createTestFile(originalFile); //: Create Testing Data

   AES_CTR_PKCS5PADDING.Encrypt(secretKey, iv, new File(originalFile), new File(encryptedFile));
   AES_CTR_PKCS5PADDING.Decrypt(secretKey, iv, new File(encryptedFile), new File(deryptedFile));
   // byte[] ret = AES_CTR_PKCS5PADDING.DecryptPartial(secretKey, iv, new File(encryptedFile), 100, 10);
   // System.out.println(new String(ret));
  }
  */
}

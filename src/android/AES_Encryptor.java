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

// http://ijecorp.blogspot.com/2016/05/java-jce-aes-encryption-decryption-2016.html

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
     int readSizes = 0, loop=0;
  byte buf[] = new byte[4096];

     InputStream in = null;
     OutputStream out = null;

  try {
   in = new FileInputStream(plainTextFile);
   out = new FileOutputStream(encryptedFile);
   int readBytes = in.read(buf);
   while(readBytes > 0){
       readSizes += readBytes;
       loop++;

       int outputSize = cipher.getOutputSize(readBytes);    // https://github.com/martinwithaar/Encryptor4j/blob/master/src/main/java/org/encryptor4j/Encryptor.java
    // byte[] cipherBytes = cipher.update(buf, 0 , readBytes);
       byte[] cipherBytes = cipher.doFinal(buf, 0, readBytes);
       out.write(cipherBytes);
    readBytes = in.read(buf);
    if( readBytes < 4096 ) {
        LOG.w(TAG, "outputSize=" + String.valueOf(outputSize) );
        LOG.w(TAG, "loop=" + String.valueOf(loop) +", readSizes=" + String.valueOf(readSizes)+", this time readBytes"+ String.valueOf(readBytes) );
    }
   }
   //   cipher.doFinal();
   /*
   byte[] bFinal = cipher.doFinal();
      LOG.w(TAG, "final length =" + String.valueOf(bFinal.length ) );
      out.write(bFinal);
    */

  } catch( Exception e ) {
      LOG.w(TAG, e.getMessage());
  } finally {
      if(in != null) {
          in.close();
      }
      if(out != null) {
          out.close();
      }
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
    byte[] decryptedBytes = cipher.update(buf, 0 , readBytes);
    out.write(decryptedBytes);
    readBytes = in.read(buf);
   }
   cipher.doFinal();
   out.close();
   in.close();
  }
 }

 public static byte[] DecryptPartial(SecretKey secretKey, byte[] iv, File cipherTextFile, int blockIndex, int blockCount ) throws Exception{
  final int offset = blockIndex * BLOCK_SIZE;
  final int bufSize = blockCount * BLOCK_SIZE;

  Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
  cipher.init(Cipher.DECRYPT_MODE, secretKey, calculateIVForBlock(new IvParameterSpec(iv), blockIndex ));

  byte[] decryptedBytes = new byte[bufSize];
  try (FileInputStream in = new FileInputStream(cipherTextFile)){
   byte inputBuf[] = new byte[bufSize];
   in.skip(offset);
   int readBytes = in.read(inputBuf);
   decryptedBytes = cipher.update(inputBuf, 0, readBytes);
  }
  return decryptedBytes;
 }

 private static IvParameterSpec calculateIVForBlock(final IvParameterSpec iv,
         final long blockIndex) {
     final BigInteger biginIV = new BigInteger(1, iv.getIV());
     final BigInteger blockIV = biginIV.add(BigInteger.valueOf(blockIndex));
     final byte[] blockIVBytes = blockIV.toByteArray();

     // Normalize the blockIVBytes as 16 bytes for IV
     if(blockIVBytes.length == BLOCK_SIZE){
      return new IvParameterSpec(blockIVBytes);
     }
     if(blockIVBytes.length > BLOCK_SIZE ){
      // For example: if the blockIVBytes length is 18, blockIVBytes is [0],[1],...[16],[17]
      // We have to remove [0],[1] , so we change the offset = 2
      int offset = blockIVBytes.length - BLOCK_SIZE;
      return new IvParameterSpec(blockIVBytes, offset, BLOCK_SIZE);
     }
     else{
      // For example: if the blockIVBytes length is 14, blockIVBytes is [0],[1],...[12],[13]
      // We have to insert 2 bytes at head
      final byte[] newBlockIV = new byte[BLOCK_SIZE]; //: default set to 0 for 16 bytes
      int offset = blockIVBytes.length - BLOCK_SIZE;
      System.arraycopy(blockIVBytes, 0, newBlockIV, offset, blockIVBytes.length);
      return new IvParameterSpec(newBlockIV);
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

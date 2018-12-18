package com.disusered;

import android.content.Context;
import android.net.Uri;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaResourceApi;
import org.apache.cordova.LOG;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.File;
import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class encrypts and decrypts files using the Conceal encryption lib
 */
public class Safe extends CordovaPlugin {


  private static final String TAG = "FileEncryption";

  public static final String ENCRYPT_ACTION = "encrypt";
  public static final String DECRYPT_ACTION = "decrypt";

  private Context CONTEXT;

  private String FILE_NAME;
  private Uri SOURCE_URI;
  private File SOURCE_FILE;
  private File TEMP_FILE;

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
          throws JSONException {
    if (action.equals(ENCRYPT_ACTION) || action.equals(DECRYPT_ACTION)) {
      CordovaResourceApi resourceApi = webView.getResourceApi();

      String path = args.getString(0);  // src file
      String dst_path = args.getString(1);  // dst file
      String key = args.getString(2);
      String iv = args.getString(3);

      // Uri normalizedPath = resourceApi.remapUri(Uri.parse(path));
      // Uri normalizedDstPath = resourceApi.remapUri(Uri.parse(dst_path));
	  
      SecretKey skey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
      // this.cryptOp(normalizedPath.toString(), pass, action, callbackContext);

      try {
        byte[] biv = iv.getBytes("UTF-8");

        if (action.equals(ENCRYPT_ACTION)) {
          AES_Encryptor.Encrypt( skey, biv, new File( path ), new File( dst_path ));
        } else if (action.equals(DECRYPT_ACTION)) {
          AES_Encryptor.Decrypt( skey, biv, new File( path ), new File( dst_path ));
		}
	  } catch (IOException e) {
		  LOG.d(TAG, "initCrypto IOException: " + e.getMessage());
		  callbackContext.error(e.getMessage());
		} catch (Exception e) {
		  LOG.d(TAG, "initCrypto Exception: " + e.getMessage());
		  callbackContext.error(e.getMessage());
		}

      return true;
    }

    return false;
  }

}

#import "Safe.h"

@implementation Safe

/**
 *  encrypt
 *
 *  @param command An array of arguments passed from javascript
 */
- (void)encrypt:(CDVInvokedUrlCommand *)command {

  CDVPluginResult *pluginResult = nil;

  // NSString *path = [self crypto:@"encrypt" command:command];
  NSString *to_filePath   = [command.arguments objectAtIndex:1];
  BOOL bRet = [self crypto:@"encrypt" command:command];

  if (path != nil) {
    pluginResult =
        [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                          messageAsString:to_filePath];
  } else {
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
  }

  [self.commandDelegate sendPluginResult:pluginResult
                              callbackId:command.callbackId];
}

/**
 *  decrypt
 *
 *  @param command An array of arguments passed from javascript
 */
- (void)decrypt:(CDVInvokedUrlCommand *)command {

  CDVPluginResult *pluginResult = nil;

  // NSString *path = [self crypto:@"decrypt" command:command];
  NSString *to_filePath   = [command.arguments objectAtIndex:1];
  BOOL bRet = [self crypto:@"decrypt" command:command];

  if (path != nil) {
    pluginResult =
        [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                          messageAsString:to_filePath];
  } else {
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
  }

  [self.commandDelegate sendPluginResult:pluginResult
                              callbackId:command.callbackId];
}

/**
 *  Encrypts or decrypts file at given URI.
 *
 *
 *  @param action  Cryptographic operation
 *  @param command Cordova arguments
 *
 *  @return Boolean value representing success or failure
 */
- (BOOL) crypto:(NSString *)action command:(CDVInvokedUrlCommand *)command {

  BOOL bRet = FALSE;
  NSString *from_filePath = [command.arguments objectAtIndex:0];
  NSString *to_filePath   = [command.arguments objectAtIndex:1];
  NSString *key = [command.arguments objectAtIndex:2];
  NSString *iv = [command.arguments objectAtIndex:3];

  NSString *fileName = [from_filePath lastPathComponent];
  NSFileManager *fileManager = [NSFileManager defaultManager];

  NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
  NSString *srcPath = [documentsPath stringByAppendingPathComponent:fileName];
  NSLog( @"%@ from path: %@ to path: %@", action, from_filePath, to_filePath);
  NSLog( @"from path: %@", path);
  BOOL srcExists = [fileManager fileExistsAtPath:srcPath];

  NSString *sErrDesc = nil;

  // if path and password args exist
  if (from_path != nil && [from_path length] > 0 && 
      to_path != nil && [to_path length] > 0 && 
      key != nil && [key length] > 0 && 
      iv != nil && [iv length] > 0) {

    // if file exists
    if (srcExists) {
      NSLog( @"from path: %@ Exists!", srcPath);

      if ([action isEqualToString:@"encrypt"]) {
        
        if( aesEncryptFile( from_filePath, to_filePath, key, iv, &sErrDesc )) {
            NSLog( @"%@ encrypt to %@ success!", from_filePath, to_filePath );
            bRet = true;
        } else {
            NSLog( @"Encrypt Error: %@", sErrDesc);
        }

      } else {

        if( aesDecryptFile( from_filePath, to_filePath, key, iv, &sErrDesc )) {
            NSLog( @"%@ decrypt to %@ success!", from_filePath, to_filePath );
            bRet = true;
        } else {
            NSLog( @"Decrypt Error: %@", sErrDesc);
        }

      }
/*
      // get file data
      NSData *fileData = [NSData dataWithContentsOfFile:path];

      NSError *error;
      if ([action isEqualToString:@"encrypt"]) {
        // encrypt data
        data = [RNEncryptor encryptData:fileData
                           withSettings:kRNCryptorAES256Settings
                               password:password
                                  error:&error];

      } else if ([action isEqualToString:@"decrypt"]) {
        // decrypt data
        data = [RNDecryptor decryptData:fileData
                           withPassword:password
                                  error:&error];
      }

      // write to generated path
      [data writeToFile:path atomically:YES];
  */
    }
  }

  return bRet;
}

@end

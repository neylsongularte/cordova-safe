//
//  AESCipher.h
//  AESCipher
//
//  Created by Welkin Xie on 8/13/16.
//  Copyright © 2016 WelkinXie. All rights reserved.
//
//  https://github.com/WelkinXie/AESCipher-iOS
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NSString * aesEncryptString(NSString *content, NSString *key, NSString *iv);
NSString * aesDecryptString(NSString *content, NSString *key, NSString *iv);

NSData * aesEncryptData(NSData *data, NSData *key, NSData *iv);
NSData * aesDecryptData(NSData *data, NSData *key, NSData *iv);

//
BOOL aesEncryptFileData( CCOperation operation, // kCC Encrypt, Decrypt
                        NSString *from_filename,
                        NSString *to_filename,
                        NSString *key_string,
                        NSString *iv_string,
                        NSError **error );

// 加密檔案
BOOL aesEncryptFile( NSString *from_filename, NSString *to_filename, NSString *key, NSString *iv, NSString **sErrDesc );
// 解密檔案
BOOL aesDecryptFile( NSString *from_filename, NSString *to_filename, NSString *key, NSString *iv, NSString **sErrDesc );

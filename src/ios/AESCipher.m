//
//  AESCipher.m
//  AESCipher
//
//  Created by Welkin Xie on 8/13/16.
//  Copyright © 2016 WelkinXie. All rights reserved.
//
//  https://github.com/WelkinXie/AESCipher-iOS
//

#import "AESCipher.h"
#import <CommonCrypto/CommonCryptor.h>

// NSString const *kInitVector = @"A-16-Byte-String";
size_t const kKeySize = kCCKeySizeAES256;
size_t const C_CHUNK_SIZE = 4096;           // 每次讀檔大小

NSData * cipherOperation(NSData *contentData, NSData *keyData, NSData *ivData, CCOperation operation) {
    NSUInteger dataLength = contentData.length;
    
    // void const *initVectorBytes = [kInitVector dataUsingEncoding:NSUTF8StringEncoding].bytes;
    void const *initVectorBytes = ivData.bytes;
    void const *contentBytes = contentData.bytes;
    void const *keyBytes = keyData.bytes;
    
    size_t operationSize = dataLength + kCCBlockSizeAES128;
    void *operationBytes = malloc(operationSize);
    if (operationBytes == NULL) {
        return nil;
    }
    size_t actualOutSize = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyBytes,
                                          kKeySize,
                                          initVectorBytes,
                                          contentBytes,
                                          dataLength,
                                          operationBytes,
                                          operationSize,
                                          &actualOutSize);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:operationBytes length:actualOutSize];
    }
    free(operationBytes);
    operationBytes = NULL;
    return nil;
}

NSString * aesEncryptString(NSString *content, NSString *key, NSString *iv) {
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encrptedData = aesEncryptData(contentData, keyData, ivData);
    return [encrptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

NSString * aesDecryptString(NSString *content, NSString *key, NSString *iv) {
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    NSData *decryptedData = aesDecryptData(contentData, keyData, ivData);
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

NSData * aesEncryptData(NSData *contentData, NSData *keyData, NSData *ivData) {
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
    NSCAssert(keyData.length == kKeySize, hint);
    return cipherOperation(contentData, keyData, ivData, kCCEncrypt);
}

NSData * aesDecryptData(NSData *contentData, NSData *keyData, NSData *ivData) {
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
    NSCAssert(keyData.length == kKeySize, hint);
    return cipherOperation(contentData, keyData, ivData, kCCDecrypt);
}


// 加密檔案區塊


NSMutableData * aesEncryptBlockData( CCOperation operation, // kCC Encrypt, Decrypt
        NSData *key,
        NSData *iv,
		NSData *dataIn,
        NSError **error )
{
	
    CCCryptorStatus ccStatus = 0;
    CCCryptorRef cryptor = NULL;
    CCMode mode = kCCModeCTR;                   // kCCMode ECB, CBC, CFB, CTR, OFB, RC4, CFB8
    CCAlgorithm algorithm = kCCAlgorithmAES;    // CCAlgorithm AES DES, 3DES, CAST, RC4, RC2, Blowfish
    CCPadding padding = ccNoPadding;            // cc NoPadding, PKCS7Padding
	
    size_t keyLength = kCCKeySizeAES256;        // kCCKeySizeAES 128, 192, 256
    size_t actualOutSize = 0;
	
    ccStatus = CCCryptorCreateWithMode(operation, mode, algorithm,
                                        padding,
                                        iv.bytes, key.bytes,
                                        keyLength,
                                        NULL, 0, 0, // tweak XTS mode, numRounds
                                        kCCModeOptionCTR_BE, // CCModeOptions
                                        &cryptor);

    if (cryptor == 0 || ccStatus != kCCSuccess) {
        NSLog(@"CCCryptorCreate status: %d", ccStatus);
        if (error) {
            *error = [NSError errorWithDomain:@"kCreateError" code:ccStatus userInfo:nil];
        }
        CCCryptorRelease(cryptor);
        return nil;
    }

	/* PERFORM Encrypt Data PROCESSING HERE */
	size_t dataOutLength = CCCryptorGetOutputLength(cryptor, dataIn.length, true);
	if( dataOutLength != C_CHUNK_SIZE ) {
		NSLog (@"dataIn.length=%d ( < 4096 )", (int) dataOutLength );
	}

    NSMutableData *dataOut = [NSMutableData dataWithLength:dataOutLength];
	char *outputBytes = (char *)dataOut.mutableBytes;
	
	ccStatus = CCCryptorUpdate(cryptor,
								dataIn.bytes, dataIn.length,
								outputBytes, dataOutLength,
								&actualOutSize);

	if (ccStatus != kCCSuccess) {
		NSLog(@"CCCryptorUpdate status: %d", ccStatus);
		if (error) {
			*error = [NSError errorWithDomain:@"kUpdateError" code:ccStatus userInfo:nil];
		}
		CCCryptorRelease(cryptor);
		return nil;
	}
	ccStatus = CCCryptorFinal(cryptor,
					//		  outputBytes, actualOutSize,
					 		  outputBytes + actualOutSize, dataOutLength - actualOutSize,
							  &actualOutSize);
	if (ccStatus != kCCSuccess) {
		NSLog(@"CCCryptorFinal status: %d", ccStatus);
		if (error) {
			*error = [NSError errorWithDomain:@"kFinalError" code:ccStatus userInfo:nil];
		}
		CCCryptorRelease(cryptor);
		return nil;
	}

    
    CCCryptorRelease(cryptor);

    return dataOut;
}


// opertaion : 加密: kCCEncrypt, 解密: kCCDecrypt
BOOL aesEncryptFileData( CCOperation operation, // kCC Encrypt, Decrypt
        NSString *from_filename,
        NSString *to_filename,
        NSString *key_string,
        NSString *iv_string,
        NSError **error )
{
    // bool bRet = false;
    bool bError = false;
    
    NSData *key = [key_string dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [iv_string dataUsingEncoding:NSUTF8StringEncoding];

    if ( key.length != kCCKeySizeAES256 ) {
        NSLog(@"CCCryptorArgument key.length: %lu != %zu", (unsigned long)key.length,(unsigned long) kCCKeySizeAES256);
        if (error) {
            *error = [NSError errorWithDomain:@"kArgumentError key length" code:key.length userInfo:nil];
        }
        return false;
    }

    const char c [] = {0};
    NSError *err;
    NSData *dTemp = [NSData dataWithBytes:c length:1];
    // [dTemp writeToFile:to_filename atomically:TRUE];
    // NSString * s_to_url = [NSString stringWithFormat:@"file://%@", to_filename];
    
    // BOOL ok = [dTemp writeToURL:[NSURL URLWithString:s_to_url] atomically:TRUE ];
    BOOL ok = [dTemp writeToFile:to_filename atomically:TRUE];
    if (!ok) {
        NSLog(@"Error creating file at %@", to_filename);
        *error = [NSError errorWithDomain:@"Error creating file" code:0 userInfo:nil];
        return false;
    }
    // 開啟來源及目的檔案
    NSFileHandle *fh_from = [NSFileHandle fileHandleForReadingAtPath:from_filename];
    NSFileHandle *fh_to   = [NSFileHandle fileHandleForUpdatingAtPath:to_filename];
    
    if (fh_from == nil) {
        *error = [NSError errorWithDomain:@"Open source file failed" code:0 userInfo:nil];
        NSLog(@"Failed to open source file: %@", from_filename );
        return false;
    }
    if (fh_to == nil) {
        *error = [NSError errorWithDomain:@"Open target file failed" code:0 userInfo:nil];
        NSLog(@"Failed to open target file: %@", to_filename );
        [fh_from closeFile];
        return false;
    }
    
    // 讀檔迴圈
    UInt64 offset = 0;
	UInt64 offset_to = 0;
	UInt32 chunkSize = C_CHUNK_SIZE;     //Read 4KB chunks.

	NSData *dataIn = [fh_from readDataOfLength:chunkSize];
    NSMutableData *dataOut = nil;

    size_t actualOutSize = 0;

	while ([dataIn length] > 0)
	{
		//Make sure for the next line you choose the appropriate string encoding.
		// NSString *dataString = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];

		/* PERFORM Encrypt Data PROCESSING HERE */
		
		dataOut = aesEncryptBlockData( operation, // kCC Encrypt, Decrypt
                                      key,iv,dataIn, &err );

        /* END Encrypt Data PROCESSING */
		// Write Data to file
        if (dataOut != nil) {
            [fh_to writeData:dataOut ]; // [NSData dataWithBytesNoCopy:outputBytes length:actualOutSize]];
            offset_to += actualOutSize; // [dataOut length];
        //    [fh_to seekToFileOffset:offset_to];
            [fh_to seekToEndOfFile];
        } else {
            bError = true;
            NSLog(@"Crypt proccess failed");
            *error = [NSError errorWithDomain:@"Crypt proccess failed" code:0 userInfo:nil];
            // free(outputBytes);
            // outputBytes = NULL;
            break;
        }
        
        // Next Read process
        offset += [dataIn length];

		[fh_from seekToFileOffset:offset];
		dataIn = [fh_from readDataOfLength:chunkSize];
	}

	[fh_from closeFile];
    [fh_to   closeFile];
    
    NSLog( @"read : %d, write : %d", (int) offset, (int) offset_to );
/*
    dataOutMovedTotal += dataOutMoved;
    dataOut.length = dataOutMovedTotal;
*/
    return !bError;
}

// 加密檔案
BOOL aesEncryptFile( NSString *from_filename, NSString *to_filename, NSString *key, NSString *iv, NSString **sErrDesc ) {
    
    NSError *error = nil;
    if( !aesEncryptFileData( kCCEncrypt, // kCC Encrypt, Decrypt
                              from_filename,
                              to_filename,
                              key,
                              iv,
                              &error ) ) {
        *sErrDesc = [error localizedDescription];
        return false;
    } else {
        return true;
    }
}

// 解密檔案
BOOL aesDecryptFile( NSString *from_filename, NSString *to_filename, NSString *key, NSString *iv, NSString **sErrDesc ) {

    NSError *error = nil;
    if( !aesEncryptFileData( kCCDecrypt, // kCC Encrypt, Decrypt
                            from_filename,
                            to_filename,
                            key,
                            iv,
                            &error ) ) {
        *sErrDesc = [error localizedDescription];
        return false;
    } else {
        return true;
    }

}

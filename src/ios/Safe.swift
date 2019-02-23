@objc(Safe) class Safe : CDVPlugin {
    
    private static let SECURE_KEY_LENGTH = 16;
    private static let SECURE_IV_LENGTH = 8;
    private static let PBKDF2_ITERATION_COUNT = 1001;
    
    // Encrypts file using aes256 encryption alogrithm
    func encrypt(_ command: CDVInvokedUrlCommand) {

        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while performing Encryption"
        )
        
        //  this.fileEncryption.encrypt(path, enc_path, Config.FILE_KEY, Config.FILE_IV);
        
        let raw_path = command.arguments[0] as? String ?? ""
        let enc_path = command.arguments[1] as? String ?? ""
        let key = command.arguments[2] as? String ?? ""
        let iv  = command.arguments[3] as? String ?? ""
        
        // let encrypted = AES256CBC.encryptString(value, password: secureKey, iv: iv)

        do {
			let fh = FileHandle(forReadingAtPath: raw_path)!
			
            var value = 0
            let data = Data(buffer: UnsafeBufferPointer(start: &value, count: 1))
            try data.write( to: NSURL(string: "file://" + enc_path)! as URL)
            NSLog("file://" + enc_path )
			
            let fh_to: FileHandle = FileHandle(forUpdatingAtPath: enc_path)!
			
            // let key: Data = self.key.data(using: String.Encoding.utf8, allowLossyConversion: true)!
            // let iv : Data = self.iv.data(using: String.Encoding.utf8, allowLossyConversion: true)!
			var aecEnc: AES = try! AES(key: key.bytes,
										iv: iv.bytes,
                                       blockMode: .CTR,
                              padding: NoPadding())
			
			// 區塊加密迴圈
			var isAtEOF: Bool = false
            var isFirst: Bool = true
			repeat {
			
                let tempData:Data = fh.readData(ofLength: chunkSize)
                if tempData.count == 0 {
                    isAtEOF = true
                    // return (buffer.count > 0) ? String(data: buffer, encoding: encoding) : nil
					
                } else {
                    let enc = try aecEnc.encrypt(tempData.bytes)
                    let encData = NSData(bytes: enc, length: enc.count)
                    NSLog( "tempData length:\(tempData.count)" )
                    NSLog( "enc.count:\(enc.count)" )
                    NSLog( "encData length:\(encData.length)\n" )
                    
                    if isFirst {
                        fh_to.seek(toFileOffset: 0)
                        isFirst = false
                    } else {
                        fh_to.seekToEndOfFile()
                    }
                    
                    fh_to.write( encData as Data )
                }
				
			} while !isAtEOF
            
            fh.closeFile()
            fh_to.closeFile()

            // Success
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
		
        } catch {
            print("\(error.localizedDescription)")
        }
        
        self.commandDelegate!.send(
            pluginResult, 
            callbackId: command.callbackId
        )
    }
    
    // Decrypts the aes256 encoded string into plain text
    func decrypt(_ command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while performing Decryption"
        )
        
        let raw_path = command.arguments[0] as? String ?? ""
        let dec_path = command.arguments[1] as? String ?? ""
        let key = command.arguments[2] as? String ?? ""
        let iv  = command.arguments[3] as? String ?? ""
        
        // let decrypted = AES256CBC.decryptString(value, password: secureKey, iv: iv)
        

        do {
			let fh = FileHandle(forReadingAtPath: path)!

            var value = 0
            let data = Data(buffer: UnsafeBufferPointer(start: &value, count: 1))
            try data.write( to: NSURL(string: "file://" + dec_path)! as URL)
            NSLog("file://" + dec_path )
			
            let fh_to: FileHandle = FileHandle(forUpdatingAtPath: dec_path)!

            // let key: Data = self.key.data(using: String.Encoding.utf8, allowLossyConversion: true)!
            // let iv : Data = self.iv.data(using: String.Encoding.utf8, allowLossyConversion: true)!
			var aecEnc: AES = try! AES(key: key.bytes,
										iv: iv.bytes,
                                       blockMode: .CTR,
                              padding: NoPadding())

			// 區塊解密迴圈
			var isAtEOF: Bool = false
            var isFirst: Bool = true
			repeat {
			
                let tempData:Data = fh.readData(ofLength: chunkSize)
                if tempData.count == 0 {
                    isAtEOF = true
					
                } else {
                    let dec = try aecEnc.decrypt(tempData.bytes)
                    let decData = NSData(bytes: dec, length: dec.count)
                    NSLog( "tempData length:\(tempData.count)" )
                    NSLog( ",dec.count:\(dec.count)" )
                    NSLog( ",decData length:\(decData.length)\n" )
                    
                    if isFirst {
                        fh_to.seek(toFileOffset: 0)
                        isFirst = false
                    } else {
                        fh_to.seekToEndOfFile()
                    }
                    
                    fh_to.write( decData as Data )

                }
				
			} while !isAtEOF
            
            fh.closeFile()
            fh_to.closeFile()

            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: dec_path)
		
        } catch {
            NSLog("\(error.localizedDescription)")
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: error.localizedDescription)
        }

        self.commandDelegate!.send(
            pluginResult,
            callbackId: command.callbackId
        )
    }
    
}

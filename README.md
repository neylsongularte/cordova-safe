cordova-safe
====

[![Build Status](https://travis-ci.org/disusered/cordova-safe.svg)](https://travis-ci.org/disusered/cordova-safe) [![Code Climate](https://codeclimate.com/github/disusered/cordova-safe/badges/gpa.svg)](https://codeclimate.com/github/disusered/cordova-safe)

> Simple file encryption for Cordova.

## Install

```bash
$ cordova plugin add https://github.com/tsaokuoyang/cordova-safe
```

## Usage

```javascript
var safe = cordova.plugins.disusered.safe,
    hexKey = '00000000000000000000000000000000', // some hex key (16 bytes for 128, 24 bytes for 192, 32 bytes for 256)
    hexIv  = '00000000000000000000000000000000'; // some hex iv


function success(encryptedFile) {
  console.log('Encrypted file: ' + encryptedFile);

  safe.decrypt(encryptedFile, dstFile, hexKey, hexIv, function(decryptedFile) {
    console.log('Decrypted file: ' + decryptedFile);
  }, error);
}

function error() {
  console.log('Error with cryptographic operation');
}

safe.encrypt('file:/storage/sdcard/DCIM/Camera/1404177327783.jpg', 'file:/storage/sdcard/DCIM/Camera/1404177327783.jpg.enc', hexKey, hexIv, success, error);
```

## API

The plugin exposes the following methods:

```javascript
cordova.plugins.disusered.safe.encrypt(file, destination_file, hexKey, hexIv, success, error);
cordova.plugins.disusered.safe.decrypt(file, destination_file, hexKey, hexIv, success, error);
```

#### Parameters:
* __file:__ A string representing a local URI
* __dst_file:__ A string representing a local URI ( destination file )
* __hexKey:__ A key for the crypto operations
* __hexIv:__  A iv for the crypto operations
* __success:__ Optional success callback
* __error:__ Optional error callback

## OpenSSL

openssl enc -d -aes-[128|192|256]-ctr -nopad -in 1404177327783.jpg.enc -out 1404177327783.jpg -K 00000000000000000000000000000000 -iv 00000000000000000000000000000000

## Issues
* fix for ios

## License

MIT © [Carlos Rosquillas](http://carlosanton.io)

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
    key = 'someKey',
    iv  = 'someIv';


function success(encryptedFile) {
  console.log('Encrypted file: ' + encryptedFile);

  safe.decrypt(encryptedFile, dstFile, key, iv, function(decryptedFile) {
    console.log('Decrypted file: ' + decryptedFile);
  }, error);
}

function error() {
  console.log('Error with cryptographic operation');
}

safe.encrypt('file:/storage/sdcard/DCIM/Camera/1404177327783.jpg', 'file:/storage/sdcard/DCIM/Camera/1404177327783.jpg.enc',key,iv, success, error);
```

## API

The plugin exposes the following methods:

```javascript
cordova.plugins.disusered.safe.encrypt(file, dst_file, key, iv, success, error);
cordova.plugins.disusered.safe.decrypt(file, dst_file, key, iv, success, error);
```

#### Parameters:
* __file:__ A string representing a local URI
* __dst_file:__ A string representing a local URI ( destination file )
* __key:__ A key for the crypto operations
* __iv:__  A iv for the crypto operations
* __success:__ Optional success callback
* __error:__ Optional error callback

## License

MIT © [Carlos Rosquillas](http://carlosanton.io)

#import <Foundation/Foundation.h>
#import <Security/SecRandom.h>
#import <Cordova/CDV.h>
#import "AESCipher.h"

@interface Safe : CDVPlugin {
}

- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;
- (CDVPluginResult *)crypto:(NSString*)action command:(CDVInvokedUrlCommand*)command;
@end

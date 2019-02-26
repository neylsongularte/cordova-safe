#import <Foundation/Foundation.h>
#import <Security/SecRandom.h>
#import <Cordova/CDV.h>
#import "AESCipher.h"

@interface Safe : CDVPlugin {
}

- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;
- (BOOL)crypto:(NSString*)action command:(CDVInvokedUrlCommand*)command;
@end

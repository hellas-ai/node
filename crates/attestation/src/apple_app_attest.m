#import <AppKit/AppKit.h>
#import <DeviceCheck/DeviceCheck.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *bytes;
    size_t len;
    char *error;
} HellasAppleResult;

static HellasAppleResult result(NSData *data, NSError *error) {
    HellasAppleResult out = {0};
    if (error) {
        const char *text = error.localizedDescription.UTF8String;
        out.error = strdup(text ?: "unknown error");
    } else {
        out.len = data.length;
        out.bytes = malloc(out.len);
        memcpy(out.bytes, data.bytes, out.len);
    }
    return out;
}

static void await(dispatch_semaphore_t done) {
    while (dispatch_semaphore_wait(done, DISPATCH_TIME_NOW))
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
}

bool hellas_apple_supported(void) {
    [NSApplication sharedApplication];
    return DCAppAttestService.sharedService.supported;
}

HellasAppleResult hellas_apple_generate_key(void) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block HellasAppleResult out;
    [DCAppAttestService.sharedService generateKeyWithCompletionHandler:^(NSString *key, NSError *error) {
        out = result([key dataUsingEncoding:NSUTF8StringEncoding], error);
        dispatch_semaphore_signal(done);
    }];
    await(done);
    return out;
}

HellasAppleResult hellas_apple_attest(const char *key, const uint8_t hash[32]) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block HellasAppleResult out;
    NSData *client = [NSData dataWithBytes:hash length:32];
    NSString *identifier = [NSString stringWithUTF8String:key];
    [DCAppAttestService.sharedService attestKey:identifier clientDataHash:client completionHandler:^(NSData *attestation, NSError *error) {
        out = result(attestation, error);
        dispatch_semaphore_signal(done);
    }];
    await(done);
    return out;
}

HellasAppleResult hellas_apple_assert(const char *key, const uint8_t hash[32]) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block HellasAppleResult out;
    NSData *client = [NSData dataWithBytes:hash length:32];
    NSString *identifier = [NSString stringWithUTF8String:key];
    [DCAppAttestService.sharedService generateAssertion:identifier clientDataHash:client completionHandler:^(NSData *assertion, NSError *error) {
        out = result(assertion, error);
        dispatch_semaphore_signal(done);
    }];
    await(done);
    return out;
}

void hellas_apple_result_free(HellasAppleResult value) {
    free(value.bytes);
    free(value.error);
}

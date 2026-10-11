// InstanceSwitcher for iOS: injectable dylib for the Discord iOS app.
// Rewrites Discord's API / gateway / CDN / media hosts to a Discord-compatible
// instance (Spacebar, FossCORD, ...). No Substrate needed: plain ObjC runtime hooks.
//
// Open the menu with a THREE-FINGER LONG PRESS anywhere in the app.

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <Security/Security.h>
#import "is_e2ee_core.h"
#import "monocypher.h"
#include <string.h>
#include <dlfcn.h>
#include <sys/utsname.h>
#include <signal.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

static NSString *const kStateKey = @"InstanceSwitcher.state.v1";
static NSDictionary *gActive;   // nil => stock Discord. Only written at startup.

#pragma mark - State

static NSDictionary *IS_Builtin(void) {
    return @{ @"id": @"discord", @"name": @"Discord" };
}

static NSDictionary *IS_State(void) {
    NSDictionary *s = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kStateKey];
    if (![s[@"instances"] isKindOfClass:NSArray.class]) {
        s = @{ @"active": @"discord", @"instances": @[ IS_Builtin() ] };
    }
    return s;
}

static void IS_Save(NSDictionary *s) {
    [[NSUserDefaults standardUserDefaults] setObject:s forKey:kStateKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

static void IS_LoadActive(void) {
    NSDictionary *s = IS_State();
    NSString *aid = s[@"active"];
    gActive = nil;
    for (NSDictionary *i in s[@"instances"]) {
        if ([i[@"id"] isEqual:aid] && ![aid isEqual:@"discord"] && [i[@"api"] length] && [i[@"gateway"] length]) {
            gActive = i;
            break;
        }
    }
}

#pragma mark - Debug log

static NSMutableArray *IS_Lines(void) {
    static NSMutableArray *a; static dispatch_once_t o;
    dispatch_once(&o, ^{ a = [NSMutableArray array]; });
    return a;
}

static void IS_Log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void IS_Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    static CFAbsoluteTime t0; static dispatch_once_t o0;
    dispatch_once(&o0, ^{ t0 = CFAbsoluteTimeGetCurrent(); });
    NSString *l = [NSString stringWithFormat:@"[%.1f] %@", CFAbsoluteTimeGetCurrent() - t0, body];
    NSMutableArray *a = IS_Lines();
    @synchronized (a) {
        [a addObject:l];
        if (a.count > 400) [a removeObjectsInRange:NSMakeRange(0, a.count - 400)];
    }
}

static void IS_LogOnce(NSString *key, NSString *line) {
    static NSMutableSet *seen; static dispatch_once_t o;
    dispatch_once(&o, ^{ seen = [NSMutableSet set]; });
    @synchronized (seen) {
        if ([seen containsObject:key]) return;
        [seen addObject:key];
    }
    IS_Log(@"%@", line);
}

// Diagnostics: the first time each kind of asset is requested (badge-icons, avatars, ...), ask the
// instance for it once and log the HTTP status, so missing images can be told apart from unrequested ones.
static void IS_ProbeAsset(NSURL *out) {
    NSArray *parts = [out.path componentsSeparatedByString:@"/"];
    NSString *seg = parts.count > 1 ? parts[1] : @"";
    if (parts.count > 3 && [seg isEqualToString:@"assets"]) seg = [NSString stringWithFormat:@"assets/%@", parts[2]];
    static NSMutableSet *seen; static dispatch_once_t o; static int probes;
    dispatch_once(&o, ^{ seen = [NSMutableSet set]; });
    @synchronized (seen) {
        if ([seen containsObject:seg] || probes >= 30) return;
        [seen addObject:seg];
        probes++;
    }
    NSString *sample = out.path.length > 70 ? [out.path substringToIndex:70] : out.path;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:out];
        [r setValue:@"bytes=0-0" forHTTPHeaderField:@"Range"];
        r.timeoutInterval = 15;
        [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *e) {
            NSHTTPURLResponse *h = [resp isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)resp : nil;
            if (h) IS_Log(@"asset /%@ -> HTTP %ld %@  (%@)", seg, (long)h.statusCode, [h valueForHTTPHeaderField:@"Content-Type"] ?: @"", sample);
            else IS_Log(@"asset /%@ -> no response: %@  (%@)", seg, e.localizedDescription, sample);
        }] resume];
    });
}

static BOOL IS_SpoofOn(void) {     // default ON
    id v = [NSUserDefaults.standardUserDefaults objectForKey:@"InstanceSwitcher.spoofVerified"];
    return v ? [v boolValue] : YES;
}

static BOOL IS_SpoofPhone(void) {  // default OFF
    return [NSUserDefaults.standardUserDefaults boolForKey:@"InstanceSwitcher.spoofPhone"];
}

#pragma mark - Saved logins (one token per instance)

static NSMutableDictionary *gTok;      // instance id -> token
static NSObject *gTokLock;
static NSString *const kTokFallbackKey = @"InstanceSwitcher.tokens.fallback";

static NSDictionary *IS_KCBaseFor(NSString *acct) {
    return @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
              (__bridge id)kSecAttrService: @"InstanceSwitcher",
              (__bridge id)kSecAttrAccount: acct };
}

static NSData *IS_KCGetFor(NSString *acct) {
    NSMutableDictionary *q = [IS_KCBaseFor(acct) mutableCopy];
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || !out) return nil;
    return CFBridgingRelease(out);
}

static BOOL IS_KCSetFor(NSString *acct, NSData *d) {
    NSDictionary *upd = @{ (__bridge id)kSecValueData: d };
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)IS_KCBaseFor(acct), (__bridge CFDictionaryRef)upd);
    if (st == errSecItemNotFound) {
        NSMutableDictionary *add = [IS_KCBaseFor(acct) mutableCopy];
        add[(__bridge id)kSecValueData] = d;
        add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
        st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    }
    return st == errSecSuccess;
}

static NSData *IS_KCGet(void) { return IS_KCGetFor(@"tokens"); }
static BOOL IS_KCSet(NSData *d) { return IS_KCSetFor(@"tokens", d); }

static void IS_TokPersist(void) {      // call with gTokLock held
    NSData *d = [NSJSONSerialization dataWithJSONObject:gTok options:0 error:nil];
    if (!d) return;
    NSUserDefaults *def = NSUserDefaults.standardUserDefaults;
    if (IS_KCSet(d)) {
        [def removeObjectForKey:kTokFallbackKey];
    } else {
        [def setObject:[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] forKey:kTokFallbackKey];
        IS_LogOnce(@"kcfail", @"keychain unavailable: saving logins in app preferences instead");
    }
}

static void IS_TokLoad(void) {
    gTokLock = [NSObject new];
    gTok = [NSMutableDictionary dictionary];
    NSData *d = IS_KCGet();
    if (!d.length) d = [[NSUserDefaults.standardUserDefaults stringForKey:kTokFallbackKey] dataUsingEncoding:NSUTF8StringEncoding];
    if (d.length) {
        id j = [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil];
        if ([j isKindOfClass:NSDictionary.class]) [gTok addEntriesFromDictionary:j];
    }
}

static void IS_TokForgetId(NSString *iid) {
    if (!gTokLock || !iid) return;
    @synchronized (gTokLock) {
        if (gTok[iid]) { [gTok removeObjectForKey:iid]; IS_TokPersist(); }
    }
}

#pragma mark - E2EE key storage (read-only decryption)

static NSMutableDictionary *gPlainUntil;
static NSObject *gPlainLock;
static NSMutableDictionary *gE2ee;      // instance id -> @{ @"user": user id, @"sk": base64url backup private key }
static NSObject *gE2eeLock;
static NSString *const kE2eeFallbackKey = @"InstanceSwitcher.e2ee.fallback";

static void IS_E2eePersist(void) {      // call with gE2eeLock held
    NSData *d = [NSJSONSerialization dataWithJSONObject:gE2ee options:0 error:nil];
    if (!d) return;
    NSUserDefaults *def = NSUserDefaults.standardUserDefaults;
    if (IS_KCSetFor(@"e2ee", d)) {
        [def removeObjectForKey:kE2eeFallbackKey];
    } else {
        [def setObject:[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] forKey:kE2eeFallbackKey];
        IS_LogOnce(@"e2eekc", @"keychain unavailable: saving the encryption key in app preferences instead");
    }
}

static void IS_E2eeLoad(void) {
    gPlainLock = [NSObject new];
    gPlainUntil = [NSMutableDictionary dictionary];
    gE2eeLock = [NSObject new];
    gE2ee = [NSMutableDictionary dictionary];
    NSData *d = IS_KCGetFor(@"e2ee");
    if (!d.length) d = [[NSUserDefaults.standardUserDefaults stringForKey:kE2eeFallbackKey] dataUsingEncoding:NSUTF8StringEncoding];
    if (d.length) {
        id j = [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil];
        if ([j isKindOfClass:NSDictionary.class]) [gE2ee addEntriesFromDictionary:j];
    }
}

static NSDictionary *IS_E2eeEntry(void) {
    if (!gActive || !gE2eeLock) return nil;
    @synchronized (gE2eeLock) { return gE2ee[gActive[@"id"]]; }
}

static BOOL IS_E2eeActive(void) { return IS_E2eeEntry() != nil; }

static void IS_E2eeStore(NSString *iid, NSString *uid, NSString *skB64u) {
    if (!gE2eeLock) return;
    @synchronized (gE2eeLock) {
        gE2ee[iid] = @{ @"user": uid, @"sk": skB64u };
        IS_E2eePersist();
    }
}

static void IS_E2eeForget(NSString *iid) {
    if (!gE2eeLock || !iid) return;
    @synchronized (gE2eeLock) {
        if (gE2ee[iid]) { [gE2ee removeObjectForKey:iid]; IS_E2eePersist(); }
    }
}

// Both the verification patch and encryption need to read gateway frames as plain text.
static BOOL IS_NeedPlain(void) { return IS_SpoofOn() || IS_E2eeActive(); }

#pragma mark - URL rewriting

static NSURLComponents *IS_Parse(NSString *s, NSString *scheme) {
    s = [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!s.length) return nil;
    if ([s hasPrefix:@"//"]) s = [scheme stringByAppendingFormat:@":%@", s];
    else if ([s rangeOfString:@"://"].location == NSNotFound) s = [scheme stringByAppendingFormat:@"://%@", s];
    NSURLComponents *c = [NSURLComponents componentsWithString:s];
    return c.host.length ? c : nil;
}

static BOOL IS_In(NSString *h, NSArray<NSString *> *list) { return [list containsObject:h]; }

static NSURL *IS_Rewrite(NSURL *url) {
    NSDictionary *cur = gActive;
    if (!cur || ![url isKindOfClass:NSURL.class]) return url;
    NSString *host = url.host.lowercaseString;
    if (!host.length) return url;

    // The server's own resume/reconnect address keeps the app's compress flag: drop it there too,
    // so READY stays readable for the verification patch.
    NSString *sch0 = url.scheme.lowercaseString;
    if (([sch0 isEqualToString:@"ws"] || [sch0 isEqualToString:@"wss"]) && IS_NeedPlain()) {
        NSURLComponents *gc = IS_Parse(cur[@"gateway"], @"wss");
        NSURLComponents *ac = IS_Parse(cur[@"api"], @"https");
        BOOL inst = (gc && [host isEqualToString:gc.host.lowercaseString]) || (ac && [host isEqualToString:ac.host.lowercaseString]);
        if (inst) {
            NSURLComponents *rc = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSUInteger before = rc.queryItems.count;
            if (before) {
                NSMutableArray *keep = [NSMutableArray array];
                for (NSURLQueryItem *qi in rc.queryItems) if (![qi.name isEqualToString:@"compress"]) [keep addObject:qi];
                if (keep.count != before) {
                    rc.queryItems = keep.count ? keep : nil;
                    return rc.URL ?: url;
                }
            }
            return url;
        }
    }

    BOOL isApiHost = IS_In(host, @[ @"discord.com", @"ptb.discord.com", @"canary.discord.com",
                                    @"discordapp.com", @"ptb.discordapp.com", @"canary.discordapp.com" ]);
    BOOL isGateway = [host hasPrefix:@"gateway"] && [host hasSuffix:@".discord.gg"];
    BOOL isCdn     = IS_In(host, @[ @"cdn.discordapp.com", @"cdn.discord.com" ]);
    BOOL isMedia   = IS_In(host, @[ @"media.discordapp.net", @"images-ext-1.discordapp.net",
                                    @"images-ext-2.discordapp.net" ]);
    if (!(isApiHost || isGateway || isCdn || isMedia)) {
        if ([host containsString:@"discord"]) IS_LogOnce(host, [@"UNMATCHED host: " stringByAppendingString:host]);
        return url;
    }

    NSURLComponents *c = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!c) return url;

    if (isApiHost) {
        NSString *path = c.percentEncodedPath ?: @"";
        if (!([path isEqualToString:@"/api"] || [path hasPrefix:@"/api/"])) {
            NSArray *pp = [path componentsSeparatedByString:@"/"];
            NSString *fs = pp.count > 1 ? pp[1] : @"";
            IS_LogOnce([NSString stringWithFormat:@"skip:%@/%@", host, fs], [NSString stringWithFormat:@"skipped non-api path on %@: %@", host, path.length > 40 ? [path substringToIndex:40] : path]);
            return url;
        }
        NSURLComponents *b = IS_Parse(cur[@"api"], @"https");
        if (!b) return url;
        NSString *rest = [path substringFromIndex:4];
        NSString *bp = b.percentEncodedPath ?: @"";
        while ([bp hasSuffix:@"/"]) bp = [bp substringToIndex:bp.length - 1];
        c.scheme = b.scheme ?: @"https";
        c.host = b.host;
        c.port = b.port;
        c.percentEncodedPath = [bp stringByAppendingString:rest];
    } else if (isGateway) {
        NSURLComponents *b = IS_Parse(cur[@"gateway"], @"wss");
        if (!b) return url;
        c.scheme = b.scheme ?: @"wss";
        c.host = b.host;
        c.port = b.port;
        NSString *bp = b.percentEncodedPath ?: @"";
        c.percentEncodedPath = bp.length > 1 ? bp : @"/";
        // The verification patch edits plain-text frames, so ask the server not to compress while it is on.
        if (IS_NeedPlain() && c.queryItems.count) {
            NSMutableArray *keep = [NSMutableArray array];
            for (NSURLQueryItem *qi in c.queryItems) if (![qi.name isEqualToString:@"compress"]) [keep addObject:qi];
            c.queryItems = keep;
        }
    } else if (isCdn) {
        NSURLComponents *b = IS_Parse(cur[@"cdn"], @"https");
        if (!b) return url;
        c.scheme = @"https";
        c.host = b.host;
        c.port = b.port;
    } else {
        NSURLComponents *b = IS_Parse(cur[@"media"], @"https");
        if (!b) return url;
        c.scheme = @"https";
        c.host = b.host;
        c.port = b.port;
    }
    NSURL *out = c.URL ?: url;
    if (out != url && (isCdn || isMedia)) IS_ProbeAsset(out);
    NSString *os = url.absoluteString;
    IS_LogOnce([@"rw:" stringByAppendingFormat:@"%@>%@", host, out.host],
               [NSString stringWithFormat:@"%@ -> %@", os.length > 70 ? [os substringToIndex:70] : os,
                out.absoluteString.length > 90 ? [out.absoluteString substringToIndex:90] : out.absoluteString]);
    return out;
}

static BOOL IS_IsAuthTarget(NSURL *n) {
    NSString *host = n.host.lowercaseString;
    if (!host.length || ![(n.path ?: @"") hasPrefix:@"/api"]) return NO;
    if (gActive) {
        NSURLComponents *b = IS_Parse(gActive[@"api"], @"https");
        return b && [host isEqualToString:b.host.lowercaseString];
    }
    return IS_In(host, @[ @"discord.com", @"ptb.discord.com", @"canary.discord.com",
                          @"discordapp.com", @"ptb.discordapp.com", @"canary.discordapp.com" ]);
}

// Decide which login token this instance should use. The app only keeps one token, so after a switch
// it still holds the previous instance's token: swap in this instance's own saved one, and never send
// one instance's token to another.
static NSString *IS_TokenResolve(NSString *seen) {
    if (!seen.length || !gTokLock || [seen hasPrefix:@"Bot "] || [seen hasPrefix:@"Bearer "]) return seen;
    NSString *cur = gActive ? gActive[@"id"] : @"discord";
    NSString *label = gActive ? gActive[@"name"] : @"Discord";
    @synchronized (gTokLock) {
        NSString *mine = gTok[cur];
        if ([mine isEqualToString:seen]) return seen;
        for (NSString *k in gTok) {
            if (![k isEqualToString:cur] && [gTok[k] isEqualToString:seen]) {
                IS_LogOnce([@"stale:" stringByAppendingString:cur],
                           [NSString stringWithFormat:@"app held another instance's login; using %@ for %@", mine.length ? @"saved login" : @"no login (you'll be asked to sign in)", label]);
                return mine.length ? mine : @"invalid";
            }
        }
        gTok[cur] = seen;      // new or refreshed login for this instance
        IS_TokPersist();
        IS_Log(@"saved login for %@", label);
        return seen;
    }
}

// SocketRocket's websocket handshake sends no User-Agent; some instances reject that (close code 4002).
static NSString *IS_UA(void) {
    static NSString *ua; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSString *build = NSBundle.mainBundle.infoDictionary[@"CFBundleVersion"] ?: @"1";
        NSString *cfn = [NSBundle bundleWithIdentifier:@"com.apple.CFNetwork"].infoDictionary[@"CFBundleVersion"] ?: @"1494.0.7";
        struct utsname u; uname(&u);
        ua = [NSString stringWithFormat:@"Discord/%@ CFNetwork/%@ Darwin/%s", build, cfn, u.release];
    });
    return ua;
}

static id IS_Fix(id a) {
    if ([a isKindOfClass:NSURL.class]) return IS_Rewrite(a);
    if ([a isKindOfClass:NSURLRequest.class]) {
        NSURLRequest *req = a;
        NSURL *u = req.URL;
        NSURL *n = IS_Rewrite(u);
        NSString *sch = n.scheme.lowercaseString;
        BOOL isWS = [sch isEqualToString:@"ws"] || [sch isEqualToString:@"wss"];
        BOOL needUA = gActive && isWS && ![req valueForHTTPHeaderField:@"User-Agent"].length;
        NSString *newAuth = nil;
        if (n && IS_IsAuthTarget(n)) {
            NSString *auth = [req valueForHTTPHeaderField:@"Authorization"];
            if (auth.length) {
                NSString *use = IS_TokenResolve(auth);
                if (![use isEqualToString:auth]) newAuth = use;
                if ([n.path hasSuffix:@"/auth/logout"]) IS_TokForgetId(gActive ? gActive[@"id"] : @"discord");
            }
        }
        if (n == u && !needUA && !newAuth) return a;
        NSMutableURLRequest *m = [a mutableCopy];
        if (n != u) [m setURL:n];
        if (needUA) {
            [m setValue:IS_UA() forHTTPHeaderField:@"User-Agent"];
            IS_LogOnce(@"ua", [@"added User-Agent to websocket handshake: " stringByAppendingString:IS_UA()]);
        }
        if (newAuth) [m setValue:newAuth forHTTPHeaderField:@"Authorization"];
        return m;
    }
    return a;
}

#pragma mark - Hook helpers (class_replaceMethod, no Substrate)

static void IS_Hook1(Class cls, SEL sel) {              // (id)
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^uintptr_t(id s, id a) {
        return ((uintptr_t (*)(id, SEL, id))orig)(s, sel, IS_Fix(a));
    }), method_getTypeEncoding(m));
}

static void IS_Hook2(Class cls, SEL sel) {              // (id, id)
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^uintptr_t(id s, id a, id b) {
        return ((uintptr_t (*)(id, SEL, id, id))orig)(s, sel, IS_Fix(a), b);
    }), method_getTypeEncoding(m));
}

static void IS_Hook3(Class cls, SEL sel) {              // (id, id, id)
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^uintptr_t(id s, id a, id b, id c) {
        return ((uintptr_t (*)(id, SEL, id, id, id))orig)(s, sel, IS_Fix(a), b, c);
    }), method_getTypeEncoding(m));
}

static void IS_Hook2Bool(Class cls, SEL sel) {          // (id, id, BOOL)
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^uintptr_t(id s, id a, id b, BOOL c) {
        return ((uintptr_t (*)(id, SEL, id, id, BOOL))orig)(s, sel, IS_Fix(a), b, c);
    }), method_getTypeEncoding(m));
}

static void IS_HookSetURL(Class cls) {                  // -[NSMutableURLRequest setURL:]
    SEL sel = @selector(setURL:);
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^void(id s, NSURL *u) {
        ((void (*)(id, SEL, id))orig)(s, sel, IS_Rewrite(u));
    }), method_getTypeEncoding(m));
}

static void IS_HookReqInit(Class cls) {                 // -[NSURLRequest initWithURL:cachePolicy:timeoutInterval:]
    SEL sel = @selector(initWithURL:cachePolicy:timeoutInterval:);
    Method m = class_getInstanceMethod(cls, sel); if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^uintptr_t(id s, NSURL *u, NSUInteger p, NSTimeInterval t) {
        return ((uintptr_t (*)(id, SEL, id, NSUInteger, NSTimeInterval))orig)(s, sel, IS_Rewrite(u), p, t);
    }), method_getTypeEncoding(m));
}

static void IS_HookSession(Class cls) {
    IS_Hook1(cls, @selector(dataTaskWithRequest:));
    IS_Hook1(cls, @selector(dataTaskWithURL:));
    IS_Hook1(cls, @selector(downloadTaskWithRequest:));
    IS_Hook1(cls, @selector(downloadTaskWithURL:));
    IS_Hook1(cls, @selector(webSocketTaskWithRequest:));
    IS_Hook1(cls, @selector(webSocketTaskWithURL:));
    IS_Hook2(cls, @selector(dataTaskWithRequest:completionHandler:));
    IS_Hook2(cls, @selector(dataTaskWithURL:completionHandler:));
    IS_Hook2(cls, @selector(downloadTaskWithRequest:completionHandler:));
    IS_Hook2(cls, @selector(downloadTaskWithURL:completionHandler:));
    IS_Hook2(cls, @selector(uploadTaskWithRequest:fromData:));
    IS_Hook2(cls, @selector(uploadTaskWithRequest:fromFile:));
    IS_Hook2(cls, @selector(webSocketTaskWithURL:protocols:));
    IS_Hook3(cls, @selector(uploadTaskWithRequest:fromData:completionHandler:));
    IS_Hook3(cls, @selector(uploadTaskWithRequest:fromFile:completionHandler:));
}

static void IS_HookSocketRocket(Class cls) {
    if (!cls) return;
    IS_Hook1(cls, @selector(initWithURL:));
    IS_Hook1(cls, @selector(initWithURLRequest:));
    IS_Hook2(cls, @selector(initWithURL:protocols:));
    IS_Hook2(cls, @selector(initWithURLRequest:protocols:));
    IS_Hook2Bool(cls, @selector(initWithURL:protocols:allowsUntrustedSSLCertificates:));
    IS_Hook2Bool(cls, @selector(initWithURLRequest:protocols:allowsUntrustedSSLCertificates:));
}

#pragma mark - Generic hooks

static void IS_HookGeneric(Class cls, Method m) {
    SEL sel = method_getName(m);
    IMP orig = method_getImplementation(m);
    unsigned n = method_getNumberOfArguments(m) - 2;
    IMP imp = NULL;
    if (n == 1) imp = imp_implementationWithBlock(^uintptr_t(id s, id a) {
        return ((uintptr_t (*)(id, SEL, id))orig)(s, sel, IS_Fix(a));
    });
    else if (n == 2) imp = imp_implementationWithBlock(^uintptr_t(id s, id a, uintptr_t b) {
        return ((uintptr_t (*)(id, SEL, id, uintptr_t))orig)(s, sel, IS_Fix(a), b);
    });
    else if (n == 3) imp = imp_implementationWithBlock(^uintptr_t(id s, id a, uintptr_t b, uintptr_t c) {
        return ((uintptr_t (*)(id, SEL, id, uintptr_t, uintptr_t))orig)(s, sel, IS_Fix(a), b, c);
    });
    if (imp) class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
}

static void IS_HookNSURL(void) {
    Class meta = object_getClass(NSURL.class);
    SEL sel = @selector(URLWithString:);
    Method m = class_getInstanceMethod(meta, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(meta, sel, imp_implementationWithBlock(^id(id s, NSString *str) {
        NSURL *u = ((id (*)(id, SEL, id))orig)(s, sel, str);
        return IS_Rewrite(u);
    }), method_getTypeEncoding(m));
}

#pragma mark - E2EE read-only decryption (meowcord / fosscord-e2ee v1)

static NSMutableDictionary *gE2eeFiles;     // virtual attachment path -> @{ url, key, iv, content_type, filename }

static NSData *IS_B64uData(id v) {
    if (![v isKindOfClass:NSString.class] || ![(NSString *)v length] || [(NSString *)v length] > 8 * 1024 * 1024) return nil;
    const char *c = [(NSString *)v UTF8String];
    size_t l = strlen(c);
    NSMutableData *out = [NSMutableData dataWithLength:l];
    int n = is_b64u_decode(c, l, out.mutableBytes, out.length);
    if (n < 0) return nil;
    out.length = (NSUInteger)n;
    return out;
}

static NSString *IS_VirtualOrigin(void) {
    NSURLComponents *b = IS_Parse(gActive[@"api"], @"https");
    if (!b.host.length) return nil;
    return b.port ? [NSString stringWithFormat:@"https://%@:%@", b.host, b.port] : [@"https://" stringByAppendingString:b.host];
}

static void IS_E2eeApplyAttachments(NSMutableDictionary *m, NSDictionary *payload) {
    NSArray *metas = [payload[@"attachments"] isKindOfClass:NSArray.class] ? payload[@"attachments"] : @[];
    NSMutableArray *atts = m[@"attachments"];
    NSString *origin = IS_VirtualOrigin();
    if (!metas.count || ![atts isKindOfClass:NSMutableArray.class] || !origin) return;
    static dispatch_once_t filesOnce;
    dispatch_once(&filesOnce, ^{ gE2eeFiles = [NSMutableDictionary dictionary]; });
    NSMutableCharacterSet *allowed = [NSCharacterSet.URLPathAllowedCharacterSet mutableCopy];
    [allowed removeCharactersInString:@"/"];
    for (NSUInteger i = 0; i < atts.count; i++) {
        NSMutableDictionary *a = atts[i];
        if (![a isKindOfClass:NSMutableDictionary.class]) continue;
        NSDictionary *meta = nil;
        for (id x in metas) if ([x isKindOfClass:NSDictionary.class] && [x[@"name"] isEqual:a[@"filename"]]) { meta = x; break; }
        NSString *fname = meta[@"filename"];
        if (!meta || ![a[@"url"] isKindOfClass:NSString.class] || ![fname isKindOfClass:NSString.class] || !fname.length || fname.length > 1024) continue;
        NSData *key = IS_B64uData(meta[@"key"]), *iv = IS_B64uData(meta[@"iv"]);
        if (key.length != 32 || iv.length != 12) continue;
        NSString *path = [NSString stringWithFormat:@"/e2ee/attachments/%@/%@/%@", m[@"channel_id"], a[@"id"], fname];
        @synchronized (gE2eeFiles) {
            gE2eeFiles[path] = @{ @"url": a[@"url"], @"key": meta[@"key"], @"iv": meta[@"iv"],
                                  @"content_type": [meta[@"content_type"] isKindOfClass:NSString.class] ? meta[@"content_type"] : @"application/octet-stream" };
        }
        NSString *url = [NSString stringWithFormat:@"%@/e2ee/attachments/%@/%@/%@", origin, m[@"channel_id"], a[@"id"],
                         [fname stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: @"file"];
        BOOL spoiler = [meta[@"spoiler"] boolValue];
        a[@"filename"] = (spoiler && ![fname hasPrefix:@"SPOILER_"]) ? [@"SPOILER_" stringByAppendingString:fname] : fname;
        if ([meta[@"content_type"] isKindOfClass:NSString.class]) a[@"content_type"] = meta[@"content_type"];
        if ([meta[@"size"] isKindOfClass:NSNumber.class]) a[@"size"] = meta[@"size"];
        a[@"url"] = url;
        a[@"proxy_url"] = url;
        if ([meta[@"width"] isKindOfClass:NSNumber.class] && [meta[@"height"] isKindOfClass:NSNumber.class]) {
            a[@"width"] = meta[@"width"];
            a[@"height"] = meta[@"height"];
        }
        if (spoiler) a[@"flags"] = @([a[@"flags"] intValue] | 8);
        for (NSString *f in @[ @"duration_secs", @"waveform", @"description" ]) if (meta[f]) a[f] = meta[f];
        [a removeObjectForKey:@"placeholder"];
        [a removeObjectForKey:@"placeholder_version"];
    }
}

// Opens the message's content key with YOUR backup key (the envelope's "backup" entry) and decrypts the payload.
// Read-only: no device registration, no signature check (same trust in the server's key directory as the default mode).
static BOOL IS_E2eeDecryptMessage(NSMutableDictionary *m) {
    NSDictionary *st = IS_E2eeEntry();
    if (!st) return NO;
    NSDictionary *env = m[@"encrypted"];
    if (![env isKindOfClass:NSDictionary.class] || [env[@"v"] intValue] != 1 || ![env[@"alg"] isEqual:@"x25519-hpke-aes256gcm-ed25519"]) return NO;
    NSString *uid = st[@"user"];
    NSData *sk = IS_B64uData(st[@"sk"]);
    NSString *channel = m[@"channel_id"], *mid = m[@"id"];
    NSString *senderId = [m[@"author"] isKindOfClass:NSDictionary.class] ? m[@"author"][@"id"] : nil;
    NSString *dev = env[@"sender_device"];
    NSString *envMid = [env[@"mid"] isKindOfClass:NSString.class] ? env[@"mid"] : nil;
    if (sk.length != 32 || ![uid isKindOfClass:NSString.class] || ![senderId isKindOfClass:NSString.class] ||
        ![dev isKindOfClass:NSString.class] || ![channel isKindOfClass:NSString.class]) return NO;
    if (envMid && ![envMid isEqualToString:mid]) return NO;
    id nv = m[@"nonce"];
    NSString *nonce = [nv isKindOfClass:NSString.class] ? nv : ([nv isKindOfClass:NSNumber.class] ? [nv stringValue] : nil);
    if (!envMid.length && !nonce.length) { IS_LogOnce(@"e2ee:nononce", @"encrypted message without a nonce: cannot decrypt"); return NO; }
    NSString *bind = envMid.length ? [@"m:" stringByAppendingString:envMid] : [@"n:" stringByAppendingString:nonce];
    NSString *aad = [NSString stringWithFormat:@"fosscord-e2ee/v1/msg\n%@\n%@\n%@\n%@", channel, senderId, dev, bind];

    NSDictionary *entry = nil;
    if ([env[@"backup"] isKindOfClass:NSArray.class])
        for (id b in env[@"backup"]) if ([b isKindOfClass:NSDictionary.class] && [b[@"user_id"] isEqual:uid]) { entry = b; break; }
    if (!entry) { IS_LogOnce(@"e2ee:nobackup", @"an encrypted message has no entry for your backup key (older message): left locked"); return NO; }
    NSData *enc = IS_B64uData(entry[@"enc"]), *wrapped = IS_B64uData(entry[@"wrapped"]);
    NSData *iv = IS_B64uData(env[@"iv"]), *ct = IS_B64uData(env[@"ct"]);
    if (enc.length != 32 || wrapped.length < 17 || wrapped.length > 128 || iv.length != 12 || ct.length < 16) return NO;

    NSData *info = [@"fosscord-e2ee/v1/backup-wrap" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *haad = [[aad stringByAppendingFormat:@"\nbackup:%@", uid] dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t ckey[128];
    int kn = is_hpke_open(sk.bytes, enc.bytes, info.bytes, info.length, haad.bytes, haad.length, wrapped.bytes, wrapped.length, ckey);
    if (kn != 32) { IS_LogOnce(@"e2ee:hpke", @"could not open a message key with your backup key (different account, or the key was reset)"); return NO; }
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *pt = [NSMutableData dataWithLength:ct.length];
    int pn = is_gcm_open(ckey, iv.bytes, aadData.bytes, aadData.length, ct.bytes, ct.length, pt.mutableBytes);
    memset(ckey, 0, sizeof ckey);
    if (pn < 0) { IS_LogOnce(@"e2ee:gcm", @"an encrypted message failed authentication (details not matching: nonce/author/device)"); return NO; }
    pt.length = (NSUInteger)pn;
    id payload = [NSJSONSerialization JSONObjectWithData:pt options:0 error:nil];
    if (![payload isKindOfClass:NSDictionary.class] || ![payload[@"content"] isKindOfClass:NSString.class]) return NO;

    m[@"content"] = payload[@"content"];
    IS_E2eeApplyAttachments(m, payload);
    if ([payload[@"stickers"] isKindOfClass:NSArray.class] && [payload[@"stickers"] count]) {
        NSMutableArray *items = [NSMutableArray array];
        for (id sdict in payload[@"stickers"])
            if ([sdict isKindOfClass:NSDictionary.class] && sdict[@"id"] && sdict[@"name"] && sdict[@"format_type"])
                [items addObject:@{ @"id": sdict[@"id"], @"name": sdict[@"name"], @"format_type": sdict[@"format_type"] }];
        if (items.count) m[@"sticker_items"] = items;
    }
    [m removeObjectForKey:@"encrypted"];
    IS_LogOnce(@"e2ee:ok", @"decrypted an encrypted message");
    return YES;
}

static BOOL IS_E2eeWalk(id node, int depth) {
    if (depth > 6) return NO;
    BOOL changed = NO;
    if ([node isKindOfClass:NSMutableDictionary.class]) {
        NSMutableDictionary *d = node;
        if ([d[@"encrypted"] isKindOfClass:NSDictionary.class] && [d[@"id"] isKindOfClass:NSString.class] && [d[@"channel_id"] isKindOfClass:NSString.class])
            if (IS_E2eeDecryptMessage(d)) changed = YES;
        for (id k in d.allKeys) {
            if ([k isEqual:@"encrypted"]) continue;
            id v = d[k];
            if (([v isKindOfClass:NSDictionary.class] || [v isKindOfClass:NSArray.class]) && IS_E2eeWalk(v, depth + 1)) changed = YES;
        }
    } else if ([node isKindOfClass:NSArray.class]) {
        for (id v in node) if (([v isKindOfClass:NSDictionary.class] || [v isKindOfClass:NSArray.class]) && IS_E2eeWalk(v, depth + 1)) changed = YES;
    }
    return changed;
}

// Decrypts any encrypted messages found in a gateway frame or REST body (JSON text). Returns the input if nothing changed.
static NSString *IS_E2eeProcess(NSString *s) {
    if (!gActive || s.length < 40 || !IS_E2eeActive() || [s rangeOfString:@"\"encrypted\":{"].location == NSNotFound) return s;
    @try {
        id root = [NSJSONSerialization JSONObjectWithData:[s dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:nil];
        if (!root || !IS_E2eeWalk(root, 0)) return s;
        NSData *out = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingWithoutEscapingSlashes error:nil];
        NSString *str = out ? [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] : nil;
        return str ?: s;
    } @catch (NSException *e) {
        IS_Log(@"e2ee: exception %@", e.reason);
        return s;
    }
}

// Chunked AES-GCM files: 64 KiB chunks, nonce = iv with the last 4 bytes XOR chunk index, AAD binds index + final flag.
static NSData *IS_E2eeDecryptFile(NSData *cipher, NSData *key, NSData *iv) {
    const NSUInteger CH = 65536 + 16;
    if (key.length != 32 || iv.length != 12 || !cipher.length) return nil;
    NSUInteger count = MAX((NSUInteger)1, (cipher.length + CH - 1) / CH);
    NSMutableData *out = [NSMutableData dataWithLength:cipher.length];
    NSUInteger outn = 0;
    const uint8_t *c = cipher.bytes;
    for (NSUInteger i = 0; i < count; i++) {
        NSUInteger off = i * CH;
        NSUInteger len = MIN(CH, cipher.length - off);
        uint8_t nonce[12];
        memcpy(nonce, iv.bytes, 12);
        uint32_t v = ((uint32_t)nonce[8] << 24) | ((uint32_t)nonce[9] << 16) | ((uint32_t)nonce[10] << 8) | nonce[11];
        v ^= (uint32_t)i;
        nonce[8] = (uint8_t)(v >> 24); nonce[9] = (uint8_t)(v >> 16); nonce[10] = (uint8_t)(v >> 8); nonce[11] = (uint8_t)v;
        char aad[64];
        int al = snprintf(aad, sizeof aad, "fosscord-e2ee/v1/file\n%lu\n%d", (unsigned long)i, i == count - 1 ? 1 : 0);
        int r = is_gcm_open(key.bytes, nonce, (const uint8_t *)aad, (size_t)al, c + off, len, (uint8_t *)out.mutableBytes + outn);
        if (r < 0) return nil;
        outn += (NSUInteger)r;
    }
    out.length = outn;
    return out;
}

static NSDictionary *IS_ServedType(NSString *type) {
    NSString *base = [[[type componentsSeparatedByString:@";"].firstObject ?: @"" stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] lowercaseString];
    NSRegularExpression *safe = [NSRegularExpression regularExpressionWithPattern:
        @"^(image/(png|jpeg|gif|webp|avif|bmp)|video/(mp4|webm|ogg|quicktime)|audio/(mpeg|mp4|ogg|wav|webm|aac|flac|x-wav|x-flac)|application/pdf)$" options:0 error:nil];
    if ([safe numberOfMatchesInString:base options:0 range:NSMakeRange(0, base.length)])
        return @{ @"type": base, @"inline": @YES };
    if ([base hasPrefix:@"text/"] || [base hasPrefix:@"image/svg"] ||
        [@[ @"application/json", @"application/xml", @"application/javascript", @"application/x-sh", @"application/toml", @"application/yaml" ] containsObject:base])
        return @{ @"type": @"text/plain; charset=utf-8", @"inline": @YES };
    return @{ @"type": @"application/octet-stream", @"inline": @NO };
}

static NSCache *IS_FileCache(void) {
    static NSCache *c; static dispatch_once_t o;
    dispatch_once(&o, ^{ c = [NSCache new]; c.totalCostLimit = 96 * 1024 * 1024; });
    return c;
}

// The iOS app only recognises discord.gg / discord.com/invite links as invites. Instances use
// <host>/invite/CODE (the plugin's INVITE_HOST), so turn those into the Discord forms the app understands.
// The app then resolves the code through the (already redirected) API, so the join card works.
static NSArray *IS_LinkRules(void) {
    static NSArray *rules; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSMutableSet *hosts = [NSMutableSet set];
        for (NSString *k in @[ @"api", @"gateway" ]) {
            NSURLComponents *c = IS_Parse(gActive[k], @"https");
            if (c.host.length) [hosts addObject:c.host.lowercaseString];
        }
        NSMutableArray *alts = [NSMutableArray array];
        for (NSString *h in hosts) [alts addObject:[NSRegularExpression escapedPatternForString:h]];
        if (!alts.count) { rules = @[]; return; }
        NSString *hostAlt = [alts componentsJoinedByString:@"|"];
        NSMutableArray *out = [NSMutableArray array];
        NSArray *kinds = @[ @[ @"invite", @"https://discord.gg/" ],
                            @[ @"template", @"https://discord.new/" ],
                            @[ @"gift", @"https://discord.gift/" ] ];
        for (NSArray *k in kinds) {
            NSString *pat = [NSString stringWithFormat:@"(?<![\\w.-])(?:https?:(?:\\\\?/){2})?(?:www\\.)?(?:%@)(?:\\\\?/)%@(?:\\\\?/)", hostAlt, k[0]];
            NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pat options:NSRegularExpressionCaseInsensitive error:nil];
            if (re) [out addObject:@{ @"kind": k[0], @"re": re, @"to": k[1], @"hosts": hosts.allObjects }];
        }
        rules = out;
    });
    return rules;
}

static NSString *IS_RewriteInviteLinks(NSString *s) {
    if (!gActive || s.length < 12) return s;
    NSArray *rules = IS_LinkRules();
    if (!rules.count) return s;
    NSString *cur = s;
    for (NSDictionary *r in rules) {
        if ([cur rangeOfString:r[@"kind"]].location == NSNotFound) continue;
        BOOL hasHost = NO;
        for (NSString *h in r[@"hosts"]) if ([cur rangeOfString:h options:NSCaseInsensitiveSearch].location != NSNotFound) { hasHost = YES; break; }
        if (!hasHost) continue;
        NSRegularExpression *re = r[@"re"];
        NSString *n = [re stringByReplacingMatchesInString:cur options:0 range:NSMakeRange(0, cur.length)
                                              withTemplate:[NSRegularExpression escapedTemplateForString:r[@"to"]]];
        if (![n isEqualToString:cur]) {
            IS_LogOnce([@"linkrw:" stringByAppendingString:r[@"kind"]], [NSString stringWithFormat:@"rewrote instance %@ link(s) to the Discord form", r[@"kind"]]);
            cur = n;
        }
    }
    return cur;
}

static void IS_PatchUser(NSMutableDictionary *u) {
    if (![u isKindOfClass:NSMutableDictionary.class]) return;
    u[@"verified"] = @YES;
    id em = u[@"email"];
    if (!em || em == NSNull.null || ([em isKindOfClass:NSString.class] && ![(NSString *)em length])) {
        NSString *name = [u[@"username"] isKindOfClass:NSString.class] ? u[@"username"] : ([u[@"id"] description] ?: @"user");
        name = [name stringByReplacingOccurrencesOfString:@" " withString:@""];
        NSURLComponents *b = IS_Parse(gActive[@"api"], @"https");
        u[@"email"] = [NSString stringWithFormat:@"%@@%@", name, b.host ?: @"instance.local"];
    }
    id ph = u[@"phone"];
    if (IS_SpoofPhone() && (!ph || ph == NSNull.null)) u[@"phone"] = @"+15555550100";
}

// Marks your own account as verified/claimed in READY and USER_UPDATE, like the Vencord plugin does (client-side only).
static id IS_PatchFrame(id msg) {
    if (!gActive) return msg;
    if ([msg isKindOfClass:NSString.class]) msg = IS_RewriteInviteLinks(IS_E2eeProcess(msg));
    if (!IS_SpoofOn()) return msg;
    if ([msg isKindOfClass:NSData.class]) {
        IS_LogOnce(@"binfr", @"gateway frames are binary (compressed): verification patch cannot edit them");
        return msg;
    }
    if (![msg isKindOfClass:NSString.class]) return msg;
    NSString *m = msg;
    NSString *head = m.length > 200 ? [m substringToIndex:200] : m;
    BOOL ready = [head containsString:@"\"t\":\"READY\""];
    BOOL upd = [head containsString:@"\"t\":\"USER_UPDATE\""];
    if (!ready && !upd) return msg;
    @try {
        NSData *data = [m dataUsingEncoding:NSUTF8StringEncoding];
        NSError *err = nil;
        id root = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&err];
        if (![root isKindOfClass:NSMutableDictionary.class]) { IS_Log(@"patch: parse failed %@", err.localizedDescription); return msg; }
        NSMutableDictionary *d = root[@"d"];
        NSMutableDictionary *u = ready ? d[@"user"] : d;
        if (![u isKindOfClass:NSMutableDictionary.class]) { IS_Log(@"patch: no user object in %@", ready ? @"READY" : @"USER_UPDATE"); return msg; }
        IS_PatchUser(u);
        NSData *out = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingWithoutEscapingSlashes error:&err];
        if (!out) { IS_Log(@"patch: serialize failed %@", err.localizedDescription); return msg; }
        NSString *str = [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
        if (!str) return msg;
        IS_Log(@"patched %@ user: verified=true email=%@%@", ready ? @"READY" : @"USER_UPDATE", u[@"email"], IS_SpoofPhone() ? @" +phone" : @"");
        return str;
    } @catch (NSException *e) {
        IS_Log(@"patch: exception %@", e.reason);
        return msg;
    }
}

// The gateway login frame carries the token too: swap it the same way.
static id IS_PatchOutFrame(id msg) {
    if (![msg isKindOfClass:NSString.class] || !gTokLock) return msg;
    NSString *m = msg;
    if (m.length < 20 || m.length > 20000) return msg;
    NSString *head = m.length > 60 ? [m substringToIndex:60] : m;
    if (![head containsString:@"\"op\":2,"]) return msg;
    NSRange r = [m rangeOfString:@"\"token\":\""];
    if (r.location == NSNotFound) return msg;
    NSUInteger st = NSMaxRange(r);
    NSRange q = [m rangeOfString:@"\"" options:0 range:NSMakeRange(st, m.length - st)];
    if (q.location == NSNotFound) return msg;
    NSString *seen = [m substringWithRange:NSMakeRange(st, q.location - st)];
    NSString *use = IS_TokenResolve(seen);
    if ([use isEqualToString:seen]) return msg;
    return [m stringByReplacingCharactersInRange:NSMakeRange(st, q.location - st) withString:use];
}

static NSString *IS_WSURL(id ws) {
    @try {
        if ([ws respondsToSelector:@selector(url)]) {
            NSURL *u = ((id (*)(id, SEL))objc_msgSend)(ws, @selector(url));
            if ([u isKindOfClass:NSURL.class]) return [NSString stringWithFormat:@"%@%@", u.host ?: @"?", u.path ?: @""];
        }
    } @catch (__unused id e) {}
    return @"?";
}

// Summarise a gateway frame WITHOUT logging its contents (frames can contain your token).
static NSString *IS_Frame(id msg) {
    if ([msg isKindOfClass:NSData.class]) return [NSString stringWithFormat:@"binary %lu bytes", (unsigned long)[(NSData *)msg length]];
    if (![msg isKindOfClass:NSString.class]) return @"?";
    NSString *m = msg;
    NSString *head = m.length > 200 ? [m substringToIndex:200] : m;
    int op = -1; NSString *t = nil;
    NSRange r = [head rangeOfString:@"\"op\":"];
    if (r.location != NSNotFound) op = [[head substringFromIndex:NSMaxRange(r)] intValue];
    r = [head rangeOfString:@"\"t\":\""];
    if (r.location != NSNotFound) {
        NSString *rest = [head substringFromIndex:NSMaxRange(r)];
        NSRange q = [rest rangeOfString:@"\""];
        if (q.location != NSNotFound) t = [rest substringToIndex:q.location];
    }
    NSMutableString *o = [NSMutableString stringWithFormat:@"op=%d", op];
    if (t.length) [o appendFormat:@" t=%@", t];
    [o appendFormat:@" size=%lu", (unsigned long)m.length];
    if (op != 0 && op != 2 && op != 3 && m.length < 120) [o appendFormat:@" %@", m];   // hello / invalid-session / reconnect only
    return o;
}

static NSMutableSet *IS_HookedSet(void) {
    static NSMutableSet *h; static dispatch_once_t o;
    dispatch_once(&o, ^{ h = [NSMutableSet set]; });
    return h;
}

static BOOL IS_FirstHook(const char *cls, const char *sel) {
    NSMutableSet *h = IS_HookedSet();
    NSString *k = [NSString stringWithFormat:@"%s|%s", cls, sel];
    @synchronized (h) {
        if ([h containsObject:k]) return NO;
        [h addObject:k];
    }
    return YES;
}

static void IS_HookWSLog(Class c, Method m, const char *cn, const char *sn) {
    SEL sel = method_getName(m);
    IMP orig = method_getImplementation(m);
    NSString *name = @(sn);
    if ([name isEqualToString:@"webSocketDidOpen:"]) {
        class_replaceMethod(c, sel, imp_implementationWithBlock(^void(id s, id ws) {
            IS_Log(@"WS OPEN %@", IS_WSURL(ws));
            ((void (*)(id, SEL, id))orig)(s, sel, ws);
        }), method_getTypeEncoding(m));
    } else if ([name isEqualToString:@"webSocket:didFailWithError:"]) {
        class_replaceMethod(c, sel, imp_implementationWithBlock(^void(id s, id ws, NSError *err) {
            IS_Log(@"WS FAIL %@ code=%ld %@ (%@)", err.domain, (long)err.code, err.localizedDescription, IS_WSURL(ws));
            ((void (*)(id, SEL, id, id))orig)(s, sel, ws, err);
        }), method_getTypeEncoding(m));
    } else if ([name isEqualToString:@"webSocket:didCloseWithCode:reason:wasClean:"]) {
        class_replaceMethod(c, sel, imp_implementationWithBlock(^void(id s, id ws, NSInteger code, id reason, BOOL clean) {
            IS_Log(@"WS CLOSE code=%ld reason=%@ clean=%d (%@)", (long)code, reason, clean, IS_WSURL(ws));
            ((void (*)(id, SEL, id, NSInteger, id, BOOL))orig)(s, sel, ws, code, reason, clean);
        }), method_getTypeEncoding(m));
    } else if ([name isEqualToString:@"webSocket:didReceiveMessage:"]) {
        class_replaceMethod(c, sel, imp_implementationWithBlock(^void(id s, id ws, id msg) {
            id out = IS_PatchFrame(msg);
            IS_Log(@"WS RECV %@", IS_Frame(out));
            ((void (*)(id, SEL, id, id))orig)(s, sel, ws, out);
        }), method_getTypeEncoding(m));
    } else if ([name isEqualToString:@"send:"] || [name isEqualToString:@"sendString:error:"] || [name isEqualToString:@"sendData:error:"]) {
        if (method_getNumberOfArguments(m) == 3) {
            class_replaceMethod(c, sel, imp_implementationWithBlock(^uintptr_t(id s, id msg) {
                id out = IS_PatchOutFrame(msg);
                IS_Log(@"WS SEND %@", IS_Frame(out));
                return ((uintptr_t (*)(id, SEL, id))orig)(s, sel, out);
            }), method_getTypeEncoding(m));
        } else {
            class_replaceMethod(c, sel, imp_implementationWithBlock(^uintptr_t(id s, id msg, uintptr_t e) {
                id out = IS_PatchOutFrame(msg);
                IS_Log(@"WS SEND %@", IS_Frame(out));
                return ((uintptr_t (*)(id, SEL, id, uintptr_t))orig)(s, sel, out, e);
            }), method_getTypeEncoding(m));
        }
    } else return;
    IS_Log(@"  logging -[%s %s]", cn, sn);
}

static void IS_HookWebSocketClasses(void) {
    unsigned cnt = 0;
    Class *all = objc_copyClassList(&cnt);
    for (unsigned i = 0; i < cnt; i++) {
        Class c = all[i];
        const char *nm = class_getName(c);
        if (!nm || !strcasestr(nm, "websocket")) continue;
        if (!strncmp(nm, "NS", 2) || !strncmp(nm, "__NS", 4) || !strncmp(nm, "_NS", 3)) continue;
        unsigned mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        for (unsigned j = 0; j < mc; j++) {
            const char *sn = sel_getName(method_getName(ms[j]));
            // 1) frame / lifecycle logging
            if (!strcmp(sn, "webSocketDidOpen:") || !strcmp(sn, "webSocket:didFailWithError:") ||
                !strcmp(sn, "webSocket:didCloseWithCode:reason:wasClean:") || !strcmp(sn, "webSocket:didReceiveMessage:") ||
                !strcmp(sn, "send:") || !strcmp(sn, "sendString:error:") || !strcmp(sn, "sendData:error:")) {
                if (IS_FirstHook(nm, sn)) IS_HookWSLog(c, ms[j], nm, sn);
                continue;
            }
            // 2) URL rewriting on init/connect/open style methods
            if (!(strstr(sn, "URL") || strstr(sn, "Url") || strstr(sn, "Request"))) continue;
            if (!(!strncmp(sn, "init", 4) || strstr(sn, "onnect") || strstr(sn, "pen"))) continue;
            unsigned na = method_getNumberOfArguments(ms[j]);
            if (na < 3 || na > 5) continue;
            BOOL ok = YES;
            char *a0 = method_copyArgumentType(ms[j], 2);
            if (!a0 || a0[0] != '@') ok = NO;
            free(a0);
            for (unsigned k = 3; k < na && ok; k++) {
                char *t = method_copyArgumentType(ms[j], k);
                if (!t || t[0] == 'd' || t[0] == 'f' || t[0] == '{') ok = NO;
                free(t);
            }
            char *rt = method_copyReturnType(ms[j]);
            if (!rt || !strchr("@vBc", rt[0])) ok = NO;
            free(rt);
            if (!ok || !IS_FirstHook(nm, sn)) continue;
            IS_Log(@"  hooked -[%s %s]", nm, sn);
            IS_HookGeneric(c, ms[j]);
        }
        free(ms);
    }
    free(all);
}

#pragma mark - UI

static UIViewController *IS_Top(void) {
    UIWindow *win = nil;
    for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
        if (![sc isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (win) break;
    }
    UIViewController *v = win.rootViewController;
    while (v.presentedViewController) v = v.presentedViewController;
    return v;
}

static void IS_Alert(NSString *title, NSString *msg, void (^ok)(void)) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) { if (ok) ok(); }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

static void IS_Switch(NSString *iid) {
    NSMutableDictionary *s = [IS_State() mutableCopy];
    s[@"active"] = iid;
    IS_Save(s);
    IS_Alert(@"Instance switched", @"Discord will close now. Open it again to connect to the new instance.",
             ^{ exit(0); });
}

static void IS_ShowLog(void) {
    NSArray *a = IS_Lines();
    NSString *all; NSArray *tail;
    @synchronized (a) {
        all = [a componentsJoinedByString:@"\n"];
        tail = a.count > 14 ? [a subarrayWithRange:NSMakeRange(a.count - 14, 14)] : [a copy];
    }
    NSMutableString *msg = [NSMutableString string];
    for (NSString *l in tail) [msg appendFormat:@"%@\n", l.length > 100 ? [l substringToIndex:100] : l];
    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"Debug log (latest)"
        message:msg.length ? msg : @"(empty)" preferredStyle:UIAlertControllerStyleAlert];
    [al addAction:[UIAlertAction actionWithTitle:@"Copy full log" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        UIPasteboard.generalPasteboard.string = all.length ? all : @"(empty)";
    }]];
    [al addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleCancel handler:nil]];
    [IS_Top() presentViewController:al animated:YES completion:nil];
}

static void IS_ShowMenu(void);
static void IS_ShowMore(void);

static void IS_AddFlow(void) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Add instance"
        message:@"Paste the instance link, e.g. https://example.com"
        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"Link (https://example.com)";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
        t.autocorrectionType = UITextAutocorrectionTypeNo;
        t.keyboardType = UIKeyboardTypeURL;
    }];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"Name (optional)";
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"Save" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        NSURLComponents *c = IS_Parse(a.textFields[0].text, @"https");
        if (!c) {
            IS_Alert(@"Invalid link", @"Enter the instance address, like https://example.com", ^{ IS_AddFlow(); });
            return;
        }
        NSString *host = c.port ? [NSString stringWithFormat:@"%@:%@", c.host, c.port] : c.host;
        NSString *name = a.textFields[1].text.length ? a.textFields[1].text : host;
        // Same defaults as the Vencord plugin: /api, /gateway and the CDN/media all on the same host.
        NSMutableDictionary *s = [IS_State() mutableCopy];
        NSMutableArray *list = [s[@"instances"] mutableCopy];
        [list addObject:@{ @"id": NSUUID.UUID.UUIDString, @"name": name,
                           @"api": [NSString stringWithFormat:@"https://%@/api", host],
                           @"gateway": [NSString stringWithFormat:@"wss://%@/gateway", host],
                           @"cdn": host,
                           @"media": [NSString stringWithFormat:@"https://%@", host] }];
        s[@"instances"] = list;
        IS_Save(s);
        IS_ShowMenu();
    }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

static void IS_RemoveMenu(void) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Remove instance" message:nil
                                                        preferredStyle:UIAlertControllerStyleAlert];
    NSDictionary *st = IS_State();
    for (NSDictionary *i in st[@"instances"]) {
        if ([i[@"id"] isEqual:@"discord"]) continue;
        [a addAction:[UIAlertAction actionWithTitle:i[@"name"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
            IS_TokForgetId(i[@"id"]);
            IS_E2eeForget(i[@"id"]);
            NSMutableDictionary *s = [IS_State() mutableCopy];
            NSMutableArray *list = [NSMutableArray array];
            for (NSDictionary *j in s[@"instances"]) if (![j[@"id"] isEqual:i[@"id"]]) [list addObject:j];
            s[@"instances"] = list;
            BOOL wasActive = [s[@"active"] isEqual:i[@"id"]];
            if (wasActive) s[@"active"] = @"discord";
            IS_Save(s);
            if (wasActive) IS_Alert(@"Removed", @"That instance was active. Discord will close; reopen it to use Discord.", ^{ exit(0); });
            else IS_ShowMenu();
        }]];
    }
    [a addAction:[UIAlertAction actionWithTitle:@"Back" style:UIAlertActionStyleCancel handler:^(UIAlertAction *x) { IS_ShowMore(); }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

#pragma mark - E2EE sending (device registration + envelope sealing)

static NSString *const kE2eeFallbackText = @"\U0001F512 Encrypted message";

static NSString *IS_B64uString(const uint8_t *d, size_t n) {
    size_t cap = (n / 3 + 1) * 4 + 1;
    char *buf = malloc(cap);
    if (!buf) return nil;
    NSString *s = is_b64u_encode(d, n, buf, cap) >= 0 ? [NSString stringWithUTF8String:buf] : nil;
    free(buf);
    return s;
}

static BOOL IS_EdVerify(id pub, id msg, id sig) {
    NSData *p = IS_B64uData(pub), *s = IS_B64uData(sig);
    if (p.length != 32 || s.length != 64 || ![msg isKindOfClass:NSString.class] || ![(NSString *)msg length]) return NO;
    NSData *m = [(NSString *)msg dataUsingEncoding:NSUTF8StringEncoding];
    return is_ed25519_verify(s.bytes, p.bytes, m.bytes, m.length) == 1;
}

static NSString *IS_EdSign(NSData *seed, NSString *msg) {
    uint8_t sig[64];
    NSData *m = [msg dataUsingEncoding:NSUTF8StringEncoding];
    is_ed25519_sign(seed.bytes, m.bytes, m.length, sig);
    return IS_B64uString(sig, 64);
}

static NSString *IS_DeviceIdFor(NSString *signingKey) {
    NSData *raw = IS_B64uData(signingKey);
    if (raw.length != 32) return nil;
    uint8_t h[32];
    is_sha256(raw.bytes, raw.length, h);
    return IS_B64uString(h, 16);
}

static NSString *IS_DeviceMsg(NSString *uid, NSString *did, NSString *sk) { return [NSString stringWithFormat:@"fosscord-e2ee/v1/device\n%@\n%@\n%@", uid, did, sk]; }
static NSString *IS_PrekeyMsg(NSString *did, long long pid, NSString *pub) { return [NSString stringWithFormat:@"fosscord-e2ee/v1/prekey\n%@\n%lld\n%@", did, pid, pub]; }
static NSString *IS_RotationMsg(NSString *uid, NSString *prev, NSString *next) { return [NSString stringWithFormat:@"fosscord-e2ee/v1/identity-rotate\n%@\n%@\n%@", uid, prev, next]; }
static NSString *IS_BackupKeyMsg(NSString *uid, NSString *pub) { return [NSString stringWithFormat:@"fosscord-e2ee/v1/backup-key\n%@\n%@", uid, pub]; }

static void IS_E2eeMerge(NSString *iid, NSDictionary *fields) {
    if (!gE2eeLock || !iid) return;
    @synchronized (gE2eeLock) {
        NSMutableDictionary *e = [gE2ee[iid] mutableCopy];
        if (!e) return;
        [e addEntriesFromDictionary:fields];
        gE2ee[iid] = e;
        IS_E2eePersist();
    }
}

static BOOL IS_E2eeCanSend(void) {
    NSDictionary *e = IS_E2eeEntry();
    return e && IS_B64uData(e[@"dev_seed"]).length == 32 && [e[@"dev_id"] isKindOfClass:NSString.class] && [e[@"idpub"] isKindOfClass:NSString.class];
}

// Blocking JSON request. Returns the parsed body (or @{} for an empty one) and the HTTP status; nil on a transport error.
static id IS_SyncJSON(NSString *method, NSString *url, NSString *token, id body, NSInteger *status, NSString **err) {
    NSURL *u = [NSURL URLWithString:url];
    if (!u) { if (err) *err = @"bad address"; return nil; }
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    r.HTTPMethod = method;
    [r setValue:token forHTTPHeaderField:@"Authorization"];
    if (body) {
        r.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:NSJSONWritingWithoutEscapingSlashes error:nil];
        [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }
    r.timeoutInterval = 20;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block id result = nil;
    __block NSInteger code = 0;
    __block NSString *e = nil;
    [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *er) {
        NSHTTPURLResponse *h = [resp isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)resp : nil;
        if (er || !h) e = er.localizedDescription ?: @"no response";
        else {
            code = h.statusCode;
            result = d.length ? [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingFragmentsAllowed error:nil] : @{};
            if (!result) result = @{};
        }
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    if (status) *status = code;
    if (e && err) *err = e;
    return e ? nil : result;
}

static BOOL IS_E2eeKnownPlain(NSString *channel) {
    if (!gPlainLock) return NO;
    @synchronized (gPlainLock) {
        NSDate *until = gPlainUntil[channel];
        return until && until.timeIntervalSinceNow > 0;
    }
}

static void IS_E2eeMarkPlain(NSString *channel) {
    if (!gPlainLock) return;
    @synchronized (gPlainLock) { gPlainUntil[channel] = [NSDate dateWithTimeIntervalSinceNow:30]; }
}

// 1 = encrypted, 0 = plain, -1 = couldn't tell (the caller must not send anything). base is ".../api/v9".
static int IS_E2eeIsEncrypted(NSString *base, NSString *token, NSString *channel) {
    static NSMutableSet *encrypted, *plain;
    static NSDate *stateAt; static NSObject *lock; static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; encrypted = [NSMutableSet set]; plain = [NSMutableSet set]; });
    BOOL needState = NO, known = NO;
    @synchronized (lock) {
        if ([encrypted containsObject:channel]) return 1;
        known = [plain containsObject:channel];
        needState = !stateAt || -[stateAt timeIntervalSinceNow] > 15;
    }
    NSString *err = nil; NSInteger st = 0;
    if (!known) {
        id info = IS_SyncJSON(@"GET", [NSString stringWithFormat:@"%@/channels/%@", base, channel], token, nil, &st, &err);
        if (!info || st != 200 || ![info isKindOfClass:NSDictionary.class]) { IS_Log(@"e2ee send: couldn't read the channel (%@ %ld)", err ?: @"", (long)st); return -1; }
        int type = [info[@"type"] intValue];
        if (type == 1 || type == 3) { @synchronized (lock) { [encrypted addObject:channel]; } return 1; }
        @synchronized (lock) { [plain addObject:channel]; }
    }
    if (needState) {
        id state = IS_SyncJSON(@"GET", [base stringByAppendingString:@"/users/@me/e2ee"], token, nil, &st, &err);
        if (!state || st != 200 || ![state[@"channels"] isKindOfClass:NSArray.class]) { IS_Log(@"e2ee send: couldn't read the encryption state (%@ %ld)", err ?: @"", (long)st); return -1; }
        @synchronized (lock) {
            for (id c in state[@"channels"]) if ([c isKindOfClass:NSString.class]) [encrypted addObject:c];
            stateAt = [NSDate date];
            if ([encrypted containsObject:channel]) return 1;
        }
    }
    IS_E2eeMarkPlain(channel);
    return 0;
}

static NSString *IS_E2eeIneligible(NSDictionary *o) {
    if ([o[@"attachments"] isKindOfClass:NSArray.class] && [o[@"attachments"] count]) return @"Files can't be sent encrypted from this tweak yet.";
    if ([o[@"sticker_ids"] isKindOfClass:NSArray.class] && [o[@"sticker_ids"] count]) return @"Stickers can't be sent encrypted yet.";
    if (o[@"poll"] && o[@"poll"] != NSNull.null) return @"Polls can't be sent encrypted yet.";
    if ([o[@"components"] isKindOfClass:NSArray.class] && [o[@"components"] count]) return @"This kind of message can't be sent encrypted yet.";
    if ([o[@"tts"] boolValue]) return @"Text-to-speech messages can't be sent encrypted.";
    id ref = o[@"message_reference"];
    if ([ref isKindOfClass:NSDictionary.class] && [ref[@"type"] intValue] == 1) return @"Forwarded messages can't be sent encrypted yet.";
    NSString *c = o[@"content"];
    if (![c isKindOfClass:NSString.class] || ![[c stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] length]) return @"This kind of message can't be sent encrypted yet.";
    return nil;
}

static NSString *IS_E2eePin(NSString *uid) {
    NSDictionary *pins = IS_E2eeEntry()[@"pins"];
    return [pins isKindOfClass:NSDictionary.class] ? pins[uid] : nil;
}

static void IS_E2eeSetPin(NSString *uid, NSString *key) {
    NSMutableDictionary *pins = [([IS_E2eeEntry()[@"pins"] isKindOfClass:NSDictionary.class] ? IS_E2eeEntry()[@"pins"] : @{}) mutableCopy];
    pins[uid] = key;
    IS_E2eeMerge(gActive[@"id"], @{ @"pins": pins });
}

// Checks one user's published keys the way the web client does (identity pin, device signatures, prekey signatures,
// backup key signature) and appends what is safe to encrypt to. Returns a reason on failure, nil on success.
static NSString *IS_E2eeVerifyUser(NSString *uid, id keys, BOOL own, NSMutableArray *targets, NSMutableArray *backups) {
    if (![keys isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"user %@ has no encryption keys yet", uid];
    NSString *idkey = keys[@"identity_key"];
    if (![idkey isKindOfClass:NSString.class] || IS_B64uData(idkey).length != 32) return [NSString stringWithFormat:@"user %@ has no encryption identity yet", uid];
    NSDictionary *st = IS_E2eeEntry();
    NSString *pinned = own ? st[@"idpub"] : IS_E2eePin(uid);
    if (pinned && ![pinned isEqualToString:idkey]) {
        NSDictionary *prev = keys[@"previous_identity"];
        BOOL rotated = !own && [prev isKindOfClass:NSDictionary.class] && [prev[@"public_key"] isEqual:pinned] &&
                       IS_EdVerify(pinned, IS_RotationMsg(uid, pinned, idkey), prev[@"signature"]);
        if (!rotated) return own ? @"your encryption identity changed; unlock encrypted messages again"
                                 : [NSString stringWithFormat:@"the safety number of user %@ changed; check it in the web client first", uid];
    }
    if (!own && ![pinned isEqualToString:idkey]) IS_E2eeSetPin(uid, idkey);

    NSUInteger found = 0;
    NSArray *devices = [keys[@"devices"] isKindOfClass:NSArray.class] ? keys[@"devices"] : @[];
    for (id d in devices) {
        if (![d isKindOfClass:NSDictionary.class] || ![d[@"status"] isEqual:@"active"]) continue;
        NSString *did = d[@"device_id"], *sk = d[@"signing_key"];
        NSDictionary *pk = [d[@"prekey"] isKindOfClass:NSDictionary.class] ? d[@"prekey"] : nil;
        BOOL good = [did isKindOfClass:NSString.class] && [sk isKindOfClass:NSString.class] && pk && [pk[@"id"] isKindOfClass:NSNumber.class] &&
                    [did isEqualToString:IS_DeviceIdFor(sk) ?: @""] && IS_B64uData(pk[@"public_key"]).length == 32 &&
                    IS_EdVerify(idkey, IS_DeviceMsg(uid, did, sk), d[@"identity_signature"]) &&
                    IS_EdVerify(sk, IS_PrekeyMsg(did, [pk[@"id"] longLongValue], pk[@"public_key"]), pk[@"signature"]);
        if (!good) { IS_Log(@"e2ee send: ignoring a device of user %@ that failed verification", uid); continue; }
        [targets addObject:@{ @"user": uid, @"dev": did, @"pid": pk[@"id"], @"pub": IS_B64uData(pk[@"public_key"]) }];
        found++;
    }
    if (!found) return [NSString stringWithFormat:@"user %@ has no verified encryption devices", uid];

    NSDictionary *bk = [keys[@"backup_key"] isKindOfClass:NSDictionary.class] ? keys[@"backup_key"] : nil;
    if (bk && IS_B64uData(bk[@"public_key"]).length == 32 && IS_EdVerify(idkey, IS_BackupKeyMsg(uid, bk[@"public_key"]), bk[@"signature"]))
        [backups addObject:@{ @"user": uid, @"pub": IS_B64uData(bk[@"public_key"]) }];
    return nil;
}

// Builds the signed envelope for a new message. base is ".../api/v9". Returns nil and sets why on failure.
static NSDictionary *IS_E2eeBuildEnvelope(NSString *base, NSString *token, NSString *channel, NSString *nonce, NSString *text, BOOL fresh, NSString **why) {
    NSDictionary *st = IS_E2eeEntry();
    NSData *seed = IS_B64uData(st[@"dev_seed"]), *bsk = IS_B64uData(st[@"sk"]);
    NSString *uid = st[@"user"], *devId = st[@"dev_id"];
    if (!IS_E2eeCanSend() || seed.length != 32 || bsk.length != 32) { *why = @"Encrypted sending isn't set up. Unlock encrypted messages again."; return nil; }

    static NSMutableDictionary *dirCache; static NSObject *dirLock; static dispatch_once_t dirOnce;
    dispatch_once(&dirOnce, ^{ dirCache = [NSMutableDictionary dictionary]; dirLock = [NSObject new]; });
    NSString *err = nil; NSInteger code = 0;
    id res = nil;
    @synchronized (dirLock) {
        NSDictionary *hit = dirCache[channel];
        if (!fresh && hit && -[hit[@"at"] timeIntervalSinceNow] < 30) res = hit[@"res"];
    }
    if (!res) {
        res = IS_SyncJSON(@"POST", [base stringByAppendingString:@"/e2ee/keys/query"], token, @{ @"channel_id": channel }, &code, &err);
        if (!res || code != 200 || ![res[@"users"] isKindOfClass:NSDictionary.class] || ![res[@"channel_members"] isKindOfClass:NSArray.class]) {
            *why = [NSString stringWithFormat:@"Couldn't fetch the encryption keys (%@).", err ?: [NSString stringWithFormat:@"server answered %ld", (long)code]];
            return nil;
        }
        @synchronized (dirLock) { dirCache[channel] = @{ @"at": [NSDate date], @"res": res }; }
    }
    NSMutableArray *targets = [NSMutableArray array], *backups = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    BOOL sawMe = NO;
    for (id m in res[@"channel_members"]) {
        if (![m isKindOfClass:NSString.class] || [seen containsObject:m]) continue;
        [seen addObject:m];
        BOOL own = [m isEqualToString:uid];
        sawMe |= own;
        NSString *bad = IS_E2eeVerifyUser(m, res[@"users"][m], own, targets, backups);
        if (bad) { *why = [NSString stringWithFormat:@"Not sent: %@.", bad]; return nil; }
    }
    BOOL meListed = NO, backupListed = NO;
    for (NSDictionary *t in targets) if ([t[@"user"] isEqual:uid] && [t[@"dev"] isEqual:devId]) meListed = YES;
    for (NSDictionary *b in backups) if ([b[@"user"] isEqual:uid]) backupListed = YES;
    if (!sawMe || !meListed) { *why = @"This device isn't registered for encryption. Unlock encrypted messages again."; return nil; }
    if (!backupListed) {
        uint8_t pub[32];
        crypto_x25519_public_key(pub, bsk.bytes);
        [backups addObject:@{ @"user": uid, @"pub": [NSData dataWithBytes:pub length:32] }];
    }

    NSData *payload = [NSJSONSerialization dataWithJSONObject:@{ @"content": text } options:NSJSONWritingWithoutEscapingSlashes error:nil];
    if (!payload.length) { *why = @"Couldn't encode the message."; return nil; }
    is_env_target *tg = calloc(targets.count, sizeof(is_env_target));
    is_env_backup *bg = calloc(backups.count ?: 1, sizeof(is_env_backup));
    NSDictionary *envelope = nil;
    if (tg && bg) {
        for (NSUInteger i = 0; i < targets.count; i++) {
            NSDictionary *t = targets[i];
            tg[i].user_id = [t[@"user"] UTF8String];
            tg[i].device_id = [t[@"dev"] UTF8String];
            tg[i].prekey_id = [t[@"pid"] longLongValue];
            memcpy(tg[i].prekey_pub, [t[@"pub"] bytes], 32);
        }
        for (NSUInteger i = 0; i < backups.count; i++) {
            bg[i].user_id = [backups[i][@"user"] UTF8String];
            memcpy(bg[i].pub, [backups[i][@"pub"] bytes], 32);
        }
        char *json = is_e2ee_seal_envelope(channel.UTF8String, uid.UTF8String, devId.UTF8String, seed.bytes, nonce.UTF8String, NULL,
                                           payload.bytes, payload.length, tg, targets.count, bg, backups.count);
        if (json) {
            id parsed = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:json length:strlen(json)] options:0 error:nil];
            if ([parsed isKindOfClass:NSDictionary.class]) envelope = parsed;
            free(json);
        }
    }
    free(tg); free(bg);
    if (!envelope) *why = @"Couldn't encrypt the message.";
    return envelope;
}

// Registers this install as an encryption device (signed by your identity key from the backup).
// Returns the fields to store, or nil with err set.
static NSDictionary *IS_E2eeRegisterDevice(NSString *v9, NSString *token, NSString *uid, NSData *identitySeed, NSString *identityPub, NSString **err) {
    uint8_t dseed[32], dpub[32], psk[32], ppub[32];
    if (is_random(dseed, 32) != 0 || is_random(psk, 32) != 0) { *err = @"no randomness available"; return nil; }
    is_ed25519_public_key(dseed, dpub);
    crypto_x25519_public_key(ppub, psk);
    NSString *signing = IS_B64uString(dpub, 32), *ppubS = IS_B64uString(ppub, 32);
    NSString *did = IS_DeviceIdFor(signing);
    NSData *dseedData = [NSData dataWithBytes:dseed length:32];
    NSString *prekeySig = IS_EdSign(dseedData, IS_PrekeyMsg(did, 1, ppubS));
    NSString *identitySig = IS_EdSign(identitySeed, IS_DeviceMsg(uid, did, signing));
    NSInteger code = 0; NSString *e = nil;
    id res = IS_SyncJSON(@"POST", [v9 stringByAppendingString:@"/users/@me/e2ee/devices"], token, @{
        @"device_id": did, @"signing_key": signing, @"identity_signature": identitySig, @"name": @"Discord iOS (InstanceSwitcher)",
        @"prekey": @{ @"id": @1, @"public_key": ppubS, @"signature": prekeySig } }, &code, &e);
    if (!res || code != 200 || ![res[@"status"] isEqual:@"active"]) {
        *err = e ?: [NSString stringWithFormat:@"server answered %ld", (long)code];
        memset(dseed, 0, 32); memset(psk, 0, 32);
        return nil;
    }
    NSDictionary *out = @{ @"idpub": identityPub, @"dev_seed": IS_B64uString(dseed, 32), @"dev_id": did, @"pk_sk": IS_B64uString(psk, 32), @"pk_id": @1 };
    memset(dseed, 0, 32); memset(psk, 0, 32);
    return out;
}

#pragma mark - Unlock (read-only encryption)

static NSData *IS_OpenBox(NSData *key, NSString *box, NSString *aad) {
    NSData *raw = IS_B64uData(box);
    if (key.length != 32 || raw.length < 28) return nil;
    NSData *a = [aad dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *out = [NSMutableData dataWithLength:raw.length];
    int n = is_gcm_open(key.bytes, raw.bytes, a.bytes, a.length, (const uint8_t *)raw.bytes + 12, raw.length - 12, out.mutableBytes);
    if (n < 0) return nil;
    out.length = (NSUInteger)n;
    return out;
}

static NSString *IS_NormalizeRecovery(NSString *code) {
    NSMutableString *o = [NSMutableString string];
    for (NSUInteger i = 0; i < code.length; i++) {
        unichar ch = [code characterAtIndex:i];
        if (ch >= 'a' && ch <= 'z') ch -= 32;
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z'))) continue;
        if (ch == 'O') ch = '0';
        else if (ch == 'I' || ch == 'L') ch = '1';
        [o appendFormat:@"%C", ch];
    }
    return o;
}

static id IS_SyncGet(NSString *url, NSString *token, NSString **err) {
    NSURL *u = [NSURL URLWithString:url];
    if (!u) { *err = @"bad address"; return nil; }
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    [r setValue:token forHTTPHeaderField:@"Authorization"];
    r.timeoutInterval = 20;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block id result = nil;
    __block NSString *e = nil;
    [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *er) {
        NSHTTPURLResponse *h = [resp isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)resp : nil;
        if (er || !h) e = er.localizedDescription ?: @"no response";
        else if (h.statusCode != 200) e = [NSString stringWithFormat:@"server answered %ld", (long)h.statusCode];
        else {
            result = [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingFragmentsAllowed error:nil];
            if (!result) e = @"unreadable answer";
        }
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    if (e) *err = e;
    return result;
}

static NSString *gUnlockNote;

// Background work. Calls done(nil) on success or done(message) on failure.
static void IS_E2eeUnlock(NSString *input, void (^done)(NSString *err)) {
    NSString *iid = gActive[@"id"];
    NSString *token = nil;
    if (gTokLock) @synchronized (gTokLock) { token = gTok[iid]; }
    NSURLComponents *b = IS_Parse(gActive[@"api"], @"https");
    if (!token.length || !b) { done(@"Sign in on this instance first, then try again."); return; }
    NSString *base = b.string;
    while ([base hasSuffix:@"/"]) base = [base substringToIndex:base.length - 1];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *err = nil;
        id me = IS_SyncGet([base stringByAppendingString:@"/v9/users/@me"], token, &err);
        NSString *uid = [me isKindOfClass:NSDictionary.class] ? [me[@"id"] description] : nil;
        if (!uid.length) { done([NSString stringWithFormat:@"Couldn't read your account (%@).", err ?: @"unknown"]); return; }
        err = nil;
        id bk = IS_SyncGet([base stringByAppendingString:@"/v9/users/@me/e2ee/backup"], token, &err);
        if (err) { done([NSString stringWithFormat:@"Couldn't fetch your key backup (%@).", err]); return; }
        if (![bk isKindOfClass:NSDictionary.class]) { done(@"This account has no encryption key backup yet. Set one up on the web client first."); return; }

        NSDictionary *kdf = [bk[@"kdf"] isKindOfClass:NSDictionary.class] ? bk[@"kdf"] : @{};
        NSData *salt = IS_B64uData(bk[@"salt"]);
        if (!salt.length || ![bk[@"wrapped_secret"] isKindOfClass:NSString.class]) { done(@"The key backup has no password-protected secret."); return; }
        uint8_t key[32];
        if ([kdf[@"name"] isEqual:@"argon2id"]) {
            uint32_t mem = kdf[@"memory"] ? [kdf[@"memory"] unsignedIntValue] : 65536;
            uint32_t it = kdf[@"iterations"] ? [kdf[@"iterations"] unsignedIntValue] : 3;
            uint32_t par = kdf[@"parallelism"] ? [kdf[@"parallelism"] unsignedIntValue] : 1;
            if (mem < 8 || mem > 262144 || it < 1 || it > 10 || par < 1 || par > 4) { done(@"The backup's key settings are outside what this device will accept."); return; }
            NSData *pw = [input dataUsingEncoding:NSUTF8StringEncoding];
            if (is_argon2id(pw.bytes, pw.length, salt.bytes, salt.length, mem, it, par, key) != 0) { done(@"Not enough memory to unlock the backup."); return; }
        } else {
            NSData *norm = [IS_NormalizeRecovery(input) dataUsingEncoding:NSUTF8StringEncoding];
            const char *info = "fosscord-e2ee/v1/recovery-code";
            is_hkdf_sha256(norm.bytes, norm.length, salt.bytes, salt.length, (const uint8_t *)info, strlen(info), key, 32);
        }
        NSData *secret = IS_OpenBox([NSData dataWithBytes:key length:32], bk[@"wrapped_secret"],
                                    [@"fosscord-e2ee/v1/backup-secret\n" stringByAppendingString:uid]);
        memset(key, 0, sizeof key);
        if (secret.length != 32) { done(@"That password or recovery code didn't unlock the backup."); return; }

        uint8_t bkey[32];
        const char *binfo = "fosscord-e2ee/v1/backup/backup-key";
        is_hkdf_sha256(secret.bytes, 32, NULL, 0, (const uint8_t *)binfo, strlen(binfo), bkey, 32);
        NSData *jwkData = IS_OpenBox([NSData dataWithBytes:bkey length:32], bk[@"wrapped_backup_key"],
                                     [@"backup-key\n" stringByAppendingString:uid]);
        memset(bkey, 0, sizeof bkey);
        id jwk = jwkData ? [NSJSONSerialization JSONObjectWithData:jwkData options:0 error:nil] : nil;
        NSData *sk = [jwk isKindOfClass:NSDictionary.class] ? IS_B64uData(jwk[@"d"]) : nil;
        if (sk.length != 32 || ![jwk[@"crv"] isEqual:@"X25519"]) { done(@"The backup unlocked, but its message key couldn't be read."); return; }
        if ([bk[@"backup_public_key"] isKindOfClass:NSString.class] && ![bk[@"backup_public_key"] isEqual:jwk[@"x"]]) { done(@"The backup's key doesn't match its public key."); return; }

        NSString *oldDevice = IS_E2eeEntry()[@"dev_id"];
        IS_E2eeStore(iid, uid, jwk[@"d"]);
        IS_Log(@"encryption: backup key unlocked for %@", gActive[@"name"]);

        // Sending: open the identity key from the backup and register this install as a device signed by it.
        gUnlockNote = nil;
        uint8_t ikey[32];
        const char *iinfo = "fosscord-e2ee/v1/backup/identity";
        is_hkdf_sha256(secret.bytes, 32, NULL, 0, (const uint8_t *)iinfo, strlen(iinfo), ikey, 32);
        NSData *idData = IS_OpenBox([NSData dataWithBytes:ikey length:32], bk[@"wrapped_identity"], [@"identity\n" stringByAppendingString:uid]);
        memset(ikey, 0, sizeof ikey);
        id ijwk = idData ? [NSJSONSerialization JSONObjectWithData:idData options:0 error:nil] : nil;
        NSData *iseed = [ijwk isKindOfClass:NSDictionary.class] ? IS_B64uData(ijwk[@"d"]) : nil;
        NSString *ipub = [ijwk isKindOfClass:NSDictionary.class] ? ijwk[@"x"] : nil;
        uint8_t derived[32];
        BOOL idOk = iseed.length == 32 && [ijwk[@"crv"] isEqual:@"Ed25519"] && [ipub isKindOfClass:NSString.class] && [ipub isEqual:bk[@"identity_key"]];
        if (idOk) { is_ed25519_public_key(iseed.bytes, derived); idOk = [IS_B64uString(derived, 32) isEqualToString:ipub]; }
        if (!idOk) {
            gUnlockNote = @"Reading works, but sending encrypted messages isn't available: the identity key in your backup couldn't be read.";
            IS_Log(@"encryption: identity key in the backup unreadable; sending stays off");
            done(nil);
            return;
        }
        NSString *regErr = nil;
        NSString *v9 = [base stringByAppendingString:@"/v9"];
        id state = IS_SyncGet([v9 stringByAppendingString:@"/users/@me/e2ee"], token, &regErr);
        if (![state isKindOfClass:NSDictionary.class] || ![state[@"identity_key"] isEqual:ipub]) {
            gUnlockNote = @"Reading works, but sending isn't available: your backup doesn't match your current encryption identity.";
            IS_Log(@"encryption: backup identity differs from the account's current identity (%@)", regErr ?: @"mismatch");
            done(nil);
            return;
        }
        NSDictionary *fields = IS_E2eeRegisterDevice(v9, token, uid, iseed, ipub, &regErr);
        if (!fields) {
            gUnlockNote = [NSString stringWithFormat:@"Reading works, but this device couldn't be registered for sending (%@).", regErr];
            IS_Log(@"encryption: device registration failed: %@", regErr);
            done(nil);
            return;
        }
        IS_E2eeMerge(iid, fields);
        IS_Log(@"encryption: registered device %@, sending is on", fields[@"dev_id"]);
        if (oldDevice.length) {
            NSInteger dc = 0;
            IS_SyncJSON(@"DELETE", [NSString stringWithFormat:@"%@/users/@me/e2ee/devices/%@", v9, oldDevice], token, nil, &dc, nil);
            IS_Log(@"encryption: removed the previous device of this install (HTTP %ld)", (long)dc);
        }
        done(nil);
    });
}

static void IS_E2eeUnlockFlow(void) {
    NSString *token = nil;
    if (gActive && gTokLock) @synchronized (gTokLock) { token = gTok[gActive[@"id"]]; }
    if (!gActive) { IS_Alert(@"Encryption", @"Switch to your instance first. Unlocking only applies to a custom instance.", nil); return; }
    if (!token.length) { IS_Alert(@"Encryption", @"Sign in on this instance first, then try again.", nil); return; }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Unlock encrypted messages"
        message:@"Enter your account password, or your recovery code if your backup uses one. It is used once to unlock your key backup and is not saved."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.secureTextEntry = YES;
        t.placeholder = @"Password or recovery code";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone;
        t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"Unlock" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        NSString *pw = a.textFields[0].text;
        if (!pw.length) return;
        UIAlertController *prog = [UIAlertController alertControllerWithTitle:@"Unlocking…" message:@"This can take a few seconds." preferredStyle:UIAlertControllerStyleAlert];
        [IS_Top() presentViewController:prog animated:YES completion:nil];
        IS_E2eeUnlock(pw, ^(NSString *err) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [prog dismissViewControllerAnimated:YES completion:^{
                    if (err) IS_Alert(@"Couldn't unlock", err, nil);
                    else IS_Alert(@"Unlocked", [(gUnlockNote ?: @"Encrypted messages are now readable and you can send encrypted messages.") stringByAppendingString:@" Discord will close; reopen it to finish."], ^{ exit(0); });
                }];
            });
        });
    }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

static void IS_E2eeForgetFlow(void) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Forget encryption key?"
        message:@"Encrypted messages will show as locked again on this device. Your account and backup are not affected."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"Forget key" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        NSString *iid = gActive[@"id"], *dev = IS_E2eeEntry()[@"dev_id"], *token = nil;
        if (gTokLock) @synchronized (gTokLock) { token = gTok[iid]; }
        NSURLComponents *b = IS_Parse(gActive[@"api"], @"https");
        NSString *api = b.string;
        while ([api hasSuffix:@"/"]) api = [api substringToIndex:api.length - 1];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            if (dev.length && token.length && api.length) {
                NSInteger dc = 0;
                IS_SyncJSON(@"DELETE", [NSString stringWithFormat:@"%@/v9/users/@me/e2ee/devices/%@", api, dev], token, nil, &dc, nil);
                IS_Log(@"encryption: removed this device from the account (HTTP %ld)", (long)dc);
            }
            IS_E2eeForget(iid);
            dispatch_async(dispatch_get_main_queue(), ^{
                IS_Alert(@"Key removed", @"Discord will close. Reopen it to finish.", ^{ exit(0); });
            });
        });
    }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

static void IS_ToggleSetting(NSString *key, BOOL value) {
    [NSUserDefaults.standardUserDefaults setBool:value forKey:key];
    [NSUserDefaults.standardUserDefaults synchronize];
    IS_Alert(@"Setting changed", @"Discord will close. Reopen it for this to apply.", ^{ exit(0); });
}

static void IS_ShowMore(void) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"More" message:nil
                                                        preferredStyle:UIAlertControllerStyleAlert];
    if ([IS_State()[@"instances"] count] > 1)
        [a addAction:[UIAlertAction actionWithTitle:@"Remove instance…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) { IS_RemoveMenu(); }]];
    NSString *t1 = [@"Skip verification lock: " stringByAppendingString:IS_SpoofOn() ? @"ON" : @"OFF"];
    [a addAction:[UIAlertAction actionWithTitle:t1 style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        IS_ToggleSetting(@"InstanceSwitcher.spoofVerified", !IS_SpoofOn());
    }]];
    NSString *t2 = [@"Fake phone number: " stringByAppendingString:IS_SpoofPhone() ? @"ON" : @"OFF"];
    [a addAction:[UIAlertAction actionWithTitle:t2 style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        IS_ToggleSetting(@"InstanceSwitcher.spoofPhone", !IS_SpoofPhone());
    }]];
    if (gActive) {
        BOOL on = IS_E2eeActive(), send = IS_E2eeCanSend();
        NSString *title = !on ? @"Unlock encrypted messages…" : (send ? @"Encrypted messages: unlocked (sending on)" : @"Encrypted messages: read-only. Unlock again to send…");
        [a addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
            if (on && send) IS_E2eeForgetFlow(); else IS_E2eeUnlockFlow();
        }]];
    }
    [a addAction:[UIAlertAction actionWithTitle:@"Debug log…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) { IS_ShowLog(); }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Back" style:UIAlertActionStyleCancel handler:^(UIAlertAction *x) { IS_ShowMenu(); }]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

static void IS_ShowMenu(void) {
    NSDictionary *st = IS_State();
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Instance Switcher"
        message:@"Switching closes Discord. Reopen it afterwards."
        preferredStyle:UIAlertControllerStyleAlert];
    for (NSDictionary *i in st[@"instances"]) {
        BOOL on = [i[@"id"] isEqual:st[@"active"]];
        NSString *title = [(on ? @"✓ " : @"") stringByAppendingString:i[@"name"]];
        [a addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
            if (!on) IS_Switch(i[@"id"]);
        }]];
    }
    [a addAction:[UIAlertAction actionWithTitle:@"Add instance…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) { IS_AddFlow(); }]];
    [a addAction:[UIAlertAction actionWithTitle:@"More…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) { IS_ShowMore(); }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleCancel handler:nil]];
    [IS_Top() presentViewController:a animated:YES completion:nil];
}

@interface ISGestureTarget : NSObject
+ (instancetype)shared;
- (void)pressed:(UILongPressGestureRecognizer *)g;
@end

@implementation ISGestureTarget
+ (instancetype)shared {
    static ISGestureTarget *t; static dispatch_once_t o;
    dispatch_once(&o, ^{ t = [ISGestureTarget new]; });
    return t;
}
- (void)pressed:(UILongPressGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateBegan && !IS_Top().presentedViewController) IS_ShowMenu();
}
@end

static const void *kInstalledKey = &kInstalledKey;

static void IS_InstallGesture(void) {
    for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
        if (![sc isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if (objc_getAssociatedObject(w, kInstalledKey)) continue;
            UILongPressGestureRecognizer *g = [[UILongPressGestureRecognizer alloc]
                initWithTarget:ISGestureTarget.shared action:@selector(pressed:)];
            g.numberOfTouchesRequired = 3;
            g.minimumPressDuration = 0.7;
            g.cancelsTouchesInView = NO;
            [w addGestureRecognizer:g];
            objc_setAssociatedObject(w, kInstalledKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    }
}

#pragma mark - Crash recorder / auto-revert

static char gCrashPath[1024];
static time_t gStart;
static struct sigaction gPrevSA[32];
static NSUncaughtExceptionHandler *gPrevEx;
static const int kSigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT, SIGFPE };

static void IS_AppendCrash(const char *buf, size_t len) {
    int fd = open(gCrashPath, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    write(fd, buf, len);
    close(fd);
}

static void IS_SigHandler(int sig) {
    if (time(NULL) - gStart < 45) {            // only startup crashes count
        char hdr[48];
        int n = snprintf(hdr, sizeof hdr, "SIGNAL %d\n", sig);
        IS_AppendCrash(hdr, (size_t)n);
        void *frames[40];
        int c = backtrace(frames, 40);
        int fd = open(gCrashPath, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) { backtrace_symbols_fd(frames, c, fd); close(fd); }
    }
    sigaction(sig, &gPrevSA[sig], NULL);       // restore the previous handler; returning re-raises the signal
}

static void IS_ExHandler(NSException *e) {
    if (time(NULL) - gStart < 45) {
        NSString *t = [NSString stringWithFormat:@"EXCEPTION %@: %@\n%@\n", e.name, e.reason,
                       [e.callStackSymbols componentsJoinedByString:@"\n"]];
        const char *u = t.UTF8String;
        if (u) IS_AppendCrash(u, strlen(u));
    }
    if (gPrevEx) gPrevEx(e);
}

static void IS_InstallCrashHandlers(void) {
    for (size_t i = 0; i < sizeof kSigs / sizeof kSigs[0]; i++) {
        int sig = kSigs[i];
        struct sigaction cur;
        if (sigaction(sig, NULL, &cur) != 0) continue;
        if (cur.sa_handler == IS_SigHandler) continue;
        gPrevSA[sig] = cur;
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = IS_SigHandler;
        sigemptyset(&sa.sa_mask);
        sigaction(sig, &sa, NULL);
    }
    NSUncaughtExceptionHandler *h = NSGetUncaughtExceptionHandler();
    if (h != IS_ExHandler) { gPrevEx = h; NSSetUncaughtExceptionHandler(IS_ExHandler); }
}

// Runs first on launch. If the previous run crashed early on a custom instance, fall back to stock Discord.
static void IS_CrashCheck(void) {
    gStart = time(NULL);
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject ?: NSTemporaryDirectory();
    NSString *path = [dir stringByAppendingPathComponent:@"InstanceSwitcher-crash.txt"];
    strlcpy(gCrashPath, path.fileSystemRepresentation, sizeof gCrashPath);
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (data.length) {
        NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"(unreadable)";
        [d setObject:txt forKey:@"InstanceSwitcher.lastCrash"];
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
        NSDictionary *st = IS_State();
        NSString *aid = st[@"active"];
        if (![aid isEqual:@"discord"]) {
            NSString *nm = @"the instance";
            for (NSDictionary *i in st[@"instances"]) if ([i[@"id"] isEqual:aid]) nm = i[@"name"];
            NSMutableDictionary *ns = [st mutableCopy];
            ns[@"active"] = @"discord";
            IS_Save(ns);
            [d setObject:nm forKey:@"InstanceSwitcher.notice"];
        }
        [d synchronize];
    }
    NSString *last = [d stringForKey:@"InstanceSwitcher.lastCrash"];
    if (last.length) {
        IS_Log(@"--- last startup crash (saved) ---");
        int n = 0;
        for (NSString *l in [last componentsSeparatedByString:@"\n"]) {
            if (!l.length) continue;
            IS_Log(@"CRASH> %@", l.length > 110 ? [l substringToIndex:110] : l);
            if (++n >= 45) break;
        }
        IS_Log(@"--- end crash ---");
    }
}

#pragma mark - SVG -> PNG for instance images

// The instance serves some images (badge icons, server-tag badges) as SVG behind .png URLs. Browsers draw
// those, the iOS app cannot, so convert them to PNG here using the system's own SVG renderer (CoreSVG).
typedef void *(*IS_SVGCreateFn)(CFDataRef, CFDictionaryRef);
typedef void (*IS_SVGReleaseFn)(void *);
typedef CGSize (*IS_SVGSizeFn)(void *);
typedef void (*IS_SVGDrawFn)(CGContextRef, void *);

static NSData *IS_SVGToPNG(NSData *svg, CGFloat targetW) {
    static IS_SVGCreateFn create; static IS_SVGReleaseFn rel; static IS_SVGSizeFn sz; static IS_SVGDrawFn draw;
    static dispatch_once_t o;
    dispatch_once(&o, ^{
        void *h = dlopen("/System/Library/PrivateFrameworks/CoreSVG.framework/CoreSVG", RTLD_LAZY);
        void *src = h ?: RTLD_DEFAULT;
        create = (IS_SVGCreateFn)dlsym(src, "CGSVGDocumentCreateFromData");
        rel    = (IS_SVGReleaseFn)dlsym(src, "CGSVGDocumentRelease");
        sz     = (IS_SVGSizeFn)dlsym(src, "CGSVGDocumentGetCanvasSize");
        draw   = (IS_SVGDrawFn)dlsym(src, "CGContextDrawSVGDocument");
        if (!create || !rel || !sz || !draw) IS_Log(@"CoreSVG symbols missing (create=%d release=%d size=%d draw=%d)", create != NULL, rel != NULL, sz != NULL, draw != NULL);
    });
    if (!create || !rel || !sz || !draw || !svg.length) return nil;
    void *doc = create((__bridge CFDataRef)svg, NULL);
    if (!doc) return nil;
    CGSize cs = sz(doc);
    if (cs.width < 1 || cs.height < 1) cs = CGSizeMake(100, 100);
    CGFloat scale = targetW / cs.width;
    CGSize out = CGSizeMake(round(targetW), MIN(1024, MAX(1, round(cs.height * scale))));
    UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
    fmt.scale = 1;
    fmt.opaque = NO;
    UIGraphicsImageRenderer *rr = [[UIGraphicsImageRenderer alloc] initWithSize:out format:fmt];
    NSData *png = [rr PNGDataWithActions:^(UIGraphicsImageRendererContext *ctx) {
        CGContextRef c = ctx.CGContext;
        CGContextTranslateCTM(c, 0, out.height);
        CGContextScaleCTM(c, scale, -scale);
        draw(c, doc);
    }];
    rel(doc);
    return png;
}

static BOOL IS_LooksSVG(NSData *d) {
    NSUInteger n = MIN(d.length, (NSUInteger)600);
    NSString *h = [[NSString alloc] initWithBytes:d.bytes length:n encoding:NSISOLatin1StringEncoding] ?: @"";
    return [h rangeOfString:@"<svg"].location != NSNotFound;
}

static NSCache *IS_ImgCache(void) {
    static NSCache *c; static dispatch_once_t o;
    dispatch_once(&o, ^{ c = [NSCache new]; c.countLimit = 300; });
    return c;
}

static NSString *const kISHandled = @"InstanceSwitcher.handled";

@interface ISImageProtocol : NSURLProtocol
@property (nonatomic, strong) NSURLSessionDataTask *task;
@end

@implementation ISImageProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSDictionary *cur = gActive;
    if (!cur) return NO;
    BOOL post = [request.HTTPMethod isEqualToString:@"POST"];
    if (!post && ![request.HTTPMethod isEqualToString:@"GET"]) return NO;
    if ([NSURLProtocol propertyForKey:kISHandled inRequest:request]) return NO;
    NSURL *u = request.URL;
    NSString *host = u.host.lowercaseString;
    NSURLComponents *b = IS_Parse(cur[@"api"], @"https");
    if (!host.length || !b || ![host isEqualToString:b.host.lowercaseString]) return NO;
    NSString *p = u.path ?: @"";
    if (post) {     // outgoing messages (and file upload slots) in a channel: sealed here when the channel is encrypted
        if (!IS_E2eeCanSend()) return NO;
        if ([[request valueForHTTPHeaderField:@"Content-Type"].lowercaseString containsString:@"multipart"]) return NO;
        if ([p rangeOfString:@"^/api/v[0-9]+/channels/[0-9]+/(messages|attachments)$" options:NSRegularExpressionSearch].location == NSNotFound) return NO;
        NSArray *seg = [p componentsSeparatedByString:@"/"];
        return !IS_E2eeKnownPlain(seg.count > 4 ? seg[4] : @"");
    }
    if ([p hasPrefix:@"/e2ee/attachments/"]) return YES;
    if ([p hasPrefix:@"/api/"] && ([p containsString:@"/messages"] || [p hasSuffix:@"/pins"])) return YES;
    if ([p hasSuffix:@".svg"]) return YES;
    for (NSString *pre in @[ @"/badge-icons/", @"/clan-badges/", @"/guild-tag-badges/", @"/role-icons/", @"/avatar-decoration-presets/" ])
        if ([p hasPrefix:pre]) return YES;
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

+ (NSURLSession *)innerSession {
    static NSURLSession *s; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 30;
        s = [NSURLSession sessionWithConfiguration:cfg];
    });
    return s;
}

// Hand the app a response whose headers match the (already decoded) body we give it.
- (void)relayStatus:(NSInteger)status headers:(NSDictionary *)hdr body:(NSData *)body type:(NSString *)ct {
    NSMutableDictionary *h = [NSMutableDictionary dictionary];
    for (id k in hdr) {
        NSString *ks = [k description];
        NSString *lk = ks.lowercaseString;
        if ([lk isEqualToString:@"content-encoding"] || [lk isEqualToString:@"content-length"] || [lk isEqualToString:@"transfer-encoding"]) continue;
        h[ks] = hdr[k];
    }
    if (ct) h[@"Content-Type"] = ct;
    h[@"Content-Length"] = @(body.length).stringValue;
    NSHTTPURLResponse *nr = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:h];
    [self.client URLProtocol:self didReceiveResponse:nr cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (body.length) [self.client URLProtocol:self didLoadData:body];
    [self.client URLProtocolDidFinishLoading:self];
}

static NSData *IS_ReadStream(NSInputStream *in) {
    if (!in) return nil;
    NSMutableData *out = [NSMutableData data];
    [in open];
    uint8_t buf[8192];
    NSInteger n;
    while ((n = [in read:buf maxLength:sizeof buf]) > 0) {
        [out appendBytes:buf length:(NSUInteger)n];
        if (out.length > 4u * 1024 * 1024) break;
    }
    [in close];
    return out;
}

- (void)failSend:(NSString *)why {
    IS_Log(@"e2ee send: %@", why);
    NSData *body = [NSJSONSerialization dataWithJSONObject:@{ @"code": @0, @"message": why } options:0 error:nil] ?: [NSData data];
    [self relayStatus:400 headers:@{} body:body type:@"application/json"];
}

- (NSData *)syncSend:(NSURLRequest *)r response:(NSHTTPURLResponse **)resp error:(NSError **)err {
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSData *data = nil; __block NSHTTPURLResponse *h = nil; __block NSError *e = nil;
    [[[ISImageProtocol innerSession] dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *rs, NSError *er) {
        data = d; e = er; h = [rs isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)rs : nil;
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    if (resp) *resp = h;
    if (err) *err = e;
    return data;
}

// Hands the server's answer back to the app. Message bodies are decrypted on the way (our own sealed messages included).
- (void)relaySend:(NSData *)data response:(NSHTTPURLResponse *)h error:(NSError *)err {
    if (err || !h) { [self.client URLProtocol:self didFailWithError:err ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]]; return; }
    NSString *ct = [[h valueForHTTPHeaderField:@"Content-Type"] lowercaseString] ?: @"";
    if (h.statusCode == 200 && data.length && [ct containsString:@"json"]) {
        NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (t) {
            NSString *rw = IS_RewriteInviteLinks(IS_E2eeProcess(t));
            if (![rw isEqualToString:t]) data = [rw dataUsingEncoding:NSUTF8StringEncoding];
        }
    }
    [self relayStatus:h.statusCode headers:h.allHeaderFields body:data ?: [NSData data] type:nil];
}

- (NSMutableURLRequest *)sendRequestWithBody:(NSData *)body {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kISHandled inRequest:r];
    r.HTTPBodyStream = nil;
    r.HTTPBody = body;
    [r setValue:@(body.length).stringValue forHTTPHeaderField:@"Content-Length"];
    return r;
}

// POST /channels/<id>/messages and /attachments. Nothing in an encrypted channel is ever sent as plain text:
// if the channel can't be classified, the message can't be sealed or the content isn't supported, the send fails here.
- (void)sendMessage {
    NSURLRequest *req = self.request;
    NSData *body = req.HTTPBody ?: IS_ReadStream(req.HTTPBodyStream);
    NSString *token = [req valueForHTTPHeaderField:@"Authorization"];
    NSString *path = req.URL.path ?: @"";
    NSRange rg = [path rangeOfString:@"/channels/"];
    NSString *prefix = [path substringToIndex:rg.location];
    NSArray *tail = [[path substringFromIndex:NSMaxRange(rg)] componentsSeparatedByString:@"/"];
    NSString *channel = tail.firstObject;
    BOOL isMessages = [tail.lastObject isEqualToString:@"messages"];
    NSURLComponents *oc = [NSURLComponents componentsWithURL:req.URL resolvingAgainstBaseURL:NO];
    oc.path = prefix; oc.query = nil; oc.fragment = nil;
    NSString *base = oc.string;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try {
            if (!token.length) { [self sendUnchanged:body]; return; }
            int enc = IS_E2eeIsEncrypted(base, token, channel);
            if (enc < 0) { [self failSend:@"Couldn't tell whether this conversation is encrypted, so the message was not sent."]; return; }
            if (enc == 0) { [self sendUnchanged:body]; return; }
            if (!isMessages) { [self failSend:@"Files can't be sent encrypted from this tweak yet."]; return; }

            id parsed = body.length ? [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingMutableContainers error:nil] : nil;
            if (![parsed isKindOfClass:NSMutableDictionary.class]) { [self failSend:@"This kind of message can't be sent encrypted yet."]; return; }
            NSMutableDictionary *obj = parsed;
            NSString *no = IS_E2eeIneligible(obj);
            if (no) { [self failSend:no]; return; }
            id nv = obj[@"nonce"];
            NSString *nonce = [nv isKindOfClass:NSString.class] ? nv : ([nv isKindOfClass:NSNumber.class] ? [nv stringValue] : nil);
            if (!nonce.length) nonce = [NSString stringWithFormat:@"%lld%03u", (long long)([NSDate date].timeIntervalSince1970 * 1000), arc4random_uniform(1000)];

            for (int attempt = 0; attempt < 2; attempt++) {
                NSString *why = nil;
                NSDictionary *env = IS_E2eeBuildEnvelope(base, token, channel, nonce, obj[@"content"], attempt > 0, &why);
                if (!env) { [self failSend:why ?: @"Couldn't encrypt the message."]; return; }
                NSMutableDictionary *out = [obj mutableCopy];
                out[@"encrypted"] = env;
                out[@"content"] = kE2eeFallbackText;
                out[@"nonce"] = nonce;
                NSData *data = [NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:nil];
                if (!data.length) { [self failSend:@"Couldn't encode the message."]; return; }
                NSHTTPURLResponse *h = nil; NSError *er = nil;
                NSData *rd = [self syncSend:[self sendRequestWithBody:data] response:&h error:&er];
                if (h.statusCode == 409 && attempt == 0) { IS_Log(@"e2ee send: the member devices changed, retrying with fresh keys"); continue; }
                if (h.statusCode == 200) IS_LogOnce(@"e2ee:sent", @"sent an encrypted message");
                else if (h) IS_Log(@"e2ee send: server answered %ld", (long)h.statusCode);
                [self relaySend:rd response:h error:er];
                return;
            }
        } @catch (NSException *e) {
            [self failSend:[NSString stringWithFormat:@"Unexpected error (%@). The message was not sent.", e.reason]];
        }
    });
}

- (void)sendUnchanged:(NSData *)body {
    NSHTTPURLResponse *h = nil; NSError *er = nil;
    NSData *rd = [self syncSend:[self sendRequestWithBody:body ?: [NSData data]] response:&h error:&er];
    [self relaySend:rd response:h error:er];
}

- (void)startLoading {
    if ([self.request.HTTPMethod isEqualToString:@"POST"]) { [self sendMessage]; return; }
    NSURL *url = self.request.URL;
    NSString *key = url.absoluteString;
    NSString *path = url.path ?: @"";
    if ([path hasPrefix:@"/e2ee/attachments/"]) { [self loadE2eeFile]; return; }
    BOOL isApi = [path hasPrefix:@"/api/"];
    NSData *hit = isApi ? nil : [IS_ImgCache() objectForKey:key];
    if (hit) { [self relayStatus:200 headers:@{ @"Cache-Control": @"max-age=86400" } body:hit type:@"image/png"]; return; }

    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kISHandled inRequest:r];
    self.task = [[ISImageProtocol innerSession] dataTaskWithRequest:r completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { [self.client URLProtocol:self didFailWithError:err]; return; }
        if (![resp isKindOfClass:NSHTTPURLResponse.class]) {
            [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]];
            return;
        }
        NSHTTPURLResponse *h = (NSHTTPURLResponse *)resp;
        NSString *ct = [[h valueForHTTPHeaderField:@"Content-Type"] lowercaseString] ?: @"";

        if (isApi) {   // message history: make instance invite links recognisable
            if (h.statusCode == 200 && data.length && [ct containsString:@"json"]) {
                NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (t) {
                    NSString *rw = IS_RewriteInviteLinks(IS_E2eeProcess(t));
                    if (![rw isEqualToString:t]) data = [rw dataUsingEncoding:NSUTF8StringEncoding];
                }
            }
            [self relayStatus:h.statusCode headers:h.allHeaderFields body:data ?: [NSData data] type:nil];
            return;
        }

        if (h.statusCode == 200 && data.length && ([ct containsString:@"svg"] || IS_LooksSVG(data))) {
            CGFloat w = 128;
            for (NSURLQueryItem *qi in [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO].queryItems)
                if ([qi.name isEqualToString:@"size"] && qi.value.intValue > 0) w = qi.value.intValue * 2;
            w = MIN(512, MAX(64, w));
            NSData *png = IS_SVGToPNG(data, w);
            if (png) {
                [IS_ImgCache() setObject:png forKey:key];
                IS_LogOnce(@"svgok", [@"converted SVG to PNG: " stringByAppendingString:path]);
                [self relayStatus:200 headers:@{ @"Cache-Control": @"max-age=86400" } body:png type:@"image/png"];
                return;
            }
            IS_LogOnce(@"svgfail", [@"SVG to PNG conversion failed for " stringByAppendingString:path]);
        }
        [self relayStatus:h.statusCode headers:h.allHeaderFields body:data ?: [NSData data] type:nil];
    }];
    [self.task resume];
}

- (void)serveFile:(NSData *)plain entry:(NSDictionary *)e {
    NSDictionary *st = IS_ServedType(e[@"content_type"]);
    NSString *range = [self.request valueForHTTPHeaderField:@"Range"];
    long long total = (long long)plain.length;
    NSMutableDictionary *h = [@{ @"Accept-Ranges": @"bytes", @"Cache-Control": @"private, max-age=3600" } mutableCopy];
    if ([range hasPrefix:@"bytes="] && total > 0) {
        NSString *spec = [[range substringFromIndex:6] componentsSeparatedByString:@","].firstObject;
        NSArray *ab = [spec componentsSeparatedByString:@"-"];
        long long a = -1, b = -1;
        if (ab.count == 2) {
            if ([ab[0] length]) a = [ab[0] longLongValue];
            if ([ab[1] length]) b = [ab[1] longLongValue];
        }
        if (a < 0 && b > 0) { a = MAX(0LL, total - b); b = total - 1; }          // suffix range
        else if (b < 0 || b >= total) b = total - 1;
        if (a >= 0 && a <= b && a < total) {
            h[@"Content-Range"] = [NSString stringWithFormat:@"bytes %lld-%lld/%lld", a, b, total];
            [self relayStatus:206 headers:h body:[plain subdataWithRange:NSMakeRange((NSUInteger)a, (NSUInteger)(b - a + 1))] type:st[@"type"]];
            return;
        }
        h[@"Content-Range"] = [NSString stringWithFormat:@"bytes */%lld", total];
        [self relayStatus:416 headers:h body:[NSData data] type:@"text/plain"];
        return;
    }
    if (![st[@"inline"] boolValue]) h[@"Content-Disposition"] = @"attachment";
    [self relayStatus:200 headers:h body:plain type:st[@"type"]];
}

// Encrypted attachment: fetch the ciphertext from the instance, decrypt it here, serve the real file.
- (void)loadE2eeFile {
    NSString *p = self.request.URL.path;
    NSDictionary *e = nil;
    if (gE2eeFiles) @synchronized (gE2eeFiles) { e = gE2eeFiles[p]; }
    if (!e) { [self relayStatus:404 headers:@{} body:[NSData data] type:@"text/plain"]; return; }
    NSData *hit = [IS_FileCache() objectForKey:p];
    if (hit) { [self serveFile:hit entry:e]; return; }
    NSURL *u = [NSURL URLWithString:e[@"url"]];
    if (!u) { [self relayStatus:502 headers:@{} body:[NSData data] type:@"text/plain"]; return; }
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    [NSURLProtocol setProperty:@YES forKey:kISHandled inRequest:r];
    self.task = [[ISImageProtocol innerSession] dataTaskWithRequest:r completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSHTTPURLResponse *h = [resp isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)resp : nil;
        if (err || !h || h.statusCode != 200 || !data.length || data.length > 150u * 1024 * 1024) {
            IS_Log(@"e2ee file: download failed (%@)", err ? err.localizedDescription : [NSString stringWithFormat:@"HTTP %ld", (long)h.statusCode]);
            [self relayStatus:502 headers:@{} body:[NSData data] type:@"text/plain"];
            return;
        }
        NSData *plain = IS_E2eeDecryptFile(data, IS_B64uData(e[@"key"]), IS_B64uData(e[@"iv"]));
        if (!plain) {
            IS_Log(@"e2ee file: decryption failed");
            [self relayStatus:502 headers:@{} body:[NSData data] type:@"text/plain"];
            return;
        }
        [IS_FileCache() setObject:plain forKey:p cost:plain.length];
        IS_LogOnce(@"e2ee:file", @"decrypted an encrypted attachment");
        [self serveFile:plain entry:e];
    }];
    [self.task resume];
}

- (void)stopLoading { [self.task cancel]; self.task = nil; }

@end

// Make every URLSession configuration (including the app's own) consult our protocol first.
static void IS_HookConfig(Class cls) {
    SEL sel = @selector(protocolClasses);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp_implementationWithBlock(^id(id s) {
        NSArray *base = ((id (*)(id, SEL))orig)(s, sel);
        for (id c in base) if (c == (id)ISImageProtocol.class) return base;
        return [@[ ISImageProtocol.class ] arrayByAddingObjectsFromArray:base ?: @[]];
    }), method_getTypeEncoding(m));
}

#pragma mark - Entry point

__attribute__((constructor))
static void IS_Init(void) {
    @autoreleasepool {
        IS_CrashCheck();
        IS_InstallCrashHandlers();
        IS_LoadActive();
        IS_TokLoad();
        IS_E2eeLoad();

        // Always on: REST + websocket hooks so each instance keeps its own saved login.
        IS_HookSession(NSURLSession.class);
        Class concrete = NSURLSession.sharedSession.class;
        if (concrete != NSURLSession.class) IS_HookSession(concrete);
        IS_HookWebSocketClasses();

        if (gActive) {
            // Only while a custom instance is active: URL rewriting everywhere else.
            IS_HookReqInit(NSURLRequest.class);
            IS_HookSetURL(NSMutableURLRequest.class);
            IS_HookSocketRocket(NSClassFromString(@"SRWebSocket"));
            IS_HookSocketRocket(NSClassFromString(@"RCTSRWebSocket"));
            IS_HookNSURL();
            [NSURLProtocol registerClass:ISImageProtocol.class];
            IS_HookConfig(NSURLSessionConfiguration.class);
            IS_HookConfig([NSURLSessionConfiguration defaultSessionConfiguration].class);
            IS_HookConfig([NSURLSessionConfiguration ephemeralSessionConfiguration].class);
            IS_Log(@"active: %@  api=%@ gateway=%@", gActive[@"name"], gActive[@"api"], gActive[@"gateway"]);
        } else {
            IS_Log(@"stock Discord mode (login tracking only)");
        }

        // The switcher UI is always available so you can get back to Discord.
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
            object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    IS_InstallGesture();
                    IS_InstallCrashHandlers();   // re-chain in case the app replaced our handlers
                    NSString *notice = [NSUserDefaults.standardUserDefaults stringForKey:@"InstanceSwitcher.notice"];
                    if (notice.length) {
                        [NSUserDefaults.standardUserDefaults removeObjectForKey:@"InstanceSwitcher.notice"];
                        IS_Alert(@"Switched back to Discord",
                                 [NSString stringWithFormat:@"Discord crashed at startup while using %@, so Instance Switcher went back to stock Discord. Open the menu (three-finger long press) > Debug log to copy the crash details.", notice], nil);
                    }
                    static dispatch_once_t late;
                    dispatch_once(&late, ^{ IS_HookWebSocketClasses(); });  // classes loaded after launch
                });
            }];
    }
}

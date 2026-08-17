#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <Security/Security.h>
#import <CoreMotion/CoreMotion.h>
#import <objc/runtime.h>

#define DEFAULT_REAL_PIN @"8888"
#define DEFAULT_DECOY_PIN @"0000"
#define KEY_REAL_PIN @"com.sec.real_pin"
#define KEY_DECOY_PIN @"com.sec.decoy_pin"
#define INACTIVITY_TIMEOUT 60.0
#define MAX_FAILED_ATTEMPTS 3

// MARK: - Controller điều khiển màn hình ngụy trang
@interface DisguiseWindowController : NSObject
+ (instancetype)sharedInstance;
@property (nonatomic, strong) UIWindow *fakeWindow;
@property (nonatomic, assign) BOOL isUnlocked;
- (void)presentDisguise;
@end

// MARK: - Helper lấy Window
static UIWindow *getAppKeyWindow(void) {
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) if (w.isKeyWindow) return w;
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
}

// MARK: - 1. Chốt chặn triệt để: Hook UIWindow setHidden
@implementation UIWindow (SecurityEnforcer)
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [UIWindow class];
        Method orig = class_getInstanceMethod(cls, @selector(setHidden:));
        Method swiz = class_getInstanceMethod(cls, @selector(sec_setHidden:));
        method_exchangeImplementations(orig, swiz);
    });
}
- (void)sec_setHidden:(BOOL)hidden {
    if (![DisguiseWindowController sharedInstance].isUnlocked && self != [DisguiseWindowController sharedInstance].fakeWindow) {
        [self sec_setHidden:YES];
    } else {
        [self sec_setHidden:hidden];
    }
}
@end

// MARK: - 2. Chốt chặn gốc: Hook UIApplication setDelegate
@implementation UIApplication (Security)
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [UIApplication class];
        Method orig = class_getInstanceMethod(cls, @selector(setDelegate:));
        Method swiz = class_getInstanceMethod(cls, @selector(sec_setDelegate:));
        method_exchangeImplementations(orig, swiz);
    });
}
- (void)sec_setDelegate:(id<UIApplicationDelegate>)delegate {
    [self sec_setDelegate:delegate];
    [[DisguiseWindowController sharedInstance] presentDisguise];
}
@end

// MARK: - 3. Implementation DisguiseWindowController
@implementation DisguiseWindowController
+ (instancetype)sharedInstance {
    static DisguiseWindowController *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ 
        inst = [[DisguiseWindowController alloc] init];
        inst.isUnlocked = NO;
    });
    return inst;
}
- (void)presentDisguise {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.fakeWindow) {
            self.fakeWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            self.fakeWindow.backgroundColor = [UIColor blackColor];
            self.fakeWindow.windowLevel = CGFLOAT_MAX;
            // Ở đây bạn có thể load FakeWeatherViewController của bạn vào
            [self.fakeWindow makeKeyAndVisible];
        }
        self.fakeWindow.hidden = NO;
    });
}
@end

// MARK: - 4. Lưu trữ Keychain (PINStore)
@interface PINStore : NSObject
+ (NSString *)getRealPIN;
+ (void)setRealPIN:(NSString *)pin;
+ (NSString *)getDecoyPIN;
+ (void)setDecoyPIN:(NSString *)pin;
@end

@implementation PINStore
// ... (Giữ nguyên code PINStore của bạn) ...
@end

// MARK: - 5. Các logic khác (InactivityManager, SecurityGuard...)
// ... (Bạn giữ nguyên phần SecurityGuard, InactivityManager, FakeWeatherViewController ở dưới đây) ...

__attribute__((constructor))
static void initFullSecuritySystem(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [[DisguiseWindowController sharedInstance] presentDisguise];
    }];
}

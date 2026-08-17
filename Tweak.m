#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CoreMotion/CoreMotion.h>
#import <objc/runtime.h>

#define DEFAULT_REAL_PIN @"8888"
#define DEFAULT_DECOY_PIN @"0000"
#define KEY_REAL_PIN @"com.sec.real_pin"
#define KEY_DECOY_PIN @"com.sec.decoy_pin"
#define INACTIVITY_TIMEOUT 60.0
#define MAX_FAILED_ATTEMPTS 3

// MARK: - Helper lấy Window & Top ViewController an toàn trên mọi iOS
static UIWindow *getAppKeyWindow(void) {
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive ||
                scene.activationState == UISceneActivationStateForegroundInactive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) return w;
                }
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
}

static UIViewController *getTopViewController(void) {
    UIWindow *window = getAppKeyWindow();
    UIViewController *topVC = window.rootViewController;
    while (topVC.presentedViewController) {
        topVC = topVC.presentedViewController;
    }
    return topVC;
}

// MARK: - 1. Lưu trữ Keychain an toàn
@interface PINStore : NSObject
+ (NSString *)getRealPIN;
+ (void)setRealPIN:(NSString *)pin;
+ (NSString *)getDecoyPIN;
+ (void)setDecoyPIN:(NSString *)pin;
@end

@implementation PINStore

+ (NSString *)readKey:(NSString *)key fallback:(NSString *)fallback {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return fallback;
}

+ (void)saveKey:(NSString *)key value:(NSString *)value {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: data
    };
    SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
}

+ (NSString *)getRealPIN { return [self readKey:KEY_REAL_PIN fallback:DEFAULT_REAL_PIN]; }
+ (void)setRealPIN:(NSString *)pin { [self saveKey:KEY_REAL_PIN value:pin]; }
+ (NSString *)getDecoyPIN { return [self readKey:KEY_DECOY_PIN fallback:DEFAULT_DECOY_PIN]; }
+ (void)setDecoyPIN:(NSString *)pin { [self saveKey:KEY_DECOY_PIN value:pin]; }

@end

// MARK: - 2. Quản lý thời gian không tương tác (Inactivity Timer)
@interface InactivityManager : NSObject
+ (instancetype)sharedInstance;
- (void)start;
- (void)stop;
- (void)reset;
@end

@implementation InactivityManager {
    NSTimer *_timer;
    BOOL _active;
}

+ (instancetype)sharedInstance {
    static InactivityManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ instance = [[InactivityManager alloc] init]; });
    return instance;
}

- (void)start { _active = YES; [self reset]; }
- (void)stop {
    _active = NO;
    if (_timer) { [_timer invalidate]; _timer = nil; }
}

- (void)reset {
    if (!_active) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_timer) [self->_timer invalidate];
        self->_timer = [NSTimer scheduledTimerWithTimeInterval:INACTIVITY_TIMEOUT
                                                        target:self
                                                      selector:@selector(timeoutTriggered)
                                                      userInfo:nil
                                                       repeats:NO];
    });
}

- (void)timeoutTriggered {
    [self stop];
    exit(0);
}

@end

// MARK: - 3. Hook sự kiện chạm toàn app
@implementation UIApplication (SecurityTracker)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Method orig = class_getInstanceMethod(self, @selector(sendEvent:));
        Method swiz = class_getInstanceMethod(self, @selector(sec_sendEvent:));
        method_exchangeImplementations(orig, swiz);
    });
}

- (void)sec_sendEvent:(UIEvent *)event {
    [self sec_sendEvent:event];
    if (event.type == UIEventTypeTouches) {
        [[InactivityManager sharedInstance] reset];
    }
}

@end

// MARK: - 4. Quản lý bảo mật tổng thể (Motion, Anti-Record, App Switcher, Menu ẩn)
@interface SecurityGuard : NSObject
+ (instancetype)sharedInstance;
- (void)startMotionAndScreenProtection;
- (void)applyAppSwitcherMask;
- (void)removeAppSwitcherMask;
- (void)presentStealthMenu;
@end

@implementation SecurityGuard {
    CMMotionManager *_motionManager;
    UIView *_privacyBlurView;
    UIView *_screenRecordMask;
}

+ (instancetype)sharedInstance {
    static SecurityGuard *guard = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ guard = [[SecurityGuard alloc] init]; });
    return guard;
}

- (void)startMotionAndScreenProtection {
    _motionManager = [[CMMotionManager alloc] init];
    if (_motionManager.isDeviceMotionAvailable) {
        _motionManager.deviceMotionUpdateInterval = 0.2;
        [_motionManager startDeviceMotionUpdatesToQueue:[NSOperationQueue mainQueue]
                                           withHandler:^(CMDeviceMotion *data, NSError *error) {
            if (data && data.gravity.z > 0.85) {
                exit(0);
            }
        }];
    }

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(screenCaptureChanged)
                                                 name:UIScreenCapturedDidChangeNotification
                                               object:nil];
}

- (void)screenCaptureChanged {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = getAppKeyWindow();
        if ([UIScreen mainScreen].isCaptured) {
            if (!self->_screenRecordMask) {
                self->_screenRecordMask = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
                self->_screenRecordMask.backgroundColor = [UIColor blackColor];
                UILabel *lbl = [[UILabel alloc] initWithFrame:self->_screenRecordMask.bounds];
                lbl.text = @"Bảo vệ quyền riêng tư\nKhông thể quay màn hình";
                lbl.textColor = [UIColor whiteColor];
                lbl.textAlignment = NSTextAlignmentCenter;
                lbl.numberOfLines = 2;
                [self->_screenRecordMask addSubview:lbl];
            }
            if (window) {
                [window addSubview:self->_screenRecordMask];
                [window bringSubviewToFront:self->_screenRecordMask];
            }
        } else {
            [self->_screenRecordMask removeFromSuperview];
        }
    });
}

- (void)applyAppSwitcherMask {
    UIWindow *window = getAppKeyWindow();
    if (!window) return;
    if (!_privacyBlurView) {
        UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleDark];
        _privacyBlurView = [[UIVisualEffectView alloc] initWithEffect:blur];
        _privacyBlurView.frame = [UIScreen mainScreen].bounds;
    }
    [window addSubview:_privacyBlurView];
    [window bringSubviewToFront:_privacyBlurView];
}

- (void)removeAppSwitcherMask {
    if (_privacyBlurView) {
        [_privacyBlurView removeFromSuperview];
    }
}

- (void)presentStealthMenu {
    UIViewController *topVC = getTopViewController();
    if (!topVC) return;

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Cài đặt bảo mật ẩn"
                                                                   message:@"Quản lý mã PIN hệ thống"
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Mã PIN thật hiện tại";
        tf.secureTextEntry = YES;
        tf.keyboardType = UIKeyboardTypeNumberPad;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Mã PIN thật mới";
        tf.secureTextEntry = YES;
        tf.keyboardType = UIKeyboardTypeNumberPad;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Mã PIN ngụy trang (Decoy) mới";
        tf.secureTextEntry = YES;
        tf.keyboardType = UIKeyboardTypeNumberPad;
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"Lưu" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *curr = alert.textFields[0].text;
        NSString *newReal = alert.textFields[1].text;
        NSString *newDecoy = alert.textFields[2].text;

        if (![curr isEqualToString:[PINStore getRealPIN]]) {
            UIAlertController *err = [UIAlertController alertControllerWithTitle:@"Lỗi" message:@"Mã PIN hiện tại không chính xác!" preferredStyle:UIAlertControllerStyleAlert];
            [err addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
            [topVC presentViewController:err animated:YES completion:nil];
            return;
        }

        if (newReal.length > 0) [PINStore setRealPIN:newReal];
        if (newDecoy.length > 0) [PINStore setDecoyPIN:newDecoy];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Huỷ" style:UIAlertActionStyleCancel handler:nil]];
    [topVC presentViewController:alert animated:YES completion:nil];
}

@end

// MARK: - 5. Giao diện Thẻ thời tiết & Màn hình Apple Weather Fake
@interface WeatherCardView : UIView
@end

@implementation WeatherCardView
- (instancetype)initWithFrame:(CGRect)frame
                        title:(NSString *)title
                     subtitle:(NSString *)subtitle
                         temp:(NSString *)temp
                    condition:(NSString *)condition
                     highLow:(NSString *)highLow
                     topColor:(UIColor *)topColor
                  bottomColor:(UIColor *)bottomColor {
    self = [super initWithFrame:frame];
    if (self) {
        self.layer.cornerRadius = 22;
        self.layer.masksToBounds = YES;

        CAGradientLayer *gradient = [CAGradientLayer layer];
        gradient.frame = self.bounds;
        gradient.colors = @[(id)topColor.CGColor, (id)bottomColor.CGColor];
        gradient.startPoint = CGPointMake(0.5, 0.0);
        gradient.endPoint = CGPointMake(0.5, 1.0);
        [self.layer insertSublayer:gradient atIndex:0];

        CGFloat w = frame.size.width;

        UILabel *titleLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 14, w - 120, 26)];
        titleLbl.text = title;
        titleLbl.textColor = [UIColor whiteColor];
        titleLbl.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
        [self addSubview:titleLbl];

        UILabel *subLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 40, w - 120, 18)];
        subLbl.text = subtitle;
        subLbl.textColor = [UIColor colorWithWhite:1.0 alpha:0.9];
        subLbl.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
        [self addSubview:subLbl];

        UILabel *condLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, frame.size.height - 32, w - 150, 20)];
        condLbl.text = condition;
        condLbl.textColor = [UIColor whiteColor];
        condLbl.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
        [self addSubview:condLbl];

        UILabel *tempLbl = [[UILabel alloc] initWithFrame:CGRectMake(w - 110, 8, 94, 55)];
        tempLbl.text = temp;
        tempLbl.textColor = [UIColor whiteColor];
        tempLbl.font = [UIFont systemFontOfSize:52 weight:UIFontWeightLight];
        tempLbl.textAlignment = NSTextAlignmentRight;
        [self addSubview:tempLbl];

        UILabel *hlLbl = [[UILabel alloc] initWithFrame:CGRectMake(w - 140, frame.size.height - 32, 124, 20)];
        hlLbl.text = highLow;
        hlLbl.textColor = [UIColor whiteColor];
        hlLbl.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
        hlLbl.textAlignment = NSTextAlignmentRight;
        [self addSubview:hlLbl];
    }
    return self;
}
@end

@interface FakeWeatherViewController : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *searchField;
@property (nonatomic, assign) NSInteger failedAttempts;
@end

@implementation FakeWeatherViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.failedAttempts = 0;
    self.view.backgroundColor = [UIColor blackColor];

    CGFloat screenWidth = UIScreen.mainScreen.bounds.size.width;
    CGFloat startY = 56.0;

    UIButton *menuBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    menuBtn.frame = CGRectMake(screenWidth - 48, startY + 6, 32, 32);
    menuBtn.backgroundColor = [UIColor colorWithWhite:0.2 alpha:0.8];
    menuBtn.layer.cornerRadius = 16;
    [menuBtn setTitle:@"•••" forState:UIControlStateNormal];
    [menuBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    menuBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [self.view addSubview:menuBtn];

    UILabel *headerTitle = [[UILabel alloc] initWithFrame:CGRectMake(16, startY, 200, 44)];
    headerTitle.text = @"Thời tiết";
    headerTitle.textColor = [UIColor whiteColor];
    headerTitle.font = [UIFont systemFontOfSize:34 weight:UIFontWeightBold];
    [self.view addSubview:headerTitle];

    CGFloat searchY = startY + 54;
    self.searchField = [[UITextField alloc] initWithFrame:CGRectMake(16, searchY, screenWidth - 32, 38)];
    self.searchField.backgroundColor = [UIColor colorWithWhite:0.16 alpha:1.0];
    self.searchField.layer.cornerRadius = 10;
    self.searchField.textColor = [UIColor whiteColor];
    self.searchField.tintColor = [UIColor whiteColor];
    self.searchField.keyboardType = UIKeyboardTypeNumberPad;
    self.searchField.delegate = self;

    UIView *leftPadding = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 36, 38)];
    UILabel *searchIcon = [[UILabel alloc] initWithFrame:CGRectMake(10, 9, 20, 20)];
    searchIcon.text = @"🔍";
    searchIcon.font = [UIFont systemFontOfSize:14];
    [leftPadding addSubview:searchIcon];
    self.searchField.leftView = leftPadding;
    self.searchField.leftViewMode = UITextFieldViewModeAlways;

    UIView *rightPadding = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 34, 38)];
    UILabel *micIcon = [[UILabel alloc] initWithFrame:CGRectMake(4, 9, 20, 20)];
    micIcon.text = @"🎙️";
    micIcon.font = [UIFont systemFontOfSize:14];
    [rightPadding addSubview:micIcon];
    self.searchField.rightView = rightPadding;
    self.searchField.rightViewMode = UITextFieldViewModeAlways;

    self.searchField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"Tìm tên thành phố/sân bay"
        attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.5 alpha:1.0],
                     NSFontAttributeName: [UIFont systemFontOfSize:16]}];
    [self.view addSubview:self.searchField];

    CGFloat cardY1 = searchY + 52;
    WeatherCardView *card1 = [[WeatherCardView alloc]
        initWithFrame:CGRectMake(16, cardY1, screenWidth - 32, 115)
                title:@"X. Tân Điền"
             subtitle:@"Vị trí của tôi • 🏠 Nhà"
                 temp:@"32°"
            condition:@"Có mây"
              highLow:@"C:33°  T:26°"
             topColor:[UIColor colorWithRed:0.48 green:0.56 blue:0.64 alpha:1.0]
          bottomColor:[UIColor colorWithRed:0.35 green:0.42 blue:0.50 alpha:1.0]];
    [self.view addSubview:card1];

    CGFloat cardY2 = cardY1 + 127;
    WeatherCardView *card2 = [[WeatherCardView alloc]
        initWithFrame:CGRectMake(16, cardY2, screenWidth - 32, 115)
                title:@"Hà Nội"
             subtitle:@"14:35"
                 temp:@"34°"
            condition:@"Nhiều nắng"
              highLow:@"C:34°  T:27°"
             topColor:[UIColor colorWithRed:0.24 green:0.52 blue:0.80 alpha:1.0]
          bottomColor:[UIColor colorWithRed:0.42 green:0.68 blue:0.90 alpha:1.0]];
    [self.view addSubview:card2];

    UILabel *footerLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, cardY2 + 130, screenWidth - 32, 45)];
    footerLbl.numberOfLines = 2;
    footerLbl.textColor = [UIColor colorWithWhite:0.45 alpha:1.0];
    footerLbl.font = [UIFont systemFontOfSize:13];
    footerLbl.text = @"Tìm hiểu thêm về dữ liệu thời tiết và dữ liệu bản đồ";
    [self.view addSubview:footerLbl];

    UITapGestureRecognizer *dismissKbd = [[UITapGestureRecognizer alloc] initWithTarget:self.view action:@selector(endEditing:)];
    [self.view addGestureRecognizer:dismissKbd];
}

- (BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string {
    NSString *input = [textField.text stringByReplacingCharactersInRange:range withString:string];
    NSString *realPIN = [PINStore getRealPIN];
    NSString *decoyPIN = [PINStore getDecoyPIN];

    if ([input isEqualToString:realPIN]) {
        [textField resignFirstResponder];
        textField.text = @"";
        [self unlockRealApp];
        return NO;
    } else if ([input isEqualToString:decoyPIN]) {
        [textField resignFirstResponder];
        textField.text = @"";
        [self triggerDecoyMode];
        return NO;
    }
    return YES;
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    self.failedAttempts++;
    textField.text = @"";

    if (self.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        [textField resignFirstResponder];
        UIAlertController *crashAlert = [UIAlertController alertControllerWithTitle:@"Lỗi hệ thống"
                                                                            message:@"Ứng dụng bị buộc dừng do lỗi phân giải bộ nhớ (0xC0000005)."
                                                                     preferredStyle:UIAlertControllerStyleAlert];
        [crashAlert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
            exit(0);
        }]];
        [self presentViewController:crashAlert animated:YES completion:nil];
    } else {
        self.searchField.attributedPlaceholder = [[NSAttributedString alloc]
            initWithString:@"Không tìm thấy vị trí..."
            attributes:@{NSForegroundColorAttributeName: [UIColor colorWithRed:1.0 green:0.5 blue:0.5 alpha:0.8]}];
    }
    return YES;
}

- (void)unlockRealApp {
    [UIView animateWithDuration:0.3 animations:^{
        self.view.window.alpha = 0.0;
    } completion:^(BOOL finished) {
        self.view.window.hidden = YES;
        [[InactivityManager sharedInstance] start];
        [[SecurityGuard sharedInstance] startMotionAndScreenProtection];

        UIWindow *appWindow = getAppKeyWindow();
        if (appWindow) {
            UITapGestureRecognizer *stealthGesture = [[UITapGestureRecognizer alloc] initWithTarget:[SecurityGuard sharedInstance] action:@selector(presentStealthMenu)];
            stealthGesture.numberOfTouchesRequired = 3;
            stealthGesture.numberOfTapsRequired = 2;
            [appWindow addGestureRecognizer:stealthGesture];
        }
    }];
}

- (void)triggerDecoyMode {
    UIAlertController *decoyAlert = [UIAlertController alertControllerWithTitle:@"Lỗi kết nối máy chủ"
                                                                        message:@"Không thể đồng bộ dữ liệu tài khoản (Mã lỗi: SSL_503). Vui lòng thử lại sau."
                                                                 preferredStyle:UIAlertControllerStyleAlert];
    [decoyAlert addAction:[UIAlertAction actionWithTitle:@"Thử lại" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        exit(0);
    }]];
    [self presentViewController:decoyAlert animated:YES completion:nil];
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end

// MARK: - 6. Quản lý Fake Window
@interface DisguiseWindowController : NSObject
+ (instancetype)sharedInstance;
- (void)presentDisguise;
- (void)resetToLocked;
@end

@implementation DisguiseWindowController {
    UIWindow *_fakeWindow;
}

+ (instancetype)sharedInstance {
    static DisguiseWindowController *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ inst = [[DisguiseWindowController alloc] init]; });
    return inst;
}

- (void)presentDisguise {
    [[InactivityManager sharedInstance] stop];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self->_fakeWindow) {
            UIWindowScene *scene = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *s in UIApplication.sharedApplication.connectedScenes) {
                    if (s.activationState == UISceneActivationStateForegroundActive ||
                        s.activationState == UISceneActivationStateForegroundInactive) {
                        scene = s;
                        break;
                    }
                }
                if (scene) self->_fakeWindow = [[UIWindow alloc] initWithWindowScene:scene];
            }
            if (!self->_fakeWindow) {
                self->_fakeWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }
            self->_fakeWindow.windowLevel = UIWindowLevelAlert + 100;
            self->_fakeWindow.rootViewController = [[FakeWeatherViewController alloc] init];
        }
        self->_fakeWindow.alpha = 1.0;
        self->_fakeWindow.hidden = NO;
        [self->_fakeWindow makeKeyAndVisible];
    });
}

- (void)resetToLocked {
    [[InactivityManager sharedInstance] stop];
    if (_fakeWindow) {
        _fakeWindow.alpha = 1.0;
        _fakeWindow.hidden = NO;
    }
}

@end

// MARK: - 7. Hooks vòng đời
__attribute__((constructor))
static void initFullSecuritySystem(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [[DisguiseWindowController sharedInstance] presentDisguise];
    }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillResignActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [[SecurityGuard sharedInstance] applyAppSwitcherMask];
    }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [[SecurityGuard sharedInstance] removeAppSwitcherMask];
    }];

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidEnterBackgroundNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [[DisguiseWindowController sharedInstance] resetToLocked];
    }];
}

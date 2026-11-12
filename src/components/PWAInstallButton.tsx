import React, { useState } from 'react';
import { usePWAInstall } from '../hooks/usePWAInstall';
import { Download, Smartphone, X } from 'lucide-react';

export const PWAInstallButton: React.FC<{ isArabic?: boolean }> = ({ isArabic = true }) => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);

  // If already running standalone, suppress
  if (isInstalled) {
    return null;
  }

  // Chromium / Android / Desktop flow
  if (isInstallable) {
    return (
      <button
        onClick={install}
        className="flex items-center space-x-1.5 space-x-reverse px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 transition-all"
        title={isArabic ? 'تثبيت المنصة كتطبيق على جهازك' : 'Install CCK as a desktop/mobile app'}
      >
        <Download className="w-3.5 h-3.5" />
        <span>{isArabic ? 'تثبيت التطبيق' : 'Install App'}</span>
      </button>
    );
  }

  // iOS Safari flow
  if (isIOS) {
    return (
      <>
        <button
          onClick={() => setShowIOSGuide(true)}
          className="flex items-center space-x-1.5 space-x-reverse px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition-all"
          title={isArabic ? 'تثبيت على أجهزة iPhone و iPad' : 'Install on iPhone/iPad'}
        >
          <Smartphone className="w-3.5 h-3.5" />
          <span>{isArabic ? 'تثبيت على iOS' : 'Add to iOS'}</span>
        </button>

        {showIOSGuide && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="w-full max-w-sm rounded-xl bg-slate-900 border border-slate-800 p-6 text-xs text-slate-200 space-y-3 animate-fadeIn">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                <h3 className="font-bold text-white text-sm">
                  {isArabic ? 'التثبيت على iPhone و iPad' : 'Install on iPhone / iPad'}
                </h3>
                <button onClick={() => setShowIOSGuide(false)} className="text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <p className="leading-relaxed text-slate-300">
                {isArabic ? (
                  <>
                    1. انقر على زر <strong>المشاركة (Share)</strong> في شريط متصفح Safari السفلي.
                    <br />
                    2. مرّر للأسفل واختر <strong>إضافة إلى الشاشة الرئيسية (Add to Home Screen)</strong>.
                    <br />
                    3. ستعمل المنصة كتطبيق مستقل بكامل مزايا الحماية والموثوقية.
                  </>
                ) : (
                  <>
                    1. Tap the <strong>Share</strong> button in Safari toolbar.
                    <br />
                    2. Scroll down and tap <strong>Add to Home Screen</strong>.
                    <br />
                    3. CCK will launch as a standalone application.
                  </>
                )}
              </p>
              <button
                onClick={() => setShowIOSGuide(false)}
                className="w-full mt-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium"
              >
                {isArabic ? 'فهمت ذلك' : 'Got it'}
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  const [showGenericGuide, setShowGenericGuide] = useState(false);

  // Generic fallback: direct in-app guide on installing
  return (
    <>
      <button
        onClick={() => setShowGenericGuide(true)}
        className="hidden sm:flex items-center space-x-1.5 space-x-reverse px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-300 text-xs border border-slate-700 transition-all"
        title={isArabic ? 'تثبيت المنصة' : 'Install CCK app'}
      >
        <Download className="w-3.5 h-3.5 text-cyan-400" />
        <span>{isArabic ? 'تثبيت PWA' : 'Install'}</span>
      </button>

      {showGenericGuide && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-xl bg-slate-900 border border-slate-800 p-6 text-xs text-slate-200 space-y-3 animate-fadeIn">
            <div className="flex justify-between items-center border-b border-slate-800 pb-2">
              <h3 className="font-bold text-white text-sm">
                {isArabic ? 'تثبيت تطبيق CCK' : 'Install CCK Application'}
              </h3>
              <button onClick={() => setShowGenericGuide(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="leading-relaxed text-slate-300">
              {isArabic ? (
                <>
                  لتثبيت CCK كتطبيق مستقل على جهازك:
                  <br />
                  1. افتح قائمة المتصفح (أيقونة <strong>⋮</strong> أو أيقونة التثبيت في شريط العنوان).
                  <br />
                  2. اختر <strong>تثبيت التطبيق</strong> أو <strong>إضافة إلى الشاشة الرئيسية</strong>.
                </>
              ) : (
                <>
                  To install CCK as a standalone desktop or mobile application:
                  <br />
                  1. Open your browser menu (click <strong>⋮</strong> or the install icon in address bar).
                  <br />
                  2. Select <strong>Install CCK</strong> or <strong>Add to Home Screen</strong>.
                </>
              )}
            </p>
            <button
              onClick={() => setShowGenericGuide(false)}
              className="w-full mt-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-colors"
            >
              {isArabic ? 'حسناً، فهمت' : 'Understood'}
            </button>
          </div>
        </div>
      )}
    </>
  );
};

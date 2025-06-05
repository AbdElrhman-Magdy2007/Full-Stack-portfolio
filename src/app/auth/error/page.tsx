'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { authConfig } from '@/config/auth.config';

export default function AuthError() {
  const searchParams = useSearchParams();
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [errorDetails, setErrorDetails] = useState<any>(null);
  const [debugInfo, setDebugInfo] = useState<any>(null);

  useEffect(() => {
    if (!searchParams) return;
    
    const errorType = searchParams.get('error');
    const specificMessage = searchParams.get('message');
    const detailsParam = searchParams.get('details');
    
    // Collect debug information
    const debug = {
      errorType,
      specificMessage,
      hasDetails: !!detailsParam,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      userAgent: navigator.userAgent,
    };
    setDebugInfo(debug);
    
    if (specificMessage) {
      setErrorMessage(specificMessage);
    }

    if (detailsParam) {
      try {
        const parsedDetails = JSON.parse(detailsParam);
        setErrorDetails(parsedDetails);
      } catch (e) {
        console.error('Error parsing error details:', e);
        setErrorDetails({ parseError: 'Failed to parse error details' });
      }
    }

    if (!specificMessage) {
      const errorMessages = authConfig.messages.errors;
      switch (errorType) {
        case 'Configuration':
          setErrorMessage(errorMessages.configuration);
          break;
        case 'AccessDenied':
          setErrorMessage(errorMessages.accessDenied);
          break;
        case 'Verification':
          setErrorMessage(errorMessages.verification);
          break;
        case 'OAuthSignin':
          setErrorMessage('خطأ في تسجيل الدخول باستخدام OAuth');
          break;
        case 'OAuthCallback':
          setErrorMessage('خطأ في معالجة استجابة OAuth');
          break;
        case 'OAuthCreateAccount':
          setErrorMessage('فشل إنشاء حساب OAuth');
          break;
        case 'EmailCreateAccount':
          setErrorMessage('فشل إنشاء حساب بالبريد الإلكتروني');
          break;
        case 'Callback':
          setErrorMessage('خطأ في معالجة استجابة المصادقة');
          break;
        case 'OAuthAccountNotLinked':
          setErrorMessage('البريد الإلكتروني مرتبط بحساب آخر');
          break;
        case 'EmailSignin':
          setErrorMessage('فشل إرسال بريد إلكتروني للتحقق');
          break;
        case 'CredentialsSignin':
          setErrorMessage(errorMessages.default);
          break;
        case 'SessionRequired':
          setErrorMessage('يجب تسجيل الدخول للوصول إلى هذه الصفحة');
          break;
        default:
          setErrorMessage(errorMessages.default);
      }
    }
  }, [searchParams]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            خطأ في المصادقة
          </h2>
          <div className="mt-4">
            <p className="text-sm text-red-600">
              {errorMessage}
            </p>
            {errorDetails && (
              <div className="mt-2 p-4 bg-red-50 rounded-md">
                <h3 className="text-sm font-medium text-red-800">تفاصيل الخطأ:</h3>
                <pre className="mt-2 text-xs text-red-800 overflow-auto">
                  {JSON.stringify(errorDetails, null, 2)}
                </pre>
              </div>
            )}
            {debugInfo && (
              <div className="mt-2 p-4 bg-gray-50 rounded-md">
                <h3 className="text-sm font-medium text-gray-800">معلومات التصحيح:</h3>
                <pre className="mt-2 text-xs text-gray-800 overflow-auto">
                  {JSON.stringify(debugInfo, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
        <div className="mt-8 space-y-6">
          <div className="flex flex-col items-center space-y-4">
            <Link
              href="/auth/signin"
              className="w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              العودة إلى صفحة تسجيل الدخول
            </Link>
            <Link
              href="/"
              className="text-sm text-indigo-600 hover:text-indigo-500"
            >
              العودة إلى الصفحة الرئيسية
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
} 
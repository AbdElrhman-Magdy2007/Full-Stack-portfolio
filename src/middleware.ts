import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";
import { withAuth } from "next-auth/middleware";
import { Routes, Pages, UserRole } from "./constants/enums";
import { authConfig } from "@/config/auth.config";

// تكوين الأمان
const securityConfig = {
  maxAge: 60 * 60 * 24 * 7, // 7 days
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
};

/**
 * Middleware to handle authentication and route protection.
 */
export default withAuth(
  async function middleware(request: NextRequest) {
    try {
      const url = request.nextUrl.clone();
      const pathname = url.pathname;
      const baseUrl = process.env.NEXTAUTH_URL || request.url.split('/').slice(0, 3).join('/');
      console.log("Pathname:", pathname);

      // إضافة رؤوس الأمان
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set("x-url", request.url);
      requestHeaders.set("x-frame-options", "DENY");
      requestHeaders.set("x-content-type-options", "nosniff");
      requestHeaders.set("referrer-policy", "strict-origin-when-cross-origin");

      const response = NextResponse.next({
        request: { headers: requestHeaders },
      });

      // التحقق من المصادقة
      const token = await getToken({ 
        req: request, 
        secret: process.env.NEXTAUTH_SECRET 
      });
      const isAuthenticated = !!token;

      // تعريف أنواع المسارات
      const isAuthPage = pathname.startsWith(`/${Routes.AUTH}`);
      const protectedRoutes = [Routes.PROFILE, Routes.ADMIN];
      const isProtectedRoute = protectedRoutes.some((route) =>
        pathname.startsWith(`/${route}`)
      );

      // إعادة توجيه المستخدمين غير المصادقين
      if (!isAuthenticated && isProtectedRoute) {
        const redirectUrl = new URL(`/${Routes.AUTH}${Pages.LOGIN}`, baseUrl);
        redirectUrl.searchParams.set('callbackUrl', pathname);
        console.log("Redirecting to Login:", redirectUrl.toString());
        return NextResponse.redirect(redirectUrl);
      }

      // إعادة توجيه المستخدمين المصادقين
      if (isAuthPage && isAuthenticated) {
        const role = token?.role as UserRole;
        const redirectUrl = new URL(
          role === UserRole.ADMIN ? `/${Routes.ADMIN}` : `/${Routes.PROFILE}`,
          baseUrl
        );
        console.log("Redirecting Authenticated User to:", redirectUrl.toString());
        return NextResponse.redirect(redirectUrl);
      }

      // تقييد الوصول إلى مسارات المشرف
      if (
        isAuthenticated &&
        pathname.startsWith(`/${Routes.ADMIN}`) &&
        token?.role !== UserRole.ADMIN
      ) {
        const redirectUrl = new URL(`/${Routes.PROFILE}`, baseUrl);
        console.log("Redirecting Non-Admin to Profile:", redirectUrl.toString());
        return NextResponse.redirect(redirectUrl);
      }

      return response;
    } catch (error) {
      console.error('Middleware Error:', error);
      // في حالة حدوث خطأ، إعادة توجيه إلى صفحة الخطأ
      const errorUrl = new URL(`/${Routes.AUTH}/${Pages.ERROR}`, process.env.NEXTAUTH_URL || request.url);
      errorUrl.searchParams.set('error', 'Configuration');
      return NextResponse.redirect(errorUrl);
    }
  },
  {
    callbacks: {
      authorized: () => true, // السماح للميدلوير بالتعامل مع الفحوصات
    },
  }
);

export const config = {
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)",
  ],
};

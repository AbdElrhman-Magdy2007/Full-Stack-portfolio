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
      console.log("Middleware - Processing request:", { pathname, baseUrl });

      // إضافة رؤوس الأمان
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set("x-url", request.url);
      requestHeaders.set("x-frame-options", "DENY");
      requestHeaders.set("x-content-type-options", "nosniff");
      requestHeaders.set("referrer-policy", "strict-origin-when-cross-origin");
      requestHeaders.set("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
      requestHeaders.set("x-xss-protection", "1; mode=block");
      requestHeaders.set(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
      );

      const response = NextResponse.next({
        request: { headers: requestHeaders },
      });

      // التحقق من المصادقة
      const token = await getToken({ 
        req: request, 
        secret: process.env.NEXTAUTH_SECRET 
      });
      const isAuthenticated = !!token;

      console.log("Middleware - Auth status:", { 
        isAuthenticated, 
        pathname,
        timestamp: new Date().toISOString()
      });

      // تعريف أنواع المسارات
      const isAuthPage = pathname.startsWith(`/${Routes.AUTH}`);
      const protectedRoutes = [Routes.PROFILE, Routes.ADMIN];
      const isProtectedRoute = protectedRoutes.some((route) =>
        pathname.startsWith(`/${route}`)
      );

      // التحقق من الصلاحيات
      if (isProtectedRoute && isAuthenticated) {
        const userRole = token?.role as UserRole;
        if (pathname.startsWith(`/${Routes.ADMIN}`) && userRole !== UserRole.ADMIN) {
          console.log("Middleware - Access denied:", { 
            pathname, 
            userRole,
            requiredRole: UserRole.ADMIN
          });
          return NextResponse.redirect(new URL(`/${Routes.AUTH}/${Pages.ERROR}`, request.url));
        }
      }

      // توجيه المستخدمين المسجلين بعيداً عن صفحات المصادقة
      if (isAuthPage && isAuthenticated) {
        console.log("Middleware - Redirecting authenticated user from auth page");
        return NextResponse.redirect(new URL('/', request.url));
      }

      // توجيه المستخدمين غير المسجلين إلى صفحة تسجيل الدخول
      if (isProtectedRoute && !isAuthenticated) {
        console.log("Middleware - Redirecting unauthenticated user to login");
        const callbackUrl = encodeURIComponent(request.url);
        return NextResponse.redirect(new URL(`/${Routes.AUTH}/${Pages.LOGIN}?callbackUrl=${callbackUrl}`, request.url));
      }

      return response;
    } catch (error) {
      console.error("Middleware Error:", {
        error: error instanceof Error ? error.message : "Unknown error",
        pathname: request.nextUrl.pathname,
        timestamp: new Date().toISOString()
      });
      return NextResponse.redirect(new URL(`/${Routes.AUTH}/${Pages.ERROR}`, request.url));
    }
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token,
    },
    pages: {
      signIn: `/${Routes.AUTH}/${Pages.LOGIN}`,
      error: `/${Routes.AUTH}/${Pages.ERROR}`,
    },
  }
);

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    "/((?!api|_next/static|_next/image|favicon.ico|public).*)",
  ],
};

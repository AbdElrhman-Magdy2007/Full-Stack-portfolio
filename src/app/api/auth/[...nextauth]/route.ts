import { authOptions } from "@/app/server/auth";
import NextAuth from "next-auth";
import { NextRequest } from "next/server";
import { loginSchema } from "@/app/validations/auth";
import { RateLimiter } from "@/lib/rate-limiter";
import { authConfig } from "@/config/auth.config";

// Initialize rate limiter
const rateLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Security headers configuration
const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
};

// Create a reusable error response helper
const createErrorResponse = (message: string, status: number = 500, details?: any) => {
  console.error("Auth Error Response:", {
    message,
    status,
    details,
    timestamp: new Date().toISOString()
  });

  return new Response(
    JSON.stringify({ 
      error: message,
      details,
      timestamp: new Date().toISOString()
    }),
    { 
      status,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, max-age=0',
        ...securityHeaders
      }
    }
  );
};

// Security middleware
const withSecurityMiddleware = async (request: NextRequest, handler: (req: NextRequest) => Promise<Response>) => {
  try {
    // Rate limiting
    const ip = request.headers.get('x-forwarded-for') || 'unknown';
    const isRateLimited = await rateLimiter.check(ip);
    
    if (isRateLimited) {
      return createErrorResponse(
        'Too many requests. Please try again later.',
        429
      );
    }

    // Method validation
    if (!['GET', 'POST'].includes(request.method)) {
      return createErrorResponse('Method not allowed', 405);
    }

    // Content type check for POST requests
    if (request.method === 'POST') {
      const contentType = request.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        return createErrorResponse('Content type must be application/json', 415);
      }
    }

    return await handler(request);
  } catch (error) {
    console.error('Security Middleware Error:', error);
    return createErrorResponse('Internal server error', 500);
  }
};

// Initialize NextAuth handler with custom error handling
const handler = NextAuth({
  ...authOptions,
  debug: process.env.NODE_ENV !== 'production',
  logger: {
    error(code, metadata) {
      console.error("NextAuth Error:", { code, metadata });
    },
    warn(code) {
      console.warn("NextAuth Warning:", { code });
    },
    debug(code, metadata) {
      console.debug("NextAuth Debug:", { code, metadata });
    }
  },
  pages: {
    ...authOptions.pages,
    error: '/auth/error',
  },
  callbacks: {
    ...authOptions.callbacks,
    async signIn({ user, account, profile, email, credentials }) {
      try {
        console.log("SignIn Callback:", {
          userId: user?.id,
          email: user?.email,
          accountType: account?.type,
          timestamp: new Date().toISOString()
        });
        return true;
      } catch (error) {
        console.error("SignIn Callback Error:", error);
        return false;
      }
    },
    async redirect({ url, baseUrl }) {
      console.log("Redirect Callback:", { url, baseUrl });
      if (url.startsWith(baseUrl)) return url;
      if (url.startsWith('/')) return `${baseUrl}${url}`;
      return baseUrl;
    },
  },
});

export async function GET(request: NextRequest) {
  return withSecurityMiddleware(request, async (req: NextRequest) => {
    try {
      const response = await handler(req);
      
      // Add security headers
      Object.entries(securityHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });

      return response;
    } catch (error) {
      console.error('Auth GET Error:', error);
      if (error instanceof Error && error.message.includes('configuration')) {
        return createErrorResponse(
          authConfig.messages.errors.configuration,
          500,
          { error: error.message }
        );
      }
      return createErrorResponse(authConfig.messages.errors.default);
    }
  });
}

export async function POST(request: NextRequest) {
  return withSecurityMiddleware(request, async (req: NextRequest) => {
    try {
      // Validate request body
      const body = await req.json();
      const validationResult = loginSchema().safeParse(body);
      
      if (!validationResult.success) {
        return createErrorResponse(
          'Invalid request data',
          400,
          { validation: validationResult.error.format() }
        );
      }

      const response = await handler(req);
      
      // Add security headers
      Object.entries(securityHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });

      return response;
    } catch (error) {
      console.error('Auth POST Error:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
        url: request.url
      });

      let errorMessage = authConfig.messages.errors.default;
      let errorDetails = {};

      if (error instanceof Error) {
        try {
          // Attempt to parse JSON error message from authorize callback
          const parsedError = JSON.parse(error.message);
          if (parsedError.validationError) {
            errorMessage = 'خطأ في التحقق من الصحة';
            errorDetails = { validation: parsedError.validationError };
          } else if (parsedError.responseError) {
            errorMessage = parsedError.responseError;
          } else if (error.message.includes('configuration')) {
            errorMessage = 'خطأ في تكوين المصادقة';
          } else {
            errorMessage = error.message;
          }
        } catch (parseError) {
          if (error.message.includes('configuration')) {
            errorMessage = 'خطأ في تكوين المصادقة';
          } else {
            errorMessage = error.message;
          }
        }
      }

      // Redirect to the error page with specific error details
      const errorUrl = new URL(`/auth/error`, request.url);
      errorUrl.searchParams.set('error', 'CredentialsSignin');
      errorUrl.searchParams.set('message', errorMessage);
      if (Object.keys(errorDetails).length > 0) {
        errorUrl.searchParams.set('details', JSON.stringify(errorDetails));
      }

      return new Response(null, {
        status: 302,
        headers: { 
          Location: errorUrl.toString(),
          ...securityHeaders
        },
      });
    }
  });
}
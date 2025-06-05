import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";
import { db } from "@/lib/prisma";

export async function GET(request: Request) {
  try {
    // Check environment variables
    const envCheck = {
      NEXTAUTH_URL: !!process.env.NEXTAUTH_URL,
      NEXTAUTH_SECRET: !!process.env.NEXTAUTH_SECRET,
      DATABASE_URL: !!process.env.DATABASE_URL,
    };

    // Check database connection
    await db.$connect();
    const dbStatus = {
      connected: true,
      userCount: await db.user.count(),
      sessionCount: await db.session.count(),
    };

    // Check authentication token
    const token = await getToken({ req: request as any });
    const authStatus = {
      isAuthenticated: !!token,
      tokenData: token ? {
        id: token.id,
        email: token.email,
        role: token.role,
      } : null,
    };

    // Get request information
    const requestInfo = {
      url: request.url,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
    };

    return NextResponse.json({
      status: "success",
      timestamp: new Date().toISOString(),
      environment: {
        nodeEnv: process.env.NODE_ENV,
        ...envCheck,
      },
      database: dbStatus,
      authentication: authStatus,
      request: requestInfo,
    });
  } catch (error) {
    console.error("Auth Status Check Error:", error);
    return NextResponse.json({
      status: "error",
      message: error instanceof Error ? error.message : "Unknown error",
      timestamp: new Date().toISOString(),
    }, { status: 500 });
  } finally {
    await db.$disconnect();
  }
} 
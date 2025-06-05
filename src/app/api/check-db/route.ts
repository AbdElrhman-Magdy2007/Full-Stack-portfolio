import { db } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  try {
    // Test database connection
    await db.$connect();
    
    // Get database statistics
    const userCount = await db.user.count();
    const sessionCount = await db.session.count();
    const accountCount = await db.account.count();
    
    // Get recent users (last 5)
    const recentUsers = await db.user.findMany({
      take: 5,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    return NextResponse.json({
      status: "success",
      message: "Database connection successful",
      stats: {
        userCount,
        sessionCount,
        accountCount,
      },
      recentUsers,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Database check error:", error);
    return NextResponse.json({
      status: "error",
      message: error instanceof Error ? error.message : "Unknown error",
      timestamp: new Date().toISOString()
    }, { status: 500 });
  } finally {
    await db.$disconnect();
  }
} 
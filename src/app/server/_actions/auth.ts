"use server";

import { Locale } from "@/i18n.config";
import { db } from "@/lib/prisma";
import bcrypt from "bcrypt";
import { Routes, Pages } from "@/constants/enums";
import { revalidatePath } from "next/cache";
import { v4 as uuidv4 } from "uuid";
import { loginSchema, signupSchema } from "@/app/validations/auth";
import { Prisma } from "@prisma/client";

// Define response interface for consistency
interface AuthResponse {
  status: number;
  message?: string;
  user?: {
    id: string;
    name: string;
    email: string;
    role: string;
  };
  error?: Record<string, string[]> | string;
  formData?: FormData;
  className?: string;
}

/**
 * Handles user login with credentials validation and authentication.
 * Returns user data (excluding password) on success, compatible with NextAuth.js.
 * @param credentials - Email and password input
 * @param locale - Current locale (unused for English-only messages)
 * @returns AuthResponse - Login result with status and optional user data
 */
export async function login(
  credentials: { email: string; password: string },
  locale: Locale
): Promise<AuthResponse> {
  try {
    // Validate credentials
    if (!credentials?.email || !credentials?.password) {
      console.log("Login attempt with missing credentials");
      return {
        status: 400,
        message: "Email and password are required",
        className: "text-red-500",
      };
    }

    // Validate with Zod schema
    const result = loginSchema().safeParse(credentials);
    if (!result.success) {
      console.log("Login validation failed:", result.error.format());
      return {
        status: 400,
        error: result.error.formErrors.fieldErrors,
        className: "text-red-500",
      };
    }

    // Find user with detailed logging
    console.log("Attempting to find user:", { email: credentials.email });
    const user = await db.user.findUnique({
      where: { email: credentials.email },
      select: {
        id: true,
        email: true,
        name: true,
        password: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      console.log("User not found:", { email: credentials.email });
      return {
        status: 401,
        message: "Invalid email or password",
        className: "text-red-500",
      };
    }

    // Verify password with detailed logging
    console.log("Verifying password for user:", { userId: user.id });
    const isValidPassword = await bcrypt.compare(credentials.password, user.password);
    
    if (!isValidPassword) {
      console.log("Invalid password for user:", { userId: user.id });
      return {
        status: 401,
        message: "Invalid email or password",
        className: "text-red-500",
      };
    }

    // Log successful login
    console.log("Login successful for user:", { 
      userId: user.id, 
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    });

    // Return user data (excluding password)
    return {
      status: 200,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    };
  } catch (error) {
    // Enhanced error logging
    console.error("Login Error:", {
      error: error instanceof Error ? error.message : "Unknown error",
      timestamp: new Date().toISOString(),
      email: credentials.email,
      stack: error instanceof Error ? error.stack : undefined,
    });

    return {
      status: 500,
      message: "An unexpected error occurred during login",
      error: error instanceof Error ? error.message : "Unknown error",
      className: "text-red-500",
    };
  }
}

/**
 * Handles user signup with validation and database insertion.
 * Creates a new user with a UUID, hashes the password, and revalidates admin paths.
 * @param prevState - Previous state from useActionState (unused)
 * @param formData - Form data from the signup form
 * @returns AuthResponse - Signup result with status and optional user data
 */
export async function signup(prevState: unknown, formData: FormData): Promise<AuthResponse> {
  // Convert FormData to object
  const credentials = Object.fromEntries(formData.entries());
  const result = signupSchema().safeParse(credentials);

  if (!result.success) {
    return {
      status: 400,
      error: result.error.formErrors.fieldErrors,
      formData,
      className: "text-red-500",
    };
  }

  try {
    // Check for existing user
    const existingUser = await db.user.findUnique({
      where: { email: result.data.email },
      select: { id: true },
    });

    if (existingUser) {
      return {
        status: 409,
        message: "User already exists",
        formData,
        className: "text-red-500",
      };
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(result.data.password, 10);
    const createdUser = await db.user.create({
      data: {
        id: uuidv4(),
        name: result.data.name,
        email: result.data.email,
        password: hashedPassword,
        role: "USER",
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
      },
    });

    // Revalidate affected paths
    const adminBasePath = `/${Routes.ADMIN}`;
    revalidatePath(`${adminBasePath}/${Pages.USERS}/${createdUser.id}/${Pages.EDIT}`);
    revalidatePath(`${adminBasePath}/${Pages.USERS}`);

    return {
      status: 201,
      message: "Registration successful",
      user: createdUser,
      className: "text-green-500",
    };
  } catch (error) {
    // Enhanced error handling for Prisma-specific errors
    const errorMessage =
      error instanceof Prisma.PrismaClientKnownRequestError
        ? `Prisma error: ${error.code} - ${error.message}`
        : error instanceof Error
        ? error.message
        : "Unknown error";

    console.error("❌ Signup Error:", {
      error: errorMessage,
      timestamp: new Date().toISOString(),
      email: result.data.email,
    });

    return {
      status: 500,
      message: "An unexpected error occurred",
      error: errorMessage,
      className: "text-red-500",
    };
  }
}
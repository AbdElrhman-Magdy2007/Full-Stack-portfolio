// src/app/server/auth.ts
import { Environments, Languages, Pages, Routes, UserRole } from "@/constants/enums";
import { LanguageType } from "@/i18n.config";
import { DefaultSession, NextAuthOptions, User } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { db } from "@/lib/prisma";
import { login } from "./_actions/auth";
import { JWT } from "next-auth/jwt";

// Validate required environment variables
const requiredEnvVars = ['NEXTAUTH_URL', 'NEXTAUTH_SECRET', 'DATABASE_URL'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missingEnvVars.join(', ')}. ` +
    'Please check your .env file and ensure all required variables are set.'
  );
}

// Module Declarations for Type Safety
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: User & {
      id: string;
      name: string;
      email: string;
      role: UserRole;
      image?: string | null;
      phone?: string | null;
      country?: string | null;
      city?: string | null;
      postalCode?: string | null;
      streetAddress?: string | null;
    };
  }

  interface User {
    id: string;
    name: string;
    email: string;
    role: UserRole;
    image?: string | null;
    phone?: string | null;
    country?: string | null;
    city?: string | null;
    postalCode?: string | null;
    streetAddress?: string | null;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id: string;
    name: string;
    email: string;
    role: UserRole;
    image?: string | null;
    phone?: string | null;
    country?: string | null;
    city?: string | null;
    postalCode?: string | null;
    streetAddress?: string | null;
  }
}

// NextAuth.js Configuration
export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(db),
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "example@email.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        try {
          if (!credentials?.email || !credentials?.password) {
            console.log("Missing credentials");
            throw new Error(JSON.stringify({
              validationError: { email: ["Email is required"], password: ["Password is required"] }
            }));
          }

          console.log("Attempting to authorize user:", { email: credentials.email });

          const response = await login(credentials, Languages.ENGLISH as LanguageType);

          if (response.status === 200 && response.user) {
            console.log("User authorized successfully:", { userId: response.user.id });
            return {
              id: response.user.id,
              name: response.user.name,
              email: response.user.email,
              role: response.user.role as UserRole,
            };
          }

          console.error("Authorization failed:", response);
          throw new Error(JSON.stringify({
            validationError: response.error,
            responseError: response.message,
          }));
        } catch (error) {
          console.error("❌ Authorize Error:", {
            error: error instanceof Error ? error.message : "Unknown error",
            timestamp: new Date().toISOString(),
            email: credentials?.email
          });
          throw error;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, account }) {
      try {
        if (user) {
          console.log("JWT Callback - User provided:", { userId: user.id });
          return {
            ...token,
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            image: user.image,
            phone: user.phone,
            country: user.country,
            city: user.city,
            postalCode: user.postalCode,
            streetAddress: user.streetAddress,
          } as JWT;
        }

        if (!token.email) {
          console.log("JWT Callback - No email in token");
          return token as JWT;
        }

        console.log("JWT Callback - Fetching user from DB:", { email: token.email });
        const dbUser = await db.user.findUnique({
          where: { email: token.email },
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
            image: true,
            phone: true,
            country: true,
            city: true,
            postalCode: true,
            streetAddress: true,
          },
        });

        if (!dbUser) {
          console.error("JWT Callback - User not found in database:", { email: token.email });
          return token as JWT;
        }

        console.log("JWT Callback - User found in database:", { userId: dbUser.id });
        return {
          ...token,
          id: dbUser.id,
          name: dbUser.name,
          email: dbUser.email,
          role: dbUser.role,
          image: dbUser.image,
          phone: dbUser.phone,
          country: dbUser.country,
          city: dbUser.city,
          postalCode: dbUser.postalCode,
          streetAddress: dbUser.streetAddress,
        } as JWT;
      } catch (error) {
        console.error("❌ JWT Callback Error:", {
          error: error instanceof Error ? error.message : "Unknown error",
          timestamp: new Date().toISOString(),
          email: token.email
        });
        return token;
      }
    },
    async session({ session, token }) {
      try {
        if (token) {
          console.log("Session Callback - Setting user data:", { userId: token.id });
          session.user = {
            id: token.id,
            name: token.name,
            email: token.email,
            role: token.role,
            image: token.image,
            phone: token.phone,
            country: token.country,
            city: token.city,
            postalCode: token.postalCode,
            streetAddress: token.streetAddress,
          };
        }
        return session;
      } catch (error) {
        console.error("❌ Session Callback Error:", {
          error: error instanceof Error ? error.message : "Unknown error",
          timestamp: new Date().toISOString(),
          email: token?.email
        });
        return session;
      }
    },
    async redirect({ url, baseUrl }) {
      console.log("Redirect Callback:", { url, baseUrl });
      // Allow NextAuth to handle /auth routes and prevent infinite loops
      if (url.startsWith('/api/auth') || url.startsWith('/auth')) {
        return url;
      }
      // Redirect to base URL for non-auth routes
      return baseUrl;
    }
  },
  session: {
    strategy: "jwt",
    maxAge: 7 * 24 * 60 * 60, // 7 days
    updateAge: 24 * 60 * 60, // 1 day
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
    signOut: '/auth/signout',
    verifyRequest: '/auth/verify-request',
  },
  secret: process.env.NEXTAUTH_SECRET,
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
};
'use client';
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { buttonVariants } from '@/components/ui/button';
import { Pages, Routes } from '@/constants/enums';
import Link from 'next/link';
import LoginForm from './_components/Form';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { Loader } from 'lucide-react';

// Fallback component in case Form fails to load
const FallbackForm: React.FC = () => (
  <div className="text-center text-red-500 dark:text-red-400 p-4">
    Error: Form component failed to load. Please check the Form component implementation.
  </div>
);

// Particle background component
const ParticleBackground: React.FC = () => {
  const particles = Array.from({ length: 15 }).map((_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: Math.random() * 6 + 4,
    duration: Math.random() * 6 + 6,
    delay: Math.random() * 4,
    opacity: Math.random() * 0.3 + 0.3,
  }));

  const particleVariants = {
    animate: (i: number) => ({
      x: [particles[i].x, particles[i].x + (Math.random() * 60 - 30), particles[i].x],
      y: [particles[i].y, particles[i].y + (Math.random() * 60 - 30), particles[i].y],
      opacity: [0, particles[i].opacity, 0],
      scale: [0, 1.2, 0],
      rotate: [0, 180, 360],
      transition: {
        duration: particles[i].duration,
        delay: particles[i].delay,
        repeat: Infinity,
        ease: 'easeInOut',
        times: [0, 0.5, 1],
      },
    }),
    pulse: {
      scale: [1, 1.3, 1],
      opacity: [0.3, 0.6, 0.3],
      transition: {
        duration: 4,
        repeat: Infinity,
        ease: 'easeInOut',
      },
    },
  };

  return (
    <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
      {particles.map((particle) => (
        <motion.div
          key={particle.id}
          className="particle animate-glow"
          style={{
            width: particle.size,
            height: particle.size,
            left: `${particle.x}%`,
            top: `${particle.y}%`,
            background: 'linear-gradient(135deg, hsl(215 91% 70% / 0.5), hsl(271 81% 75% / 0.5))',
          }}
          variants={particleVariants}
          animate={['animate', 'pulse']}
          custom={particle.id}
        />
      ))}
      <motion.div
        className="absolute inset-0"
        style={{
          background: 'linear-gradient(45deg, transparent, hsl(215 91% 70% / 0.2), transparent)',
        }}
        animate={{
          opacity: [0.1, 0.2, 0.1],
          x: [-30, 30, -30],
        }}
        transition={{
          duration: 10,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      {Array.from({ length: 3 }).map((_, i) => (
        <div
          key={`sparkle-${i}`}
          className="sparkle"
          style={{
            width: `${Math.random() * 3 + 3}px`,
            height: `${Math.random() * 3 + 3}px`,
            top: `${Math.random() * 80 + 10}%`,
            left: `${Math.random() * 80 + 10}%`,
            animation: `sparkle ${Math.random() * 0.5 + 1.2}s ease-in-out infinite`,
            animationDelay: `${Math.random() * 2}s`,
          }}
        />
      ))}
    </div>
  );
};

export default function SignInPage() {
  const [sparkles, setSparkles] = useState<{ id: number; x: number; y: number }[]>([]);
  const { data: session, status } = useSession();
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    if (status === 'authenticated') {
      console.log('User is already authenticated, redirecting...');
      router.replace('/');
    } else if (status === 'unauthenticated') {
      console.log('User is not authenticated, showing login form');
      setIsLoading(false);
    }
  }, [status, router]);

  const containerVariants = {
    hidden: { opacity: 0, y: 50, scale: 0.9 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: 0.8,
        ease: 'easeOut',
        type: 'spring',
        stiffness: 80,
        staggerChildren: 0.2,
      },
    },
  };

  const childVariants = {
    hidden: { opacity: 0, y: 30, scale: 0.9 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: { duration: 0.6, ease: 'easeOut', type: 'spring', stiffness: 90 },
    },
  };

  const createSparkle = (x: number, y: number) => {
    const id = Date.now();
    setSparkles((prev) => [...prev, { id, x: x + Math.random() * 8 - 4, y: y + Math.random() * 8 - 4 }]);
    setTimeout(() => setSparkles((prev) => prev.filter((s) => s.id !== id)), 600);
  };

  if (isLoading) {
    return (
      <main className="relative flex items-center justify-center min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 overflow-hidden dark">
        <div className="flex flex-col items-center justify-center space-y-4">
          <Loader className="h-8 w-8 animate-spin text-blue-400" />
          <p className="text-slate-300">Loading...</p>
        </div>
      </main>
    );
  }

  return (
    <main className="relative flex items-center justify-center min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 overflow-hidden dark">
      <ParticleBackground />
      <motion.div
        className="w-full max-w-md sm:max-w-lg p-6 sm:p-8 glass-card border-gradient hover:scale-105 transition-transform duration-300 animate-glow z-10"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        role="region"
        aria-labelledby="signin-title"
        dir="ltr"
      >
        <motion.h2
          id="signin-title"
          className="text-3xl sm:text-4xl font-heading font-bold mb-8 text-center text-blue-400 animate-typewriter"
          variants={childVariants}
        >
          Sign In
        </motion.h2>
        <motion.div variants={childVariants} className="min-h-[200px]">
          {LoginForm ? <LoginForm /> : <FallbackForm />}
        </motion.div>
        <motion.p
          className="text-center text-slate-300 text-sm sm:text-base mt-8"
          variants={childVariants}
        >
          Don't have an account?{' '}
          <span className="sparkle-container relative inline-block">
            <Link
              href={`/${Routes.AUTH}/${Pages.Register}`}
              className={`${buttonVariants({
                variant: 'link',
                size: 'sm',
              })} !text-purple-400 hover:underline animate-reveal-text delay-200 relative group`}
              onMouseEnter={(e) => createSparkle(e.clientX, e.clientY)}
              onClick={(e) => createSparkle(e.clientX, e.clientY)}
            >
              <span className="relative z-10">Create an Account</span>
              <span className="absolute inset-0 bg-gradient-to-r from-blue-400/50 to-purple-400/50 opacity-0 group-hover:opacity-50 transition-opacity duration-600 rounded-full" />
            </Link>
          </span>
        </motion.p>
      </motion.div>
      {sparkles.map((sparkle) => (
        <motion.div
          key={sparkle.id}
          className="sparkle absolute rounded-full"
          style={{
            left: sparkle.x,
            top: sparkle.y,
            width: 8,
            height: 8,
            background: 'linear-gradient(135deg, hsl(215 91% 70% / 0.8), hsl(271 81% 75% / 0.8))',
          }}
          initial={{ scale: 0, opacity: 1, rotate: 0 }}
          animate={{ scale: 2, opacity: 0, rotate: 180 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
      ))}
    </main>
  );
}
'use client';

import { useState, useRef, useCallback, useReducer, memo } from 'react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { useRouter } from 'next/navigation';
import { InputTypes, Pages } from '@/constants/enums';
import useFormFields from '@/hooks/useFormFields';
import { signIn } from 'next-auth/react';
import { Button } from '@/components/ui/button';
import clsx from 'clsx';
import { Loader } from 'lucide-react';
import FormFields from '@/components/from-fields/from-fieds';

// Interface for form errors
interface FormErrors {
  [key: string]: string[];
}

// Reducer for managing form errors
type FormAction =
  | { type: 'SET_ERRORS'; payload: FormErrors }
  | { type: 'CLEAR_ERRORS' };

const errorsReducer = (state: FormErrors, action: FormAction): FormErrors => {
  switch (action.type) {
    case 'SET_ERRORS':
      return { ...state, ...action.payload };
    case 'CLEAR_ERRORS':
      return {};
    default:
      return state;
  }
};

const LoginForm = memo(() => {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastToastMessage, setLastToastMessage] = useState<string | null>(null);
  const [isFormValid, setIsFormValid] = useState(true);
  const [errors, dispatchErrors] = useReducer(errorsReducer, {});
  const [sparkles, setSparkles] = useState<{ id: number; x: number; y: number }[]>([]);

  const { getFormFields } = useFormFields({ slug: Pages.LOGIN });
  const formFields = getFormFields().map(field => ({
    ...field,
    type: field.type as InputTypes
  }));

  const onSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      if (!formRef.current || !isFormValid) return;

      const formData = new FormData(formRef.current);
      const data: Record<string, string> = {};
      formData.forEach((value, key) => {
        data[key] = value.toString();
      });

      console.log('Login attempt:', { email: data.email, timestamp: new Date().toISOString() });

      const newErrors: FormErrors = {};
      if (!data.email) newErrors.email = ['Email is required'];
      if (!data.password) newErrors.password = ['Password is required'];

      if (Object.keys(newErrors).length > 0) {
        console.log('Validation errors:', newErrors);
        dispatchErrors({ type: 'SET_ERRORS', payload: newErrors });
        toast.error('Please fill in all required fields', {
          style: toastStyles.error,
          duration: 3000,
          className: 'glass-card border-gradient animate-glow toast-error',
        });
        return;
      }

      try {
        setIsLoading(true);
        dispatchErrors({ type: 'CLEAR_ERRORS' });

        console.log('Attempting to sign in with credentials...');
        const res = await signIn('credentials', {
          email: data.email,
          password: data.password,
          redirect: false,
          callbackUrl: '/',
        });

        console.log('Sign in response:', { 
          ok: res?.ok, 
          error: res?.error,
          status: res?.status,
          url: res?.url 
        });

        if (res?.error) {
          try {
            const parsedError = JSON.parse(res.error);
            console.log('Parsed error:', parsedError);
            
            const validationErrors = parsedError.validationError || {};
            dispatchErrors({ type: 'SET_ERRORS', payload: validationErrors });

            const errorMessage = parsedError.responseError || 'Authentication failed';
            if (errorMessage !== lastToastMessage) {
              toast.error(errorMessage, {
                style: toastStyles.error,
                duration: 3000,
                className: 'glass-card border-gradient animate-glow toast-error',
              });
              setLastToastMessage(errorMessage);
            }
          } catch (parseError) {
            console.error('Error parsing error response:', parseError);
            const errorMessage = 'An unexpected error occurred during authentication';
            if (errorMessage !== lastToastMessage) {
              toast.error(errorMessage, {
                style: toastStyles.error,
                duration: 3000,
                className: 'glass-card border-gradient animate-glow toast-error',
              });
              setLastToastMessage(errorMessage);
            }
          }
        } else if (res?.ok) {
          console.log('Login successful, redirecting...');
          if ('Login successful' !== lastToastMessage) {
            toast.success('Login successful', {
              style: toastStyles.success,
              duration: 3000,
              className: 'glass-card border-gradient animate-glow toast-success',
            });
            setLastToastMessage('Login successful');
          }
          router.replace('/');
        } else {
          console.warn('Unexpected signIn response:', res);
          const errorMessage = 'Login failed - Please try again';
          if (errorMessage !== lastToastMessage) {
            toast.error(errorMessage, {
              style: toastStyles.error,
              duration: 3000,
              className: 'glass-card border-gradient animate-glow toast-error',
            });
            setLastToastMessage(errorMessage);
          }
        }
      } catch (error) {
        console.error('Login error:', error);
        const errorMessage = 'An unexpected error occurred';
        if (errorMessage !== lastToastMessage) {
          toast.error(errorMessage, {
            style: toastStyles.error,
            duration: 3000,
            className: 'glass-card border-gradient animate-glow toast-error',
          });
          setLastToastMessage(errorMessage);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [router, lastToastMessage, isFormValid]
  );

  const toastStyles = {
    error: {
      color: '#F87171',
      backgroundColor: 'hsl(217 33% 17.5% / 0.2)',
      border: '1px solid hsl(3 81% 67% / 0.5)',
      borderRadius: '0.5rem',
      padding: '12px 16px',
      fontFamily: 'Inter, sans-serif',
      fontSize: '0.875rem',
      fontWeight: 500,
      boxShadow: '0 4px 12px hsl(215 91% 70% / 0.2)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      position: 'relative' as const,
      overflow: 'hidden',
    },
    success: {
      color: '#34D399',
      backgroundColor: 'hsl(217 33% 17.5% / 0.2)',
      border: '1px solid hsl(160 64% 43% / 0.5)',
      borderRadius: '0.5rem',
      padding: '12px 16px',
      fontFamily: 'Inter, sans-serif',
      fontSize: '0.875rem',
      fontWeight: 500,
      boxShadow: '0 4px 12px hsl(215 91% 70% / 0.2)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      position: 'relative' as const,
      overflow: 'hidden',
    },
  };

  const createSparkle = (x: number, y: number) => {
    const id = Date.now();
    setSparkles((prev) => [...prev, { id, x: x + Math.random() * 8 - 4, y: y + Math.random() * 8 - 4 }]);
    setTimeout(() => setSparkles((prev) => prev.filter((s) => s.id !== id)), 600);
  };

  const fieldVariants = {
    hidden: { opacity: 0, y: 20, scale: 0.95 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: 0.6,
        ease: 'easeOut',
        type: 'spring',
        stiffness: 90,
        delay: i * 0.1,
      },
    }),
  };

  const handleValidationChange = (isValid: boolean) => {
    setIsFormValid(isValid);
  };

  return (
    <form
      className={clsx(
        'space-y-6 w-full max-w-md mx-auto p-6 sm:p-8',
        'glass-card border-gradient animate-glow',
        'transition-all duration-300'
      )}
      onSubmit={onSubmit}
      ref={formRef}
      dir="ltr"
    >
      <div className="relative">
        {formFields.map((field, index) => (
          <motion.div
            key={field.name || index}
            className="space-y-3 relative"
            variants={fieldVariants}
            initial="hidden"
            animate="visible"
            custom={index}
          >
            <FormFields
              {...field}
              label={field.name === 'email' ? 'Email' : 'Password'}
              placeholder={field.name === 'email' ? 'Enter your email' : 'Enter your password'}
              error={errors[field.name]?.[0]}
              disabled={isLoading}
              onValidationChange={handleValidationChange}
              pattern={field.name === 'email' ? '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$' : '^.{6,}$'}
              ariaLabel={field.name === 'email' ? 'Email input field' : 'Password input field'}
              className={clsx(
                'w-full p-3 rounded-lg bg-slate-900/50 border border-slate-700',
                'text-slate-300 placeholder-slate-500 focus:ring-2 focus:ring-blue-400',
                'transition-all duration-200 hover:shadow-md hover:shadow-blue-400/20'
              )}
            />
          </motion.div>
        ))}
      </div>

      <motion.div
        variants={fieldVariants}
        initial="hidden"
        animate="visible"
        custom={formFields.length}
      >
        <Button
          type="submit"
          className={clsx(
            'w-full font-semibold rounded-lg py-2 px-4 transition-all duration-200',
            'bg-gradient-to-r from-blue-400 to-purple-400 hover:from-blue-500 hover:to-purple-500',
            'text-white border-gradient',
            (isLoading || !isFormValid) && 'opacity-50 cursor-not-allowed'
          )}
          disabled={isLoading || !isFormValid}
          onMouseEnter={(e) => createSparkle(e.clientX, e.clientY)}
          onClick={(e) => createSparkle(e.clientX, e.clientY)}
        >
          {isLoading ? (
            <span className="flex items-center justify-center gap-2">
              <Loader className="animate-spin h-5 w-5" />
              Logging in...
            </span>
          ) : (
            'Login'
          )}
        </Button>
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
    </form>
  );
});

export default LoginForm;
import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/hooks/useAuth";
import coverImage from "@/assets/cover.webp";

const Index = lazy(() => import("./pages/Index"));
const Informacoes = lazy(() => import("./pages/Informacoes"));
const Auth = lazy(() => import("./pages/Auth"));
const ResetPassword = lazy(() => import("./pages/ResetPassword"));
const Admin = lazy(() => import("./pages/Admin"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      retry: 2,
    },
  },
});

const SplashScreen = () => (
  <div className="min-h-screen bg-background flex flex-col items-center justify-center">
    <div className="w-full max-w-xs mx-auto text-center space-y-5 px-4">
      <div className="mx-auto rounded-2xl overflow-hidden shadow-lg border border-primary/15 animate-fade-in">
        <img src={coverImage} alt="Carrinho TPL Ribeirão" className="w-full h-auto" />
      </div>
      <div className="animate-fade-in">
        <h1 className="text-2xl font-bold text-primary">Carrinho TPL Ribeirão</h1>
        <p className="text-sm text-primary mt-1">Agenda de Testemunho Público</p>
      </div>
      <div className="flex justify-center animate-fade-in">
        <div className="h-1.5 w-20 bg-primary/20 rounded-full overflow-hidden">
          <div className="h-full bg-primary rounded-full w-1/2 animate-pulse" />
        </div>
      </div>
    </div>
  </div>
);

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, loading } = useAuth();
  if (loading) return <SplashScreen />;
  if (!user) return <Navigate to="/auth" replace />;
  return <>{children}</>;
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <Suspense fallback={<SplashScreen />}>
            <Routes>
              <Route path="/auth" element={<Auth />} />
              <Route path="/reset-password" element={<ResetPassword />} />
              <Route path="/" element={<ProtectedRoute><Index /></ProtectedRoute>} />
              <Route path="/informacoes" element={<ProtectedRoute><Informacoes /></ProtectedRoute>} />
              <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;

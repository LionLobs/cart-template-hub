import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import coverImage from "@/assets/cover.webp";

const Auth = () => {
  const { user, loading } = useAuth();
  const [mode, setMode] = useState<"login" | "signup" | "forgot">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [nome, setNome] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (user && !loading) return <Navigate to="/" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      if (mode === "forgot") {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${window.location.origin}/reset-password`,
        });
        if (error) throw error;
        toast.success("E-mail de recuperação enviado! Verifique sua caixa de entrada.");
        setMode("login");
      } else if (mode === "login") {
        const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
        if (error) throw error;
        toast.success("Login realizado com sucesso!");
      } else {
        if (password.length < 8) {
          toast.error("A senha deve ter pelo menos 8 caracteres");
          setSubmitting(false);
          return;
        }
        const { error } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            data: { nome: nome.trim() },
            emailRedirectTo: window.location.origin,
          },
        });
        if (error) throw error;
        toast.success("Conta criada! Verifique seu e-mail para confirmar.");
      }
    } catch (err: any) {
      toast.error(err.message || "Erro ao autenticar");
    } finally {
      setSubmitting(false);
    }
  };

  const titles = {
    login: { title: "Bem-vindo!", desc: "Faça login para acessar a agenda dos carrinhos" },
    signup: { title: "Criar Conta", desc: "Cadastre-se para participar da agenda" },
    forgot: { title: "Recuperar Senha", desc: "Enviaremos um link para redefinir sua senha" },
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4 py-8">
      <div className="w-full max-w-xs mb-6 rounded-2xl overflow-hidden shadow-lg border border-primary/15 animate-fade-in">
        <img src={coverImage} alt="Carrinho TPL Armação" className="w-full h-auto" />
      </div>

      <div className="w-full max-w-md animate-fade-in">
        <Card className="border border-primary/15 shadow-lg overflow-hidden">
          <CardHeader className="bg-primary/5 text-center pb-3">
            <CardTitle className="text-xl text-primary">
              {titles[mode].title}
            </CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              {titles[mode].desc}
            </p>
          </CardHeader>
          <CardContent className="pt-5">
            <form onSubmit={handleSubmit} className="space-y-4">
              {mode === "signup" && (
                <div className="space-y-1.5 pb-1">
                  <Label htmlFor="nome">Nome</Label>
                  <Input
                    id="nome"
                    value={nome}
                    onChange={(e) => setNome(e.target.value)}
                    placeholder="Seu nome completo"
                    required
                    className="h-10"
                  />
                </div>
              )}

              <div className="space-y-1.5">
                <Label htmlFor="email">E-mail</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="seu@email.com"
                  required
                  className="h-10"
                />
              </div>

              {mode !== "forgot" && (
                <div className="space-y-1.5 pb-1">
                  <Label htmlFor="password">Senha</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Mínimo 8 caracteres"
                    minLength={8}
                    required
                    className="h-10"
                  />
                </div>
              )}

              <Button type="submit" className="w-full font-semibold text-base h-11" disabled={submitting}>
                {submitting
                  ? "Aguarde..."
                  : mode === "login"
                  ? "Entrar"
                  : mode === "signup"
                  ? "Criar Conta"
                  : "Enviar Link de Recuperação"}
              </Button>
            </form>

            <div className="mt-5 text-center space-y-3">
              {mode === "login" && (
                <>
                  <button
                    type="button"
                    className="block w-full text-sm text-muted-foreground hover:text-primary transition-colors"
                    onClick={() => setMode("forgot")}
                  >
                    Esqueceu a senha?
                  </button>
                  <div className="border-t border-border pt-3">
                    <p className="text-sm text-muted-foreground mb-2">Ainda não tem conta?</p>
                    <Button
                      type="button"
                      variant="outline"
                      className="w-full font-semibold"
                      onClick={() => setMode("signup")}
                    >
                      Criar Conta
                    </Button>
                  </div>
                </>
              )}
              {mode === "signup" && (
                <button
                  type="button"
                  className="text-sm text-primary hover:underline"
                  onClick={() => setMode("login")}
                >
                  Já tem conta? Entrar
                </button>
              )}
              {mode === "forgot" && (
                <button
                  type="button"
                  className="text-sm text-primary hover:underline"
                  onClick={() => setMode("login")}
                >
                  Voltar ao login
                </button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <p className="mt-4 text-xs text-muted-foreground text-center animate-fade-in">
        Congregação Ribeirão da Ilha
      </p>
    </div>
  );
};

export default Auth;

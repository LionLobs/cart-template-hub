import { useState } from "react";
import { supabase } from "@/lib/supabase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import { Link, Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { z } from "zod";

const emailSchema = z.string().trim().email("Email inválido").max(255);

const Admin = () => {
  const { isAdmin, loading } = useAuth();
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (loading) return null;
  if (!isAdmin) return <Navigate to="/" replace />;

  const handleAssignAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      toast.error(parsed.error.errors[0]?.message || "Email inválido");
      return;
    }

    setSubmitting(true);
    try {
      const { data, error } = await supabase.functions.invoke("assign-admin-role", {
        body: { email: parsed.data },
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      toast.success(`Usuário ${parsed.data} agora é admin!`);
      setEmail("");
    } catch (err: any) {
      toast.error(err?.message || "Erro ao atribuir role de admin.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-card/95 backdrop-blur-md shadow-sm">
        <div className="mx-auto flex max-w-4xl items-center gap-3 px-4 py-3">
          <Link to="/">
            <Button variant="ghost" size="icon" className="h-9 w-9">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <h1 className="text-lg sm:text-xl font-bold text-foreground">Painel Admin</h1>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-lg px-4 py-8">
        <Card className="border border-primary/15 shadow-md">
          <CardHeader className="bg-primary/5 rounded-t-lg pb-3">
            <CardTitle className="flex items-center gap-2 text-primary text-base">
              <ShieldCheck className="h-5 w-5" />
              Atribuir Admin por Email
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-5">
            <form onSubmit={handleAssignAdmin} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="adminEmail" className="font-semibold text-sm">
                  Email do usuário
                </Label>
                <Input
                  id="adminEmail"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="usuario@email.com"
                  maxLength={255}
                  required
                  className="h-10"
                />
                <p className="text-xs text-muted-foreground">
                  O usuário precisa já ter uma conta cadastrada.
                </p>
              </div>
              <Button
                type="submit"
                className="w-full font-semibold h-11"
                disabled={submitting}
              >
                {submitting ? "Atribuindo..." : "Tornar Admin"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

export default Admin;

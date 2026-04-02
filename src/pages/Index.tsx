import { useState, useEffect, useCallback, useMemo, memo, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase, type Agendamento } from "@/lib/supabase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  CalendarDays, CalendarIcon, MapPin, Users, Trash2, Plus, Clock,
  Repeat, LogOut, Filter, Sun, Moon, LayoutGrid, List, Megaphone,
  ShieldCheck, Menu, Hand, Phone, Camera, User, AlertTriangle,
} from "lucide-react";
import WhatsAppIcon from "@/components/WhatsAppIcon";
import { Link } from "react-router-dom";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger, SheetDescription,
} from "@/components/ui/sheet";
import { z } from "zod";
import { getDay, format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import coverImage from "@/assets/cover.webp";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

const HORAS = Array.from({ length: 17 }, (_, i) => String(i + 7).padStart(2, "0"));
const MINUTOS = ["00", "15", "30", "45"];
const DIAS = ["Domingo", "Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"];
const LOCAIS = ["Areias", "Armação", "Display"];

const agendamentoSchema = z.object({
  nome: z.string().trim().min(1, "Nome é obrigatório").max(100),
  nome_dupla: z.string().trim().max(100).optional(),
  sem_dupla: z.boolean(),
  local: z.enum(["Carrinho", "Areias", "Armação", "Display"]),
  horario: z.string().min(1, "Selecione um horário"),
  data: z.string().optional(),
  toda_semana: z.boolean(),
});

const LOCAL_COLORS: Record<string, string> = {
  Carrinho: "bg-primary/10 text-primary border-primary/30",
  Areias: "bg-accent/10 text-accent-foreground border-accent/30",
  Armação: "bg-secondary text-secondary-foreground border-border",
  Display: "bg-primary/15 text-primary border-primary/20",
};

type Disponibilidade = {
  id: string; user_id: string; agendamento_id: string; nome: string; created_at: string;
};

type Profile = {
  nome: string | null;
  email: string | null;
  genero: string | null;
  telefone: string | null;
  avatar_url: string | null;
};

// ── Agenda Card ──────────────────────────────────────────────
const AgendamentoCard = memo(({
  a, isAdmin, onDelete, currentUserId, disponibilidades,
  onDisponibilizar, isDisponibilizando,
}: {
  a: Agendamento; isAdmin: boolean; onDelete: (id: string) => void;
  currentUserId?: string; disponibilidades: Disponibilidade[];
  onDisponibilizar: (agendamentoId: string, ownerUserId: string) => void;
  isDisponibilizando: boolean;
}) => {
  const disps = useMemo(() => disponibilidades.filter(d => d.agendamento_id === a.id), [disponibilidades, a.id]);
  const jaSeOfereceu = disps.some(d => d.user_id === currentUserId);
  const isOwner = a.user_id === currentUserId;
  const semDupla = a.sem_dupla || (!a.nome_dupla && !a.sem_dupla);

  return (
    <Card className={cn(
      "group relative transition-all duration-200 border-border/60",
      "hover:shadow-md hover:border-primary/20",
      semDupla && "border-l-4 border-l-orange-400"
    )}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-2 flex-1 min-w-0">
            {/* Nome e dupla */}
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <User className="h-4 w-4 text-primary shrink-0" />
                <p className="font-bold text-foreground truncate">{a.nome}</p>
              </div>
              {semDupla ? (
                <div className="flex items-center gap-1.5 text-orange-600 dark:text-orange-400">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span className="text-sm font-medium">Sem dupla</span>
                </div>
              ) : a.nome_dupla ? (
                <div className="flex items-center gap-1.5 text-muted-foreground">
                  <Users className="h-3.5 w-3.5 shrink-0" />
                  <span className="text-sm">Dupla: <span className="font-medium text-foreground">{a.nome_dupla}</span></span>
                </div>
              ) : null}
            </div>

            {/* Info badges */}
            <div className="flex flex-wrap gap-1.5">
              <span className={cn("inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold gap-1", LOCAL_COLORS[a.local] || "")}>
                <MapPin className="h-3 w-3" />{a.local}
              </span>
              {a.horario && (
                <span className="inline-flex items-center rounded-full border border-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground gap-1">
                  <Clock className="h-3 w-3" />{a.horario}
                </span>
              )}
              {a.data && (
                <span className="inline-flex items-center rounded-full border border-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground gap-1">
                  <CalendarIcon className="h-3 w-3" />
                  {format(new Date(a.data + "T12:00:00"), "dd/MM/yyyy")}
                </span>
              )}
              {a.toda_semana && (
                <span className="inline-flex items-center rounded-full border border-primary/30 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary gap-1">
                  <Repeat className="h-3 w-3" />Semanal
                </span>
              )}
            </div>

            {/* Disponibilidade button */}
            {a.sem_dupla && !isOwner && !jaSeOfereceu && (
              <Button
                size="sm" variant="outline"
                className="mt-1 gap-1.5 text-xs border-primary/30 text-primary hover:bg-primary/10"
                onClick={() => onDisponibilizar(a.id, a.user_id)}
                disabled={isDisponibilizando}
              >
                <Hand className="h-3.5 w-3.5" />Estou disponível como dupla
              </Button>
            )}
            {jaSeOfereceu && (
              <span className="inline-flex items-center mt-1 rounded-full bg-primary/10 border border-primary/30 px-2.5 py-0.5 text-xs font-semibold text-primary gap-1">
                <Hand className="h-3 w-3" />Você se ofereceu
              </span>
            )}
            {disps.length > 0 && isOwner && (
              <div className="mt-1 space-y-1">
                <p className="text-xs font-semibold text-primary">Duplas disponíveis:</p>
                <div className="flex flex-wrap gap-1">
                  {disps.map(d => (
                    <span key={d.id} className="inline-flex items-center rounded-full bg-accent/10 border border-accent/30 px-2.5 py-0.5 text-xs font-medium text-accent-foreground">
                      {d.nome}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          {isAdmin && (
            <Button
              variant="ghost" size="icon"
              className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity text-destructive hover:bg-destructive/10 shrink-0"
              onClick={() => onDelete(a.id)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
});
AgendamentoCard.displayName = "AgendamentoCard";

// ── Main Component ───────────────────────────────────────────
const Index = () => {
  const { user, isAdmin, signOut } = useAuth();
  const queryClient = useQueryClient();

  // Form state
  const [nome, setNome] = useState("");
  const [nomeDupla, setNomeDupla] = useState("");
  const [semDupla, setSemDupla] = useState(false);
  const [local, setLocal] = useState<string>("Areias");
  const [horaInicio, setHoraInicio] = useState("09");
  const [minInicio, setMinInicio] = useState("00");
  const [horaFim, setHoraFim] = useState("11");
  const [minFim, setMinFim] = useState("00");
  const horario = `${horaInicio}:${minInicio} - ${horaFim}:${minFim}`;
  const [data, setData] = useState<Date>();
  const [todaSemana, setTodaSemana] = useState(false);

  // Filters
  const [filtroLocal, setFiltroLocal] = useState<string>("todos");
  const [displayMode, setDisplayMode] = useState<"grid" | "list">(() =>
    (localStorage.getItem("displayMode") as "grid" | "list") || "grid"
  );
  const [darkMode, setDarkMode] = useState(() => {
    const isDark = localStorage.getItem("theme") === "dark";
    document.documentElement.classList.toggle("dark", isDark);
    return isDark;
  });

  // Avisos
  const [novoAviso, setNovoAviso] = useState("");
  const [mediaUrl, setMediaUrl] = useState("");

  // UI state
  const [activeSection, setActiveSection] = useState<"form" | "agenda" | "avisos">("form");
  const [menuOpen, setMenuOpen] = useState(false);

  // Profile state
  const [profile, setProfile] = useState<Profile>({ nome: null, email: null, genero: null, telefone: null, avatar_url: null });
  const [editTelefone, setEditTelefone] = useState("");
  const [editNome, setEditNome] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── Profile loading ────────────────────────────────────────
  useEffect(() => {
    if (!user?.id) return;
    supabase.from("profiles").select("nome, email, genero, telefone, avatar_url").eq("id", user.id).maybeSingle().then(({ data: p }) => {
      if (p) {
        setProfile(p as Profile);
        setEditTelefone(p.telefone || "");
        setEditNome(p.nome || "");
      }
      if (!p?.email && user.email) {
        supabase.from("profiles").update({ email: user.email }).eq("id", user.id);
      }
    });
  }, [user?.id, user?.email]);

  const saveProfile = useCallback(async (updates: Partial<Profile>) => {
    if (!user?.id) return;
    const newProfile = { ...profile, ...updates };
    setProfile(newProfile);
    await supabase.from("profiles").update(updates).eq("id", user.id);
    toast.success("Perfil atualizado!");
  }, [user?.id, profile]);

  const handleAvatarUpload = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user?.id) return;
    if (file.size > 2 * 1024 * 1024) { toast.error("Imagem muito grande. Máximo 2MB."); return; }
    try {
      const ext = file.name.split(".").pop() || "jpg";
      const path = `avatars/${user.id}.${ext}`;
      const { error: uploadError } = await supabase.storage.from("avatars").upload(path, file, { upsert: true });
      if (uploadError) throw uploadError;
      const { data: urlData } = supabase.storage.from("avatars").getPublicUrl(path);
      await saveProfile({ avatar_url: urlData.publicUrl + "?t=" + Date.now() });
    } catch {
      toast.error("Erro ao enviar foto. Tente novamente.");
    }
  }, [user?.id, saveProfile]);

  // ── Data queries ───────────────────────────────────────────
  const { data: agendamentos = [], isLoading } = useQuery({
    queryKey: ["agendamentos"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("agendamentos")
        .select("*")
        .order("data", { ascending: true });
      if (error) throw error;
      return data as Agendamento[];
    },
    staleTime: 30_000,
  });

  const { data: avisos = [] } = useQuery({
    queryKey: ["avisos"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("avisos")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data as { id: string; mensagem: string; media_url: string | null; media_type: string | null; created_at: string; user_id: string }[];
    },
    staleTime: 30_000,
  });

  const { data: disponibilidades = [] } = useQuery({
    queryKey: ["disponibilidade"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("disponibilidade")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data as Disponibilidade[];
    },
    staleTime: 30_000,
  });

  // ── Mutations ──────────────────────────────────────────────
  const disponibilizarMutation = useMutation({
    mutationFn: async ({ agendamentoId, ownerUserId }: { agendamentoId: string; ownerUserId: string }) => {
      if (!user?.id) throw new Error("Não autenticado");
      const { data: prof } = await supabase.from("profiles").select("nome, genero").eq("id", user.id).maybeSingle();
      const nomeVoluntario = prof?.nome || user.email || "Alguém";
      const titulo = prof?.genero === "feminino" ? "Uma irmã" : prof?.genero === "masculino" ? "Um irmão" : "Alguém";
      const { error } = await supabase.from("disponibilidade").insert({
        user_id: user.id, agendamento_id: agendamentoId, nome: nomeVoluntario,
      });
      if (error) throw error;
      const { data: ownerProfile } = await supabase.from("profiles").select("email").eq("id", ownerUserId).maybeSingle();
      if (ownerProfile?.email) {
        supabase.functions.invoke("notify-dupla-disponivel", {
          body: { recipientEmail: ownerProfile.email, voluntarioNome: nomeVoluntario, titulo },
        }).catch(() => {});
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["disponibilidade"] });
      toast.success("Você se ofereceu como dupla!");
    },
    onError: () => toast.error("Erro ao se disponibilizar."),
  });

  const addMutation = useMutation({
    mutationFn: async (formData: z.infer<typeof agendamentoSchema>) => {
      if (!user?.id) throw new Error("Usuário não autenticado");
      const baseRow = {
        nome: formData.nome, nome_dupla: formData.sem_dupla ? null : formData.nome_dupla || null,
        sem_dupla: formData.sem_dupla, local: formData.local, horario: formData.horario,
        toda_semana: formData.toda_semana, user_id: user.id,
      };
      if (formData.toda_semana && formData.data) {
        const rows = [];
        for (let i = 0; i < 4; i++) {
          const d = new Date(formData.data + "T12:00:00");
          d.setDate(d.getDate() + i * 7);
          rows.push({ ...baseRow, data: format(d, "yyyy-MM-dd") });
        }
        const { error } = await supabase.from("agendamentos").insert(rows);
        if (error) throw error;
      } else {
        const { error } = await supabase.from("agendamentos").insert({
          ...baseRow, data: formData.data || null,
        });
        if (error) throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agendamentos"] });
      setNome(""); setNomeDupla(""); setSemDupla(false); setLocal("Areias");
      setHoraInicio("09"); setMinInicio("00"); setHoraFim("11"); setMinFim("00");
      setData(undefined); setTodaSemana(false);
      toast.success("Agendamento salvo com sucesso!");
    },
    onError: (error: any) => {
      toast.error(error?.code === "23505"
        ? "Esse horário já foi reservado nessa data e local!"
        : "Erro ao salvar. Tente novamente.");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("agendamentos").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["agendamentos"] }); toast.success("Agendamento removido!"); },
    onError: () => toast.error("Erro ao remover."),
  });

  const addAvisoMutation = useMutation({
    mutationFn: async ({ mensagem, media_url }: { mensagem: string; media_url?: string }) => {
      if (!user?.id) throw new Error("Não autenticado");
      let media_type: string | null = null;
      if (media_url) {
        media_type = media_url.toLowerCase().match(/\.(mp4|webm|ogg|mov)(\?|$)/) ? "video" : "image";
      }
      const { error } = await supabase.from("avisos").insert({
        mensagem, media_url: media_url || null, media_type, user_id: user.id,
      });
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["avisos"] });
      setNovoAviso(""); setMediaUrl("");
      toast.success("Aviso publicado!");
    },
    onError: () => toast.error("Erro ao publicar aviso."),
  });

  const deleteAvisoMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("avisos").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["avisos"] }); toast.success("Aviso removido!"); },
    onError: () => toast.error("Erro ao remover aviso."),
  });

  // ── Realtime (debounced) ───────────────────────────────────
  useEffect(() => {
    const timeouts: Record<string, ReturnType<typeof setTimeout>> = {};
    const channel = supabase
      .channel("realtime-all")
      .on("postgres_changes", { event: "*", schema: "public", table: "agendamentos" }, () => {
        clearTimeout(timeouts.ag);
        timeouts.ag = setTimeout(() => queryClient.invalidateQueries({ queryKey: ["agendamentos"] }), 1500);
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "avisos" }, () => {
        clearTimeout(timeouts.av);
        timeouts.av = setTimeout(() => queryClient.invalidateQueries({ queryKey: ["avisos"] }), 1500);
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "disponibilidade" }, () => {
        clearTimeout(timeouts.di);
        timeouts.di = setTimeout(() => queryClient.invalidateQueries({ queryKey: ["disponibilidade"] }), 1500);
      })
      .subscribe();
    return () => {
      Object.values(timeouts).forEach(clearTimeout);
      supabase.removeChannel(channel);
    };
  }, [queryClient]);

  // ── Derived data ───────────────────────────────────────────
  const agendamentosFiltrados = useMemo(
    () => agendamentos.filter(a => filtroLocal === "todos" || a.local === filtroLocal),
    [agendamentos, filtroLocal]
  );

  const dayGroups = useMemo(() => {
    const groups: Record<number, Agendamento[]> = {};
    for (const a of agendamentosFiltrados) {
      if (a.data) {
        const day = getDay(new Date(a.data + "T12:00:00"));
        (groups[day] ??= []).push(a);
      }
    }
    return groups;
  }, [agendamentosFiltrados]);

  // ── Handlers ───────────────────────────────────────────────
  const handleDelete = useCallback((id: string) => deleteMutation.mutate(id), [deleteMutation]);

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    const parsed = agendamentoSchema.safeParse({
      nome, nome_dupla: semDupla ? undefined : nomeDupla, sem_dupla: semDupla,
      local, horario, data: data ? format(data, "yyyy-MM-dd") : undefined, toda_semana: todaSemana,
    });
    if (!parsed.success) { toast.error(parsed.error.errors[0]?.message || "Dados inválidos"); return; }
    addMutation.mutate(parsed.data);
  }, [nome, nomeDupla, semDupla, local, horario, data, todaSemana, addMutation]);

  const toggleTheme = useCallback(() => {
    setDarkMode(prev => {
      const next = !prev;
      document.documentElement.classList.toggle("dark", next);
      localStorage.setItem("theme", next ? "dark" : "light");
      return next;
    });
  }, []);

  const initials = useMemo(() => {
    const n = profile.nome || user?.email || "";
    return n.split(" ").filter(Boolean).slice(0, 2).map(w => w[0]?.toUpperCase()).join("");
  }, [profile.nome, user?.email]);

  const handleDisponibilizar = useCallback((agId: string, ownerId: string) => {
    disponibilizarMutation.mutate({ agendamentoId: agId, ownerUserId: ownerId });
  }, [disponibilizarMutation]);

  // ── Render helpers ─────────────────────────────────────────
  const renderAgendamentoList = useCallback((items: Agendamento[]) => (
    <div className={displayMode === "grid" ? "grid gap-3 sm:grid-cols-2" : "flex flex-col gap-2"}>
      {items.map(a => (
        <AgendamentoCard
          key={a.id} a={a} isAdmin={isAdmin} onDelete={handleDelete}
          currentUserId={user?.id} disponibilidades={disponibilidades}
          onDisponibilizar={handleDisponibilizar}
          isDisponibilizando={disponibilizarMutation.isPending}
        />
      ))}
    </div>
  ), [displayMode, isAdmin, handleDelete, user?.id, disponibilidades, handleDisponibilizar, disponibilizarMutation.isPending]);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-card/95 backdrop-blur-md shadow-sm">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="h-9 w-9">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 flex flex-col">
                <SheetHeader>
                  <SheetTitle className="text-primary">Menu</SheetTitle>
                  <SheetDescription className="sr-only">Navegação principal</SheetDescription>
                </SheetHeader>

                {/* Profile Section */}
                <div className="mt-4 p-3 rounded-xl bg-muted/50 border border-border space-y-3">
                  <div className="flex items-center gap-3">
                    <div className="relative cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                      <Avatar className="h-14 w-14 border-2 border-primary/30">
                        {profile.avatar_url && <AvatarImage src={profile.avatar_url} alt="Avatar" />}
                        <AvatarFallback className="bg-primary/10 text-primary font-bold text-lg">
                          {initials || <User className="h-6 w-6" />}
                        </AvatarFallback>
                      </Avatar>
                      <div className="absolute -bottom-1 -right-1 bg-primary rounded-full p-1">
                        <Camera className="h-3 w-3 text-primary-foreground" />
                      </div>
                      <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleAvatarUpload} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <input
                        className="font-semibold text-sm text-foreground bg-transparent border-b border-transparent hover:border-border focus:border-primary outline-none w-full truncate"
                        value={editNome}
                        onChange={e => setEditNome(e.target.value)}
                        placeholder="Seu nome"
                      />
                      <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Phone className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <input
                      className="text-xs text-foreground bg-transparent border-b border-transparent hover:border-border focus:border-primary outline-none w-full"
                      value={editTelefone}
                      onChange={e => setEditTelefone(e.target.value)}
                      placeholder="Seu telefone"
                    />
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant={profile.genero === "masculino" ? "default" : "outline"} className="flex-1 text-xs h-8" onClick={() => setProfile(p => ({ ...p, genero: "masculino" }))}>
                      Irmão
                    </Button>
                    <Button size="sm" variant={profile.genero === "feminino" ? "default" : "outline"} className="flex-1 text-xs h-8" onClick={() => setProfile(p => ({ ...p, genero: "feminino" }))}>
                      Irmã
                    </Button>
                  </div>
                  <Button
                    size="sm"
                    className="w-full text-xs h-9 font-semibold"
                    onClick={() => {
                      const updates: Partial<Profile> = {};
                      if (editNome !== profile.nome) updates.nome = editNome;
                      if (editTelefone !== (profile.telefone || "")) updates.telefone = editTelefone;
                      if (profile.genero) updates.genero = profile.genero;
                      if (Object.keys(updates).length > 0) {
                        saveProfile(updates);
                      } else {
                        toast.info("Nenhuma alteração para salvar.");
                      }
                    }}
                  >
                    Salvar Perfil
                  </Button>
                </div>

                <nav className="mt-4 flex flex-col gap-1.5 flex-1">
                  {[
                    { key: "form" as const, icon: Plus, label: "Novo Agendamento" },
                    { key: "agenda" as const, icon: Users, label: "Agenda" },
                    { key: "avisos" as const, icon: Megaphone, label: "Quadro de Avisos" },
                  ].map(item => (
                    <Button
                      key={item.key}
                      variant={activeSection === item.key ? "default" : "ghost"}
                      className="justify-start gap-2"
                      onClick={() => { setActiveSection(item.key); setMenuOpen(false); }}
                    >
                      <item.icon className="h-4 w-4" />{item.label}
                    </Button>
                  ))}

                  <div className="border-t border-border my-2" />

                  <Link to="/informacoes" onClick={() => setMenuOpen(false)}>
                    <Button variant="ghost" className="w-full justify-start gap-2">
                      <MapPin className="h-4 w-4" />Informações
                    </Button>
                  </Link>

                  {isAdmin && (
                    <Link to="/admin" onClick={() => setMenuOpen(false)}>
                      <Button variant="ghost" className="w-full justify-start gap-2">
                        <ShieldCheck className="h-4 w-4" />Painel Admin
                      </Button>
                    </Link>
                  )}

                  <div className="flex-1" />
                  <div className="border-t border-border my-2" />
                  <Button
                    variant="ghost"
                    className="justify-start gap-2 text-destructive hover:text-destructive"
                    onClick={() => { setMenuOpen(false); signOut(); }}
                  >
                    <LogOut className="h-4 w-4" />Sair
                  </Button>
                </nav>
              </SheetContent>
            </Sheet>
            <CalendarDays className="h-6 w-6 text-primary" />
            <h1 className="text-lg sm:text-xl font-bold text-foreground">Agenda dos Carrinhos</h1>
          </div>
          <div className="flex items-center gap-1.5">
            <Button variant="outline" size="icon" className="h-8 w-8" title={darkMode ? "Fundo branco" : "Fundo preto"} onClick={toggleTheme}>
              {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </Button>
            <a href="https://wa.me/5548988425163?text=Ol%C3%A1%2C%20preciso%20de%20ajuda%20com%20a%20agenda%20do%20carrinho" target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="icon" className="h-8 w-8" title="Ajuda via WhatsApp">
                <WhatsAppIcon className="h-4 w-4 text-primary" />
              </Button>
            </a>
          </div>
        </div>
      </header>

      {/* Cover Image */}
      <div className="relative w-full h-44 sm:h-56 md:h-64 overflow-hidden">
        <img src={coverImage} alt="Carrinho TPL Ribeirão" className="w-full h-full object-cover" loading="eager" />
        <div className="absolute inset-0 bg-gradient-to-t from-background via-background/20 to-transparent" />
        <div className="absolute bottom-4 left-0 right-0 text-center">
          <h2 className="text-2xl sm:text-3xl font-bold drop-shadow-lg text-secondary-foreground">Carrinho TPL Ribeirão</h2>
          <p className="text-sm drop-shadow text-secondary-foreground">Agenda de Testemunho Público</p>
        </div>
      </div>

      <main className="mx-auto max-w-4xl px-4 py-6 sm:py-8 space-y-6">
        {/* ── Form ──────────────────────────────────────── */}
        {activeSection === "form" && (
          <Card className="border border-primary/15 shadow-md">
            <CardHeader className="bg-primary/5 rounded-t-lg pb-3">
              <CardTitle className="flex items-center gap-2 text-primary text-base sm:text-lg">
                <Plus className="h-5 w-5" />CARRINHO TPL RIBEIRÃO
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-5">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="nome" className="font-semibold text-sm">Seu Nome</Label>
                  <Input id="nome" value={nome} onChange={e => setNome(e.target.value)} placeholder="Digite seu nome" maxLength={100} required className="h-10" />
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox id="semDupla" checked={semDupla} onCheckedChange={v => setSemDupla(v === true)} />
                  <Label htmlFor="semDupla" className="cursor-pointer text-sm">Estou sem dupla</Label>
                </div>
                {!semDupla && (
                  <div className="space-y-1.5">
                    <Label htmlFor="nomeDupla" className="font-semibold text-sm">Nome da Dupla</Label>
                    <Input id="nomeDupla" value={nomeDupla} onChange={e => setNomeDupla(e.target.value)} placeholder="Digite o nome da dupla" maxLength={100} className="h-10" />
                  </div>
                )}
                <div className="space-y-2">
                  <Label className="font-semibold text-sm">Local</Label>
                  <RadioGroup value={local} onValueChange={setLocal} className="flex gap-4 flex-wrap">
                    {LOCAIS.map(l => (
                      <div key={l} className="flex items-center gap-2">
                        <RadioGroupItem value={l} id={l} />
                        <Label htmlFor={l} className="cursor-pointer font-medium text-sm">{l}</Label>
                      </div>
                    ))}
                  </RadioGroup>
                </div>
                <div className="space-y-2">
                  <Label className="font-semibold text-sm flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5" />Horário
                  </Label>
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-muted-foreground font-medium">De</span>
                      <div className="flex items-center bg-card border border-border rounded-lg overflow-hidden shadow-sm">
                        <select value={horaInicio} onChange={e => setHoraInicio(e.target.value)} className="bg-transparent text-2xl font-mono font-bold text-primary text-center appearance-none px-2 py-1.5 outline-none cursor-pointer w-14">
                          {HORAS.map(h => <option key={h} value={h}>{h}</option>)}
                        </select>
                        <span className="text-2xl font-bold text-primary">:</span>
                        <select value={minInicio} onChange={e => setMinInicio(e.target.value)} className="bg-transparent text-2xl font-mono font-bold text-primary text-center appearance-none px-2 py-1.5 outline-none cursor-pointer w-14">
                          {MINUTOS.map(m => <option key={m} value={m}>{m}</option>)}
                        </select>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-muted-foreground font-medium">Até</span>
                      <div className="flex items-center bg-card border border-border rounded-lg overflow-hidden shadow-sm">
                        <select value={horaFim} onChange={e => setHoraFim(e.target.value)} className="bg-transparent text-2xl font-mono font-bold text-primary text-center appearance-none px-2 py-1.5 outline-none cursor-pointer w-14">
                          {HORAS.map(h => <option key={h} value={h}>{h}</option>)}
                        </select>
                        <span className="text-2xl font-bold text-primary">:</span>
                        <select value={minFim} onChange={e => setMinFim(e.target.value)} className="bg-transparent text-2xl font-mono font-bold text-primary text-center appearance-none px-2 py-1.5 outline-none cursor-pointer w-14">
                          {MINUTOS.map(m => <option key={m} value={m}>{m}</option>)}
                        </select>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label className="font-semibold text-sm flex items-center gap-1.5">
                    <CalendarIcon className="h-3.5 w-3.5" />Data
                  </Label>
                  <Popover>
                    <PopoverTrigger asChild>
                      <Button variant="outline" className={cn("w-full justify-start text-left font-normal h-10", !data && "text-muted-foreground")}>
                        <CalendarIcon className="mr-2 h-4 w-4" />
                        {data ? format(data, "PPP", { locale: ptBR }) : "Selecione uma data"}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-auto p-0" align="start">
                      <Calendar mode="single" selected={data} onSelect={setData} initialFocus locale={ptBR} disabled={date => date < new Date(new Date().setHours(0, 0, 0, 0))} className="p-3 pointer-events-auto" />
                    </PopoverContent>
                  </Popover>
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox id="todaSemana" checked={todaSemana} onCheckedChange={v => setTodaSemana(v === true)} />
                  <Label htmlFor="todaSemana" className="cursor-pointer flex items-center gap-1 text-sm">
                    <Repeat className="h-3.5 w-3.5" />Toda semana
                  </Label>
                </div>
                <Button type="submit" className="w-full font-semibold h-11 text-sm sm:text-base" disabled={addMutation.isPending}>
                  {addMutation.isPending ? "Salvando..." : "Salvar Agendamento"}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* ── Agenda ────────────────────────────────────── */}
        {activeSection === "agenda" && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="flex items-center gap-2 text-lg sm:text-xl font-bold text-foreground">
                <CalendarDays className="h-5 w-5 text-primary" />Agenda
                <span className="text-sm font-normal text-muted-foreground">({agendamentosFiltrados.length})</span>
              </h2>
              <div className="flex gap-1 border border-border rounded-md p-0.5">
                <Button variant={displayMode === "grid" ? "default" : "ghost"} size="icon" className="h-7 w-7" onClick={() => { setDisplayMode("grid"); localStorage.setItem("displayMode", "grid"); }}>
                  <LayoutGrid className="h-3.5 w-3.5" />
                </Button>
                <Button variant={displayMode === "list" ? "default" : "ghost"} size="icon" className="h-7 w-7" onClick={() => { setDisplayMode("list"); localStorage.setItem("displayMode", "list"); }}>
                  <List className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>

            {/* Filter */}
            <div className="flex items-center gap-2 mb-4">
              <Filter className="h-4 w-4 text-muted-foreground shrink-0" />
              <Select value={filtroLocal} onValueChange={setFiltroLocal}>
                <SelectTrigger className="w-[160px] h-9 text-xs">
                  <SelectValue placeholder="Filtrar por local" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="todos">Todos os locais</SelectItem>
                  {LOCAIS.map(l => <SelectItem key={l} value={l}>{l}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>

            {isLoading ? (
              <div className="flex justify-center py-12">
                <div className="h-8 w-8 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
              </div>
            ) : agendamentosFiltrados.length === 0 ? (
              <Card className="py-12 text-center border-dashed">
                <CardContent>
                  <CalendarDays className="h-10 w-10 mx-auto text-muted-foreground/40 mb-3" />
                  <p className="text-muted-foreground font-medium">
                    {agendamentos.length === 0 ? "Nenhum agendamento ainda." : "Nenhum resultado para os filtros."}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {agendamentos.length === 0 ? "Seja o primeiro a agendar!" : "Tente alterar o filtro de local."}
                  </p>
                </CardContent>
              </Card>
            ) : (
              <Tabs defaultValue="todos" className="w-full">
                <TabsList className="w-full flex flex-wrap h-auto gap-1 bg-muted/50 p-1">
                  <TabsTrigger value="todos" className="text-xs">Todos</TabsTrigger>
                  {DIAS.map((dia, i) => {
                    const count = dayGroups[i]?.length || 0;
                    if (count === 0) return null;
                    return (
                      <TabsTrigger key={dia} value={String(i)} className="text-xs">
                        {dia.slice(0, 3)} <span className="ml-1 text-muted-foreground">({count})</span>
                      </TabsTrigger>
                    );
                  })}
                </TabsList>

                <TabsContent value="todos" className="mt-3">
                  {renderAgendamentoList(agendamentosFiltrados)}
                </TabsContent>

                {DIAS.map((_, i) => {
                  const filtered = dayGroups[i];
                  if (!filtered?.length) return null;
                  return (
                    <TabsContent key={i} value={String(i)} className="mt-3">
                      {renderAgendamentoList(filtered)}
                    </TabsContent>
                  );
                })}
              </Tabs>
            )}
          </div>
        )}

        {/* ── Quadro de Avisos ──────────────────────────── */}
        {activeSection === "avisos" && (
          <Card className="border border-primary/30 shadow-md">
            <CardHeader className="bg-primary/10 rounded-t-lg pb-3">
              <CardTitle className="flex items-center gap-2 text-primary text-base sm:text-lg">
                <Megaphone className="h-5 w-5 text-primary" />Quadro de Avisos
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 space-y-3">
              {isAdmin && (
                <form onSubmit={e => { e.preventDefault(); if (novoAviso.trim() || mediaUrl.trim()) addAvisoMutation.mutate({ mensagem: novoAviso.trim(), media_url: mediaUrl.trim() || undefined }); }} className="space-y-2">
                  <Textarea value={novoAviso} onChange={e => setNovoAviso(e.target.value)} placeholder="Escreva um aviso..." maxLength={500} className="min-h-[60px] text-sm" />
                  <Input value={mediaUrl} onChange={e => setMediaUrl(e.target.value)} placeholder="URL da imagem ou vídeo (opcional)" className="h-9 text-sm" />
                  <Button type="submit" size="sm" className="w-full" disabled={addAvisoMutation.isPending}>Publicar</Button>
                </form>
              )}
              {avisos.length === 0 ? (
                <div className="text-center py-8">
                  <Megaphone className="h-8 w-8 mx-auto text-muted-foreground/40 mb-2" />
                  <p className="text-sm text-muted-foreground">Nenhum aviso no momento.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {avisos.map(aviso => (
                    <div key={aviso.id} className="rounded-lg bg-secondary p-3 flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        {aviso.mensagem && <p className="text-sm text-foreground whitespace-pre-wrap">{aviso.mensagem}</p>}
                        {aviso.media_url && aviso.media_type === "video" && (
                          <video src={aviso.media_url} controls className="mt-2 rounded-lg w-full max-h-40 object-contain" />
                        )}
                        {aviso.media_url && aviso.media_type !== "video" && (
                          <img src={aviso.media_url} alt="Aviso" className="mt-2 rounded-lg w-full max-h-40 object-contain" loading="lazy" />
                        )}
                        <p className="text-xs text-muted-foreground mt-1">{format(new Date(aviso.created_at), "dd/MM/yyyy 'às' HH:mm", { locale: ptBR })}</p>
                      </div>
                      {isAdmin && (
                        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0 text-destructive hover:bg-destructive/10" onClick={() => deleteAvisoMutation.mutate(aviso.id)}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
};

export default Index;

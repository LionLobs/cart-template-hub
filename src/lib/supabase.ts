import { supabase } from "@/integrations/supabase/client";

export { supabase };

export type Agendamento = {
  id: string;
  nome: string;
  nome_dupla: string | null;
  sem_dupla: boolean;
  local: string;
  horario: string | null;
  data: string | null;
  toda_semana: boolean;
  created_at: string;
  user_id: string;
};

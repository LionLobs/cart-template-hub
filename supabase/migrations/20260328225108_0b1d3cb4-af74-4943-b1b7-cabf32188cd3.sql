
-- Add genero to profiles
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS genero text CHECK (genero IN ('masculino', 'feminino'));

-- Add email to profiles for notifications
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS email text;

-- Create disponibilidade table for users offering to be a partner
CREATE TABLE IF NOT EXISTS public.disponibilidade (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  agendamento_id uuid NOT NULL REFERENCES public.agendamentos(id) ON DELETE CASCADE,
  nome text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, agendamento_id)
);

ALTER TABLE public.disponibilidade ENABLE ROW LEVEL SECURITY;

-- Anyone authenticated can see disponibilidade
CREATE POLICY "Authenticated users can view disponibilidade" ON public.disponibilidade
  FOR SELECT TO authenticated USING (true);

-- Users can insert their own
CREATE POLICY "Users can insert own disponibilidade" ON public.disponibilidade
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

-- Users can delete their own
CREATE POLICY "Users can delete own disponibilidade" ON public.disponibilidade
  FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- Admins can delete any
CREATE POLICY "Admins can delete any disponibilidade" ON public.disponibilidade
  FOR DELETE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

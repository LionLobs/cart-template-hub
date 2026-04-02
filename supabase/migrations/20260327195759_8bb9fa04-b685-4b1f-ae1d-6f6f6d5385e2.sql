
-- Table for notice board (quadro de avisos)
CREATE TABLE public.avisos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mensagem text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE
);

ALTER TABLE public.avisos ENABLE ROW LEVEL SECURITY;

-- Everyone authenticated can read
CREATE POLICY "Avisos are viewable by all authenticated users"
  ON public.avisos FOR SELECT TO authenticated
  USING (true);

-- Only admins can insert
CREATE POLICY "Admins can insert avisos"
  ON public.avisos FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- Only admins can delete
CREATE POLICY "Admins can delete avisos"
  ON public.avisos FOR DELETE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

-- Enable realtime for avisos
ALTER PUBLICATION supabase_realtime ADD TABLE public.avisos;

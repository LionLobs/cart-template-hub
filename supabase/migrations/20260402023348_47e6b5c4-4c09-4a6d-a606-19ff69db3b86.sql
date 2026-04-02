
ALTER TABLE public.agendamentos DROP CONSTRAINT agendamentos_local_check;
ALTER TABLE public.agendamentos ADD CONSTRAINT agendamentos_local_check CHECK (local IN ('Carrinho', 'Areias', 'Armação', 'Display'));

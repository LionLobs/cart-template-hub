-- Remove all existing admin roles
DELETE FROM public.user_roles WHERE role = 'admin';

-- Assign admin to the new user
INSERT INTO public.user_roles (user_id, role)
VALUES ('cdcb45f1-6127-4698-8fe2-aefeff0bbe9e', 'admin')
ON CONFLICT (user_id, role) DO NOTHING;
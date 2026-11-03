-- INTERACTIVE LENS LAB: production-oriented Supabase schema
-- Run in a NEW Supabase project and test with separate student/teacher accounts.
create extension if not exists pgcrypto;

create table public.classrooms (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  grade text not null,
  created_at timestamptz not null default now()
);

create table public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('teacher','student')),
  display_name text not null,
  created_at timestamptz not null default now()
);

create table public.students (
  id uuid primary key default gen_random_uuid(),
  user_id uuid unique not null references auth.users(id) on delete cascade,
  student_code text unique not null,
  full_name text not null,
  grade text not null,
  room text not null,
  student_number integer,
  classroom_id uuid not null references public.classrooms(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table public.teacher_classrooms (
  teacher_user_id uuid not null references public.profiles(user_id) on delete cascade,
  classroom_id uuid not null references public.classrooms(id) on delete cascade,
  primary key (teacher_user_id, classroom_id)
);

create table public.lessons (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  title text not null,
  content jsonb not null default '{}'::jsonb,
  published boolean not null default true
);

create table public.experiments (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  title text not null,
  lens_type text not null check (lens_type in ('convex','concave'))
);

create table public.experiment_records (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  experiment_id uuid references public.experiments(id) on delete set null,
  lens_type text not null check (lens_type in ('convex','concave')),
  object_distance numeric not null check (object_distance > 0),
  focal_length numeric not null,
  image_distance numeric,
  magnification numeric,
  image_type text,
  image_orientation text,
  image_size text,
  observation text,
  created_at timestamptz not null default now()
);

create table public.quiz_results (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  quiz_slug text not null,
  phase text not null check (phase in ('pre','post','practice')),
  score numeric not null check (score >= 0),
  max_score numeric not null check (max_score > 0),
  answers jsonb not null default '[]'::jsonb,
  submitted_at timestamptz not null default now()
);

create table public.activity_submissions (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  activity_slug text not null,
  answers jsonb not null default '{}'::jsonb,
  submitted_at timestamptz not null default now()
);

create table public.learning_progress (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  lesson_slug text not null,
  completed boolean not null default false,
  progress_percent integer not null default 0 check (progress_percent between 0 and 100),
  updated_at timestamptz not null default now(),
  unique(student_id, lesson_slug)
);

create index experiment_records_student_time_idx
  on public.experiment_records(student_id, created_at desc);
create index quiz_results_student_time_idx
  on public.quiz_results(student_id, submitted_at desc);
create index activity_submissions_student_time_idx
  on public.activity_submissions(student_id, submitted_at desc);

-- Security-definer helpers avoid recursive RLS policy lookups.
create or replace function public.is_teacher()
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid() and p.role = 'teacher'
  );
$$;

create or replace function public.is_student_of(p_student_id uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.students s
    where s.id = p_student_id and s.user_id = auth.uid()
  );
$$;

create or replace function public.teacher_can_access_student(p_student_id uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.students s
    join public.teacher_classrooms tc on tc.classroom_id = s.classroom_id
    where s.id = p_student_id and tc.teacher_user_id = auth.uid()
  );
$$;

alter table public.profiles enable row level security;
alter table public.classrooms enable row level security;
alter table public.students enable row level security;
alter table public.teacher_classrooms enable row level security;
alter table public.lessons enable row level security;
alter table public.experiments enable row level security;
alter table public.experiment_records enable row level security;
alter table public.quiz_results enable row level security;
alter table public.activity_submissions enable row level security;
alter table public.learning_progress enable row level security;

-- Profiles: users read only their own profile; teacher profile provisioning is admin-side.
create policy "profile_select_self" on public.profiles
for select to authenticated using (user_id = auth.uid());

-- Classroom metadata is visible to assigned teachers and students belonging to it.
create policy "classroom_select_member" on public.classrooms
for select to authenticated using (
  exists(select 1 from public.students s where s.classroom_id = classrooms.id and s.user_id = auth.uid())
  or exists(select 1 from public.teacher_classrooms tc where tc.classroom_id = classrooms.id and tc.teacher_user_id = auth.uid())
);

create policy "student_select_self_or_assigned_teacher" on public.students
for select to authenticated using (
  user_id = auth.uid() or public.teacher_can_access_student(id)
);

create policy "teacher_select_own_assignments" on public.teacher_classrooms
for select to authenticated using (teacher_user_id = auth.uid());

create policy "published_lessons_read" on public.lessons
for select to authenticated using (published = true);

create policy "experiments_read_authenticated" on public.experiments
for select to authenticated using (true);

create policy "experiment_select_student_or_teacher" on public.experiment_records
for select to authenticated using (
  public.is_student_of(student_id) or public.teacher_can_access_student(student_id)
);
create policy "experiment_insert_student_self" on public.experiment_records
for insert to authenticated with check (public.is_student_of(student_id));

create policy "quiz_select_student_or_teacher" on public.quiz_results
for select to authenticated using (
  public.is_student_of(student_id) or public.teacher_can_access_student(student_id)
);
create policy "quiz_insert_student_self" on public.quiz_results
for insert to authenticated with check (public.is_student_of(student_id));

create policy "activity_select_student_or_teacher" on public.activity_submissions
for select to authenticated using (
  public.is_student_of(student_id) or public.teacher_can_access_student(student_id)
);
create policy "activity_insert_student_self" on public.activity_submissions
for insert to authenticated with check (public.is_student_of(student_id));

create policy "progress_select_student_or_teacher" on public.learning_progress
for select to authenticated using (
  public.is_student_of(student_id) or public.teacher_can_access_student(student_id)
);
create policy "progress_insert_student_self" on public.learning_progress
for insert to authenticated with check (public.is_student_of(student_id));
create policy "progress_update_student_self" on public.learning_progress
for update to authenticated using (public.is_student_of(student_id))
with check (public.is_student_of(student_id));

-- No public insert/update/delete policies for student roster or teacher assignments.
-- Create Auth users and their profile/roster rows through a trusted admin process only.
-- Never expose the Supabase service_role key in frontend code.

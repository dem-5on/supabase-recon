import re

# Supabase project URL
SUPABASE_URL_RE = re.compile(r"https://([a-zA-Z0-9]+)\.supabase\.co")

# JWT — anon / service-role keys
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")

# Supabase JS SDK initialisation
CREATE_CLIENT_RE = re.compile(r"createClient\s*\(")

# Inline key=value config leaks
INLINE_CONFIG_RE = re.compile(
    r'(?:supabaseUrl|supabaseKey|SUPABASE_URL|SUPABASE_ANON_KEY)\s*[=:]\s*["\']([^"\']+)["\']'
)

# Headers that fingerprint a PostgREST / Supabase backend
SUPABASE_HEADERS: set[str] = {"server", "x-powered-by"}
POSTGREST_VALUES: set[str] = {"postgrest", "supabase"}

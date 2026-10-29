#!/bin/sh
# Real-Koel first-run setup, run once per version container via `docker compose exec`.
# Initialises the sqlite-persistent DB through Koel's OWN koel:init wizard (migrations +
# default admin), then provisions a real NON-admin "listener" account. Idempotent.
set -e
cd /var/www/html

touch database/koel.sqlite
# koel:init: migrate + seed + create default admin (admin@koel.dev / KoelIsCool).
php artisan koel:init --no-assets --no-interaction >/tmp/koel_init.log 2>&1 || \
  php artisan koel:init --no-assets --no-interaction

# Provision a real, authenticated, NON-admin user via Koel's own models.
php artisan tinker --execute='
$email="listener@pcb.test"; $pw="ListenerPass123";
$u = App\Models\User::firstWhere("email",$email);
if(!$u){
  $data=["email"=>$email,"name"=>"listener","password"=>Illuminate\Support\Facades\Hash::make($pw)];
  try { $data["organization_id"]=App\Models\Organization::default()->id; } catch (\Throwable $e){}
  $u = App\Models\User::query()->create($data);
}
$nonadmin="unknown";
try { $u->syncRoles(App\Enums\Acl\Role::USER); $nonadmin=$u->fresh()->role->value; }
catch (\Throwable $e){ try { $u->is_admin=false; $u->save(); $nonadmin="is_admin=0"; } catch(\Throwable $e2){} }
echo "USER_READY ".$email." role=".$nonadmin."\n";
'

# Apache runs as www-data; the sqlite DB + storage must be writable by it (token issue,
# episode cache, downloaded episode file).
chown -R www-data:www-data database storage
echo "SETUP_DONE"

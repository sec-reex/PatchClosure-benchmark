#!/bin/sh
# Real-Koel first-run setup. Idempotent. Copied into the official phanan/koel
# container by start.sh / reset.sh. koel:init also runs from the image entrypoint;
# this re-runs it and provisions the non-admin listener used by verify.
set -e
cd /var/www/html

mkdir -p database storage
touch database/koel.sqlite
php artisan koel:init --no-assets --no-interaction >/tmp/koel_init.log 2>&1 || \
  php artisan koel:init --no-assets --no-interaction

php artisan tinker --execute='
$email="listener@pcb.test"; $pw="ListenerPass123";
$u = App\Models\User::firstWhere("email",$email);
if(!$u){
  $data=["email"=>$email,"name"=>"listener","password"=>Illuminate\Support\Facades\Hash::make($pw)];
  try { $data["organization_id"]=App\Models\Organization::default()->id; } catch (\Throwable $e){}
  $u = App\Models\User::query()->create($data);
}
try { $u->syncRoles(App\Enums\Acl\Role::USER); }
catch (\Throwable $e){ try { $u->is_admin=false; $u->save(); } catch(\Throwable $e2){} }
echo "USER_READY\n";
'

chown -R www-data:www-data database storage
echo "SETUP_DONE"

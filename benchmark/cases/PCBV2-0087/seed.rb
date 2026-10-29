# Idempotent seed run via `rails runner`. Creates ONE site (=> current_site == Site.first),
# an admin + a low-privilege 'client' user, and sets the media-storage backend per BACKEND env.
backend = ENV.fetch('BACKEND', 'local')   # 'local' or 's3'

site = CamaleonCms::Site.first
unless site
  site = CamaleonCms::Site.create!(name: 'PCB', slug: 'localhost', description: 'PatchClosure-Bench')
end
puts "SITE id=#{site.id} slug=#{site.slug}"

def upsert_user(site, username, email, password, role)
  u = site.users.find_by_username(username)
  unless u
    u = site.users.create!(username: username, email: email, first_name: username.capitalize,
                           password: password, password_confirmation: password, role: role)
  end
  # Always (re)assert the credentials so a boot is deterministic regardless of any create-time hook.
  u.role = role
  u.password = password
  u.password_confirmation = password
  u.save!
  ok = u.reload.authenticate(password) ? 'OK' : 'FAIL'
  puts "USER #{u.username} role=#{u.role} id=#{u.id} auth=#{ok}"
end

upsert_user(site, 'admin',   'admin@pcb.test',   'AdminPass123!', 'admin')
upsert_user(site, 'lowpriv', 'lowpriv@pcb.test', 'LowPass123!',   'client')  # registered low-priv user

if backend == 's3'
  site.set_option('filesystem_type', 's3')
  site.set_option('filesystem_region', ENV.fetch('AWS_REGION', 'us-east-1'))
  site.set_option('filesystem_s3_access_key', ENV.fetch('AWS_ACCESS_KEY_ID', 'minioadmin'))
  site.set_option('filesystem_s3_secret_key', ENV.fetch('AWS_SECRET_ACCESS_KEY', 'minioadmin'))
  site.set_option('filesystem_s3_bucket_name', ENV.fetch('S3_BUCKET', 'camaleon'))
  # Ensure the minio bucket exists so enable_private_mode!/setup_private_folder succeeds.
  # NOTE: minio rejects Host headers containing '_' ("invalid hostname"); use an
  # underscore-free endpoint host (e.g. alias 'minio'). Avoid bucket.exists? (HEAD => BadRequest on minio).
  require 'aws-sdk-s3'
  c = Aws::S3::Client.new
  begin
    c.create_bucket(bucket: ENV.fetch('S3_BUCKET', 'camaleon'))
  rescue Aws::S3::Errors::BucketAlreadyOwnedByYou, Aws::S3::Errors::BucketAlreadyExists
  end
  puts "BACKEND=s3 bucket=#{ENV.fetch('S3_BUCKET', 'camaleon')} endpoint=#{ENV['AWS_ENDPOINT']}"
else
  site.set_option('filesystem_type', 'local')
  puts 'BACKEND=local'
end

puts "FILESYSTEM_TYPE=#{site.get_option('filesystem_type')}"
puts 'SEED_DONE'

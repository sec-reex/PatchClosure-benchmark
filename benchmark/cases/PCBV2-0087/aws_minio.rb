# Point aws-sdk-s3 at a minio (S3-compatible) endpoint when AWS_ENDPOINT is set.
# CamaleonCmsAwsUploader#bucket calls Aws.config.update({region, credentials}); .update MERGES,
# so these endpoint/path-style keys survive.
if ENV['AWS_ENDPOINT'].present?
  require 'aws-sdk-s3'
  Aws.config.update(
    endpoint: ENV['AWS_ENDPOINT'],
    force_path_style: true,
    region: ENV.fetch('AWS_REGION', 'us-east-1'),
    credentials: Aws::Credentials.new(
      ENV.fetch('AWS_ACCESS_KEY_ID', 'minioadmin'),
      ENV.fetch('AWS_SECRET_ACCESS_KEY', 'minioadmin')
    )
  )
end

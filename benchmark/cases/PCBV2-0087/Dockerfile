# Real Camaleon CMS per version (gem-pinned) on Rails, sqlite DB, aws-sdk-s3 -> minio.
# One image per CAMALEON_VERSION; the same image is run as a LOCAL-backend or S3-backend
# site by the BACKEND env at container start (entrypoint seeds a fresh DB each boot).
FROM ruby:3.3-bookworm

ARG CAMALEON_VERSION
ARG RAILS_VERSION=7.1.5
ENV CAMALEON_VERSION=${CAMALEON_VERSION} \
    RAILS_ENV=development \
    BUNDLE_JOBS=4 \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      imagemagick libmagickwand-dev libsqlite3-dev libvips build-essential git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN gem install rails -v "${RAILS_VERSION}" --no-document

# Generate a fresh Rails app skeleton (sprockets asset pipeline retained for Camaleon).
RUN rails _${RAILS_VERSION}_ new app -d sqlite3 --skip-git --skip-test \
      --skip-action-cable --skip-hotwire --skip-jbuilder --skip-kamal --skip-solid \
    || rails _${RAILS_VERSION}_ new app -d sqlite3 --skip-git --skip-test --skip-action-cable

WORKDIR /build/app

# Pin the exact Camaleon gem version under test (puma + sqlite3 already in the generated Gemfile).
# Replace the generated rails '~> 7.1.5' with an exact pin (bundle otherwise floats to 7.1.6+)
# and cap cama_contact_form (0.1.15+ requires camaleon_cms >= 2.9.4, breaking 2.8.x builds).
RUN sed -i "s/gem ['\"]rails['\"].*/gem 'rails', '= ${RAILS_VERSION}'/" Gemfile \
    && printf "\ngem 'camaleon_cms', '= %s'\n" "${CAMALEON_VERSION}" >> Gemfile \
    && printf "\ngem 'cama_contact_form', '= 0.1.13'\n" >> Gemfile \
    && bundle install

# Camaleon install generator (non-interactive) + copy engine migrations into the app.
RUN yes | bundle exec rails generate camaleon_cms:install \
    && bundle exec rake camaleon_cms:generate_migrations

# Allow any Host header in dev + point aws-sdk at the minio endpoint when provided.
RUN printf "Rails.application.config.hosts.clear\n" > config/initializers/zz_allow_hosts.rb
COPY aws_minio.rb config/initializers/aws_minio.rb

COPY seed.rb /build/app/seed.rb
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM ruby:3.2-slim
ARG RACK_VERSION
WORKDIR /app
# Install the REAL published Rack gem at the pinned version (build-arg per profile) plus a real
# HTTP server (webrick) and its rackup handler. No vendored/edited Rack source.
RUN gem install rack -v "${RACK_VERSION}" --no-document && \
    gem install webrick -v "1.8.1" --no-document && \
    gem install rackup -v "2.1.0" --no-document && \
    ruby -e "require 'rack'; require 'rack/files'; loc = Rack::Files.instance_method(:call).source_location[0]; abort('not gem') unless loc.include?('/gems/rack-'); puts 'rack ' + Rack.release.to_s; puts 'Rack::Files ' + loc"
COPY app/ /app/
ENV DATA_DIR=/data FILE_SIZE=900000 PORT=3000
EXPOSE 3000
# A REAL running Rack web app: WEBrick serves Rack::Files; GET /file honours the Range header.
CMD ["ruby", "/app/server.rb"]

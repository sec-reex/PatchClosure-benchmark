# Shared per-version image for deser_yii2_behavior_typecheck (CVE-2024-4990 -> CVE-2024-58136).
# Recipe only (NO vendored source): composer pulls the EXACT published yiisoft/yii2 at a pinned
# version (build-arg YII_VER) from Packagist, then a REAL, unmodified Yii2 web app is served by the
# PHP built-in web server. External HTTP `POST /trigger` mass-assigns the request body onto a
# yii\base\Component, driving the REAL, unmodified yii\base\Component::__set() 'as <name>'
# object-injection sink. yii2's bower-asset hard-deps are resolved via the asset-packagist repository.
FROM php:8.1-cli
ARG YII_VER
ENV COMPOSER_ALLOW_SUPERUSER=1

# Pin Composer 2.7: latest composer:2 rejects `allow-plugins true` as a scalar
# and `composer config -g repositories.*` without a project file.
COPY --from=composer:2.7.9 /usr/bin/composer /usr/bin/composer
RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY composer.json /work/composer.json
# Whole published yiisoft/yii2 from Packagist. YII_VER overrides the placeholder.
RUN composer config --no-interaction allow-plugins.yiisoft/yii2-composer true \
 && composer config --no-interaction allow-plugins.composer/installers true \
 && composer config --no-interaction allow-plugins.oomphinc/composer-installers-extender true \
 && composer require --no-interaction --no-progress --no-audit --prefer-dist \
      oomphinc/composer-installers-extender:^2.0 "yiisoft/yii2:${YII_VER}"

# The REAL Yii2 web app (entry script, config, controller, benign canary classes).
COPY app/ /work/app/

EXPOSE 8080

# Plant the rce-oob (read/exfil) canary OUTSIDE the app dir at RUNTIME, then serve the REAL Yii2 app
# on the PHP built-in web server so an EXTERNAL HTTP request can drive `POST /trigger`.
CMD ["sh","-c","mkdir -p /canary && printf '%s\\n' \"$PCB_FLAG\" > /canary/flag.txt && chmod 644 /canary/flag.txt && exec php -S 0.0.0.0:8080 -t /work/app/web /work/app/web/router.php"]

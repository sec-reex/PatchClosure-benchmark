# Faithful-core harness image (shared by v0/v1/v2; behaviour selected by PCB_VER).
FROM php:8.2-cli
RUN docker-php-ext-install pdo pdo_mysql >/dev/null
WORKDIR /app
COPY harness/ /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
CMD ["/app/entrypoint.sh"]

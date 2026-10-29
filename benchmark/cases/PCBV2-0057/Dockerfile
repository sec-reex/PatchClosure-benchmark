# PatchClosure-Bench: cpp-httplib CRLF response-header-injection SUT
# Builds a real HTTP server against the REAL httplib.h at a pinned release tag.
FROM gcc:12

ARG HTTPLIB_TAG
RUN test -n "$HTTPLIB_TAG"

WORKDIR /app

# Fetch the REAL, published httplib.h bytes for the requested release tag.
ADD https://raw.githubusercontent.com/yhirose/cpp-httplib/${HTTPLIB_TAG}/httplib.h /app/httplib.h
RUN test -s /app/httplib.h && grep -q "CPPHTTPLIB_HTTPLIB_H" /app/httplib.h

COPY server.cpp /app/server.cpp
# Header-only, no OpenSSL/zlib features enabled -> plain C++11 build.
RUN g++ -std=c++11 -O2 -pthread server.cpp -o /app/server

ENV PORT=8080
EXPOSE 8080
CMD ["/app/server"]

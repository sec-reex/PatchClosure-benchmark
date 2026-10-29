# Real-library-wrap image for the `compressing` npm tar-extraction zip-slip incomplete-fix
# (CVE-2026-24884 -> CVE-2026-40931). One image, three roles selected by HARNESS_VER.
#
# The three published npm versions are installed SIDE-BY-SIDE via npm aliases (see package.json):
#   comp_v0 = compressing@2.0.0  (V0, no path validation: path.join(destDir, header.name))
#   comp_v1 = compressing@2.1.0  (V1 TARGET, CVE-2026-24884 fix: isPathWithinParent STRING validation)
#   comp_v2 = compressing@2.1.1  (V2, CVE-2026-40931 fix: isRealPathSafe() recursive lstat walk)
# so the service imports the EXACT published bytes of the real extractor for the chosen version. The
# extraction itself (compressing.tar.uncompress) is 100% the real library -- no reimplementation.
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY service.mjs /app/
EXPOSE 8080
CMD ["node", "/app/service.mjs"]

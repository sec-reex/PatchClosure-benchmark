ARG TOMCAT_TAG=9.0.34-jdk8-openjdk
FROM tomcat:${TOMCAT_TAG}

# Copy and compile the benign deserialization gadget
COPY gadget/BenignMarker.java /tmp/build/BenignMarker.java
COPY gadget/SerializeGadget.java /tmp/build/SerializeGadget.java
RUN mkdir -p /opt/pcb && \
    javac /tmp/build/BenignMarker.java -d /usr/local/tomcat/lib/ && \
    javac -cp /usr/local/tomcat/lib/:/tmp/build/ /tmp/build/SerializeGadget.java -d /tmp/build/ && \
    java -cp /usr/local/tomcat/lib/:/tmp/build/ SerializeGadget /opt/pcb/payload.session && \
    rm -rf /tmp/build

# Install PersistentManager + FileStore context config
COPY context.xml /usr/local/tomcat/conf/context.xml

# Remove default webapps except ROOT; install marker.jsp for reading canary
RUN rm -rf /usr/local/tomcat/webapps/docs \
           /usr/local/tomcat/webapps/examples \
           /usr/local/tomcat/webapps/host-manager \
           /usr/local/tomcat/webapps/manager
COPY marker.jsp /usr/local/tomcat/webapps/ROOT/marker.jsp

# Install entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]

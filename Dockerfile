# Use your favorite image
FROM debian:bookworm
ARG S6_OVERLAY_VERSION=3.2.0.0

RUN apt-get update && apt-get install -y apache2 libapache2-mod-security2 vim curl wget sudo iproute2 xz-utils gpg unzip jq

# install jdk8
RUN wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk/8u412-b08/openlogic-openjdk-8u412-b08-linux-x64-deb.deb
#RUN wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk/8u422-b05/openlogic-openjdk-8u422-b05-linux-x64-deb.deb
RUN apt install -y ./openlogic-openjdk-8u412-b08-linux-x64-deb.deb
#RUN apt install -y ./openlogic-openjdk-8u422-b05-linux-x64-deb.deb
RUN rm openlogic-openjdk-8u412-b08-linux-x64-deb.deb
#RUN rm openlogic-openjdk-8u422-b05-linux-x64-deb.deb

# install ofbiz
RUN wget https://mirror.csclub.uwaterloo.ca/apache/ofbiz/apache-ofbiz-18.12.14.zip
RUN unzip apache-ofbiz-18.12.14.zip 
RUN mv apache-ofbiz-18.12.14 /opt
RUN rm apache-ofbiz-18.12.14.zip
RUN ln -s /opt/apache-ofbiz-18.12.14 /opt/ofbiz
RUN useradd -M -d /opt/ofbiz ofbiz
RUN chown -R ofbiz:ofbiz /opt/apache-ofbiz-18.12.14
RUN cd /opt/ofbiz/ && su - ofbiz -c "./gradle/init-gradle-wrapper.sh"
RUN cd /opt/ofbiz/ && su - ofbiz -c "./gradlew cleanAll loadAll"
COPY ./data/derby/ /opt/ofbiz/runtime/data/derby/
RUN chown -R ofbiz:ofbiz /opt/apache-ofbiz-18.12.14/runtime/data

# install wazuh manager
RUN apt-get -y install gnupg apt-transport-https
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt update
RUN apt-get -y install wazuh-manager
#RUN apt-get -y install filebeat
RUN mv /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.old
COPY --chmod=660 --chown=root:wazuh ./config/ossec.conf /var/ossec/etc/ossec.conf
COPY --chmod=660 --chown=root:wazuh ./config/custom_rules.xml /var/ossec/etc/rules/

# install apache + ofbiz site
COPY ./config/ofbiz.conf /etc/apache2/sites-available/
RUN a2enmod proxy_http ssl security2 headers
RUN a2ensite ofbiz

# enable mod security
RUN mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
RUN wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
RUN tar xvf v3.3.0.tar.gz
RUN rm v3.3.0.tar.gz
RUN mkdir /etc/apache2/modsecurity-crs/
RUN mv coreruleset-3.3.0/ /etc/apache2/modsecurity-crs/
RUN mv /etc/apache2/modsecurity-crs/coreruleset-3.3.0/crs-setup.conf.example /etc/apache2/modsecurity-crs/coreruleset-3.3.0/crs-setup.conf
COPY config/security2.conf /etc/apache2/mods-enabled/
RUN sed -i 's/SecAuditLog/#SecAuditLog/g' /etc/modsecurity/modsecurity.conf

# install checkscript urandom
RUN mknod -m 444 /root/urandom_host c 1 9

# ssh stuff
RUN mkdir -p /root/.ssh
#COPY ./config/authorized_keys /root/.ssh/
RUN chmod 700 /root/.ssh
#RUN chmod 600 /root/.ssh/authorized_keys
RUN mkdir /var/run/sshd
RUN chmod 0755 /var/run/sshd

# log directory stuff
RUN mkdir -p /var/log/ids/
#RUN mv /var/ossec/logs/ /var/log/ids/ossec #this does not work since ossec is jailed
#RUN ln -s /var/log/ids/ossec /var/ossec/logs #see above
RUN mv /var/log/apache2 /var/log/ids/
RUN ln -s /var/log/ids/apache2/ /var/log/apache2
RUN mv /opt/ofbiz/runtime/logs/ /var/log/ids/ofbiz
RUN ln -s /var/log/ids/ofbiz/ /opt/ofbiz/runtime/logs

# snoopy and some etc configs
RUN apt-get -y install snoopy logrotate xinetd
COPY ./config/etc/ /etc/

COPY --chmod=750 ./flagcheck.sh /root/

#CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
#COPY --chmod=750 healthcheck.sh /root/
#HEALTHCHECK --interval=2s --start-period=5s --retries=1 CMD /root/healthcheck.sh

COPY --chmod=750 ./init.sh /root/
COPY --chmod=750 ./check-size2.sh /root/

ENTRYPOINT ["/root/init.sh"]

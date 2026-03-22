FROM quay.io/pypa/manylinux2014_x86_64

COPY redhat/fix-yum-repos-after-centos-7-eol.sh ./

RUN ./fix-yum-repos-after-centos-7-eol.sh && \
    yum install -y epel-release centos-release-scl && \
    ./fix-yum-repos-after-centos-7-eol.sh && \
    yum clean all && \
    rm -rf /var/yum/cache

COPY redhat/rpms.txt /tmp/

RUN xargs --arg-file /tmp/rpms.txt yum install -y && yum clean all && rm -rf /var/yum/cache

ENV CC=/opt/rh/devtoolset-11/root/usr/bin/gcc

COPY . /marine

WORKDIR /build

RUN cmake3 -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_LTO=ON -DLUAJIT=ON -GNinja /marine && ninja

FROM quay.io/pypa/manylinux2014_x86_64

COPY redhat/rpms.txt /tmp/

RUN xargs --arg-file /tmp/rpms.txt yum install -y && yum clean all && rm -rf /var/yum/cache

ENV CC=/opt/rh/devtoolset-9/root/usr/bin/gcc

COPY . /marine

WORKDIR /build

RUN cmake3 -DCMAKE_INSTALL_PREFIX=/usr -DLUAJIT=ON -GNinja /marine && ninja

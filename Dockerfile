FROM ubuntu:jammy
RUN apt update && apt install -y curl python3 python3-pip mingw-w64=8.0.0-1
RUN apt install -y wget git
RUN wget https://nim-lang.org/choosenim/init.sh && CHOOSENIM_CHOOSE_VERSION=1.6.2 bash init.sh -y
ENV PATH=/root/.nimble/bin:$PATH
RUN nimble install -y nimcrypto@0.6.0 docopt ptr_math winim https://github.com/S3cur3Th1sSh1t/nim-strenc/
RUN cd /opt/ && git clone https://github.com/S4ntiagoP/donut --branch syscalls && cd donut && make
ENV PATH=/opt/donut/:$PATH
ADD . /opt/packer
WORKDIR /opt/packer
RUN nim c -d:noRES NimSyscallLoader.nim
RUN mkdir /shared
ENTRYPOINT ["/opt/packer/NimSyscallLoader"]

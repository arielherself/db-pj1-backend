FROM arielherself/build-boost:1.85.0 as builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install libpq-dev cmake -y
RUN apt clean
WORKDIR /bserv
ADD . /bserv
WORKDIR /bserv/dependencies/cryptopp
RUN make -j8
WORKDIR /bserv/dependencies/libpqxx
RUN ./configure
RUN make -j8
WORKDIR /bserv
RUN mkdir build
WORKDIR /bserv/build
RUN cmake ..
RUN ldconfig
RUN cmake --build . -j8

FROM arielherself/build-boost:1.85.0
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN mkdir /bserv
COPY --from=builder /bserv/build /bserv
WORKDIR /bserv/WebApp
CMD ./WebApp /data/config.json

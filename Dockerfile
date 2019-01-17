FROM golang:1.10

RUN DEBIAN_FRONTEND=noninteractive \
	apt update && apt install -y \
		automake \
		bison \
		help2man \
		m4 \
		texinfo \
		texlive

RUN go get golang.org/x/tools/cmd/goyacc
RUN go get github.com/pebbe/flexgo/...

ENV FLEXGO=/go/src/github.com/pebbe/flexgo

RUN cd ${FLEXGO} && ./configure && cd -
RUN make -C ${FLEXGO} && make -C ${FLEXGO} install
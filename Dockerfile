FROM daocloud.io/centos:7 as builder
RUN yum install -y gcc-c++

ENV PATH /usr/local/go/bin:$PATH
ENV GOROOT /usr/local/go
ENV GOPATH /home/go
ENV GOPROXY=https://goproxy.cn

RUN yum -y install wget \
    && mkdir /home/go \
    && wget https://studygolang.com/dl/golang/go1.17.8.linux-amd64.tar.gz \
    && tar -C /usr/local -zxf go1.17.8.linux-amd64.tar.gz


COPY . /home/go/pmu_exporter/
WORKDIR /home/go/pmu_exporter/
RUN CGO_ENABLED=1 go build -ldflags "-s -w" -o pmu_exporter
RUN ["chmod", "+x", "/home/go/pmu_exporter/pmu_exporter"]
CMD ["/home/go/pmu_exporter/pmu_exporter"]

FROM daocloud.io/centos:7 as runner
COPY --from=builder /home/go/pmu_exporter/pmu_exporter /usr/local/pmu_exporter

RUN ["chmod", "+x", "/usr/local/pmu_exporter"]
CMD ["/usr/local/pmu_exporter"]
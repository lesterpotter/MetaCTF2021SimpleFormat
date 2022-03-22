FROM debian:buster-20200803

RUN apt-get update -y 
RUN apt-get install xinetd -y
RUN apt-get install gdbserver -y


RUN mkdir -p /fundamentals

ADD fundamentals.sh /fundamentals
ADD fundamentals.gdb.sh /fundamentals
ADD fundamentals /fundamentals
ADD flag.txt /fundamentals
ADD flag2.txt /fundamentals
ADD init.sh /bin
ADD fundamentals.xinetd /etc/xinetd.d/fundamentals
ADD fundamentals.gdb.xinetd /etc/xinetd.d/fundamentals_gdb

RUN groupadd -r fundamentals && useradd -r -g fundamentals fundamentals && \
    chown -R root:fundamentals /fundamentals && \
    chmod 750 /fundamentals/fundamentals.sh && \
    chmod 750 /fundamentals/fundamentals.gdb.sh && \
    chmod 750 /fundamentals/fundamentals && \
    chmod 440 /fundamentals/flag.txt && \
    chmod 440 /fundamentals/flag2.txt && \
    chmod 700 /bin/init.sh

RUN service xinetd restart

EXPOSE 4444
EXPOSE 3006
EXPOSE 3005
ENTRYPOINT [ "/bin/init.sh" ]


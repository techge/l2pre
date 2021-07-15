FROM python:3.8-buster

WORKDIR /l2pre

# install missing system deps
# tshark installation includes interactive question, thus using DEBIAN_FRONTEND var to prevent this
RUN echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections -
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcap-dev \
    tshark

# pylstar and numpy should be installed by netzob, but pip fails to install it there somehow :shrug:
RUN pip3 install pylstar==0.1.2 numpy==1.20.2

# install netzob
COPY src/netzob-src netzob-src
RUN cd netzob-src/netzob && \
    python3 setup.py install && \
    cd ../..

# install modules needed by nemere
COPY src/nemesys/requirements.txt nemesys-requirements.txt
RUN pip3 install -r nemesys-requirements.txt

# finally install our required python modules
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# create input and output folder
RUN mkdir input output

# copy complete src folder only now, to prevent regular trigger of pip installs
COPY src .

# create user and add them to wireshark group
RUN useradd -ms /bin/bash user
RUN gpasswd -a user wireshark
USER user

# start in blank shell
CMD [ "/bin/bash" ]

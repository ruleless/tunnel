MAKE:=make
BIN:=/usr/local/bin
RM:=rm -f

TUN_LOCAL:=tun-local
TUN_REMOTE:=tun-remote

all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean

install-local:
	cp src/local $(BIN)/$(TUN_LOCAL)
	cp script/$(TUN_LOCAL) /etc/rc.d/init.d/$(TUN_LOCAL) && chmod 0775 /etc/rc.d/init.d/$(TUN_LOCAL)
	chkconfig --add $(TUN_LOCAL)

remote-local:
	-service $(TUN_LOCAL) stop
	-chkconfig --del $(TUN_LOCAL)
	-$(RM) /etc/rc.d/init.d/$(TUN_LOCAL)
	-$(RM) $(BIN)/$(TUN_LOCAL)

install-remote:
	cp src/remote $(BIN)/$(TUN_REMOTE)
	cp script/$(TUN_REMOTE) /etc/rc.d/init.d/$(TUN_REMOTE) && chmod 0775 /etc/rc.d/init.d/$(TUN_REMOTE)
	chkconfig --add $(TUN_REMOTE)

remote-remote:
	-service $(TUN_REMOTE) stop
	-chkconfig --del $(TUN_REMOTE)
	-$(RM) /etc/rc.d/init.d/$(TUN_REMOTE)
	-$(RM) $(BIN)/$(TUN_REMOTE)

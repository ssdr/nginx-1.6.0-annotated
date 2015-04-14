
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

install:
	$(MAKE) -f objs/Makefile install

upgrade:
	/data/liuyan/bin/nginx-1.6-bak//sbin/nginx -t

	kill -USR2 `cat /data/liuyan/bin/nginx-1.6-bak//logs/nginx.pid`
	sleep 1
	test -f /data/liuyan/bin/nginx-1.6-bak//logs/nginx.pid.oldbin

	kill -QUIT `cat /data/liuyan/bin/nginx-1.6-bak//logs/nginx.pid.oldbin`

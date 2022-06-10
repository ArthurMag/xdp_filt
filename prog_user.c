#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>

#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <arpa/inet.h>


const char *pin_basedir =  "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

void PrintHelp()
{
	printf("HELP:\n"
		"load:             Load filter\n"
		"unload:           Unload filter\n"
		"ip <ipname>:      Work with ipv4/ipv6 ip <ipname>\n"
		"port <portname>:  Work with UDP/TCP port <portname>\n"
		"help:             Show help\n");
	exit(1);
}

void PrintLoadHelp()
{
	printf("HELP:\n"
        	"interface <ifname>:      Load filter on <ifname> interface (required)\n"
        	"reuse_maps:              Reuse maps if exist\n"
		"help:                    Show help\n");
       // exit(1);
}

struct load_config {
	char interface[6];
	int ifindex;
	bool reuse_maps;
};

void do_load(int argc, char** argv){
	struct load_config l_cfg;
	l_cfg.ifindex = -1;
	l_cfg.reuse_maps = false;
	struct bpf_object *bpf_obj;
	struct bpf_map *map;
	char ifname[6];
	const char* const load_short_opts = "i:rh";
	struct option load_long_opts[] = {
            {"interface",  required_argument, NULL, 'i'},
            {"reuse_maps", no_argument,       NULL, 'r'},
            {"help",       no_argument,       NULL, 'h'},
            {NULL,         no_argument,       NULL,  0}
	};
	while (true)
	{
		int opt = getopt_long(argc, argv, load_short_opts, load_long_opts, NULL);
		if (-1 == opt)
        	break;
		switch (opt)
        	{
		case 'i':
			strcpy(ifname, optarg);
			int ifindex = if_nametoindex(ifname);
			if (ifindex > 0){
				strcpy(l_cfg.interface, optarg);
				l_cfg.ifindex = ifindex;
			}
			else { printf("Wrong interface name\n"); }
			break;
		case 'r':
			l_cfg.reuse_maps = true;
			break;
		case 'h':
			PrintLoadHelp();
			break;
		case '?':
			break;
		default:
			PrintLoadHelp();
			break;
		}
	}

	if (l_cfg.ifindex > 0) {
		char pin_map_path[PATH_MAX], check_map_path[PATH_MAX];
		struct xdp_program *prog = NULL;
		struct bpf_object *bpf_obj;
	        const char* filename = "prog_kern.o";
	        const char* progsec = "xdp_filter";
		struct bpf_map *map;
		int ret, err;

		prog = xdp_program__open_file(filename, progsec, NULL);
		bpf_obj = xdp_program__bpf_obj(prog);
		//ret = xdp_program__attach(prog, l_cfg.ifindex, XDP_MODE_SKB, 0);
		snprintf(pin_map_path, PATH_MAX, "%s/%s", pin_basedir, l_cfg.interface);

		if (!l_cfg.reuse_maps) {
			bpf_object__for_each_map(map, bpf_obj) {
				snprintf(check_map_path, PATH_MAX, "%s/%s", pin_map_path, bpf_map__name(map));
				printf("Map path: %s\n", check_map_path);
				if (access(check_map_path, F_OK) == 0) {
					err = bpf_object__unpin_maps(bpf_obj, pin_map_path);
				}
			}
			ret = xdp_program__attach(prog, l_cfg.ifindex, XDP_MODE_SKB, 0);
			printf("Loaded on %s\n", l_cfg.interface);
			err = bpf_object__pin_maps(bpf_obj, pin_map_path);
			if (err != 0) {
			printf("Failed to pin maps, err = %i\n", err);
			}
		}
		else {
		bpf_object__for_each_map(map, bpf_obj) {
			int len;
			int pinned_map_fd;
			char buf[PATH_MAX];
			len = snprintf(buf, PATH_MAX, "%s/%s", pin_map_path, bpf_map__name(map));
			pinned_map_fd = bpf_obj_get(buf);
			err = bpf_map__reuse_fd(map, pinned_map_fd);
			if (err != 0) {
				printf("Failed to reuse maps, fd = %i\n", pinned_map_fd);
				exit(1);
				}
			}
		ret = xdp_program__attach(prog, l_cfg.ifindex, XDP_MODE_SKB, 0);
		printf("Loaded on %s\n", l_cfg.interface);
		}
		xdp_program__close(prog);
	}
	exit(1);
}

void PrintUnloadHelp()
{
        printf("HELP:\n"
                "interface <ifname>:      Unload filter from <ifname> interface (required)\n"
                "id <id>:                 Unload prog with <id>\n"
		"all:                     Unload all progs\n"
                "help:                    Show help\n");
       // exit(1);
}

struct unload_config {
        char interface[6];
        int ifindex;
        int id;
};

void do_unload(int argc, char** argv) {
	struct unload_config ul_cfg;
	char ifname[6];
        ul_cfg.ifindex = -1;
        ul_cfg.id = -1;
	const char* const unload_short_opts = "i:d:ah";
        struct option unload_long_opts[] = {
            {"interface",  required_argument, NULL, 'i'},
            {"id",         required_argument, NULL, 'd'},
            {"all",        no_argument,       NULL, 'a'},
	    {"help",       no_argument,       NULL, 'h'},
            {NULL,         no_argument,       NULL,  0}
        };

	while (true)
	{
		int opt = getopt_long(argc, argv, unload_short_opts, unload_long_opts, NULL);
		if (-1 == opt)
			break;
		switch (opt)
		{
		case 'i':
			strcpy(ifname, optarg);
			int ifindex = if_nametoindex(ifname);
			if (ifindex > 0) {
				strcpy(ul_cfg.interface, ifname);
				ul_cfg.ifindex = ifindex;
			}
			else { printf("Wrong interface name\n"); }
			break;
		case 'd':
			ul_cfg.id = atoi(optarg);
			if (ul_cfg.id == 0) {
				printf("Wrong prog id!\n");
			}
			break;
		case 'a':
                        ul_cfg.id = 0;
                        break;

		case 'h':
			PrintUnloadHelp();
			break;
		case '?':
			break;
		default:
			PrintUnloadHelp();
			break;
		}
	}

	if (ul_cfg.ifindex > 0) {
		if (ul_cfg.id == -1){
		printf("Specify prog id or use --all\n");
		exit(1);
		}
		if (ul_cfg.id == 0){
			struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ul_cfg.ifindex);
			xdp_multiprog__detach(mp);
			}
		else {
			struct xdp_program *prog = NULL;
			printf("Prog id: %u\n", ul_cfg.id);
			prog = xdp_program__from_id(ul_cfg.id);
			xdp_program__detach(prog, ul_cfg.ifindex, XDP_MODE_SKB, 0);
		}
	}
	exit(1);
}

void PrintIpHelp()
{
        printf("HELP:\n"
		"interface <ifname>	  Use maps dedicated to <ifname> interface(required)\n"
                "ip <ip>:                 Work with <ip> ip(required)\n"
                "block:                   Block ip\n"
                "unblock:                 Unblock ip if blocked\n"
		"check:                   Check if ip is blocked\n"
		"dump:                    Show all blocked ip\n"
		"type:                    Specify ip as v4 or v6 (default v4)\n"
                "help:                    Show help\n");
       // exit(1);
}

struct ip_config {
        char interface[6];
        int ifindex;
        __u32 ip;
	uint8_t ip6[16];
	char action;
	int value;
	bool dump;
	int map_fd;
	int type;
};

void do_ip(int argc, char** argv) {
	struct ip_config ip_cfg;
        char ifname[6];
        ip_cfg.ifindex = -1;
        ip_cfg.ip = -1;
	ip_cfg.ip6[0] = -1;
	ip_cfg.value = -1;
	ip_cfg.dump = false;
	ip_cfg.map_fd = -1;
	ip_cfg.action = ' ';
	ip_cfg.type = 4;
	int err;
	char ip[INET6_ADDRSTRLEN];
	strncpy(ip, "", sizeof(ip));
        const char* const ip_short_opts = "i:p:b::ucdt:h";
        struct option ip_long_opts[] = {
            {"interface",  required_argument, NULL, 'i'},
            {"ip",         required_argument, NULL, 'p'},
            {"block",      optional_argument, NULL, 'b'},
            {"unblock",    no_argument,       NULL, 'u'},
	    {"check",      no_argument,       NULL, 'c'},
	    {"dump",       no_argument,       NULL, 'd'},
	    {"type",	   required_argument, NULL, 't'},
	    {"help",       no_argument,       NULL, 'h'},
            {NULL,         no_argument,       NULL,  0}
        };

	while (true)
        {
                int opt = getopt_long(argc, argv, ip_short_opts, ip_long_opts, NULL);
                if (-1 == opt)
                        break;
                switch (opt)
                {
                case 'i':
                        strcpy(ifname, optarg);
                        int ifindex = if_nametoindex(ifname);
                        if (ifindex > 0) {
                                strcpy(ip_cfg.interface, optarg);
                                ip_cfg.ifindex = ifindex;
                        }
                        else { printf("Wrong interface name\n"); }
                        break;
                case 'p':
			strncpy(ip, optarg, sizeof(ip));
			printf("Converted IP: %s\n", ip);
			break;
                case 'b':
			if (ip_cfg.action == ' ') {
				ip_cfg.action = 'b';
	                	if (optarg == NULL && optind < argc && argv[optind][0] != '-') {
					optarg = argv[optind++];
				}
			        if (optarg) {
	                                if (strcmp(optarg, "all") == 0) {
        	                                ip_cfg.value = 0;
                	                }
                        	        if (strcmp(optarg, "src") == 0) {
                                	        ip_cfg.value = 1;
                                	}
                               		if (strcmp(optarg, "dest") == 0) {
                                	        ip_cfg.value = 2;
                               		}
                        	}
				if (ip_cfg.value == -1) {
					ip_cfg.value = 0;
				}
			}
			else { printf("Block, unblock and check can not be used together\n"); }
                        break;
		case 'u':
			if (ip_cfg.action == ' ') {
                                ip_cfg.action = 'u';
                        }
                        else { printf("Unblock, block and check can not be used together\n"); }
                        break;
		case 'c':
			if (ip_cfg.action == ' ') {
                                ip_cfg.action = 'c';
                        }
                        else { printf("Check, block and unblock can not be used together\n"); }
                        break;
		case 'd':
			ip_cfg.dump = true;
                        break;
                case 't':
			if (strcmp(optarg, "6") == 0) {
				ip_cfg.type = 6;
			}
			else {
				if (strcmp(optarg, "4") == 0) {
					ip_cfg.type = 4;
				}
				else { printf("Wrong type optarg: %s", optarg); }
			}
			break;
		case 'h':
                        PrintIpHelp();
                        break;
                case '?':
                        break;
                default:
                        PrintIpHelp();
                        break;
                }
	}
	//printf("INFO: Interface %s\nIfindex %i\nIP %u\nAction %c\nValue %i\nDump %i\n", ip_cfg.interface, ip_cfg.ifindex, ip_cfg.ip, ip_cfg.action, ip_cfg.value, ip_cfg.dump);
	struct sockaddr_in sa_param;
	struct sockaddr_in6 sa6_param;
	char map_name[30];
	printf("IP: %s\n", ip);
	if (ip_cfg.type == 6) {
		strcpy(map_name, "blocked_ip6_map");
		if (strcmp(ip, "") != 0) {
			if (inet_pton(AF_INET6, ip, &(sa6_param.sin6_addr)) != 1) {
				printf("Error, not valid ipv6\n");
				exit(1);
			}
			for (int i = 0; i < 16; i++) {
				ip_cfg.ip6[i] = sa6_param.sin6_addr.s6_addr[i];
			}
			printf("\n");
		}
	}
	else {
		if (ip_cfg.type == 4) {
			strcpy(map_name, "blocked_ip4_map");
			if (strcmp(ip, "") != 0) {
				if (inet_pton(AF_INET, ip, &(sa_param.sin_addr)) != 1) {
					printf("Error, not valid ipv4\n");
					exit(1);
				}
				ip_cfg.ip = sa_param.sin_addr.s_addr;
				printf("The ip to use is %s/%u\n", ip, ip_cfg.ip);
			}
		}
		else { printf("Wrong --type argument, use '4' or '6'\n"); }
	}
	char map_path[PATH_MAX];
	snprintf(map_path, PATH_MAX, "%s/%s/%s", pin_basedir, ip_cfg.interface, map_name);
	if (access(map_path, F_OK) == 0) {
		ip_cfg.map_fd = bpf_obj_get(map_path);
		printf("Map fd: %i\n", ip_cfg.map_fd);
	}
	else {
		printf("Can't access ip map\n");
		exit(1);
		}
	//рассмотреть ошибки всякие

	if (strcmp(ip, "") != 0) {
		switch (ip_cfg.action) {
		case 'b':
			if (ip_cfg.ip != -1) {
				err = bpf_map_update_elem(ip_cfg.map_fd, &ip_cfg.ip, &ip_cfg.value, BPF_ANY);
			}
			else {err = bpf_map_update_elem(ip_cfg.map_fd, &ip_cfg.ip6, &ip_cfg.value, BPF_ANY); }
			break;
		case 'u':
			if (ip_cfg.ip != -1) {
				err = bpf_map_delete_elem(ip_cfg.map_fd, &ip_cfg.ip);
			}
			else {err = bpf_map_delete_elem(ip_cfg.map_fd, &ip_cfg.ip6); }
			break;
		case 'c':
			if (ip_cfg.ip != -1) {
				err = bpf_map_lookup_elem(ip_cfg.map_fd, &ip_cfg.ip, &ip_cfg.value);
			}
			else {err = bpf_map_lookup_elem(ip_cfg.map_fd, &ip_cfg.ip6, &ip_cfg.value); }
			if (err == 0) {
				printf("That ip is blocked\n");
			}
			else { printf("That ip is not blocked\n"); }
			break;
		case ' ':
			if (!ip_cfg.dump) {
				printf("Specify what to do with that ip: --block; --unblock; --check\n");
			}
			break;
		default:
			break;
		}
	}
	if (ip_cfg.dump) {
		__u32 key, next_key, value;
		__int128 key6, next_key6;
        	struct sockaddr_in6 so6_param;
		char str[INET6_ADDRSTRLEN];
		if (ip_cfg.type == 4) {
			printf("IP4 map elements:\nKey		Value\n");
			while (bpf_map_get_next_key(ip_cfg.map_fd, &key, &next_key) == 0) {
				bpf_map_lookup_elem(ip_cfg.map_fd, &next_key, &value);
				inet_ntop(AF_INET, &next_key, str, INET_ADDRSTRLEN);
				printf("%s		%u\n", str, value);
				key = next_key;
			}
		}
		else {
			printf("IP6 map elements:\nKey				Value\n");
                        while (bpf_map_get_next_key(ip_cfg.map_fd, &key6, &next_key6) == 0) {
                                bpf_map_lookup_elem(ip_cfg.map_fd, &next_key6, &value);
				inet_ntop(AF_INET6, &next_key6, str, INET6_ADDRSTRLEN);
                                printf("%s              %u\n", str, value);
                                key6 = next_key6;
                        }

		}
	}
	exit(1);
}

void PrintPortHelp()
{
	printf("HELP:\n"
		"interface <ifname>	  Use maps dedicated to <ifname> interface(required)\n"
		"port <port>:             Work with <port>(required)\n"
		"block:                   Block port\n"
		"unblock:                 Unblock port if blocked\n"
		"check:                   Check if port is blocked\n"
		"dump:                    Show all blocked ports\n"
		"type:                    Specify port type (default TCP)\n"
		"help:                    Show help\n");
	// exit(1);
}

struct port_config {
	char interface[6];
	int ifindex;
	__u32 port;
	char action;
	bool dump;
	int map_fd;
	char type;
};

void do_port(int argc, char** argv) {
	struct port_config port_cfg;
	char ifname[6];
	port_cfg.ifindex = -1;
	port_cfg.port = -1;
	port_cfg.dump = false;
	port_cfg.map_fd = -1;
	port_cfg.action = ' ';
	port_cfg.type = 't';
	char port[17];
	int err;
	const char* const port_short_opts = "i:p:bucdt:h";
	struct option port_long_opts[] = {
		{"interface",  required_argument, NULL, 'i'},
		{"port",       required_argument, NULL, 'p'},
		{"block",      no_argument,       NULL, 'b'},
		{"unblock",    no_argument,       NULL, 'u'},
		{"check",      no_argument,       NULL, 'c'},
		{"dump",       no_argument,       NULL, 'd'},
		{"type",       required_argument, NULL, 't'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL,         no_argument,       NULL,  0}
	};

	while (true)
	{
		int opt = getopt_long(argc, argv, port_short_opts, port_long_opts, NULL);
		if (-1 == opt)
			break;
		switch (opt)
		{
		case 'i':
			strcpy(ifname, optarg);
			int ifindex = if_nametoindex(ifname);
			if (ifindex > 0) {
				strcpy(port_cfg.interface, optarg);
				port_cfg.ifindex = ifindex;
			}
			else { printf("Wrong interface name\n"); }
			break;
		case 'p':
			port_cfg.port = atoi(optarg);
			printf("The port to use is %u\n", port_cfg.port);
			break;
		case 'b':
			if (port_cfg.action == ' ') {
				port_cfg.action = 'b';
			}
			else { printf("Block, unblock and check can not be used together\n"); }
			break;
		case 'u':
			if (port_cfg.action == ' ') {
				port_cfg.action = 'u';
			}
			else { printf("Unblock, block and check can not be used together\n"); }
			break;
		case 'c':
			if (port_cfg.action == ' ') {
				port_cfg.action = 'c';
			}
			else { printf("Check, block and unblock can not be used together\n"); }
			break;
		case 'd':
			port_cfg.dump = true;
			break;
		case 't':
			if (strcmp(optarg, "udp") == 0) {
				port_cfg.type = 'u';
			}
			break;
		case 'h':
			PrintPortHelp();
			break;
		case '?':
			break;
		default:
			PrintPortHelp();
			break;
		}
	}
	/*не учитываем тип*/
	char* map_name = "blocked_port_map";
	char map_path[PATH_MAX];
	snprintf(map_path, PATH_MAX, "%s/%s/%s", pin_basedir, port_cfg.interface, map_name);
	if (access(map_path, F_OK) != -1) {
		port_cfg.map_fd = bpf_obj_get(map_path);
		printf("Map fd: %i\n", port_cfg.map_fd);
	}
	else {
		printf("Can't access ip map\n");
		exit(1);
	}
	//рассмотреть ошибки всякие

	__u32 value = 0;
	switch (port_cfg.action) {
	case 'b':
		err = bpf_map_update_elem(port_cfg.map_fd, &port_cfg.port, &value, BPF_ANY);
		break;
	case 'u':
		err = bpf_map_delete_elem(port_cfg.map_fd, &port_cfg.port);
		break;
	case 'c':
		err = bpf_map_lookup_elem(port_cfg.map_fd, &port_cfg.port, &value);
		if (err == 0) {
			printf("That ip is blocked\n");
		}
		else { printf("That ip is not blocked\n"); }
		break;
	case ' ':
		break;
	default:
		break;
	}
	if (port_cfg.dump) {
		__u32 key, next_key, value;
		printf("Port map elements:\nKeys\n");
		while (bpf_map_get_next_key(port_cfg.map_fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(port_cfg.map_fd, &next_key, &value);
			printf("%u\n", next_key);
			key = next_key;
		}
	}
	exit(1);
}

void ProcessArgs(int argc, char** argv)
{
	char* my_options[] = {"load", "unload", "ip", "port", "help"};
	for (int i = 0; i < argc; i++)	{
		for (int j = 0; j < 5; j++) {
			//printf("j: %i i: %i argv: %s\n", j, i, argv[i]);
			if (strcmp(argv[i], my_options[j]) == 0) {
				switch(j) {
				case 0:
					printf("Your option is load\n");
					do_load(argc, argv);
					break;
				case 1:
                                        printf("Your option is unload\n");
                                        do_unload(argc, argv);
					break;
				case 2:
                                        printf("Your option is ip\n");
					do_ip(argc, argv);
                                        break;
				case 3:
                                        printf("Your option is port\n");
                                        do_port(argc, argv);
					break;
				case 4:
                                        PrintHelp();
                                        break;
				default:
					PrintHelp();
					break;
				}
			}
		}
	}
}


int main(int argc, char **argv)
{
    ProcessArgs(argc, argv);

    return 0;
}

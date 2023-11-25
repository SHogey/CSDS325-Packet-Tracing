/*
Name: Stephen Hogeman
Case ID: ssh115
Filename: proj4.c
Date 11/13/2023
Description: This source file is the main file for project 4.
When run it accepts the mandatory argument -r and a selection of
-s|-l|-p|-c. Only 1 from these 4 arguments is accepted.
This source file also contains my submission for the 425 extension of this project.
For this, I implemented -w, which analyzes the 425 trace to print the application layer
protocols for the packets based on the sort and destination ports of the iphdr.
*/

# include <iostream>
# include <cstdio>
# include <unordered_map>
# include <map>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# include <net/ethernet.h>
# include <netinet/ip.h>
# include <netinet/in.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/stat.h>

# define ERROR 1
# define SET_FLAG 1
# define REQ_ARG_CNT 2
# define MAX_PKT_SIZE 1600
# define MICRO_SECOND 0.000001
# define IHL_BYTES 4
# define IP_ADDR_BUFLEN 16
# define IP_ADDR_OCTET 8
# define IP_BIT_ROT 0xFF
# define IP_ADDR_BYTES 4
# define IP_ADDR_TRAIL 3
# define COMMON_PORT_BOUND 1023
# define HTTP_PORT 80
# define HTTPS_PORT 443
# define SSH_PORT 22
# define SMTP_PORT 25
# define DNS_PORT 53
# define POP3_PORT 110
# define IMAP_PORT 143

char *trace_file;
int total_flags, r_flag, s_flag, p_flag, l_flag, c_flag, w_flag;

/* Declaring meta info about the packets (same as trace file) */
struct meta_info {
	unsigned int usecs;
	unsigned int secs;
	unsigned short ignored;
	unsigned short caplen;
};

/* Record info about the current packet */
struct pkt_info {
	unsigned short caplen;
	double now;
	unsigned char pkt [MAX_PKT_SIZE];
	struct ether_header *ethh;  // Ptr to ethernet header if present, otherwise null
	struct iphdr *iph;          // Ptr to IP header if present, otherwise null
	struct tcphdr *tcph;        // Ptr to TCP header if present, otherwise null
	struct udphdr *udph;        // Ptr to UDP header if present, otherwise null
};

/* Record info about the counted packets */
struct count_info {
	double key;
	char *saddr;
	char *daddr;
	unsigned int total_pkts;
	unsigned int traffic_volume;
};

/* Method formatting all error messages */
void errExit (const char *format, char *arg)
{
	fprintf (stderr, format, arg);
	fprintf (stderr, "\n");
	exit (ERROR);
}

/*
parseArgs is tasked with handling all command line arguments, and ensuring
that mandatory arguments are present
*/
void parseArgs (int argc, char *argv[])
{
	int opt;
	extern char *optarg;

	/* Parses through the command line arguments */
	while ((opt = getopt (argc, argv, "r:slpcw")) != -1)
	{
		switch (opt)
		{
			case 'r':
				trace_file = optarg;
				r_flag++;
				total_flags++;
				break;
			case 's':
				s_flag++;
				total_flags++;
				break;
			case 'l':
				l_flag++;
				total_flags++;
				break;
			case 'p':
				p_flag++;
				total_flags++;
				break;
			case 'c':
				c_flag++;
				total_flags++;
				break;
			case 'w':
				w_flag++;
				total_flags++;
				break;
			case '?':
				errExit ("Error: invalid argument given", NULL);
				break;
		}
	}

	/* Validates command line arguments (mandatory r flag and only 2 total flags) */
	if (r_flag < SET_FLAG)
	{
		errExit ("Error: mandatory -r flag (with packet trace) not set", NULL);
	}

	else if (total_flags != REQ_ARG_CNT)
	{
		errExit ("Error: invalid number of arguments provided", NULL);
	}
}

/* Small method tasked with opening the input file */
int openFile()
{
	int fd = open (trace_file, O_RDONLY);
	if (fd < 0)
	{
		errExit ("Error: cannot open trace file", NULL);
	}
	return fd;
}

/*
fd - An open file to read packets from
pinfo - Allocated memory to put packets info into for one packet

Returns:
1 - A packet was read and pinfo is setup for processing the packet
0 - We have hit the end of the file and no packet is available
*/
unsigned short nextPkt (int fd, struct pkt_info *pinfo)
{
	struct meta_info meta;
	int bytes_read;
	int current_size;

	memset (pinfo, 0x0, sizeof (*pinfo));
	memset (&meta, 0x0, sizeof (meta));

	/* Read the meta information */
	bytes_read = read (fd, &meta, sizeof (meta));
	if (bytes_read == 0)
	{
		return (0);
	}
	if ((long unsigned int)bytes_read < sizeof (meta))
	{
		errExit ("Error: cannot read this information", NULL);
	}

	pinfo -> caplen = ntohs (meta.caplen);
	if (pinfo -> caplen == 0)
	{
		return (1);
	}
	if (pinfo->caplen > MAX_PKT_SIZE)
	{
		errExit ("Error: packet too big", NULL);
	}

	pinfo -> now = ntohl (meta.secs) + (MICRO_SECOND * ntohl (meta.usecs));

	/* Reads the packet info */
	bytes_read = read (fd, pinfo->pkt, pinfo->caplen);
	if (bytes_read < 0)
	{
		errExit ("Error: reading packet", NULL);
	}
	if (bytes_read < pinfo->caplen)
	{
		errExit ("Error: unexpected end of file encountered", NULL);
	}
	if ((long unsigned int)bytes_read < sizeof (struct ether_header))
	{
		return (1);
	}

	pinfo->ethh = (struct ether_header *)pinfo->pkt;
	pinfo->ethh->ether_type = ntohs (pinfo->ethh->ether_type);
	if (pinfo->ethh->ether_type != ETHERTYPE_IP)
	{
		/* Nothing more to do with non-ip packets */
		return (1);
	}
	if (pinfo->caplen == sizeof (struct ether_header))
	{
		/* We don't have anything beyond the ethernet header to process */
		return (1);
	}
	current_size = sizeof (struct ether_header);

	/* Handles all of the IP hdr info */
	pinfo->iph = (struct iphdr *)(pinfo->pkt + sizeof (struct ether_header));
	pinfo->iph->tot_len = ntohs (pinfo->iph->tot_len);
	pinfo->iph->id = ntohs (pinfo->iph->id);
	pinfo->iph->saddr = ntohl (pinfo->iph->saddr);
	pinfo->iph->daddr = ntohl (pinfo->iph->daddr);

	if (pinfo->caplen == current_size + (pinfo->iph->ihl * IHL_BYTES))
	{
		return (1);
	}
	current_size = current_size + (pinfo->iph->ihl * IHL_BYTES);

	if (pinfo->iph->protocol == IPPROTO_TCP)
	{
		pinfo->tcph = (struct tcphdr *)(pinfo->pkt + current_size);
		pinfo->tcph->source = ntohs (pinfo->tcph->source);
		pinfo->tcph->dest = ntohs (pinfo->tcph->dest);
		pinfo->tcph->window = ntohs (pinfo->tcph->window);
		pinfo->tcph->ack_seq = ntohl (pinfo->tcph->ack_seq);
	}
	else if (pinfo->iph->protocol == IPPROTO_UDP)
	{
		pinfo->udph = (struct udphdr *)(pinfo->pkt + current_size);
		pinfo->udph->len = ntohs(pinfo->udph->len);
	}
	return (1); 	// Return 1 here because even if not TCP or UDP we have nothing left to do
}

/* Method handles the case when -s is present, and returns summary data */
void summaryMode()
{
	int fd_s = openFile();
	struct pkt_info *pkt = (struct pkt_info *) malloc(sizeof(struct pkt_info));
	int total_pkts = 0, ip_pkts = 0;
	double first_pkt = 0, last_pkt = 0, duration;
	while (nextPkt (fd_s, pkt) > 0)
	{
		if (total_pkts == 0)
		{
			first_pkt = pkt->now;
		}
		if (pkt->ethh != NULL && pkt->ethh->ether_type == ETHERTYPE_IP)
		{
			ip_pkts++;
		}
		total_pkts++;
		last_pkt = pkt->now;
	}
	duration = last_pkt - first_pkt;
	fprintf (stdout, "time: first: %f last: %f duration: %f\n", first_pkt,last_pkt,duration);
	fprintf (stdout, "pkts: total: %d ip: %d\n", total_pkts,ip_pkts);
	free(pkt);
	close (fd_s);
}

/* Determines the payload bytes for each packet, for both -l and -c */
int payloadBytes(struct pkt_info *pkt)
{
	if (pkt->iph->protocol == IPPROTO_TCP)
	{
		return (pkt->iph->tot_len - ((pkt->tcph->doff + pkt->iph->ihl) * IHL_BYTES));
	}
	else
	{
		return (pkt->iph->tot_len - (sizeof(struct udphdr) + (pkt->iph->ihl * IHL_BYTES)));
	}
}

/* Method handles the -l flag, and prints length mode arguments */
void lengthMode()
{
	int trans_hl;
	int fd_l = openFile();
	struct pkt_info *pkt = (struct pkt_info *) malloc(sizeof(struct pkt_info));
	while (nextPkt (fd_l, pkt) > 0)
	{
		if (pkt-> ethh != NULL && pkt->ethh->ether_type == ETHERTYPE_IP)
		{
			fprintf (stdout, "%f %d ", pkt->now, pkt->caplen);
			if (pkt->iph == NULL)
			{
				fprintf (stdout, "- - - - -\n");
			}
			else if (pkt->iph != NULL)
			{
				fprintf (stdout, "%d ", pkt->iph->tot_len);
				fprintf (stdout, "%d ", (pkt->iph->ihl * IHL_BYTES));
				if (pkt->iph->protocol == IPPROTO_TCP && pkt->tcph != NULL)
				{
					fprintf (stdout, "T ");
					fprintf (stdout, "%u ", (pkt->tcph->doff * IHL_BYTES));
					fprintf (stdout, "%d\n", payloadBytes(pkt));
				}
				else if (pkt->iph->protocol == IPPROTO_UDP && pkt->udph != NULL)
				{
					fprintf (stdout, "U ");
					trans_hl = sizeof(struct udphdr);
					fprintf (stdout, "%d ", trans_hl);
					fprintf (stdout, "%d\n", payloadBytes(pkt));
				}
				else if (pkt->iph->protocol == IPPROTO_TCP && pkt->tcph == NULL)
				{
				fprintf (stdout, "T - -\n");
				}
				else if (pkt->iph->protocol == IPPROTO_UDP && pkt->udph == NULL)
				{
					fprintf (stdout, "U - -\n");
				}
				else
				{
					fprintf (stdout, "? ? ?\n");
				}
			}
		}
	}
	close(fd_l);
}

/* Method to convert values to ip address format */
char* ipConvert (uint32_t ip_value)
{
	static char addr[IP_ADDR_BUFLEN];
	addr[0] = '\0';
	for (int i = IP_ADDR_TRAIL; i >= 0; --i)
	{
		char byte[IP_ADDR_BYTES];
		if (i < IP_ADDR_TRAIL)
		{
			sprintf (byte, ".%u", (unsigned int)((ip_value >> (i*IP_ADDR_OCTET) & IP_BIT_ROT)));
		}
		else
		{
			sprintf (byte, "%u", (unsigned int)((ip_value >> (i*IP_ADDR_OCTET) & IP_BIT_ROT)));
		}
		strcat (addr, byte);
	}
	return addr;
}

/* Method handles the TCP Packet Printing mode, outputting info about TCP packets */
void packetPrintingMode()
{
	int fd_p = openFile();
	struct pkt_info *pkt = (struct pkt_info *) malloc(sizeof(struct pkt_info));
	while (nextPkt (fd_p, pkt) > 0)
	{
		if ((pkt->iph != NULL && pkt->tcph != NULL) && pkt->iph->protocol == IPPROTO_TCP)
		{
			fprintf (stdout, "%f ", pkt->now);
			fprintf (stdout, "%s ", ipConvert (pkt->iph->saddr));
			fprintf (stdout, "%d ", pkt->tcph->source);
			fprintf (stdout, "%s ", ipConvert (pkt->iph->daddr));
			fprintf (stdout, "%d ", pkt->tcph->dest);
			fprintf (stdout, "%d %d ", pkt->iph->id, pkt->iph->ttl);
			fprintf (stdout, "%d ", pkt->tcph->window);
			if (pkt->tcph->ack == 1)
			{
				fprintf (stdout, "%u\n", pkt->tcph->ack_seq);
			}
			else
			{
				fprintf (stdout, "-\n");
			}
		}
	}
	close (fd_p);
}

/* Method handles packet counting mode */
void packetCountingMode()
{
	int fd_c = openFile();
	struct pkt_info *pkt = (struct pkt_info *) malloc(sizeof(struct pkt_info));
	struct count_info count;
	std::unordered_map<double, struct count_info> count_map;
	while (nextPkt (fd_c, pkt) > 0)
	{
		if ((pkt->ethh != NULL && pkt->ethh->ether_type == ETHERTYPE_IP) && pkt->tcph != NULL)
		{
			double key = static_cast<double>(pkt->iph->saddr) / pkt->iph->daddr;
			auto iterator = count_map.find(key);
			if (iterator == count_map.end())
			{
				count.key = key;
				count.saddr = strdup(ipConvert(pkt->iph->saddr));
				count.daddr = strdup(ipConvert(pkt->iph->daddr));
				count.total_pkts = 1;
				count.traffic_volume = payloadBytes(pkt);
				count_map[key] = count;
			}
			else
			{
				count_map[key].total_pkts++;
				count_map[key].traffic_volume += payloadBytes(pkt);
			}
		}
	}
	for (const auto& pair: count_map)
	{
		fprintf (stdout, "%s %s ", pair.second.saddr, pair.second.daddr);
		fprintf (stdout, "%d %u\n", pair.second.total_pkts, pair.second.traffic_volume);
	}
}

/* Method commonPortBounds is a simple conditional used by -w to determine if the source/dest
 * port of the packet is one of the preselected ports for analysis. If it is, method returns 1,
 * if it isn't, method returns 0.
 */
int commonPortBounds (uint16_t port)
{
	return (port == HTTP_PORT || port == HTTPS_PORT || port == SSH_PORT || port == SMTP_PORT ||
	port == DNS_PORT || port == POP3_PORT || port == IMAP_PORT);
}

/* -w method is my implementation of the 425 portion of this project
 * this method will determine how many packets are being sent to/received from
 * well known port numbers, from 0-1023
 */
void wellKnownPorts()
{
	int fd_w = openFile();
	uint16_t port_num;
	struct pkt_info *pkt = (struct pkt_info *) malloc(sizeof(struct pkt_info));
	int s_unkin = 0, r_unkin = 0, s_unkout = 0, r_unkout = 0;
	std::map<uint16_t,std::string> portNames = {
		{HTTP_PORT, "HTTP"},
		{HTTPS_PORT, "HTTPS"},
		{SSH_PORT, "SSH"},
		{SMTP_PORT, "SMTP"},
		{DNS_PORT, "DNS"},
		{POP3_PORT, "POP3"},
		{IMAP_PORT, "IMAP"}
	};
	std::map<std::string, int> sourceCounters;
	std::map<std::string, int> destCounters;
	while (nextPkt(fd_w, pkt) > 0)
	{
		if ((pkt->iph != NULL && pkt->tcph != NULL) && pkt->iph->protocol == IPPROTO_TCP)
		{
			if (commonPortBounds(pkt->tcph->source) > 0)
			{
				port_num = pkt->tcph->source;
				sourceCounters[portNames[port_num]]++;
			}
			else if (pkt->tcph->source > 0 && pkt->tcph->source < COMMON_PORT_BOUND)
			{
				s_unkin++;
			}
			else
			{
				s_unkout++;
			}

			if (commonPortBounds(pkt->tcph->dest) > 0)
                        {
                                port_num = pkt->tcph->dest;
                                destCounters[portNames[port_num]]++;
                        }
                        else if (pkt->tcph->dest > 0 && pkt->tcph->dest < COMMON_PORT_BOUND)
                        {
                                r_unkin++;
                        }
                        else
                        {
                                r_unkout++;
                        }
		}
	}
	fprintf (stdout, "Source Packets:\n");
	for (const auto &entry : sourceCounters)
	{
		fprintf (stdout, "%s: %d\n", entry.first.c_str(), entry.second);
	}
	fprintf (stdout, "UNKNOWN IN: %d\nUNKNOWN OUT: %d\n\n",s_unkin,s_unkout);
	fprintf (stdout, "Destination Packets:\n");
	for (const auto &entry : destCounters)
	{
		fprintf (stdout, "%s: %d\n", entry.first.c_str(), entry.second);
	}
	fprintf (stdout, "UNKNOWN IN: %d\nUNKNOWN OUT: %d\n\n",r_unkin,r_unkout);
}

/* Method parses different modes given that the proper flags are set */
void parseFlags()
{
	if (s_flag == SET_FLAG)
	{
		summaryMode();
	}
	else if (l_flag == SET_FLAG)
	{
		lengthMode();
	}
	else if (p_flag == SET_FLAG)
	{
		packetPrintingMode();
	}
	else if (c_flag == SET_FLAG)
	{
		packetCountingMode();
	}
	else if (w_flag == SET_FLAG)
	{
		wellKnownPorts();
	}
}

/* Main method for the project, initiates packet analysis */
int main (int argc, char *argv[])
{
	parseArgs (argc, argv); // Parse command line arguments
	parseFlags();		// Switch modes given input flags
}


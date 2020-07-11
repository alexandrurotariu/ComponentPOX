from pox.openflow.discovery import Discovery
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
import sys
import collections

#variabile globale usata per l'inizializzazione delle porte degli switch
port_init = False

#Convenzione: TUTTI gli IP e i DPID vengono gestiti come STRINGHE

class Rete(object):
	
	def __init__ (self, discovery):
		discovery.addListeners(self)
		core.openflow.addListeners(self)
		self.lista_link = []   #[[swA,ptB,swC,ptD], [...], ...]  lista che indica attraverso quali porte sono collegati i divesi switch
		self.nodi = {}   #mappa che indica per ciascun nodo il suo dpid
		self.lista_host = []   #lista con tutti gli host della rete
		self.nodi_scoperti = 0   #numero di nodi scoperti
		self.host_switch = {}  #mappa che indica come value una quadrupa (MAC HOST, DPID SW, INTERFACCIA SW, IP HOST}
		self.adiacenza = []  #matrice di adiacenza
		self.lista_connessioni = []  #lista con tutti i pid del data plane
		self.disattiva = {}  #porte da disattivare per ogni switch per evitare il loop infinito di alcuni pacchetti
		self.tabellaC = {}  #mappa con key = ipHost e value = (MAC Host, DPID piu' vicino all'host), e' la tabella del CONTROLLER

	#gestione LinkEvent
	def _handle_LinkEvent(self, event):
		#aggiungi il nuovo collegamento a list_link
		self.lista_link.append([int(event.link.dpid1), int(event.link.port1), int(event.link.dpid2), int(event.link.port2)])
		#estrapola dall'evento gli switch e le porte interessate
		l = event.link
		sw1 = dpid_to_str(l.dpid1)
		pt1 = l.port1
		sw2 = dpid_to_str(l.dpid2)
		pt2 = l.port2
		#aggiungi alle porte da disattivare le 2 porte appena trovate (controlla se la chiave e' gia' esiste o no)
		if sw1 in self.disattiva:
			self.disattiva.get(sw1).append(pt1) 
		else:
			self.disattiva[sw1] = [pt1]
		
	#gestione ConnectionUp
	def _handle_ConnectionUp(self, event):
		self.lista_connessioni.append(event.connection)  #aggiungi il dpid dello sw alla lista di tutti i dpid
		self.nodi_scoperti += 1  #aggiorna il numero di nodi della rete
		self.nodi[self.nodi_scoperti] = event.dpid  #salva il dpid del nodo

	#gestione PacketIn
	def _handle_PacketIn (self, event):
		global port_init
		#se e' il primo packetIn, la rete e' stata tutta scoperta e si possono impostare le porte degli switch su NOFLOOD e si puo' costruire la matrice di adiacenza
		if port_init==False:
			port_init = True
			self.inizializzaPorte()
			self.costruisciMatAdiacenza()
			print "Porte degli switch impostate e matrice di adiacenza creata"
		#bisogna gestire il pacchetto
		packet = event.parsed  #pacchetto che ha generato il packet in (es arp)
		packet_in = event.ofp  #pacchetto ricevuto dal controller (packet in)	
		dpid = event.dpid
		self.gestisciPacketIn(packet, packet_in ,dpid, event)

	#imposta tutte le porte  degli switch che non sono connesse ad host, su NOFLOOD, per evitare loop 
	def inizializzaPorte(self):
		for c in self.lista_connessioni:  #per ogni switch
			for p in c.ports.itervalues():  #per ogni porta dello switch
				#se deve essere disabilitata, manda messaggio per modificare lo stato della porta
				if p.port_no not in self.disattiva[dpid_to_str(c.dpid)]: 
					print "Porta connessa ad host, non disattivabile"
				else:
					pm = of.ofp_port_mod( port_no=p.port_no,hw_addr=p.hw_addr,config = of.OFPPC_NO_FLOOD, mask = of.OFPPC_NO_FLOOD )
					c.send(pm)

	#construisce matrice di adiacenza per poter usare Dijkstra
	def costruisciMatAdiacenza(self):
		#crea la matrice composta da tutti 0
		for i in range(0, self.nodi_scoperti):
			tmp = []
			for j in range(0, self.nodi_scoperti ):
					tmp.append(0)
			self.adiacenza.append(tmp)
		#imposta a distanza 1 gli switch che presentano dei collegamenti tra loro
		for link in self.lista_link:
			i = link[0] - 1  #(il -1 viene usato perche' lo switch n, nella matrice, si trovera' nella colonna/riga n-1)
			j = link[2] - 1
			self.adiacenza[i][j] = 1

	

	#gestione dei packetIn
	def gestisciPacketIn (self, packet, packet_in, dpid, event):
		#eseguendo una gestione manuale delle ARP, bisogna salvane le info importanti
		if packet.type == packet.ARP_TYPE:
			self.registraHost(packet.src, event.connection.dpid, event.port, packet.payload.protosrc)  
			ipSource = str(packet.payload.protosrc)
			ipDest = str(packet.payload.protodst)
			macSource = str(packet.src)
			#se non e' presente il mittente in tabella, viene aggiunto
			if ipSource not in self.tabellaC.keys():
				self.tabellaC[ipSource] = (macSource, dpid) 
			#se e' un arp request
			if packet.payload.opcode == pkt.arp.REQUEST:
				if  ipDest in self.tabellaC.keys():  #trovato destinatario nella tabella, rispondi direttamente con arp reply
					arp_reply = pkt.arp()
					coppia = self.tabellaC[ipDest]  #ottieni coppia (MAC, SWITCH) del destinatario
					macDest = coppia[0]  #prendi MAC del destinatario
					arp_reply.hwsrc = EthAddr(macDest)
					arp_reply.hwdst = EthAddr(macSource)
					arp_reply.opcode = pkt.arp.REPLY
					arp_reply.protosrc = IPAddr(ipDest)
					arp_reply.protodst = IPAddr(ipSource)
					ether = pkt.ethernet()
					ether.type = pkt.ethernet.ARP_TYPE
					ether.src = EthAddr(macDest)
					ether.dst = EthAddr(macSource)
					ether.payload = arp_reply
					self.sendPacketToDPID(ether,dpid)
				else:  #non c'e in tabella manda una arp request a tutti gli switch
					arp_request = pkt.arp()
					arp_request.hwsrc = EthAddr(macSource)
					arp_request.opcode = pkt.arp.REQUEST	
					arp_request.protosrc = IPAddr(ipSource)
					arp_request.protodst = IPAddr(ipDest)
					ether = pkt.ethernet()
					ether.type = pkt.ethernet.ARP_TYPE
					ether.src = EthAddr(macSource)
					ether.dst = pkt.ETHER_BROADCAST
					ether.payload = arp_request
					self.sendPacketAll(ether)
			else: # e' una arp reply, viene inoltrata al destinatario
				arp_reply = pkt.arp()
				coppia = self.tabellaC[ipDest]  #ottieni coppia (MAC, SWITCH) del destinatario
				macDest = coppia[0]  #prendi MAC del destinatario
				arp_reply.hwsrc = EthAddr(macDest)
				arp_reply.hwdst = EthAddr(macSource)
				arp_reply.opcode = pkt.arp.REPLY
				arp_reply.protosrc = IPAddr(ipDest)
				arp_reply.protodst = IPAddr(ipSource)
				ether = pkt.ethernet()
				ether.type = pkt.ethernet.ARP_TYPE
				ether.src = EthAddr(macDest)
				ether.dst = EthAddr(macSource)
				ether.payload = arp_reply
				self.sendPacketToDPID(ether,coppia[1])
		#il pacchetto non e' un ARP
		else:
			#prende le info dal pacchetto
			ipDest = str(packet.payload.dstip)
			ipSrc = str(packet.payload.srcip)
			coppia_dst = self.tabellaC[ipDest]  #ottieni lo coppia (MAC, DPID) del destinatario
			dpid_dst = coppia_dst[1]  #ottieni il dpid dello switch destinatario
			mac_dst = coppia_dst[0]
			coppia_src = self.tabellaC[ipSrc]
			mac_src = coppia_src[0]
			#calcola il percorso per la destinazione con dijkstra
			percorso = self.dijkstra(dpid,dpid_dst)
			#avvia l'installazione negli switch del percorso
			self.avvia_instal(percorso, ipDest, ipSrc)
			#riesegui il procedimento, ma sul percorso inverso
			percorso.reverse()
			self.avvia_instal(percorso, ipSrc, ipDest)
			print percorso
			#dato che si conosce il dpid destinatario, inoltra direttamente il pacchetto, senza passare per la rete 
			self.sendPacketToDPID(packet,dpid_dst)		

	#salva le informazioni sull'host
	def registraHost (self, host, dpid, interfaccia, ip_address):
		if str(host) not in self.lista_host:
			print "scoperto host " + str(host) + " connesso allo switch " + str(dpid)
			self.lista_host.append(str(host))
			self.host_switch[len(self.lista_host)] = (host, dpid, interfaccia, ip_address)

	#cerca i nodi su cui installare lel regole
	def avvia_instal(self, percorso, ipSrc, ipDest):
		#per ogni nodo del percorso
		for count in range(0,len(percorso)):
			src = percorso[count]
			#se sei arrivato all'ultimo nodo intermedio
			if count == (len(percorso)-1):
				#cerca l'interfaccia dello switch verso ipDest
				for data in self.host_switch.values():
					if data[1] == src and data[3] == ipDest:
						out_port = data[2] 
			#altrimenti cerca la porta verso il prossimo nodo del percorso	
			else:
				dst = percorso[count+1]
				for lista in self.lista_link:
					if lista[0]==src and lista[2]==dst:
						out_port = lista[1]
			#installa la regola su ogni switch
			self.installa_flow_rule(src, out_port, ipSrc, ipDest)
		print "FLOW RULE ISTALLATE"
				
	#installa la regola di instradamento su uno switch
	def installa_flow_rule(self, id_switch, out_port, ip_src, ip_dst):
		msg = of.ofp_flow_mod()
		msg.priority = 1000
		msg.match.dl_type = 0x0800
		msg.match.nw_src = ip_src
		msg.match.nw_dst = ip_dst
		msg.actions.append(of.ofp_action_output(port = out_port))
		core.openflow.sendToDPID(id_switch, msg)
	

	
	#pacchetto da mandare a tutti gli switch
	def sendPacketAll (self, packet):
		msg = of.ofp_packet_out()
		msg.data = packet
		action = of.ofp_action_output(port = of.OFPP_FLOOD)
		msg.actions.append(action)
		for connection in core.openflow.connections:
  			connection.send(msg)
		print "PACCHETTO MANDATO A TUTTI GLI SWITCH" 

	#pacchetto da mandare ad uno specifico switch
	def sendPacketToDPID(self,packet,dpid):
		msg = of.ofp_packet_out()
		msg.data = packet
		action = of.ofp_action_output(port = of.OFPP_FLOOD)
		msg.actions.append(action)
		core.openflow.sendToDPID(dpid,msg)
		print "PACCHETTO MANDATO ALLO SWITCH " + dpid_to_str(dpid)



#************************************** DIJKSTRA ***************************************

	#ritorna il nodo che minimizza la distanza
	def minDist(self, nodi, dist): 
		min_dist = sys.maxint
		min_nodo = sys.maxint
		for nodo in nodi:
			if dist[nodo-1] < min_dist: 
				min_dist = dist[nodo-1] 
				min_nodo = nodo 
		return min_nodo 


	#insieme degli switch adiacenti al nodo n
	def adiacenti(self, n):
		insieme = set()
		val = 0
		#aggiungi all'insieme tutti i nodi adiacenti ad n
		for i in self.adiacenza[n-1]:
			val = val+1
			#se lo switch e' connesso direttemte al nodo n (in tabella si ha 1), allora aggiunge lo switch all'insieme
			if i != 0:
				insieme.add(val)
		return insieme
		
				

	def dijkstra(self, src, dst):
		dist = [sys.maxint] * self.nodi_scoperti  #inizializza array con tutti i nodi a dist inf
		pred = [None] * self.nodi_scoperti  #imposta a tutti i nodi, il nodo precede pari a None
		dist[src-1] = 0  #il nodo di partenza si trova a distanza 0 (il nodo di partenza si trova in posizione src-1 nell array)
		visited = set()  #nodi visitati, insieme vuoto
		unvisited = set()  #nodi da visitare, insieme vuoto
		for n in self.nodi.keys():  #tutti i nodi devono essere visitati vengono aggiunti all'insieme
			unvisited.add(n)
		while len(unvisited) != 0:  #fino a quando ci sono nodi da visitare
			current = self.minDist(unvisited,dist)	#current = nodo ancora da visitare a distanza minima (prima iterazione e' sempre src a distanza 0)
			if current == dst:  #se ho trovato il nodo destinazione esci
				break
			#sposta il nodo corrente da unvisited a visited
			unvisited.remove(current)
			visited.add(current)
			#trova l'insime di tutti i nodi adiacenti a quello corrente togliendo quelli visitati
			nodi_adiacenti = self.adiacenti(current)
			nodi_adiacenti = nodi_adiacenti-visited
			#analizza ogni nodo adiacente
			for v in nodi_adiacenti:
				#se e' stato gia' visitato esci
				if v in visited:
					break
				#calcola la distanza del nodo, se e' inferiore a quella precedente, allora aggiorna i dati
				alt = dist[current-1] + self.adiacenza[current-1][v-1]
				if alt < dist[v-1]:
					dist[v-1] = alt
					pred[v-1] = current	
				
		#trova il percorso piu' breve (invertito)
		path = [dst]
		self.shortest(dst,path,pred)	
		return path
		
  	#funzione ricorsiva che torno il percorso piu' breve invertito
	def shortest(self, v, path, pred):
		if pred[v-1] is not None: #se il nodo ha un nodo precedente (non e' il nodo sorgente), aggiungilo al percorso
			path.append(pred[v-1])
			self.shortest(pred[v-1], path, pred)
    		return

#************************************** DIJKSTRA ***************************************


#funzione iniziale
def launch ():
	discovery = Discovery()
	rete = Rete(discovery)

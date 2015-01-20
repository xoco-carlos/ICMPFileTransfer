#!/usr/bin/perl -w
$|=1;						#Buffer en 1 para imprimir sin encolar
use strict;					#Pragma para buenas practicas de programacion
use warnings;
use Crypt::CBC;
#use Net::RawIP;				#Modulo para creacion de paquetes IP
use Net::PcapUtils;			#Modulo para captura de trafico
use NetPacket::Ethernet;	#Modulo para manejo de cabeceras Ethernet
use NetPacket::IP;			#Modulo para manejo de cabeceras IP
use NetPacket::ICMP;		#Modulo para manejo de cabeceras ICMP
use MIME::Base64::Perl;		#Modulo de/codificacion en base64
use Net::Address::IP::Local;#Modulo para obtener direccion IP

my @packets=();				#Arreglo que almacena los paquetes recibidos
my $message_length;			#Almacena la longitud del mensaje
my $src_ip = Net::Address::IP::Local->public; #Direccion IP del equipo local
my $dst_ip;					#Direccion IP del equipo destino
my $missing_packets;		#Paquetes no recibidos
my $i;						#Contador de paquetes
my $key=$ARGV[0];						#Contador de paquetes
my $cipher = Crypt::CBC->new(-key=> $key,-cipher => 'Rijndael');

Net::PcapUtils::loop(\&process_pkt,
   PROMISC => 1,			#Operar en modo promiscuo
   NUMPACKETS => -1,		#Paquetes a monitorear (-1 = loop forever)
   DEV => 'eth0'			#Interfaz de monitoreo
); #Rutina que captura paquetes IP


sub process_pkt {
	my ($user_data,$hdr,$pkt)=@_;
	my $eth=NetPacket::Ethernet->decode($pkt);				#Decodificar la cabecera Ethernet
	if($eth->{type} == 2048){								#Verificar que sea de tipo IP
		my $ip=NetPacket::IP->decode($eth->{data});			#Decodificar la cabecera IP
		if($ip->{proto} == 1){								#Verificar que sea de tipo ICMP
			my $icmp=NetPacket::ICMP->decode($ip->{data});	#Decodificar la cabecera ICMP
			#Verificar que el paquete sea ECHO_REQUEST y que contenga el payload convenido para inicio de transmision(BEGIN--longitud)
			if($icmp->{type} eq 8 and $icmp->{data} =~ /BEGIN--/){	
				$dst_ip=$ip->{src_ip};						#Obtener direccion IP del equipo que transmite
				print "Se detecto una transmision desde ",$dst_ip,"\n";
				@packets=();								#Reiniciar la captura para evitar capturar diferentes mensajes transmitidos
				$message_length=$';							#Longitud del mensaje, obtenida del payload
				$missing_packets="";
				$packets[$message_length]=" ";
			}
			#Verificar que el paquete sea ECHO_REQUEST y que contenga el payload convenido para transmision(seq(num)(num)(num) criptograma)
			if($icmp->{type} eq 8 and $icmp->{data} =~ /(seq\.)([0-9]+)(\.)/){
				$packets[$2]=$';
				$missing_packets="";
			}
			#Verificar que el paquete sea ECHO_REQUEST y que contenga el payload convenido para re-transmision(req(num)(num)(num) criptograma)
			if($icmp->{type} eq 8 and $icmp->{data} =~ /(req\.)([0-9]+)(\.)/){
				$packets[$2]=$';
				$missing_packets="";
			}
			#Verificar que el paquete sea ECHO_REQUEST y que contenga el payload convenido para fin de transmision(DEADEND)
			if($icmp->{type} eq 8 and $icmp->{data} =~ /DEADEND/){
				$i=0;
				$dst_ip=$ip->{src_ip};		#Obtener direccion IP del equipo que transmite
				foreach(@packets){
					print $i,"->",$packets[$i],"\n";
					if(!$packets[$i]){
						$missing_packets.=$i.":";
					}
					$i++;
				}
				if($missing_packets){							#En caso de existir paquetes faltantes
					###RETRANSMISION
					print $missing_packets;
					sendICMP("MISP".$missing_packets);#cesar($missing_packets));	#Enviar la lista cifrada
					$missing_packets="";
				}
				else{											#En caso de paquetes completos
					sleep 2;
					sendICMP("SUCCESS");		#Avisar fin de la comunicacion
					print "\nDESCIFRAR\n";
					$missing_packets="";
					###DESCIFRAR
					my $messageB64=createMessage(\@packets);	#Obtener el mensaje del arreglo
					$messageB64=~ s/\.*//g;						#Eliminar informacion de relleno
					$messageB64=~ tr{*}{\n};
					my $filename=(localtime)[2].(localtime)[1].(localtime)[0];#Nombre de archivo para guardar criptograma B64
					bytes2file($filename,$cipher->decrypt(decode_base64($messageB64)));
				}
			}
		}
	}
}
#Obtiene $data como argumento y lo envia mediante ICMP
sub sendICMP{
        my $data=shift;						#Obtiene los datos a transmitir
        my $packet = new Net::RawIP ({		#Crea un nuevo objeto RawIP
                ip => {						#Cabecara IP
                        saddr => $src_ip,	#Direccion IP origen
                        daddr => $dst_ip,	#Direccion IP destino
                },
                icmp => {					#Cabecera ICMP
                        type => 8,			#ECHO_REQUEST
                        data => $data,		#Datos a transmitir
                },
        });
        $packet->send();					#Enviar el paquete
}
#Concatena lo paquetes almacenados en @packets y guarda la cadena en $message
sub createMessage{
        my $packets=shift;		#Obtiene la referencia del arreglo
        my $message;			
        foreach(@$packets){		#Itera el arreglo
                $message.=$_;	#Concatena paquetes
        }
        return $message;		#Devuelve el mensaje
}
sub bytes2file{
	my ($filename,$rawbytes)=@_;
	open FILE, ">:raw", $filename or die "Couldn't create $filename!";
	print FILE $rawbytes;
	close FILE;
	print "Se creo el archivo $filename \n";
}

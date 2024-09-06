'''
PRÁTICA 3 - REDES DE COMPUTADORES

ALUNOS:
    - Brainer Sueverti de Campos - 790829
    - Rafael da Silva Ferreira Alves - 810996
'''

'''
1 - Bibliotecas necessárias: 

- iputils: dada pelo professor 
- struct: permite empacotar e desempacotar dados binários em estruturas de bytes, facilitando a manipulação de formatos de dados de baixo nível, como cabeçalhos de protocolos de rede.
'''

from iputils import *
import struct

class IP:
    # Contador global para gerenciar o identificador único de datagramas IP enviados
    count_ID = 0

    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        # Inicializa a instância IP com o enlace de camada inferior
        self.callback = None  # Callback a ser chamado quando um segmento TCP é recebido
        self.enlace = enlace
        # Registra o método de recebimento de datagramas nesta instância
        self.enlace.registrar_recebedor(self.__raw_recv)
        # Configuração para ignorar o checksum de datagramas (definido no enlace)
        self.ignore_checksum = self.enlace.ignore_checksum
        # Endereço IP atribuído ao host local
        self.meu_endereco = None
        # Inicializa a tabela de roteamento como uma lista vazia
        self.tabela_roteamento = []

    def __raw_recv(self, datagrama):
        """
        Método chamado automaticamente quando um datagrama IP é recebido.
        Este método processa o datagrama para verificar se é destinado a este
        host ou se deve ser encaminhado para outro roteador. Lida também com 
        a geração de mensagens ICMP "Time Exceeded" quando o TTL chega a zero.
        """
        # Extrai campos do cabeçalho IPv4 a partir do datagrama recebido
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        # Verifica se o datagrama é destinado ao endereço IP deste host
        if dst_addr == self.meu_endereco:
            # Se o protocolo for TCP e um callback estiver registrado, chama o callback
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Decrementa o campo TTL para o encaminhamento
            ttl -= 1
            if ttl == 0:
                # TTL é zero, descarta o datagrama e envia uma mensagem ICMP "Time Exceeded"
                next_hop = self._next_hop(self.meu_endereco)  # Próximo salto para enviar ICMP
                proto = IPPROTO_ICMP  # Define o protocolo como ICMP
                type_msg = 11  # Tipo de mensagem ICMP: "Time Exceeded"
                code = 0  # Código ICMP para "tempo excedido durante o trânsito"

                # Monta a mensagem ICMP de tempo excedido
                checksum = calc_checksum(struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28])
                time_exceeded_msg = struct.pack('!BBHI', type_msg, code, checksum, 0) + datagrama[:28]

                # Constrói o cabeçalho IP com a mensagem ICMP
                header = struct.pack('!BBHHHBBH', 0x45, 0x00, 20 + len(time_exceeded_msg), identification, \
                            flags + frag_offset, 0x40, proto, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                checksum = calc_checksum(header)
                header = struct.pack('!BBHHHBBH', 69, 0, 20 + len(time_exceeded_msg), identification, \
                            flags + frag_offset, 64, proto, checksum) + str2addr(self.meu_endereco) + str2addr(src_addr)
                datagrama = header + time_exceeded_msg
            else:
                # Calcula o próximo salto para o endereço de destino
                next_hop = self._next_hop(dst_addr)

                # Reconstroi o cabeçalho IP e o datagrama com o payload original
                header = self.cria_cabecalho_ipv4(ttl, proto, identification, flags, frag_offset, src_addr, dst_addr, payload)
                datagrama = header + payload

            # Envia o datagrama atualizado para o próximo salto definido
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        """
        Determina o próximo salto (next hop) para o endereço de destino fornecido,
        com base na tabela de roteamento configurada. Se mais de um CIDR corresponder,
        usa a correspondência com o prefixo mais longo (maior máscara).
        Retorna o endereço IP do próximo salto como uma string ou None se não houver correspondência.
        """
        best_match = None
        for enter in self.tabela_roteamento:
            cidr, next_hop = enter
            rede_addr, mask = cidr.split('/')

            # Converte o endereço IP de destino e o endereço da tabela de roteamento em formato binário
            val_dest, = struct.unpack('!I', str2addr(dest_addr))
            val_rede, = struct.unpack('!I', str2addr(rede_addr))

            # Aplica a máscara de sub-rede para verificar se o endereço de destino
            # está na mesma rede que o endereço na tabela de roteamento
            if (val_dest & (0xFFFFFFFF << (32 - int(mask)))) == val_rede:
                # Se for a melhor correspondência até agora (maior prefixo), atualiza best_match
                if (best_match is None) or (int(mask) > int(best_match[0].split('/')[1])):
                    best_match = enter
        if best_match is not None:
            # Retorna o next_hop da melhor correspondência encontrada
            return best_match[1]

        # Retorna None se nenhum endereço correspondente for encontrado na tabela
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_roteamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia um datagrama IP com um segmento TCP fornecido como payload.
        Monta o cabeçalho IP e envia o datagrama para o próximo salto de acordo com a tabela de roteamento.
        """
        # Determina o próximo salto para o endereço de destino
        next_hop = self._next_hop(dest_addr)
        
        # Cria o cabeçalho IP para o datagrama
        header = self.cria_cabecalho_ipv4(64, IPPROTO_TCP, IP.count_ID, 0x00, 0x00, self.meu_endereco, dest_addr, segmento)
        datagrama = header + segmento

        # Incrementa o identificador do datagrama para garantir unicidade nos próximos envios
        IP.count_ID += 1

        # Envia o datagrama montado para o próximo salto determinado
        self.enlace.enviar(datagrama, next_hop)

    def cria_cabecalho_ipv4(self, ttl, proto, identification, flags, frag_offset, src_addr, dst_addr, payload):
        """
        Constrói o cabeçalho IPv4 usando os parâmetros fornecidos e calcula o checksum do cabeçalho.
        Retorna o cabeçalho IPv4 pronto para ser utilizado em um datagrama.
        """
        vihl = 0x45  # Versão IPv4 e IHL (Internet Header Length)
        dscpecn = 0x00  # DSCP (Differentiated Services Code Point) e ECN (Explicit Congestion Notification)
        total_len = 20 + len(payload)  # Comprimento total do pacote (cabeçalho + payload)
        checksum = 0x00  # Checksum inicial (marcador de posição)

        # Monta o cabeçalho sem o checksum para calculá-lo
        header = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, \
                             flags + frag_offset, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr)
        
        # Calcula o checksum real do cabeçalho IP
        checksum = calc_checksum(header)

        # Atualiza o cabeçalho com o checksum calculado
        header = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, \
                     flags + frag_offset, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr)
        
        return header


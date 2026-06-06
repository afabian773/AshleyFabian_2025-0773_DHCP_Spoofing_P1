# AshleyFabian_2025-0773_DHCP_Spoofing_P1

## Ataque DHCP Spoofing — Servidor DHCP Falso
**Estudiante:** Ashley Fabian  
**Matrícula:** 2025-0773  
**Práctica:** P1  
**Asignatura:** Seguridad en Redes  
**Plataforma:** GNS3 — Kali Linux  

---

## Descripción

Este repositorio contiene el script y la documentación técnica del ataque DHCP Spoofing. El atacante levanta un servidor DHCP malicioso que responde solicitudes DHCP antes que el servidor legítimo, asignando a los nuevos hosts un gateway y DNS controlados por el atacante.

---

## Contenido del repositorio

| Archivo | Descripción |
|---|---|
| `AshleyFabian_2025-0773_DHCP_Spoofing_P1.py` | Script del ataque |
| `AshleyFabian_2025-0773_Informe_DHCP_Spoofing_P1.pdf` | Documentación técnica profesional |

---

## Topología de red

| Dispositivo | IP | Puerto |
|---|---|---|
| R1 (CSR1000v) | 25.7.73.1/24 | Gi1 → SW1 Gi0/0 |
| SW1 (vIOS L2) | 25.7.73.2/24 | Gi0/1→VPCS, Gi0/2→Kali |
| Kali Linux | 25.7.73.50/24 | eth0 → SW1 Gi0/2 |
| VPCS (PC1) | 25.7.73.20/24 | eth0 → SW1 Gi0/1 |

**Red:** 25.7.73.0/24 (basada en matrícula 2025-0773)

---

## Uso del script

```bash
# Ejecutar el servidor DHCP falso
sudo python3 AshleyFabian_2025-0773_DHCP_Spoofing_P1.py \
     -i eth0 -s 25.7.73.100 -e 25.7.73.150 \
     -g 25.7.73.50 -n 25.7.73.50

# En la VPCS (sin IP previa):
dhcp
show ip  # debe mostrar IP del pool del atacante y GW=25.7.73.50

# Parámetros disponibles
# -i  Interfaz de red
# -s  IP inicio del pool falso
# -e  IP fin del pool falso
# -g  Gateway falso a anunciar
# -n  DNS falso a anunciar
# -m  Máscara de subred (default: 255.255.255.0)
```

---

## Evidencia del ataque

- VPCS obtiene IP del pool del atacante (25.7.73.100-150)
- Gateway asignado es la IP de Kali (25.7.73.50)
- Handshake DORA completo: DISCOVER → OFFER → REQUEST → ACK

---

## Contra-medida

```
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 1
SW1(config)# no ip dhcp snooping information option
SW1(config-if)# ip dhcp snooping trust  ← solo en uplink al router (Gi0/0)
```

---

## Video de demostración

🎬 [Ver video en YouTube](https://youtu.be/sWnY8PzryGo?si=huZT9KctphUjGn9n)

> El video muestra el ataque en funcionamiento y la aplicación de la contra-medida.

---

## Requisitos

- Kali Linux
- Python 3.6+
- Scapy: `sudo apt install python3-scapy`
- GNS3 con CSR1000v y vIOS L2
- Ejecutar como root

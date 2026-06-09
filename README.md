# IP-Fragmentation-DDoS
# El ataque silencioso que satura tu red: IP Fragmentation DDoS y cómo lo frenamos en Waugi

En Waugi: nuestra infraestructura de borde está diseñada para mitigar ataques volumétricos y de agotamiento de recursos con un enfoque quirúrgico. No nos limitamos a bloquear IPs en masa; analizamos el comportamiento íntimo del protocolo de red en tiempo real.

El borde de Waugi Cloud, potenciado por nuestros firewalls ZEUS de desarrollo propio, está optimizado para desarmar tácticas complejas que buscan deprimir el rendimiento de los servidores de nuestros clientes antes de que el tráfico siquiera toque su infraestructura.

🔍 Hoy hablaremos de un vector de ataque tan antiguo como efectivo, y de cómo ZEUS lo neutraliza en el router de borde: el **IP Fragmentation DDoS**.

---

### 📦 ¿Qué es el ataque por fragmentación de IP?

Cuando un paquete de red supera la Unidad Máxima de Transmisión (MTU), que típicamente es de 1500 bytes, el protocolo IP lo divide en fragmentos más pequeños. Cada fragmento viaja con un identificador común y un valor llamado **Fragment Offset**, que le indica al destino la posición exacta de esa pieza para poder reensamblar el paquete original (por ejemplo, en un flujo TCP o UDP).

⚠️ El problema ocurre cuando los atacantes envían ráfagas masivas de paquetes fragmentados con IPs de origen *spoofeadas* (aleatorias) y **valores de Fragment Offset completamente randomizados**. 

Al recibir este "tren" de paquetes inconsistentes, la víctima se queda acumulando basura en su memoria, esperando fragmentos que nunca llegarán para completar un reensamblado imposible. El resultado: el buffer de fragmentación del sistema operativo se satura, agotando la CPU y la memoria, dejando al servidor fuera de servicio.

---

### 🔑 La validación de fragmentos en el firewall ZEUS:

En Waugi: la mitigación de este ataque se realiza directamente en la línea de comandos de nuestro borde, aplicando una inspección minuciosa al comportamiento de la trama IP. 

Nuestra lógica de mitigación se basa en dos reglas de oro inquebrantables dentro de ZEUS:

* **Análisis de Secuencialidad:** En un tráfico legítimo, el *Fragment Offset* debe caer en una secuencia lógica. Si bien la red puede desordenar paquetes, este desorden es mínimo y temporal. Cuando ZEUS detecta saltos de offset ilógicos y caóticos, el flujo es marcado inmediatamente como malicioso.
* **Validación de Tamaño de Trama:** Si un paquete fragmentado mide significativamente menos de 1500 bytes en sus primeras etapas, la matemática no cierra. Un paquete solo se fragmenta si excede el límite. Como mucho, un paquete pequeño podría ser el "último fragmento" del tren, pero nunca el primero ni el cuerpo del flujo.

Si el comportamiento no cumple con estas validaciones, XDP y BPF entran en acción en nuestras placas Intel E810, descartando los paquetes falsificados en nanosegundos antes de que impacten en el procesador principal.

---

### 🖥️ ¿Cómo se ve un ataque de fragmentación en el borde?

A nivel de inspección de tráfico, un tren de paquetes bajo ataque carece de la estructura secuencial que un sistema operativo espera. Mientras que un flujo legítimo reconstruye la información limpiamente, el ataque inyecta ruido constante con offsets aleatorios para forzar el *timeout* del buffer.

Con el firewall ZEUS integrado en nuestros routers de borde, todo este procesamiento se delega a nivel de kernel y hardware. El tráfico legítimo de nuestros clientes sigue su curso limpio y fluido, mientras que las ráfagas fragmentadas mueren en la frontera de nuestra red.

---

### 🚀 Infraestructura resiliente ante amenazas modernas

Este nivel de inspección granular es lo que diferencia a Waugi Cloud de las soluciones de mitigación genéricas ("cajas negras") que suelen generar falsos positivos o degradar la latencia general del servicio.

Al entender el comportamiento real de los protocolos de red, seguimos construyendo una nube robusta en la región, capaz de absorber incidentes complejos sin que tu aplicación experimente un solo milisegundo de degradación.

---

### 🤔 Pregunta abierta

Para cerrar, dejo una pregunta abierta a los lectores y administradores de infraestructura: **¿Cuántos proveedores de datacenter y nube en Argentina inspeccionan la coherencia del Fragment Offset en su borde para proteger tus servidores antes de que colapsen?**

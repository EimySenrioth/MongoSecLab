# Proyecto Proxy Anti-Leak

Este proyecto integra herramientas en C, Go y Python para la gestión y análisis de proxies, orientado a la detección y reporte de intentos bloqueados. Fue desarrollado específicamente para abordar el problema de memoria descubierto en MongoDB. Esta es fase de vercion 0.001

## Estructura de archivos


## Funcionamiento

1. El orquestador Python lanza el proxy Go, que a su vez utiliza la librería en C para analizar los datos.
2. El proxy Go genera un archivo de reporte con los intentos bloqueados.
3. El orquestador recopila los logs y copia el reporte a la carpeta `logs` para su consulta.

## Ejecución

- Para compilar los módulos en C, use GCC:
  ```sh
  gcc -shared -o analyzer_c.dll analyzer_c.c
  ```
- Para ejecutar el proxy Go:
  ```sh
  go run controller_go.go
  ```
- Para orquestar todo el proceso y recolectar los reportes:
  ```sh
  python orquestador.py
  ```

## Requisitos

- GCC (para compilar C)
- Go (para ejecutar el proxy)
- Python 3 (para el orquestador)

## Autoría y licencia

Desarrollado por el equipo de desarrollo. Licencia libre para modificar y distribuir.
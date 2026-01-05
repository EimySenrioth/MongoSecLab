# Orquestador Python para Proxy Anti-Leak
"""
Este script orquesta los proxies en C y Go, recolecta los logs de ambos y genera un reporte unificado de intentos bloqueados.
"""
import subprocess
import time
import os


GO_PROXY = 'controller_go.go'
LOGS_DIR = 'logs'
REPORT_FILE = 'reporte_intentos.txt'

os.makedirs(LOGS_DIR, exist_ok=True)

# Lanzar proxy Go (que usa analyzer_c.dll)
def start_go_proxy(port=27018):
    return subprocess.Popen(['go', 'run', GO_PROXY], stdout=open(f'{LOGS_DIR}/proxy_go.log', 'w'), stderr=subprocess.STDOUT)

# Copiar el reporte generado por Go
def copiar_reporte():
    src = 'reporte_intentos.txt'
    dst = f'{LOGS_DIR}/reporte_intentos.txt'
    if os.path.exists(src):
        with open(src, encoding='utf-8', errors='ignore') as fsrc, open(dst, 'w', encoding='utf-8') as fdst:
            fdst.write(fsrc.read())
        print(f'Reporte copiado a {dst}')
    else:
        print('No se encontró reporte_intentos.txt generado por Go.')

if __name__ == '__main__':
    print('Iniciando proxy Go (usa analyzer_c)...')
    proc_go = start_go_proxy(27018)
    print('Proxy corriendo. Espera 30 segundos para pruebas...')
    time.sleep(30)
    print('Deteniendo proxy...')
    proc_go.terminate()
    time.sleep(2)
    copiar_reporte()
    print('Listo.')

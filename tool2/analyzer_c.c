// analyzer_c.c
// Solo analiza los datos recibidos y reporta si detecta patrones maliciosos
// Compilar: gcc -shared -o analyzer_c.dll -fPIC analyzer_c.c

#include <stdio.h>
#include <stdint.h>

__declspec(dllexport) int is_malicious(const unsigned char *data, int len) {
    FILE *logf = fopen("fragmentos_sospechosos.log", "a");
    int sospechoso = 0;
    // Vector de ataque mongobleed: analizar encabezado MongoDB
    if (len >= 16) {
        int msg_len = *(int *)(data);
        int op_code = *(int *)(data + 12);
        // OP_COMPRESSED = 2012
        if (op_code == 2012 && len > 21) {
            int claimed_size = *(int *)(data + 16);
            unsigned char compression_type = data[20];
            // Si claimed_size es mucho mayor que el tamaño real y usa zlib
            if (compression_type == 2 && (claimed_size > 2 * (len - 21) || claimed_size > 5000)) {
                sospechoso = 1;
            }
        }
        // Mensajes muy grandes
        if (msg_len > 4096 || len > 4096) {
            sospechoso = 1;
        }
    }
    // Encabezado zlib directo
    if (len > 100 && data[0] == 0x78 && data[1] == 0x9c) {
        sospechoso = 1;
    }
    // Patrones BSON/ping
    for (int i = 0; i < len - 3; i++) {
        if (data[i] == 'p' && data[i+1] == 'i' && data[i+2] == 'n' && data[i+3] == 'g') {
            sospechoso = 1;
        }
        if (data[i] == '$' && data[i+1] == 'd' && data[i+2] == 'b') {
            sospechoso = 1;
        }
    }
    // Registrar fragmentos sospechosos
    if (sospechoso && logf) {
        fprintf(logf, "[VECTOR] len=%d: ", len);
        for (int i = 0; i < (len < 64 ? len : 64); i++) {
            fprintf(logf, "%02x ", data[i]);
        }
        fprintf(logf, "\n");
        fclose(logf);
    } else if (logf) {
        fclose(logf);
    }
    return sospechoso;
}

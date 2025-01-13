/***************************************************
 * File: smb2_pipe_exec_client.c
 *
 * Demonstrates a more “universal” SMB2/3 approach:
 *   1. Dialect negotiation for SMB 2.0.2 up to 3.1.1
 *   2. (Placeholder) multi-round Session Setup for 
 *      potential NTLM/Kerberos auth.
 *   3. Tree connect to IPC$.
 *   4. Create/open the named pipe (e.g., "\\PIPE\\svcctl").
 *   5. Exchange raw data over the pipe (placeholder 
 *      for real DCERPC calls to create/start services).
 *
 * Warnings/Disclaimers:
 *   - This code is incomplete, insecure, and does NOT
 *     fully implement NTLM or Kerberos.
 *   - Do NOT use in production or on any network
 *     without explicit permission.
 *   - Real remote exec requires correct DCERPC calls
 *     to Service Control Manager or a similar service.
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
// SMB2/3 Header
//--------------------------------------------------
typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];  // 0xFE 'S' 'M' 'B'
    uint16_t       StructureSize;  // Always 64
    uint16_t       CreditCharge;
    uint32_t       Status;
    uint16_t       Command;
    uint16_t       Credits;
    uint32_t       Flags;
    uint32_t       NextCommand;
    uint64_t       MessageId;
    uint32_t       Reserved;
    uint32_t       TreeId;
    uint64_t       SessionId;
    unsigned char  Signature[16];
} SMB2Header;

//--------------------------------------------------
// SMB2 Commands
//--------------------------------------------------
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009

//--------------------------------------------------
// Common Status Codes
//--------------------------------------------------
#define STATUS_SUCCESS                0x00000000
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define STATUS_LOGON_FAILURE          0xC000006D
#define STATUS_ACCESS_DENIED          0xC0000022

//--------------------------------------------------
// SMB2 Dialects
//--------------------------------------------------
#define SMB2_DIALECT_0202  0x0202
#define SMB2_DIALECT_0210  0x0210
#define SMB2_DIALECT_0300  0x0300
#define SMB2_DIALECT_0302  0x0302  // Windows 8.1
#define SMB2_DIALECT_0311  0x0311  // Windows 10/Server 2016

//--------------------------------------------------
// Minimal structs for Negotiate, Session Setup, etc.
//--------------------------------------------------
typedef struct _SMB2NegotiateRequest {
    uint16_t StructureSize;  // 36
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    uint64_t ClientGuid;     
    uint32_t NegotiateContextOffset;
    uint16_t NegotiateContextCount;
    uint16_t Reserved2;
    // followed by array of Dialects
} SMB2NegotiateRequest;

typedef struct _SMB2NegotiateResponse {
    uint16_t StructureSize;  
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint32_t ServerGuid;     
    uint32_t Capabilities;
    uint32_t MaxTransSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
    // etc...
} SMB2NegotiateResponse;

typedef struct _SMB2SessionSetupRequest {
    uint16_t StructureSize;  // 25
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // security buffer (SPNEGO token) follows
} SMB2SessionSetupRequest;

typedef struct _SMB2SessionSetupResponse {
    uint16_t StructureSize;  // 9
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // security buffer (SPNEGO token) follows
} SMB2SessionSetupResponse;

typedef struct _SMB2TreeConnectRequest {
    uint16_t StructureSize;  // 9
    uint16_t Reserved;
    uint32_t PathOffset;
    uint32_t PathLength;
} SMB2TreeConnectRequest;

typedef struct _SMB2TreeConnectResponse {
    uint16_t StructureSize;  // 16
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2TreeConnectResponse;

typedef struct _SMB2CreateRequest {
    uint16_t StructureSize;     
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
    // filename follows
} SMB2CreateRequest;

typedef struct _SMB2CreateResponse {
    uint16_t StructureSize; 
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
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CreateResponse;

typedef struct _SMB2WriteRequest {
    uint16_t StructureSize; 
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
    // data follows
} SMB2WriteRequest;

typedef struct _SMB2WriteResponse {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2WriteResponse;

typedef struct _SMB2ReadRequest {
    uint16_t StructureSize;
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
    uint16_t StructureSize;
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
} SMB2ReadResponse;

#pragma pack(pop)

//--------------------------------------------------
// Global variables (for brevity)
//--------------------------------------------------
static int      gSock        = -1;
static uint64_t gMessageId   = 1;
static uint64_t gSessionId   = 0;
static uint32_t gTreeId      = 0;
static uint64_t gPipeFidPersistent = 0;
static uint64_t gPipeFidVolatile   = 0;

//--------------------------------------------------
// sendSMB2Request: send header + optional payload
//--------------------------------------------------
int sendSMB2Request(const SMB2Header *hdr, const void *payload, size_t payloadLen) {
    // Send header
    ssize_t sent = send(gSock, hdr, sizeof(SMB2Header), 0);
    if (sent < 0) {
        perror("send SMB2 header");
        return -1;
    }
    // Send payload if any
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
// recvSMB2Response: recv header + up to bufSize
//--------------------------------------------------
int recvSMB2Response(SMB2Header *outHdr, void *outBuf, size_t bufSize, ssize_t *outPayloadLen) {
    ssize_t recvd = recv(gSock, outHdr, sizeof(SMB2Header), 0);
    if (recvd <= 0) {
        perror("recv SMB2 header");
        return -1;
    }
    if (recvd < (ssize_t)sizeof(SMB2Header)) {
        fprintf(stderr, "Partial SMB2 header received.\n");
        return -1;
    }
    // Check signature
    if (!(outHdr->ProtocolId[0] == 0xFE &&
          outHdr->ProtocolId[1] == 'S'  &&
          outHdr->ProtocolId[2] == 'M'  &&
          outHdr->ProtocolId[3] == 'B')) {
        fprintf(stderr, "Invalid SMB2 signature.\n");
        return -1;
    }

    // Attempt to read any additional payload (non-blocking peek)
    int peekLen = recv(gSock, outBuf, bufSize, MSG_DONTWAIT);
    if (peekLen > 0) {
        int actualLen = recv(gSock, outBuf, peekLen, 0);
        if (actualLen < 0) {
            perror("recv payload");
            return -1;
        }
        *outPayloadLen = actualLen;
    } else {
        *outPayloadLen = 0;
    }
    return 0;
}

//--------------------------------------------------
// buildSMB2Header: fill out common fields
//--------------------------------------------------
void buildSMB2Header(uint16_t command, uint32_t treeId, uint64_t sessionId, SMB2Header *hdrOut) {
    memset(hdrOut, 0, sizeof(*hdrOut));
    hdrOut->ProtocolId[0] = 0xFE;
    hdrOut->ProtocolId[1] = 'S';
    hdrOut->ProtocolId[2] = 'M';
    hdrOut->ProtocolId[3] = 'B';
    hdrOut->StructureSize = 64;
    hdrOut->Command       = command;
    hdrOut->MessageId     = gMessageId++;
    hdrOut->TreeId        = treeId;
    hdrOut->SessionId     = sessionId;
    hdrOut->Credits       = 1; // minimal
}

//--------------------------------------------------
// doNegotiate: propose multiple dialects
//--------------------------------------------------
int doNegotiate() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_NEGOTIATE, 0, 0, &hdr);

    SMB2NegotiateRequest negReq;
    memset(&negReq, 0, sizeof(negReq));
    negReq.StructureSize = 36;

    // Propose a range of dialects from 2.0.2 to 3.1.1
    uint16_t dialects[] = {
        SMB2_DIALECT_0202,
        SMB2_DIALECT_0210,
        SMB2_DIALECT_0300,
        SMB2_DIALECT_0302,
        SMB2_DIALECT_0311
    };
    negReq.DialectCount = sizeof(dialects)/sizeof(dialects[0]);
    // SecurityMode, Capabilities, etc. remain zero for simplicity

    // Send the request struct first
    if (sendSMB2Request(&hdr, &negReq, sizeof(negReq)) < 0) {
        return -1;
    }
    // Then send the dialect array
    if (send(gSock, dialects, sizeof(dialects), 0) < 0) {
        perror("send dialects");
        return -1;
    }

    // Receive
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen = 0;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "Negotiate failed: 0x%08X\n", respHdr.Status);
        return -1;
    }

    printf("[Client] Negotiation succeeded. Possibly SMB dialect up to 3.1.1.\n");
    return 0;
}

//--------------------------------------------------
// doSessionSetup: minimal multi-round approach
//--------------------------------------------------
int doSessionSetup() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);

    // We'll do multiple rounds if the server returns STATUS_MORE_PROCESSING_REQUIRED
    unsigned char   outBuf[1024];
    unsigned char   inBuf[1024];
    ssize_t         payloadLen;
    SMB2Header      respHdr;
    int             done = 0;
    int             round = 0;

    // We’ll store any "security token" we get from the server and send back, etc.
    // This is incomplete. Real NTLM or Kerberos logic is more complex.
    size_t securityTokenSize = 0;

    while (!done && round < 5) {
        // Build a minimal SessionSetupRequest
        SMB2SessionSetupRequest ssreq;
        memset(&ssreq, 0, sizeof(ssreq));
        ssreq.StructureSize    = 25;
        // For NTLM, flags might include 0x01 for binding
        // For Kerberos, etc. we might do something else
        // This is only a placeholder
        ssreq.SecurityBufferOffset = sizeof(SMB2SessionSetupRequest);
        ssreq.SecurityBufferLength = (uint16_t)securityTokenSize; // zero if none

        // Build request buffer
        size_t totalReqSize = sizeof(ssreq) + securityTokenSize;
        memset(outBuf, 0, sizeof(outBuf));
        memcpy(outBuf, &ssreq, sizeof(ssreq));
        // If we had a token from previous round, we'd copy it after ssreq

        buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);
        if (sendSMB2Request(&hdr, outBuf, totalReqSize) < 0) {
            return -1;
        }

        // Receive
        if (recvSMB2Response(&respHdr, inBuf, sizeof(inBuf), &payloadLen) < 0) {
            return -1;
        }

        if (respHdr.Status == STATUS_SUCCESS) {
            // All done
            gSessionId = respHdr.SessionId;
            printf("[Client] Session Setup complete. SessionId=0x%llx\n",
                   (unsigned long long)gSessionId);
            done = 1;
        }
        else if (respHdr.Status == STATUS_MORE_PROCESSING_REQUIRED) {
            // We’d parse the new SPNEGO/NTLM token from the server, store it,
            // and send it back in the next round. This code is a placeholder.
            printf("[Client] Session Setup round %d: server wants more processing.\n", round);
            // Extract the SecurityBuffer from the response if we want to continue
            // For brevity, we skip it and pretend we have no token to send back.
        }
        else {
            fprintf(stderr, "Session Setup failed: 0x%08X\n", respHdr.Status);
            return -1;
        }
        round++;
    }

    if (!done) {
        fprintf(stderr, "Session Setup did not complete within 5 rounds.\n");
        return -1;
    }
    return 0;
}

//--------------------------------------------------
// doTreeConnect: connect to IPC$ share
//--------------------------------------------------
int doTreeConnect(const char *uncPath) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_TREE_CONNECT, 0, gSessionId, &hdr);

    SMB2TreeConnectRequest req;
    memset(&req, 0, sizeof(req));
    req.StructureSize = 9;
    req.PathOffset    = sizeof(req);
    uint32_t pathLen  = (uint32_t)strlen(uncPath);
    req.PathLength    = pathLen;

    size_t totalSize = sizeof(req) + pathLen;
    unsigned char *buf = (unsigned char*)malloc(totalSize);
    if (!buf) {
        fprintf(stderr, "malloc failed in doTreeConnect\n");
        return -1;
    }
    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), uncPath, pathLen);

    if (sendSMB2Request(&hdr, buf, totalSize) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    SMB2Header respHdr;
    unsigned char rbuf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, rbuf, sizeof(rbuf), &payloadLen) < 0) {
        return -1;
    }

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "TreeConnect to %s failed: 0x%08X\n", uncPath, respHdr.Status);
        return -1;
    }

    if (payloadLen < (ssize_t)sizeof(SMB2TreeConnectResponse)) {
        fprintf(stderr, "TreeConnect response too small.\n");
        return -1;
    }

    gTreeId = respHdr.TreeId;
    printf("[Client] TREE_CONNECT to %s succeeded. TreeId=0x%08X\n",
           uncPath, gTreeId);
    return 0;
}

//--------------------------------------------------
// doOpenPipe: open named pipe via SMB2_CREATE
//--------------------------------------------------
int doOpenPipe(const char *pipeName) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CREATE, gTreeId, gSessionId, &hdr);

    SMB2CreateRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize        = 57;
    creq.RequestedOplockLevel = 0; // none
    creq.ImpersonationLevel   = 2; // SecurityImpersonation
    creq.DesiredAccess        = 0x001F01FF; // Full control for demonstration
    creq.FileAttributes       = 0;
    creq.ShareAccess          = 3; // read/write share
    creq.CreateDisposition    = 1; // FILE_OPEN
    creq.CreateOptions        = 0;
    creq.NameOffset           = sizeof(creq);

    // Convert ASCII to UTF-16LE
    uint32_t pipeNameLenBytes = (uint32_t)(strlen(pipeName) * 2);
    creq.NameLength = (uint16_t)pipeNameLenBytes;

    size_t reqSize = sizeof(creq) + pipeNameLenBytes;
    unsigned char *buf = (unsigned char*)malloc(reqSize);
    if (!buf) {
        fprintf(stderr, "malloc failed in doOpenPipe\n");
        return -1;
    }
    memcpy(buf, &creq, sizeof(creq));

    // Simple ASCII->UTF16
    unsigned char *namePtr = buf + sizeof(creq);
    for (size_t i = 0; i < strlen(pipeName); i++) {
        namePtr[i*2]   = (unsigned char)pipeName[i];
        namePtr[i*2+1] = 0x00;
    }

    if (sendSMB2Request(&hdr, buf, reqSize) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    // Receive
    SMB2Header respHdr;
    unsigned char rbuf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, rbuf, sizeof(rbuf), &payloadLen) < 0) {
        return -1;
    }
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "OpenPipe '%s' failed: 0x%08X\n", pipeName, respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2CreateResponse)) {
        fprintf(stderr, "CreateResponse too small.\n");
        return -1;
    }
    SMB2CreateResponse *cres = (SMB2CreateResponse*)rbuf;
    gPipeFidPersistent = cres->FileIdPersistent;
    gPipeFidVolatile   = cres->FileIdVolatile;

    printf("[Client] Pipe '%s' opened OK. Fid=(%llx:%llx)\n",
           pipeName,
           (unsigned long long)gPipeFidPersistent,
           (unsigned long long)gPipeFidVolatile);
    return 0;
}

//--------------------------------------------------
// doWritePipe: write data into pipe
//--------------------------------------------------
int doWritePipe(const unsigned char *data, size_t dataLen) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);

    SMB2WriteRequest wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.StructureSize    = 49;
    wreq.DataOffset       = sizeof(wreq);
    wreq.Length           = (uint32_t)dataLen;
    wreq.FileIdPersistent = gPipeFidPersistent;
    wreq.FileIdVolatile   = gPipeFidVolatile;

    size_t reqSize = sizeof(wreq) + dataLen;
    unsigned char *buf = (unsigned char*)malloc(reqSize);
    if (!buf) {
        fprintf(stderr, "malloc failed in doWritePipe\n");
        return -1;
    }
    memcpy(buf, &wreq, sizeof(wreq));
    memcpy(buf + sizeof(wreq), data, dataLen);

    if (sendSMB2Request(&hdr, buf, reqSize) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    // Receive
    SMB2Header respHdr;
    unsigned char rbuf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, rbuf, sizeof(rbuf), &payloadLen) < 0) {
        return -1;
    }

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "WritePipe failed: 0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2WriteResponse)) {
        fprintf(stderr, "WriteResponse too small.\n");
        return -1;
    }
    SMB2WriteResponse *wres = (SMB2WriteResponse*)rbuf;
    printf("[Client] Wrote %u bytes to pipe.\n", wres->Count);
    return 0;
}

//--------------------------------------------------
// doReadPipe: read data from pipe
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

    if (sendSMB2Request(&hdr, &rreq, sizeof(rreq)) < 0) {
        return -1;
    }

    // Recv
    SMB2Header respHdr;
    unsigned char rbuf[2048];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, rbuf, sizeof(rbuf), &payloadLen) < 0) {
        return -1;
    }
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ReadPipe failed: 0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2ReadResponse)) {
        fprintf(stderr, "ReadResponse too small.\n");
        return -1;
    }
    SMB2ReadResponse *rres = (SMB2ReadResponse*)rbuf;
    uint32_t dataLen = rres->DataLength;

    if (dataLen > 0) {
        // Ensure offset+length is within payload
        if (rres->DataOffset + dataLen <= (uint32_t)payloadLen) {
            // Copy to outBuf
            const unsigned char *dataStart = rbuf + rres->DataOffset;
            if (dataLen > outBufSize) {
                dataLen = outBufSize; 
            }
            memcpy(outBuf, dataStart, dataLen);
        } else {
            fprintf(stderr, "Data offset out of bounds.\n");
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

    // 3. SMB2 NEGOTIATE (for 2.0.2 through 3.1.1)
    if (doNegotiate() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 4. SMB2 SESSION_SETUP (Placeholder multi-round)
    if (doSessionSetup() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 5. TREE_CONNECT to IPC$ share
    char ipcPath[256];
    snprintf(ipcPath, sizeof(ipcPath), "\\\\%s\\IPC$", serverIp);
    if (doTreeConnect(ipcPath) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 6. CREATE named pipe: "\\PIPE\\svcctl" or "\\PIPE\\atsvc", etc.
    //    This is where you'd do “remote exec” via DCERPC calls to the service manager.
    if (doOpenPipe("\\PIPE\\svcctl") < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 7. Write some fake RPC data (placeholder)
    //    In reality, you'd craft a DCERPC "bind" packet, then SVCCTL requests.
    unsigned char fakeRpcRequest[] = {
        0x05, 0x00, 0x0B, 0x03, // DCE/RPC version stubs, etc. Just placeholder
        // ...
    };
    if (doWritePipe(fakeRpcRequest, sizeof(fakeRpcRequest)) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 8. Read any response
    unsigned char responseBuf[1024];
    memset(responseBuf, 0, sizeof(responseBuf));
    uint32_t bytesRead = 0;
    if (doReadPipe(responseBuf, sizeof(responseBuf), &bytesRead) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (bytesRead > 0) {
        printf("[Client] Received %u bytes (hex):\n", bytesRead);
        for (uint32_t i = 0; i < bytesRead; i++) {
            printf("%02X ", responseBuf[i]);
        }
        printf("\n");
    }

    // 9. If you were implementing real “remote exec,” you’d:
    //    - Send a DCERPC “bind” to SVCCTL
    //    - Call CreateServiceW specifying something like cmd.exe /c "..."
    //    - Call StartService
    //    - Optionally call DeleteService
    //    This is all beyond the scope of this simple example.

    // 10. Cleanup
    close(gSock);
    printf("[Client] Finished.\n");
    return EXIT_SUCCESS;
}

/*********************************************************************
 * Security & Implementation Considerations:
 *
 * 1. Real SMB2 Authentication:
 *    - The code above stubs multi-round Session Setup but does not
 *      properly implement NTLM/Kerberos token exchange. Production
 *      code must handle these tokens carefully.
 *
 * 2. SMB2 Signing/Encryption:
 *    - Strongly recommended in real environments, but not shown here.
 *
 * 3. Named Pipes & DCERPC:
 *    - Achieving “remote exec” typically means sending correct SVCCTL
 *      or ATSVC DCERPC calls over the named pipe. This is complicated
 *      and must be done with proper IDL, marshalling, etc.
 *
 * 4. Permissions:
 *    - Windows requires that the client have rights to create/start
 *      services. If your credentials lack privileges, you’ll get
 *      STATUS_ACCESS_DENIED.
 *
 * 5. Legal/Ethical:
 *    - Creating or starting arbitrary services on remote hosts can be
 *      highly invasive. Only do so with explicit permission in a 
 *      controlled environment (e.g., a pen test under contract).
 *********************************************************************/
#include "Limelight-internal.h"
#include <irohnet.h>
#include <stdio.h>
#include <stdlib.h>
static int counter = 1; // Initialize counter
char filename[50]; // Buffer to hold the filename
#define FIRST_FRAME_MAX 1500
#define FIRST_FRAME_TIMEOUT_SEC 20

#define FIRST_FRAME_PORT 47996

int iroh_rtt= 0;
static RTP_VIDEO_QUEUE rtpQueue;

// static SOCKET rtpSocket = INVALID_SOCKET;
static SOCKET firstFrameSocket = INVALID_SOCKET;

static MagicEndpoint_t* irohEndpoint = NULL;
static Connection_t* irohConnection = NULL;
static RecvStream_t *recvStream = NULL;

static PPLT_CRYPTO_CONTEXT decryptionCtx;

static PLT_THREAD udpPingThread;
static PLT_THREAD receiveThread;
static PLT_THREAD decoderThread;

static bool receivedDataFromPeer;
static uint64_t firstDataTimeMs;
static bool receivedFullFrame;

// We can't request an IDR frame until the depacketizer knows
// that a packet was lost. This timeout bounds the time that
// the RTP queue will wait for missing/reordered packets.
#define RTP_QUEUE_DELAY 10

// This is the desired number of video packets that can be
// stored in the socket's receive buffer. 2048 is chosen
// because it should be large enough for all reasonable
// frame sizes (probably 2 or 3 frames) without using too
// much kernel memory with larger packet sizes. It also
// can smooth over transient pauses in network traffic
// and subsequent packet/frame bursts that follow.
#define RTP_RECV_PACKETS_BUFFERED 2048

// Initialize the video stream
void initializeVideoStream(MagicEndpoint_t* ep) {
    initializeVideoDepacketizer(StreamConfig.packetSize);
    RtpvInitializeQueue(&rtpQueue);
    decryptionCtx = PltCreateCryptoContext();
    receivedDataFromPeer = false;
    firstDataTimeMs = 0;
    receivedFullFrame = false;
    irohEndpoint = ep;
}

// Clean up the video stream
void destroyVideoStream(void) {
    PltDestroyCryptoContext(decryptionCtx);
    destroyVideoDepacketizer();
    RtpvCleanupQueue(&rtpQueue);
    irohEndpoint = NULL;
}

// UDP Ping proc
static void VideoPingThreadProc(void* context) {
    char legacyPingData[] = { 0x50, 0x49, 0x4E, 0x47 };
    LC_SOCKADDR saddr;

    LC_ASSERT(VideoPortNumber != 0);

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, VideoPortNumber);

    // We do not check for errors here. Socket errors will be handled
    // on the read-side in ReceiveThreadProc(). This avoids potential
    // issues related to receiving ICMP port unreachable messages due
    // to sending a packet prior to the host PC binding to that port.
    int pingCount = 0;

    // buffer for iroh sends
    slice_ref_uint8_t buffer;
    size_t maxSize = connection_max_datagram_size(&irohConnection);
    if (maxSize < sizeof(VideoPingPayload)) {
        Limelog("Cannot send video pings, max datagram size too small");
        return;
    }

    while (!PltIsThreadInterrupted(&udpPingThread)) {
        if (VideoPingPayload.payload[0] != 0) {
            pingCount++;
            VideoPingPayload.sequenceNumber = BE32(pingCount);

            // sendto(rtpSocket, (char*)&VideoPingPayload, sizeof(VideoPingPayload), 0, (struct sockaddr*)&saddr, AddrLen);

            // send via iroh
            buffer.ptr = (uint8_t*) &VideoPingPayload;
            buffer.len = sizeof(VideoPingPayload);
            connection_write_datagram(&irohConnection, buffer);
        }
        else {
            // sendto(rtpSocket, legacyPingData, sizeof(legacyPingData), 0, (struct sockaddr*)&saddr, AddrLen);

            // send via iroh
            buffer.ptr = (uint8_t*) &legacyPingData;
            buffer.len = sizeof(legacyPingData);
            connection_write_datagram(&irohConnection, buffer);
        }

        PltSleepMsInterruptible(&udpPingThread, 500);
    }
}

// Receive thread proc
static void VideoReceiveThreadProc(void* context) {
    int err;
    int bufferSize, receiveSize, decryptedSize, minSize;
    char* buffer;
    char* encryptedBuffer;
    int queueStatus;
    // bool useSelect;
    int waitingForVideoMs;
    bool encrypted;

    encrypted = !!(EncryptionFeaturesEnabled & SS_ENC_VIDEO);
    decryptedSize = StreamConfig.packetSize + MAX_RTP_HEADER_SIZE;
    minSize = sizeof(RTP_PACKET) + ((EncryptionFeaturesEnabled & SS_ENC_VIDEO) ? sizeof(ENC_VIDEO_HEADER) : 0);
    receiveSize = decryptedSize + ((EncryptionFeaturesEnabled & SS_ENC_VIDEO) ? sizeof(ENC_VIDEO_HEADER) : 0);
    bufferSize = decryptedSize + sizeof(RTPV_QUEUE_ENTRY);
    buffer = NULL;

    /*if (setNonFatalRecvTimeoutMs(rtpSocket, UDP_RECV_POLL_TIMEOUT_MS) < 0) {
        // SO_RCVTIMEO failed, so use select() to wait
        useSelect = true;
    }
    else {
        // SO_RCVTIMEO timeout set for recv()
        useSelect = false;
        }*/

    // Allocate a staging buffer to use for each received packet
    if (encrypted) {
        encryptedBuffer = (char*)malloc(receiveSize);
        if (encryptedBuffer == NULL) {
            Limelog("Video Receive: malloc() failed\n");
            ListenerCallbacks.connectionTerminated(-1);
            return;
        }
    }
    else {
        encryptedBuffer = NULL;
    }

    waitingForVideoMs = 0;

    // // buffer for reading datagrams from iroh
    Vec_uint8_t recvBuffer = rust_buffer_alloc(receiveSize);
    int maxSize = connection_max_datagram_size(&irohConnection);
    if (maxSize < receiveSize) {
      Limelog("Video Receive: maxDatagramSize too small %d %d %d %d \n", maxSize, encrypted, receiveSize, bufferSize);
      ListenerCallbacks.connectionTerminated(-1);
      return;
    }

    while (!PltIsThreadInterrupted(&receiveThread)) {
        PRTP_PACKET packet;

        if (buffer == NULL) {
            buffer = (char*)malloc(bufferSize);
            if (buffer == NULL) {
                Limelog("Video Receive: malloc() failed\n");
                ListenerCallbacks.connectionTerminated(-1);
                break;
            }
        }
        /* err = recvUdpSocket(rtpSocket,
                            encrypted ? encryptedBuffer : buffer,
                            receiveSize,
                            useSelect);*/
        // TODO: read with timeout
        err = connection_read_datagram_timeout(&irohConnection, &recvBuffer, UDP_RECV_POLL_TIMEOUT_MS);
       Limelog("RTT is %d", connection_rtt(&irohConnection));
        iroh_rtt = connection_rtt(&irohConnection);
        // err = recv_stream_read(&recvStream, recvBufferSlice);

        if (err < 0) {
            Limelog("Video Receive: stream_read() failed\n");
            ListenerCallbacks.connectionTerminated(LastSocketFail());
            break;
        }
        else if (rust_buffer_len(&recvBuffer) == 0 || err == MAGIC_ENDPOINT_RESULT_TIMEOUT) {
            if (!receivedDataFromPeer) {
                // If we wait many seconds without ever receiving a video packet,
                // assume something is broken and terminate the connection.
                waitingForVideoMs += UDP_RECV_POLL_TIMEOUT_MS;
                if (waitingForVideoMs >= FIRST_FRAME_TIMEOUT_SEC * 1000) {
                    Limelog("Terminating connection due to lack of video traffic\n");
                    ListenerCallbacks.connectionTerminated(ML_ERROR_NO_VIDEO_TRAFFIC);
                    break;
                }
            }

            // Receive timed out; try again
            continue;
        } else {
            // TODO: avoid copy
            // if (encrypted) {
            //   if ((int)rust_buffer_len(&recvBuffer) < receiveSize) {
            //       // read too little, ignore
            //       Limelog(
            //               "Received video packets of %d bytes, expected %d bytes, ignoring\n",
            //               rust_buffer_len(&recvBuffer),
            //               receiveSize);
            //   } else {
            //       memcpy(encryptedBuffer, recvBuffer.ptr, receiveSize);
            //   }
            // } else
            {
               // Limelog(" %d %d ", rust_buffer_len(&recvBuffer), receiveSize);
              if ((int)rust_buffer_len(&recvBuffer) < receiveSize) {
                  // read too little, ignore
                  Limelog(
                          "Received video packets of %d bytes, expected %d bytes, ignoring\n",
                          rust_buffer_len(&recvBuffer),
                          bufferSize);
              } else {
                  memcpy(buffer, recvBuffer.ptr, receiveSize);
                  //Limelog("received buffer %d",  rust_buffer_len(&recvBuffer));
              }
            }
        }

        if (!receivedDataFromPeer) {
            receivedDataFromPeer = true;
            Limelog("Received first video packet after %d ms\n", waitingForVideoMs);

            firstDataTimeMs = PltGetMillis();
        }

#ifndef LC_FUZZING
        if (!receivedFullFrame) {
            uint64_t now = PltGetMillis();

            if (now - firstDataTimeMs >= FIRST_FRAME_TIMEOUT_SEC * 1000) {
                Limelog("Terminating connection due to lack of a successful video frame\n");
                ListenerCallbacks.connectionTerminated(ML_ERROR_NO_VIDEO_FRAME);
                break;
            }
        }
#endif

        if (rust_buffer_len(&recvBuffer) < minSize) {
            // Runt packet
            continue;
        }

        // if(counter < 100) {
        //     sprintf(filename, "moonlight-iroh2-%d.bin", counter++);

        //     // Open the file in binary write mode
        //     FILE *file = fopen(filename, "wb");
        //     if (file == NULL) {

        //     }


        //     // Write the data to the file
        //     size_t written = fwrite(buffer, sizeof(unsigned char), receiveSize, file);
        //     if (written < receiveSize) {
        //         perror("Error writing to file");
        //         fclose(file); // Close the file before returning
        //     }

        //     // Close the file
        //     fclose(file);
        // }
        // Decrypt the packet into the buffer if encryption is enabled
        if (encrypted) {
            PENC_VIDEO_HEADER encHeader = (PENC_VIDEO_HEADER)encryptedBuffer;

            // If this frame is below our current frame number, discard it before decryption
            // to save CPU cycles decrypting FEC shards for a frame we already reassembled.
            //
            // Since this is happening _before_ decryption, this packet is not trusted yet.
            // It's imperative that we do not mutate any state based on this packet until
            // after it has been decrypted successfully!
            //
            // It's possible for an attacker to inject a fake packet that has any value of
            // header fields they want, however this provides them no benefit because we will
            // simply drop said packet here (if it's below the current frame number) or it
            // will pass this check and be dropped during decryption (if contents is tampered)
            // or after decryption in the RTP queue (if it's a replay of a previous authentic
            // packet from the host).
            //
            // In short, an attacker spoofing this value via MITM or sending malicious values
            // impersonating the host from off-link doesn't gain them anything. If they have
            // a true MITM, they can DoS our connection by just dropping all our traffic, so
            // tampering with packets to fail this check doesn't accomplish anything they
            // couldn't already do. If they're not on-link, we just throw their malicious
            // traffic away (as mentioned in the paragraph above) and continue accepting
            // legitmate video traffic.
            if (encHeader->frameNumber && LE32(encHeader->frameNumber) < RtpvGetCurrentFrameNumber(&rtpQueue)) {
                continue;
            }

            if (!PltDecryptMessage(decryptionCtx, ALGORITHM_AES_GCM, 0,
                                   (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                                   encHeader->iv, sizeof(encHeader->iv),
                                   encHeader->tag, sizeof(encHeader->tag),
                                   ((unsigned char*)(encHeader + 1)), err - sizeof(ENC_VIDEO_HEADER), // The ciphertext is after the header
                                   (unsigned char*)buffer, &err)) {
                Limelog("Failed to decrypt video packet!\n");
                continue;
            }
        }

        // Convert fields to host byte-order
        packet = (PRTP_PACKET)&buffer[0];
        packet->sequenceNumber = BE16(packet->sequenceNumber);
        packet->timestamp = BE32(packet->timestamp);
        packet->ssrc = BE32(packet->ssrc);
       //Limelog(" Sequence number %d ",  packet->sequenceNumber);

       // Limelog(" Adding to queue of RTP ");
        queueStatus = RtpvAddPacket(&rtpQueue, packet, 1008, (PRTPV_QUEUE_ENTRY)&buffer[decryptedSize]);
        //Limelog(" Queuestatus : %d ", queueStatus);
        if (queueStatus == RTPF_RET_QUEUED) {
            // The queue owns the buffer

            buffer = NULL;
        }
    }

    if (buffer != NULL) {
        free(buffer);
    }

    if (encryptedBuffer != NULL) {
        free(encryptedBuffer);
    }

    rust_buffer_free(recvBuffer);
}

void notifyKeyFrameReceived(void) {
    // Remember that we got a full frame successfully
    receivedFullFrame = true;
}

// Decoder thread proc
static void VideoDecoderThreadProc(void* context) {
    while (!PltIsThreadInterrupted(&decoderThread)) {
        VIDEO_FRAME_HANDLE frameHandle;
        PDECODE_UNIT decodeUnit;

        if (!LiWaitForNextVideoFrame(&frameHandle, &decodeUnit)) {
            return;
        }

        LiCompleteVideoFrame(frameHandle, VideoCallbacks.submitDecodeUnit(decodeUnit));
    }
}

// Read the first frame of the video stream
int readFirstFrame(void) {
    // All that matters is that we close this socket.
    // This starts the flow of video on Gen 3 servers.

    closeSocket(firstFrameSocket);
    firstFrameSocket = INVALID_SOCKET;

    return 0;
}

// Terminate the video stream
void stopVideoStream(void) {
    if (!receivedDataFromPeer) {
        Limelog("No video traffic was ever received from the host!\n");
    }

    VideoCallbacks.stop();

    // Wake up client code that may be waiting on the decode unit queue
    stopVideoDepacketizer();

    PltInterruptThread(&udpPingThread);
    PltInterruptThread(&receiveThread);
    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        PltInterruptThread(&decoderThread);
    }

    if (firstFrameSocket != INVALID_SOCKET) {
        shutdownTcpSocket(firstFrameSocket);
    }

    PltJoinThread(&udpPingThread);
    PltJoinThread(&receiveThread);
    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        PltJoinThread(&decoderThread);
    }

    PltCloseThread(&udpPingThread);
    PltCloseThread(&receiveThread);
    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        PltCloseThread(&decoderThread);
    }

    if (firstFrameSocket != INVALID_SOCKET) {
        closeSocket(firstFrameSocket);
        firstFrameSocket = INVALID_SOCKET;
    }
    /*if (rtpSocket != INVALID_SOCKET) {
        closeSocket(rtpSocket);
        rtpSocket = INVALID_SOCKET;
    }*/
    if (irohConnection != NULL) {
        connection_free(irohConnection);
        irohConnection = NULL;
    }


    VideoCallbacks.cleanup();
}

// Start the video stream
int startVideoStream(void* rendererContext, int drFlags, char* nodeAddress) {
    int err;

    firstFrameSocket = INVALID_SOCKET;

    // This must be called before the decoder thread starts submitting
    // decode units
    LC_ASSERT(NegotiatedVideoFormat != 0);
    err = VideoCallbacks.setup(NegotiatedVideoFormat, StreamConfig.width,
        StreamConfig.height, StreamConfig.fps, rendererContext, drFlags);
    if (err != 0) {
        return err;
    }

    /*rtpSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen,
                              RTP_RECV_PACKETS_BUFFERED * (StreamConfig.packetSize + MAX_RTP_HEADER_SIZE),
                              SOCK_QOS_TYPE_VIDEO);
    if (rtpSocket == INVALID_SOCKET) {
        VideoCallbacks.cleanup();
        return LastSocketError();
    }*/

    // Open video connection



    // TODO: improve API
    char videoAlpn[] = "/moonlight/video/1";
    slice_ref_uint8_t videoAlpnSlice;
    videoAlpnSlice.ptr = (uint8_t *) &videoAlpn[0];
    videoAlpnSlice.len = strlen(videoAlpn);

    irohEndpoint = magic_endpoint_default();
    MagicEndpointConfig_t config = magic_endpoint_config_default();
    magic_endpoint_config_add_alpn(&config, videoAlpnSlice);
    int bind_res = magic_endpoint_bind(&config, 0, &irohEndpoint);

    if (bind_res != 0)
    {
        Limelog(stderr, "failed to bind\n");
        return -1;
    }
    IrohServerNodeAddr = node_addr_default();
    err = node_addr_from_string(nodeAddress, &IrohServerNodeAddr);
    irohConnection = connection_default();
    err = magic_endpoint_connect(&irohEndpoint, videoAlpnSlice, IrohServerNodeAddr, &irohConnection);
    if (err != 0) {
        VideoCallbacks.cleanup();
        return err;
    }

    VideoCallbacks.start();

    err = PltCreateThread("VideoRecv", VideoReceiveThreadProc, NULL, &receiveThread);
    if (err != 0) {
        VideoCallbacks.stop();
        // closeSocket(rtpSocket);
        VideoCallbacks.cleanup();
        return err;
    }

    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        err = PltCreateThread("VideoDec", VideoDecoderThreadProc, NULL, &decoderThread);
        if (err != 0) {
            VideoCallbacks.stop();
            PltInterruptThread(&receiveThread);
            PltJoinThread(&receiveThread);
            PltCloseThread(&receiveThread);
            // closeSocket(rtpSocket);
            VideoCallbacks.cleanup();
            return err;
        }
    }

    if (AppVersionQuad[0] == 3) {
        // Connect this socket to open port 47998 for our ping thread
        firstFrameSocket = connectTcpSocket(&RemoteAddr, AddrLen,
                                            FIRST_FRAME_PORT, FIRST_FRAME_TIMEOUT_SEC);
        if (firstFrameSocket == INVALID_SOCKET) {
            VideoCallbacks.stop();
            stopVideoDepacketizer();
            PltInterruptThread(&receiveThread);
            if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
                PltInterruptThread(&decoderThread);
            }
            PltJoinThread(&receiveThread);
            if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
                PltJoinThread(&decoderThread);
            }
            PltCloseThread(&receiveThread);
            if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
                PltCloseThread(&decoderThread);
            }
            // closeSocket(rtpSocket);
            VideoCallbacks.cleanup();
            return LastSocketError();
        }
    }

    // Start pinging before reading the first frame so GFE knows where
    // to send UDP data
    err = PltCreateThread("VideoPing", VideoPingThreadProc, NULL, &udpPingThread);
    if (err != 0) {
        VideoCallbacks.stop();
        stopVideoDepacketizer();
        PltInterruptThread(&receiveThread);
        if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
            PltInterruptThread(&decoderThread);
        }
        PltJoinThread(&receiveThread);
        if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
            PltJoinThread(&decoderThread);
        }
        PltCloseThread(&receiveThread);
        if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
            PltCloseThread(&decoderThread);
        }
        // closeSocket(rtpSocket);
        if (firstFrameSocket != INVALID_SOCKET) {
            closeSocket(firstFrameSocket);
            firstFrameSocket = INVALID_SOCKET;
        }
        VideoCallbacks.cleanup();
        return err;
    }

    if (AppVersionQuad[0] == 3) {
        // Read the first frame to start the flow of video
        err = readFirstFrame();
        if (err != 0) {
            stopVideoStream();
            return err;
        }
    }

    return 0;
}

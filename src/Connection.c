#include "Limelight-internal.h"
#include <irohnet.h>

static int stage = STAGE_NONE;
static ConnListenerConnectionTerminated originalTerminationCallback;
static bool alreadyTerminated;
static PLT_THREAD terminationCallbackThread;
static int terminationCallbackErrorCode;

// Common globals
char* RemoteAddrString;
struct sockaddr_storage RemoteAddr;
struct sockaddr_storage LocalAddr;
SOCKADDR_LEN AddrLen;
int AppVersionQuad[4];
STREAM_CONFIGURATION StreamConfig;
CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;
DECODER_RENDERER_CALLBACKS VideoCallbacks;
AUDIO_RENDERER_CALLBACKS AudioCallbacks;
int NegotiatedVideoFormat;
volatile bool ConnectionInterrupted;
bool HighQualitySurroundSupported;
bool HighQualitySurroundEnabled;
OPUS_MULTISTREAM_CONFIGURATION NormalQualityOpusConfig;
OPUS_MULTISTREAM_CONFIGURATION HighQualityOpusConfig;
int AudioPacketDuration;
bool AudioEncryptionEnabled;
bool ReferenceFrameInvalidationSupported;
uint16_t RtspPortNumber;
uint16_t ControlPortNumber;
uint16_t AudioPortNumber;
uint16_t VideoPortNumber;
SS_PING AudioPingPayload;
SS_PING VideoPingPayload;
uint32_t ControlConnectData;
uint32_t SunshineFeatureFlags;
uint32_t EncryptionFeaturesSupported;
uint32_t EncryptionFeaturesRequested;
uint32_t EncryptionFeaturesEnabled;
char *irohNodeAddressTest = NULL;

// iroh node addr
NodeAddr_t IrohServerNodeAddr;

MagicEndpoint_t * irohEndpoint, *irohEndpoint2;
Connection_t* irohConnection, *irohAudioConnection, *irohVideoConnection, *controlConnection;

// Connection stages
static const char* stageNames[STAGE_MAX] = {
    "none",
    "platform initialization",
    "name resolution",
    "audio stream initialization",
    "RTSP handshake",
    "control stream initialization",
    "video stream initialization",
    "input stream initialization",
    "control stream establishment",
    "video stream establishment",
    "audio stream establishment",
    "input stream establishment"
};

// Get the name of the current stage based on its number
const char* LiGetStageName(int stage) {
    return stageNames[stage];
}

// Interrupt a pending connection attempt. This interruption happens asynchronously
// so it is not safe to start another connection before LiStartConnection() returns.
void LiInterruptConnection(void) {
    // Signal anyone waiting on the global interrupted flag
    ConnectionInterrupted = true;
}

// Stop the connection by undoing the step at the current stage and those before it
void LiStopConnection(void) {
    // Disable termination callbacks now
    alreadyTerminated = true;

    // Set the interrupted flag
    LiInterruptConnection();

    if (stage == STAGE_INPUT_STREAM_START) {
        Limelog("Stopping input stream...");
        stopInputStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_AUDIO_STREAM_START) {
        Limelog("Stopping audio stream...");
        stopAudioStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_VIDEO_STREAM_START) {
        Limelog("Stopping video stream...");
        stopVideoStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_CONTROL_STREAM_START) {
        Limelog("Stopping control stream...");
        stopControlStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_INPUT_STREAM_INIT) {
        Limelog("Cleaning up input stream...");
        destroyInputStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_VIDEO_STREAM_INIT) {
        Limelog("Cleaning up video stream...");
        destroyVideoStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_CONTROL_STREAM_INIT) {
        Limelog("Cleaning up control stream...");
        //destroyControlStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_RTSP_HANDSHAKE) {
        Limelog("Cleaning up handshake...");
        connection_free(irohConnection);
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_AUDIO_STREAM_INIT) {
        Limelog("Cleaning up audio stream...");
        destroyAudioStream();
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_NAME_RESOLUTION) {
        Limelog("Cleaning up name resolution...");
        magic_endpoint_free(irohEndpoint);
        stage--;
        Limelog("done\n");
    }
    if (stage == STAGE_PLATFORM_INIT) {
        Limelog("Cleaning up platform...");
        cleanupPlatform();
        stage--;
        Limelog("done\n");
    }
    LC_ASSERT(stage == STAGE_NONE);

    if (RemoteAddrString != NULL) {
        free(RemoteAddrString);
        RemoteAddrString = NULL;
    }
}

static void terminationCallbackThreadFunc(void* context)
{
    // Invoke the client's termination callback
    originalTerminationCallback(terminationCallbackErrorCode);
}

// This shim callback runs the client's connectionTerminated() callback on a
// separate thread. This is neccessary because other internal threads directly
// invoke this callback. That can result in a deadlock if the client
// calls LiStopConnection() in the callback when the cleanup code
// attempts to join the thread that the termination callback (and LiStopConnection)
// is running on.
static void ClInternalConnectionTerminated(int errorCode)
{
    int err;

    // Avoid recursion and issuing multiple callbacks
    if (alreadyTerminated || ConnectionInterrupted) {
        return;
    }

    terminationCallbackErrorCode = errorCode;
    alreadyTerminated = true;

    // Invoke the termination callback on a separate thread
    err = PltCreateThread("AsyncTerm", terminationCallbackThreadFunc, NULL, &terminationCallbackThread);
    if (err != 0) {
        // Nothing we can safely do here, so we'll just assert on debug builds
        Limelog("Failed to create termination thread: %d\n", err);
        LC_ASSERT(err == 0);
    }

    // Close the thread handle since we can never wait on it
    PltCloseThread(&terminationCallbackThread);
}

static bool parseRtspPortNumberFromUrl(const char* rtspSessionUrl, uint16_t* port)
{
    // If the session URL is not present, we will just use the well known port
    if (rtspSessionUrl == NULL) {
        return false;
    }

    // Pick the last colon in the string to match the port number
    char* portNumberStart = strrchr(rtspSessionUrl, ':');
    if (portNumberStart == NULL) {
        return false;
    }

    // Skip the colon
    portNumberStart++;

    // Validate the port number
    long int rawPort = strtol(portNumberStart, NULL, 10);
    if (rawPort <= 0 || rawPort > 65535) {
        return false;
    }

    *port = (uint16_t)rawPort;
    return true;
}

void
init_alpn_slice(slice_ref_uint8_t *slice, const char *str) {
    slice->ptr = (uint8_t *) str;  // Point to the string literal
    slice->len = strlen(str);  // Compute the length of the string
}

// Starts the connection to the streaming machine
int LiStartConnection(PSERVER_INFORMATION serverInfo, PSTREAM_CONFIGURATION streamConfig, PCONNECTION_LISTENER_CALLBACKS clCallbacks,
    PDECODER_RENDERER_CALLBACKS drCallbacks, PAUDIO_RENDERER_CALLBACKS arCallbacks, void* renderContext, int drFlags,
    void* audioContext, int arFlags) {
    int err;

    if (drCallbacks != NULL && (drCallbacks->capabilities & CAPABILITY_PULL_RENDERER) && drCallbacks->submitDecodeUnit) {
        Limelog("CAPABILITY_PULL_RENDERER cannot be set with a submitDecodeUnit callback\n");
        LC_ASSERT(false);
        err = -1;
        goto Cleanup;
    }

    if (drCallbacks != NULL && (drCallbacks->capabilities & CAPABILITY_PULL_RENDERER) && (drCallbacks->capabilities & CAPABILITY_DIRECT_SUBMIT)) {
        Limelog("CAPABILITY_PULL_RENDERER and CAPABILITY_DIRECT_SUBMIT cannot be set together\n");
        LC_ASSERT(false);
        err = -1;
        goto Cleanup;
    }

    if (serverInfo->serverCodecModeSupport == 0) {
        Limelog("serverCodecModeSupport field in SERVER_INFORMATION must be set!\n");
        LC_ASSERT(false);
        err = -1;
        goto Cleanup;
    }

    // Extract the appversion from the supplied string
    if (extractVersionQuadFromString(serverInfo->serverInfoAppVersion,
                                     AppVersionQuad) < 0) {
        Limelog("Invalid appversion string: %s\n", serverInfo->serverInfoAppVersion);
        err = -1;
        goto Cleanup;
    }

    // Replace missing callbacks with placeholders
    fixupMissingCallbacks(&drCallbacks, &arCallbacks, &clCallbacks);
    memcpy(&VideoCallbacks, drCallbacks, sizeof(VideoCallbacks));
    memcpy(&AudioCallbacks, arCallbacks, sizeof(AudioCallbacks));

#ifdef LC_DEBUG_RECORD_MODE
    // Install the pass-through recorder callbacks
    setRecorderCallbacks(&VideoCallbacks, &AudioCallbacks);
#endif

    // Hook the termination callback so we can avoid issuing a termination callback
    // after LiStopConnection() is called.
    //
    // Initialize ListenerCallbacks before anything that could call Limelog().
    originalTerminationCallback = clCallbacks->connectionTerminated;
    memcpy(&ListenerCallbacks, clCallbacks, sizeof(ListenerCallbacks));
    ListenerCallbacks.connectionTerminated = ClInternalConnectionTerminated;

    memset(&LocalAddr, 0, sizeof(LocalAddr));
    NegotiatedVideoFormat = 0;
    memcpy(&StreamConfig, streamConfig, sizeof(StreamConfig));
    RemoteAddrString = strdup(serverInfo->address);

    // The values in RTSP SETUP will be used to populate these.
    VideoPortNumber = 0;
    ControlPortNumber = 0;
    AudioPortNumber = 0;

    IrohServerNodeAddr = node_addr_default();

    // reuse the address field from the server info
    //char *nodeAddrToUse = TEST_NODE_ADDR;
    err = node_addr_from_string(serverInfo->irohNodeAddress, &IrohServerNodeAddr);
    irohNodeAddressTest = strdup(serverInfo->irohNodeAddress);
    Limelog("connecting to %s", serverInfo->irohNodeAddress);
    if (err != 0) {
        Limelog("invalid iroh node address: %s\n", serverInfo->address);
        err = -1;
        goto Cleanup;
    }

    // Parse RTSP port number from RTSP session URL
    if (!parseRtspPortNumberFromUrl(serverInfo->rtspSessionUrl, &RtspPortNumber)) {
        // Use the well known port if parsing fails
        RtspPortNumber = 48010;

        Limelog("RTSP port: %u (RTSP URL parsing failed)\n", RtspPortNumber);
    }
    else {
        Limelog("RTSP port: %u\n", RtspPortNumber);
    }

    alreadyTerminated = false;
    ConnectionInterrupted = false;

    // Validate the audio configuration
    if (MAGIC_BYTE_FROM_AUDIO_CONFIG(StreamConfig.audioConfiguration) != 0xCA ||
            CHANNEL_COUNT_FROM_AUDIO_CONFIGURATION(StreamConfig.audioConfiguration) > AUDIO_CONFIGURATION_MAX_CHANNEL_COUNT) {
        Limelog("Invalid audio configuration specified\n");
        err = -1;
        goto Cleanup;
    }

    // FEC only works in 16 byte chunks, so we must round down
    // the given packet size to the nearest multiple of 16.
    StreamConfig.packetSize -= StreamConfig.packetSize % 16;
    Limelog("Vivek stream config size , %d", StreamConfig.packetSize);
    if (StreamConfig.packetSize == 0) {
        Limelog("Invalid packet size specified\n");
        err = -1;
        goto Cleanup;
    }

    // Height must not be odd or NVENC will fail to initialize
    if (StreamConfig.height & 0x1) {
        Limelog("Encoder height must not be odd. Rounding %d to %d\n",
                StreamConfig.height,
                StreamConfig.height & ~0x1);
        StreamConfig.height = StreamConfig.height & ~0x1;
    }

    // Dimensions over 4096 are only supported with HEVC on NVENC
    if (!(StreamConfig.supportedVideoFormats & ~VIDEO_FORMAT_MASK_H264) &&
            (StreamConfig.width > 4096 || StreamConfig.height > 4096)) {
        Limelog("WARNING: Streaming at resolutions above 4K using H.264 will likely fail! Trying anyway!\n");
    }
    // Dimensions over 8192 aren't supported at all (even on Turing)
    else if (StreamConfig.width > 8192 || StreamConfig.height > 8192) {
        Limelog("WARNING: Streaming at resolutions above 8K will likely fail! Trying anyway!\n");
    }

    // Reference frame invalidation doesn't seem to work with resolutions much
    // higher than 1440p. I haven't figured out a pattern to indicate which
    // resolutions will work and which won't, but we can at least exclude
    // 4K from RFI to avoid significant persistent artifacts after frame loss.
    if (StreamConfig.width == 3840 && StreamConfig.height == 2160 &&
            (VideoCallbacks.capabilities & CAPABILITY_REFERENCE_FRAME_INVALIDATION_AVC) &&
            !IS_SUNSHINE()) {
        Limelog("Disabling reference frame invalidation for 4K streaming with GFE\n");
        VideoCallbacks.capabilities &= ~CAPABILITY_REFERENCE_FRAME_INVALIDATION_AVC;
    }

    Limelog("Initializing platform...");
    ListenerCallbacks.stageStarting(STAGE_PLATFORM_INIT);
    err = initializePlatform();
    if (err != 0) {
        Limelog("failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_PLATFORM_INIT, err);
        goto Cleanup;
    }
    stage++;
    LC_ASSERT(stage == STAGE_PLATFORM_INIT);
    ListenerCallbacks.stageComplete(STAGE_PLATFORM_INIT);
    Limelog("done\n");

    // Limelog("Resolving host name...");
    ListenerCallbacks.stageStarting(STAGE_NAME_RESOLUTION);

    Limelog("Initializing iroh endpoint...");
    MagicEndpointConfig_t config = magic_endpoint_config_default();
    // TODO: improve API
    slice_ref_uint8_t videoAlpnSlice;
    init_alpn_slice(&videoAlpnSlice, "/moonlight/video/1");
    magic_endpoint_config_add_alpn(&config, videoAlpnSlice);
    slice_ref_uint8_t audioAlpnSlice;
    init_alpn_slice(&audioAlpnSlice, "/moonlight/audio/1");
    magic_endpoint_config_add_alpn(&config, audioAlpnSlice);
    slice_ref_uint8_t rtspAlpnSlice;
    init_alpn_slice(&rtspAlpnSlice, "/moonlight/rtsp/1");
    magic_endpoint_config_add_alpn(&config, rtspAlpnSlice);
    slice_ref_uint8_t controlAlpnSlice;
    init_alpn_slice(&controlAlpnSlice, "/moonlight/control/1");
    magic_endpoint_config_add_alpn(&config, controlAlpnSlice);

    irohEndpoint = magic_endpoint_default();
    err = magic_endpoint_bind(&config, 0, &irohEndpoint);

    if (err != 0) {
        Limelog("failed %d\n", err);
        goto Cleanup;
    }
    Limelog("done\n");

    stage++;
    LC_ASSERT(stage == STAGE_NAME_RESOLUTION);
    ListenerCallbacks.stageComplete(STAGE_NAME_RESOLUTION);
    StreamConfig.packetSize = 992;
    StreamConfig.streamingRemotely = STREAM_CFG_REMOTE;
    Limelog("Initializing audio stream...");
    ListenerCallbacks.stageStarting(STAGE_AUDIO_STREAM_INIT);
    err = initializeAudioStream(irohEndpoint);
    if (err != 0) {
        Limelog("[iroh Audio] failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_AUDIO_STREAM_INIT, err);
        goto Cleanup;
    }
    stage++;
    LC_ASSERT(stage == STAGE_AUDIO_STREAM_INIT);
    ListenerCallbacks.stageComplete(STAGE_AUDIO_STREAM_INIT);
    Limelog("done\n");

    Limelog("Starting RTSP handshake...");
    ListenerCallbacks.stageStarting(STAGE_RTSP_HANDSHAKE);

    // Setup the control iroh connection, used for the RTSP handshake and the control stream
    irohConnection = connection_default();
    err = magic_endpoint_connect(&irohEndpoint, rtspAlpnSlice, IrohServerNodeAddr, &irohConnection);
    if (err != 0) {
        Limelog("[iroh control] failed endpoint connect: %d\n", err);
        goto Cleanup;
    }
    Limelog("[iroh] Sendig RTSP handshake\n");
    err = performRtspHandshake(serverInfo, irohConnection);
    if (err != 0) {
        Limelog("failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_RTSP_HANDSHAKE, err);
        goto Cleanup;
    }
    stage++;
    LC_ASSERT(stage == STAGE_RTSP_HANDSHAKE);
    ListenerCallbacks.stageComplete(STAGE_RTSP_HANDSHAKE);
    Limelog("done\n");

    Limelog("Initializing control stream...");
    ListenerCallbacks.stageStarting(STAGE_CONTROL_STREAM_INIT);
    // controlConnection = connection_default();
    // err = magic_endpoint_connect(&irohEndpoint, rtspAlpnSlice, IrohServerNodeAddr, &irohConnection);
    //err = magic_endpoint_connect(&irohEndpoint2, controlAlpnSlice, IrohServerNodeAddr, &controlConnection);
     Limelog("Initializing control stream... 2 ");
    err = initializeControlStream(serverInfo->irohNodeAddress, irohEndpoint );
    if (err != 0) {
        Limelog("failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_CONTROL_STREAM_INIT, err);
        goto Cleanup;
    }
    stage++;
    LC_ASSERT(stage == STAGE_CONTROL_STREAM_INIT);
    ListenerCallbacks.stageComplete(STAGE_CONTROL_STREAM_INIT);
    Limelog("done\n");

    Limelog("Initializing video stream...");
    ListenerCallbacks.stageStarting(STAGE_VIDEO_STREAM_INIT);
    initializeVideoStream(irohEndpoint);
    stage++;
    LC_ASSERT(stage == STAGE_VIDEO_STREAM_INIT);
    ListenerCallbacks.stageComplete(STAGE_VIDEO_STREAM_INIT);
    Limelog("done\n");

    Limelog("Initializing input stream...");
    ListenerCallbacks.stageStarting(STAGE_INPUT_STREAM_INIT);
    initializeInputStream();
    stage++;
    LC_ASSERT(stage == STAGE_INPUT_STREAM_INIT);
    ListenerCallbacks.stageComplete(STAGE_INPUT_STREAM_INIT);
    Limelog("done\n");

    Limelog("NOT Starting control stream...");
    ListenerCallbacks.stageStarting(STAGE_CONTROL_STREAM_START);
    err = startControlStream();
    if (err != 0) {
        Limelog("failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_CONTROL_STREAM_START, err);
        goto Cleanup;
    }
    stage++;
    LC_ASSERT(stage == STAGE_CONTROL_STREAM_START);

    Limelog("done\n");
    //stage++;
    ListenerCallbacks.stageComplete(STAGE_CONTROL_STREAM_START);
    Limelog("Starting video stream...");
    ListenerCallbacks.stageStarting(STAGE_VIDEO_STREAM_START);
    err = startVideoStream(renderContext, drFlags, serverInfo->irohNodeAddress);
    if (err != 0) {
        Limelog("Video stream start failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_VIDEO_STREAM_START, err);
        goto Cleanup;
    }
    stage++;
    Limelog(" STAGE IS %d", stage );
    LC_ASSERT(stage == STAGE_VIDEO_STREAM_START);
    ListenerCallbacks.stageComplete(STAGE_VIDEO_STREAM_START);
    Limelog("done\n");

    Limelog("Starting audio stream...");
    ListenerCallbacks.stageStarting(STAGE_AUDIO_STREAM_START);
     err = startAudioStream(audioContext, arFlags);
     if (err != 0) {
         Limelog("Audio stream start failed: %d\n", err);
         ListenerCallbacks.stageFailed(STAGE_AUDIO_STREAM_START, err);
         goto Cleanup;
     }
    stage++;
    LC_ASSERT(stage == STAGE_AUDIO_STREAM_START);
    ListenerCallbacks.stageComplete(STAGE_AUDIO_STREAM_START);
    Limelog("done\n");

    Limelog("Starting input stream...");
    ListenerCallbacks.stageStarting(STAGE_INPUT_STREAM_START);
    err = startInputStream();
    if (err != 0) {
        Limelog("Input stream start failed: %d\n", err);
        ListenerCallbacks.stageFailed(STAGE_INPUT_STREAM_START, err);
        goto Cleanup;
    }
     stage++;
    LC_ASSERT(stage == STAGE_INPUT_STREAM_START);
    ListenerCallbacks.stageComplete(STAGE_INPUT_STREAM_START);
    Limelog("done\n");

    // Wiggle the mouse a bit to wake the display up
    LiSendMouseMoveEvent(1, 1);
    PltSleepMs(10);
    LiSendMouseMoveEvent(-1, -1);
    PltSleepMs(10);

    ListenerCallbacks.connectionStarted();

Cleanup:
    if (err != 0) {
        // Undo any work we've done here before failing
        LiStopConnection();
    }
    return err;
}

const char* LiGetLaunchUrlQueryParameters() {
    // v0 = Video encryption and control stream encryption v2
    // v1 = RTSP encryption
    return "&corever=1";
}

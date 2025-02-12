// Copyright 2021-2024 Phil Karn, KA9Q
#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#if defined(linux)
#include <bsd/string.h>
#include <byteswap.h>
#else // bsd
#define bswap_16(value) ((((value) & 0xff) << 8) | ((value) >> 8)) // hopefully gets optimized
#endif
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/stat.h>
#include <poll.h>
#include <sysexits.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <ogg/ogg.h>
#include <stdarg.h>

#include "misc.h"
#include "attr.h"
#include "multicast.h"
#include "radio.h"

// size of stdio buffer for disk I/O. 8K is probably the default, but we have this for possible tuning
#define OPUS_SAMPRATE 48000 // Opus always operates at 48 kHz virtual sample rate

// One for each session being recorded
struct session {
  struct session *prev;
  struct session *next;
  struct sockaddr sender;      // Sender's IP address and source port

  uint32_t ssrc;               // RTP stream source ID
  struct rtp_state rtp_state;

  // information obtained from status stream
  struct channel chan;
  struct frontend frontend;

  int type;                    // RTP payload type (with marker stripped)
  int channels;                // 1 (PCM_MONO) or 2 (PCM_STEREO)
  unsigned int samprate;
  enum encoding encoding;

  uint32_t next_expected_rtp_ts;
  uint16_t next_expected_rtp_seq;
  bool active;
};


int Verbose;
static char PCM_mcast_address_text[256];
static char const *Locale;
static uint32_t Ssrc; // SSRC, when manually specified

const char *App_path;
static int Input_fd,Status_fd;
static struct session *Sessions;
int Mcast_ttl;
struct sockaddr Metadata_dest_socket;

static void closedown(int a);
static void input_loop(void);
static void cleanup(void);
int session_file_init(struct session *sp);
static int close_session(struct session **spp);

static struct option Options[] = {
  {"locale", required_argument, NULL, 'l'},
  {"verbose", no_argument, NULL, 'v'},
  {"ssrc", required_argument, NULL, 'S'},
  {"version", no_argument, NULL, 'V'},
  {NULL, no_argument, NULL, 0},
};
static char Optstring[] = "l:S:vV";

int main(int argc,char *argv[]){
  App_path = argv[0];

  // Defaults
  Locale = getenv("LANG");

  int c;
  while((c = getopt_long(argc,argv,Optstring,Options,NULL)) != EOF){
    switch(c){
    case 'l':
      Locale = optarg;
      break;
    case 'S':
      {
	char *ptr;
	uint32_t x = strtol(optarg,&ptr,0);
	if(ptr != optarg)
	  Ssrc = x;
      }
      break;
    case 'v':
      Verbose++;
      break;
    case 'V':
      VERSION();
      exit(EX_OK);
    default:
      fprintf(stderr,"Usage: %s [-l locale] [-v] PCM_multicast_address\n",argv[0]);
      exit(EX_USAGE);
      break;
    }
  }
  setlocale(LC_ALL,Locale);
  if(optind >= argc){
    fprintf(stderr,"Specify PCM_mcast_address_text_address\n");
    exit(EX_USAGE);
  }
  strlcpy(PCM_mcast_address_text,argv[optind],sizeof(PCM_mcast_address_text));
  setlinebuf(stderr); // In case we're redirected to a file

  // Set up input socket for multicast data stream from front end
  {
    struct sockaddr sock;
    char iface[1024];
    resolve_mcast(PCM_mcast_address_text,&sock,DEFAULT_RTP_PORT,iface,sizeof(iface),0);
    Input_fd = listen_mcast(&sock,iface);
    resolve_mcast(PCM_mcast_address_text,&sock,DEFAULT_STAT_PORT,iface,sizeof(iface),0);
    Status_fd = listen_mcast(&sock,iface);
  }
  if(Input_fd == -1){
    fprintf(stderr,"Can't set up PCM input, exiting\n");
    exit(EX_IOERR);
  }
  int n = 1 << 20; // 1 MB
  if(setsockopt(Input_fd,SOL_SOCKET,SO_RCVBUF,&n,sizeof(n)) == -1)
    perror("setsockopt");

  // Graceful signal catch
  signal(SIGPIPE,closedown); // Should catch the --exec or --stdout receiving process terminating
  signal(SIGINT,closedown);
  signal(SIGKILL,closedown);
  signal(SIGQUIT,closedown);
  signal(SIGTERM,closedown);

  atexit(cleanup);
  input_loop(); // Doesn't return
  exit(EX_OK);
}

double time_diff(struct timespec x,struct timespec y){
  double xd = (1.0e-9 * x.tv_nsec) + x.tv_sec;
  double yd = (1.0e-9 * y.tv_nsec) + y.tv_sec;
  return xd - yd;
}

static const char *wd_time(){
  struct timespec now;
  clock_gettime(CLOCK_REALTIME,&now);
  struct tm *tm_now = gmtime(&now.tv_sec);;
  static char timebuff[256];
  size_t s = strftime(timebuff,sizeof(timebuff),"%a %d %b %Y %H:%M:%S",tm_now);
  if (s) {
    snprintf(&timebuff[s],sizeof(timebuff)-s,".%03lu UTC", now.tv_nsec / 1000000);
  }
  return timebuff;
}

void wd_log(int v_level,const char *format,...) __attribute__ ((format (printf, 2, 3)));

void wd_log(int v_level,const char *format,...){
  if (Verbose < v_level){
    return;
  }
  va_list args;
  va_start(args,format);
  char *msg;
  if (vasprintf(&msg,format,args) >= 0){
    fputs(wd_time(),stderr);
    fputs(msg,stderr);
    FREE(msg);
  }
  va_end(args);
}

static void wd_write(struct session * const sp,int buffer_size){
  // track sequence numbers and report if we see one out of order
  if (sp->active && (sp->rtp_state.seq != sp->next_expected_rtp_seq)){
    wd_log(0,": Weird rtp.seq: expected %u, received %u (delta %d) on SSRC %d\n",
           sp->next_expected_rtp_seq,
           sp->rtp_state.seq,
           (int16_t)(sp->rtp_state.seq - sp->next_expected_rtp_seq),
           sp->ssrc);
  }
  sp->next_expected_rtp_seq = sp->rtp_state.seq + 1;    // next expected RTP sequence number

  int framesize = sp->channels * (sp->encoding == F32LE ? 4 : 2); // bytes per sample time
  int frames = buffer_size / framesize;  // One frame per sample time

  // is the rtp.timestamp value what we expect from the last datagram
  if (sp->active && (sp->rtp_state.timestamp != sp->next_expected_rtp_ts)){
    wd_log(0,": Weird rtp.timestamp: expected %u, received %u (delta %d) on SSRC %d\n",
           sp->next_expected_rtp_ts,
           sp->rtp_state.timestamp,
           sp->rtp_state.timestamp - sp->next_expected_rtp_ts,
           sp->ssrc);
  }
  sp->next_expected_rtp_ts = sp->rtp_state.timestamp + frames;    // next expected RTP timestamp
  sp->active = true;
}

static void wd_state_machine(struct session * const sp,int buffer_size){
  if (NULL == sp){
    return;
  }

  wd_write(sp,buffer_size);
}

static void closedown(int a){
  if(Verbose)
    fprintf(stderr,"%s: caught signal %d: %s\n",App_path,a,strsignal(a));

  cleanup();
  exit(EX_OK);  // Will call cleanup()
}

// Read both data and status from RTP network socket, assemble blocks of samples
// Doing both in one thread avoids a lot of synchronization problems with the session structure, since both write it
static void input_loop(){
  struct sockaddr sender;
  while(true){
    // Receive status or data
    struct pollfd pfd[2];
    pfd[0].fd = Input_fd;
    pfd[1].fd = Status_fd;
    pfd[1].events = pfd[0].events = POLLIN;
    pfd[1].revents = pfd[0].revents = 0;

    int const n = poll(pfd,sizeof(pfd)/sizeof(pfd[0]),1000); // Wait 1 sec max so we can scan active session list
    if(n < 0)
      break; // error of some kind - should we exit or retry?

    if(pfd[1].revents & (POLLIN|POLLPRI)){
      // Process status packet
      uint8_t buffer[PKTSIZE];
      socklen_t socksize = sizeof(sender);
      int length = recvfrom(Status_fd,buffer,sizeof(buffer),0,&sender,&socksize);
      if(length <= 0){    // ??
	perror("recvfrom");
	goto statdone; // Some sort of error
      }
      if(buffer[0] != STATUS)
	goto statdone;
      // Extract just the SSRC to see if the session exists
      // NB! Assumes same IP source address *and UDP source port* for status and data
      // This is only true for recent versions of radiod, after the switch to unconnected output sockets
      // But older versions don't send status on the output channel anyway, so no problem
      struct channel chan;
      memset(&chan,0,sizeof(chan));
      struct frontend frontend;
      memset(&frontend,0,sizeof(frontend));
      decode_radio_status(&frontend,&chan,buffer+1,length-1);

      if(Ssrc != 0 && chan.output.rtp.ssrc != Ssrc)
	goto statdone; // Unwanted session, but still clear any data packets

      // Look for existing session
      // Everything must match, or we create a different session & file
      struct session *sp;
      for(sp = Sessions;sp != NULL;sp=sp->next){
	if(sp->ssrc == chan.output.rtp.ssrc
	   && sp->type == chan.output.rtp.type
	   && address_match(&sp->sender,&sender)
	   && getportnumber(&sp->sender) == getportnumber(&sender))
	  break;
      }
      if(sp != NULL && sp->prev != NULL){
	// Move to top of list to speed later lookups
	sp->prev->next = sp->next;
	if(sp->next != NULL)
	  sp->next->prev = sp->prev;
	sp->next = Sessions;
	sp->prev = NULL;
	Sessions = sp;
      }
      if(sp == NULL){
	// Create session and initialize
	sp = calloc(1,sizeof(*sp));
	if(sp == NULL)
	  goto statdone; // unlikely

	sp->prev = NULL;
	sp->next = Sessions;
	if(sp->next)
	  sp->next->prev = sp;
	Sessions = sp;
      }
      // Wav can't change channels or samprate mid-stream, so if they're going to change we
      // should probably add an option to force stereo and/or some higher sample rate.
      // OggOpus can restart the stream with the new parameters, so it's not a problem
      sp->ssrc = chan.output.rtp.ssrc;
      sp->type = chan.output.rtp.type;
      sp->channels = chan.output.channels;
      sp->encoding = chan.output.encoding;
      sp->samprate = (sp->encoding == OPUS) ? OPUS_SAMPRATE : chan.output.samprate;
      memcpy(&sp->sender,&sender,sizeof(sp->sender));
      memcpy(&sp->chan,&chan,sizeof(sp->chan));
      memcpy(&sp->frontend,&frontend,sizeof(sp->frontend));
    }
    statdone:;
    if(pfd[0].revents & (POLLIN|POLLPRI)){
      uint8_t buffer[PKTSIZE];
      socklen_t socksize = sizeof(sender);
      int size = recvfrom(Input_fd,buffer,sizeof(buffer),0,&sender,&socksize);
      if(size <= 0){    // ??
	perror("recvfrom");
	goto datadone; // Some sort of error, quit
      }
      if(size < RTP_MIN_SIZE)
	goto datadone; // Too small for RTP, ignore

      struct rtp_header rtp;
      uint8_t *dp = (uint8_t *)ntoh_rtp(&rtp,buffer);
      if(rtp.pad){
	// Remove padding
	size -= dp[size-1];
	rtp.pad = 0;
      }
      if(size <= 0)
	goto datadone; // Bogus RTP header

      size -= (dp - buffer);

      if(Ssrc != 0 && rtp.ssrc != Ssrc)
	goto datadone;

      // Sessions are defined by the tuple {ssrc, payload type, sending IP address, sending UDP port}
      struct session *sp;
      for(sp = Sessions;sp != NULL;sp=sp->next){
	if(sp->ssrc == rtp.ssrc
	   && sp->type == rtp.type
	   && address_match(&sp->sender,&sender)
	   && getportnumber(&sp->sender) == getportnumber(&sender))
	  break;
      }
      // If a matching session is not found, drop packet and wait for first status packet to create it
      // This is a change from previous behavior without status when the first RTP packet would create it
      // This is the only way to work with dynamic payload types since we need the status info
      // We can't even process RTP timestamps without knowing how big a frame is
      if(sp == NULL)
	goto datadone;

      if(sp->prev != NULL){
	// Move to top of list to speed later lookups
	sp->prev->next = sp->next;
	if(sp->next != NULL)
	  sp->next->prev = sp->prev;
	sp->next = Sessions;
	sp->prev = NULL;
	Sessions = sp;
      }

      sp->rtp_state.seq = rtp.seq;
      sp->rtp_state.timestamp = rtp.timestamp;
      wd_state_machine(sp,size);
      goto datadone;

    } // end of packet processing
    datadone:;
  }
}

static void cleanup(void){
  while(Sessions){
    // Flush and close each write stream
    // Be anal-retentive about freeing and clearing stuff even though we're about to exit
    struct session *next_s = Sessions->next;
    close_session(&Sessions); // Sessions will be NULL
    Sessions = next_s;
  }
}

static int close_session(struct session **spp){
  if(spp == NULL)
    return -1;
  struct session *sp = *spp;

  if(sp == NULL)
    return -1;

  if(sp->prev)
    sp->prev->next = sp->next;
  else
    Sessions = sp->next;
  if(sp->next)
    sp->next->prev = sp->prev;
  FREE(sp);
  return 0;
}


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <getopt.h>

struct auxi_t {
  // 'auxi' chunk to pass center frequency to SDR Console
  // http://www.moetronix.com/files/spectravue.pdf had some details on this chunk
  // and https://sdrplay.com/resources/IQ/ft4.zip
  // has some .wav files with a center frequency that SDR Console can use
  char AuxID[4];
  int32_t AuxSize;
  int16_t StartYear;
  int16_t StartMon;
  int16_t StartDOW;
  int16_t StartDay;
  int16_t StartHour;
  int16_t StartMinute;
  int16_t StartSecond;
  int16_t StartMillis;
  int16_t StopYear;
  int16_t StopMon;
  int16_t StopDOW;
  int16_t StopDay;
  int16_t StopHour;
  int16_t StopMinute;
  int16_t StopSecond;
  int16_t StopMillis;
  int32_t CenterFrequency;
  char AuxUknown[128];
};

struct __attribute__((packed)) wav_debug_1 {
  uint8_t version;
  long long write_ns[2];
  long long usb_transfer_ns[2];
  long long fft_ns[2];
  uint64_t usb_samples[2];
  uint32_t fft_jobnum[2];
  uint32_t rtp_ts[2];
  uint16_t rtp_seq[2];
};

struct chunk_t {
  const char *name;
  int offset;
};

static const struct chunk_t chunk_table[] = {
  {"RIFF",0x00},
  {"WAVEfmt ",0x08},
  {"fact",0x3c},
  {"auxi",0x48},
  {"data",0xf4},
};

static struct option options[] = {
  {"usage",no_argument,NULL,'h'},
  {"help",no_argument,NULL,'h'},
  {"verbose",no_argument,NULL,'v'},
  {"version",no_argument,NULL,'V'},
  {NULL,no_argument,NULL,0},
};

int verbose;

static char optstring[] = "hvV";

static int usage(const char *s){
  printf("Usage: %s [-v|--verbose] [-V|--version] [-h|--usage|--help] wavfile\n",s);
  return 0;
}

int main(int argc,char *argv[]){
  int c;
  while((c = getopt_long(argc,argv,optstring,options,NULL)) != EOF){
    switch(c){
    case 'v':
      verbose++;
      break;

    case 'h':
      return usage(argv[0]);

    case 'V':
      printf("wsprdaemon wav file debug info parser v0.1\n");
      return 0;
    }
  }

  if (optind >= argc){
    return usage(argv[0]);
  }

  const char *in_filename = argv[optind];
  FILE *f = fopen(in_filename,"rb");
  if (!f){
    printf("Error: Can't open file %s\n",argv[optind]);
    return -1;
  }

  char buff[256];
  size_t s = fread(buff,1,sizeof(buff),f);
  if (s < sizeof(buff)){
    printf("Error: file too small?!\n");
  }

  for(unsigned i = 0; i < sizeof(chunk_table) / sizeof(chunk_table[0]); ++i){
    if (0 != strncmp(chunk_table[i].name,&buff[chunk_table[i].offset],strlen(chunk_table[i].name))){
      printf("Error: expected %s chunk at file offset %d\n",
             chunk_table[i].name,
             chunk_table[i].offset);
      return -1;
    }
  }

  // all the headers are where we expect, so read the auxi stuff
  struct auxi_t *header = (struct auxi_t*)&buff[0x48];
  struct wav_debug_1 *w = (struct wav_debug_1*)(void*)header->AuxUknown;
  if (1 != w->version){
    printf("Error: expected wav file debug info version 1, but file appears to contain debug info version %d\n",w->version);
    return -1;
  }

  if (verbose){
    printf("debug info version: %d\n",w->version);
    printf("write_ns[] = %lld %lld %.3f ms\n",w->write_ns[0],w->write_ns[1],1.0e-6 * (w->write_ns[1] - w->write_ns[0]));
    printf("usb_ns[] = %lld %lld %.3f ms\n",w->usb_transfer_ns[0],w->usb_transfer_ns[1],1.0e-6 * (w->usb_transfer_ns[1] - w->usb_transfer_ns[0]));
    printf("fft_ns[] = %lld %lld %.3f ms\n",w->fft_ns[0],w->fft_ns[1],1.0e-6 * (w->fft_ns[1] - w->fft_ns[0]));
    printf("usb_samples[] = %lu %lu  %lu\n",w->usb_samples[0],w->usb_samples[1],w->usb_samples[1] - w->usb_samples[0]);
    printf("fft_jobnum[] = %u %u %u\n",w->fft_jobnum[0],w->fft_jobnum[1],w->fft_jobnum[1] - w->fft_jobnum[0]);
    printf("rtp_ts[] = %u %u %u\n",w->rtp_ts[0],w->rtp_ts[1],w->rtp_ts[1] - w->rtp_ts[0]);
    printf("rtp_seq[] = %u %u %u\n",w->rtp_seq[0],w->rtp_seq[1],w->rtp_seq[1] - w->rtp_seq[0]);
    printf("FFT delay: %.3f %.3f ms\n",1.0e-6 * (w->write_ns[0]-w->fft_ns[0]),1.0e-6 * (w->write_ns[1]-w->fft_ns[1]));
    printf("USB delay: %.3f %.3f ms\n",1.0e-6 * (w->write_ns[0]-w->usb_transfer_ns[0]),1.0e-6 * (w->write_ns[1]-w->usb_transfer_ns[1]));
  }
  else{
    printf("FFT delay: %.3f ms\n",((w->write_ns[0] - w->fft_ns[0]) / 1000000.0));
  }
  fclose(f);
}

#define main base_wpa_suite
#include "polaris-wifi-wpa-test.c"
#undef main
static uint8_t group_messages[9][640],group_gtk[16],next_gtk[16];
static unsigned group_length[9];
static int group_message(unsigned n)
{
    CHECK(pwpa_receive(&wpa,group_messages[n],group_length[n],++ticks)==1&&wpa.phase==2);
    int result=1;for(unsigned k=0;k<64&&wpa.phase==2;k++)result=pwpa_step(&wpa,++ticks);return result;
}
int main(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!base_wpa_suite(2,argv));FILE*f=fopen(argv[2],"rb");CHECK(f);uint8_t magic[8];
    CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPG001",8)&&fread(group_gtk,1,16,f)==16&&fread(next_gtk,1,16,f)==16);
    for(unsigned n=0;n<9;n++){group_length[n]=number(f);CHECK(group_length[n]<=640&&fread(group_messages[n],1,group_length[n],f)==group_length[n]);}CHECK(fgetc(f)==EOF&&!fclose(f));
    setup();message1();CHECK(message3(2)==2&&pwpa_sent(&wpa,++ticks,1)==1&&pwpa_install(&wpa,++ticks)&&pwpa_installed(&wpa,++ticks,1)==1);
    CHECK(group_message(0)==5&&wpa.phase==6&&wpa.group_ready&&!wpa.pending&&wpa.authorized&&!memcmp(wpa.gtk,gtk,16)&&wpa.rsc[0]==1);
    CHECK(pwpa_group_installed(&wpa,++ticks,1)==-1); /* returns -1 before actual issue */
    CHECK(pwpa_group_install(&wpa,++ticks)&&!pwpa_group_install(&wpa,++ticks));
    CHECK(!pwpa_receive(&wpa,group_messages[0],group_length[0],++ticks)&&wpa.group_issued);
    CHECK(pwpa_group_installed(&wpa,++ticks,1)==1&&wpa.group_generation==1&&wpa.pending==6&&wpa.gtk_id==2&&!memcmp(wpa.gtk,group_gtk,16)&&wpa.rsc[0]==7);
    CHECK(wpa.reply_bytes==group_length[1]&&!memcmp(wpa.reply,group_messages[1],group_length[1])&&pwpa_sent(&wpa,++ticks,1)==1);
    CHECK(pwpa_receive(&wpa,group_messages[0],group_length[0],++ticks)==1&&wpa.pending==6&&!wpa.group_ready&&!wpa.group_issued&&wpa.group_generation==1);
    CHECK(!memcmp(wpa.reply,group_messages[1],group_length[1])&&pwpa_sent(&wpa,++ticks,1)==1&&wpa.rsc[0]==7);
    CHECK(group_message(2)==2&&!wpa.group_ready&&wpa.group_generation==1&&wpa.rsc[0]==7&&!memcmp(wpa.reply,group_messages[3],group_length[3])&&pwpa_sent(&wpa,++ticks,1)==1);
    for(unsigned n=4;n<7;n++)CHECK(group_message(n)==1&&!wpa.group_ready&&!wpa.pending&&wpa.group_generation==1&&wpa.rsc[0]==7);
    CHECK(group_message(7)==5&&pwpa_group_install(&wpa,++ticks)&&pwpa_group_installed(&wpa,++ticks,1)==1);
    CHECK(wpa.group_generation==2&&wpa.gtk_id==2&&!memcmp(wpa.gtk,next_gtk,16)&&wpa.rsc[0]==3&&!memcmp(wpa.reply,group_messages[8],group_length[8]));
    CHECK(pwpa_sent(&wpa,++ticks,1)==1);unsigned bad=wpa.bad;
    CHECK(pwpa_receive(&wpa,group_messages[0],group_length[0],++ticks)==1&&wpa.bad==bad+1&&!wpa.pending);
    pwpa_stop(&wpa);CHECK(!wpa.authorized&&!pwpa_nonzero(wpa.group_key,16));
    printf("PASS %u four-way/GTK renewal checks; SOFTWARE only\n",checks);return 0;
}

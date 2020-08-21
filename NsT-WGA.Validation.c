/*
        Name: NsT - Windows Genuine Advantage Validation Patch (1.5.532.0)
   Copyright: [N]eo [S]ecurity [T]eam
      Author: HaCkZaTaN
        Date: 20060606
     Version: 0.5
   Disclamer: This info is provided ONLY as a Proof-Of-Concept, so
                the author and all nst members can not be responsability
                of the use that you take with this PoC.
                USE IT AT YOUR OWN RISK!
Description: This patch is designed as a PoC of a bypass method
              which demostrate, the easly way to get free updates
                just patching some bytes to the dll that certificates
                the MS Windows Copy.
                Updated To 1.5.532.0
*/

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

typedef struct bytepair BYTEPAIR;

struct bytepair
{
  long offset;
  unsigned char old;
  unsigned char new;
};

static const BYTEPAIR byte_pairs[6]=
{
  {0x303BA, 0x90, 0x8B},
  {0x303BB, 0x90, 0x85},
  {0x303BC, 0x6A, 0x60},
  {0x303BD, 0x00, 0xFF},
  {0x303BE, 0x58, 0xFF},
  {0x303BF, 0x90, 0xFF},
};

int main()
{
  unsigned short i;
  int LegitCheckControl;
  unsigned char check;

  printf("\nt臂 北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北躙n"
           "\t臂哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌弑踈n"
           "\t臂                                                         臂\n"
           "\t臂           [N]eo [S]ecurity [T]eam - [N][S][T]           臂\n"
           "\t臂       Windows Genuine Advantage Validation Patch        臂\n"
           "\t臂                       Version 0.5                       臂\n"
           "\t臂                                                         臂\n"
           "\t臂                  LegitCheckControl.dll                  臂\n"
           "\t臂                  *** For Version: ***                   臂\n"
           "\t臂                     -> 1.5.532.0                        臂\n"
           "\t臂                                                         臂\n"
           "\t臂 圹圹圹?  圹圹圹?  圹圹   圹 圹 圹圹  圹圹圹圹圹圹圹圹 臂\n"
           "\t臂 圹? 圹圹  圹  圹   圹?  圹 圹? 圹? 圹?圹 圹 圹 圹?臂\n"
           "\t臂 圹? ?圹?圹  圹   圹?  圹      圹? 圹?   圹    圹?臂\n"
           "\t臂 圹? ?圹?圹  圹   圹?  圹圹    圹? 圹?   圹    圹?臂\n"
           "\t臂 圹? ?  圹圹  圹   圹?   圹圹? 圹? 圹?   圹    圹?臂\n"
           "\t臂 圹? ?   圹? 圹   圹?     圹? 圹? 圹?   圹    圹?臂\n"
           "\t臂 圹? ?   圹? 圹   圹?  圹 圹? 圹? 圹?   圹    圹?臂\n"
           "\t臂 圹?圹?   圹  圹   圹?  ?圹    圹? 圹?  圹圹   圹?臂\n"
           "\t臂 圹?           圹   圹?          圹? 圹?         圹?臂\n"
           "\t臂 圹圹          圹?  圹圹         圹圹  圹圹        圹圹 臂\n"
           "\t臂                                                         臂\n"
           "\t臂           This is my last work as NST member            臂\n"
           "\t臂            Dedicated to all my Teammates:               臂\n"
           "\t臂                                                         臂\n"
           "\t臂                 [ HaCkZaTaN  ..... ]                    臂\n"
           "\t臂                 [ Paisterist ..... ]                    臂\n"
           "\t臂                 [ Daemon21   ..... ]                    臂\n"
           "\t臂                 [ Link       ..... ]                    臂\n"
           "\t臂                 [ K4P0       ..... ]                    臂\n"
           "\t臂                 [ g30rg3_x   ..... ]                    臂\n"           
           "\t臂                                                         臂\n"
           "\t臂           [ http://www.neosecurityteam.net  ]           臂\n"
           "\t臂           [ http://www.neosecurityteam.info ]           臂\n"
           "\t臂                                                         臂\n"
           "\t臂 北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北踈n"
           "\t 哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌哌\n\n");
  
  getchar();
  printf("Verifying LegitCheckControl.dll...");
  LegitCheckControl = open("LegitCheckControl.dll", O_RDWR);

  if(LegitCheckControl == -1)
  {
     printf(" FAIL\n");
     perror("LegitCheckControl.dll");
     getchar();
     return 1;
  } else printf(" DONE\n");

  printf("Validating LegitCheckControl.dll...");
  
  for(i = 0; i < 6; i++)
  {
        if((lseek(LegitCheckControl, byte_pairs[i].offset,SEEK_SET) == -1))
        {
            perror(" ! lseek");
            getchar();
            return 1;
        }
        
        if((read(LegitCheckControl,&check,1) != 1))
        {
            perror(" ! read");
            getchar();
            return 1;
        }
        
        if(check != byte_pairs[i].old)
        {
           fprintf(stderr, "\n -> There is a problem validating the DLL, Seems to be Already Patched or Version Not Supported\n\n -> Aborting...");
           getchar();
           return 1;
        }
  }
  
  printf(" DONE\n");
  printf("Applying patch...");
  
  for(i=0; i<6; i++)
  {
           if((lseek(LegitCheckControl, byte_pairs[i].offset,SEEK_SET) == -1))
           {
               perror(" ! lseek");
               getchar();
               return 1;
           }
           
           if((write(LegitCheckControl, &byte_pairs[i].new, 1) != 1))
           {
               perror(" ! write");
               getchar();
               return 1;
           }
  }
  
  printf(" DONE\n");
  close(LegitCheckControl);
  printf("Patch Completed!!!\nEnjoy The Updates :)\n");
  printf("\nHit Any Key to Exit");
  getchar();
  return 0;
}

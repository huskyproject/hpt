/* source to implement dir.h for ibm VisualAge C++
*/
#ifdef __IBMC__
#include <dir.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

DIR      *opendir( const char * dirName)
{
   DIR *temp;
   FILEFINDBUF3 findBuffer;
   ULONG findCount;
   char path[255];

   findCount = 1;
   temp = (DIR *) malloc(sizeof(DIR));
   temp->d_hdir = HDIR_SYSTEM;
   temp->d_first = 1;

   // make sure: <path>\*
   strcpy(path, dirName);
   if (dirName[strlen(dirName)-1] != '\\') strcat(path, "\\");
   strcat(path, "*");

   if (NO_ERROR != DosFindFirst(path, &(temp->d_hdir), FILE_NORMAL, &findBuffer, sizeof(findBuffer), &findCount ,FIL_STANDARD)) {
      free(temp);
      return NULL;
   }

   // fill struct
   temp->d_attr = findBuffer.attrFile;
   strcpy(temp->d_name,findBuffer.achName);
   temp->d_size = findBuffer.cbFile;
//   temp->d_date = findBuffer.fdateLastWrite;
//   temp->d_time = findBuffer.ftimeLastWrite;

   return temp;
}

struct dirent *readdir( DIR * dir)
{
   APIRET rc;
   FILEFINDBUF3 findBuffer;
   ULONG findCount = 1;

   if (1 == dir->d_first) {
      dir->d_first = 0;         // if d_first == 1 then the struct is already filled from DosFindFirst
   } else {
      rc = DosFindNext(dir->d_hdir, &findBuffer, sizeof(findBuffer), &findCount);
      if (rc != NO_ERROR) return NULL;

      // fill struct
      dir->d_attr = findBuffer.attrFile;
      strcpy(dir->d_name,findBuffer.achName);
      dir->d_size = findBuffer.cbFile;
//      dir->d_date = findBuffer.fdateLastWrite;
//      dir->d_time = findBuffer.ftimeLastWrite;
   } /* endif */

   return dir;
}

int      closedir( DIR * dir)
{
   APIRET rc;

   rc = DosFindClose(dir->d_hdir);
   free (dir);
   if (rc == NO_ERROR) return 0;
   else return (-1);
}
#endif


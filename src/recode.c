#include <fcommon.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <recode.h>

CHAR *intab  = NULL;

CHAR *outtab = NULL;

VOID initCharsets(VOID)
{
	int i;
	intab		= (CHAR *) malloc(sizeof(CHAR) * 256);
	outtab	= (CHAR *) malloc(sizeof(CHAR) * 256);
	for (i = 0; i < 256; i++) intab[i] = outtab[i] = (CHAR) i;
}

VOID doneCharsets(VOID)
{
	free(intab);
	free(outtab);
}

VOID recodeToInternalCharset(CHAR *string)
{
INT c;

    if (string != NULL) {

	for( ; *string != '\000'; string++ )
	    {
	    c=((INT)*string)&0xFF;
        *string = intab[c];
        }

    }

}

VOID recodeToTransportCharset(CHAR *string)
{
INT c;

    if (string != NULL) {

	for( ; *string != '\000'; string++ )
	    {
	    c=((INT)*string)&0xFF;
        *string = outtab[c];
        }

    }

}


INT ctoi(char *s)
{
	char *foo;
	INT res = strtoul(s, &foo, 0);
	if (*foo)	/* parse error */
		return 0;
	return res;
}

void getctab(CHAR *dest, UCHAR *charMapFileName )
{
FILE *fp;
UCHAR buf[512],*p,*q;
INT in,on,count;
	INT line;

	if ((fp=fopen(charMapFileName,"r")) == NULL)
	 {
		fprintf(stderr,"getctab: cannot open mapchan file \"%s\"\n", charMapFileName);
		return ;
	 }

	count=0;	 
	line = 0;
	while (fgets((char*)buf,sizeof(buf),fp))
	{
		line++;
		p=(unsigned char *)strtok((char*)buf," \t\n#");
		q=(unsigned char *)strtok(NULL," \t\n#");

		if (p && q)
		{
			in = ctoi((char *)p);
			if (in > 255) {
				fprintf(stderr, "getctab: %s: line %d: char val too big\n", charMapFileName, line);
				break;
			}

			on=ctoi((char *)q);
			if (in && on) 
			 if( count++ < 256 ) dest[in]=on; 
			 else 
			  { 
			  fprintf(stderr,"getctab: char map table \"%s\" is big\n",charMapFileName); 
			  break;
			  }
		}
	}
	fclose(fp);
	return ;
}

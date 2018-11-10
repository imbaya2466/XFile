#include "XELF.h"
#include "mian.h"
#include <iostream>
using namespace std;


int main(int argc, char** argv)
{
	if (argc==1)
	{
		cout << "you should input a file!\n";
		return 0;
	}
	
	errno_t err;
	FILE * fd;
	 err=fopen_s(&fd,argv[1], "rb");
	if (fd==NULL|| err!=0)
	{
		cout << "file error\n";
		return 0;
	}
	fseek(fd, 0L, SEEK_END);
	long length;
	length = ftell(fd);
	void *fileCache = malloc(length);
	if (fileCache==NULL)
	{
		fclose(fd);
		cout << "malloc error\n";
		return 0;
	}
	fseek(fd, 0L, SEEK_SET);
	fread(fileCache, length, 1, fd);
	fclose(fd);


	char mag[5];
	memcpy(mag, fileCache, 4);
	mag[4] = 0;
	if (strcmp(mag, ELFMAG) == 0)
	{
		doELF(fileCache);
	}
	else
	{
		// ´ýÌí¼ÓÎÄ¼þ
	}

}

void putHelpELF()
{
	cout << "h:header\n"
		"s:section\n"
		"p:program header\n"
		"S:dynsym\n"
		"q:quit\n";
}
void doELF(void * file)
{
	char command;
	XELF elf(file);
	while (true)
	{
		cout << ">>";
		cin >> command;
		if (command=='H')
		{
			putHelpELF();
		} 
		else if (command=='q')
		{
			return;
		}
		else if(command=='h')
		{
			elf.showHeader();

		}
		else if (command == 's')
		{
			elf.showSectionList();
		}
		else if(command=='p')
		{
			elf.showSegmentList();
		}
		else if (command=='S')
		{
			elf.showdynsym();
		}
		else
		{
			putHelpELF();
		}



	}








}